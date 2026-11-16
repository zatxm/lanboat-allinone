package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"hash"
	"net"
	"strings"
	"sync"
	"time"
)

type shadowFlight struct {
	mu                sync.Mutex
	version           int
	password          string
	hello, random     []byte
	negotiated        uint16
	transcript, proof hash.Hash
	digests           [4][8]byte
	records           int
}

func (f *shadowFlight) process(frame []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.version == 2 {
		f.transcript.Write(frame)
		copy(f.digests[f.records%4][:], shadowSum(f.transcript, 8))
		f.records++
	}
	if frame[0] == 22 && (len(f.hello) > 0 || frame[5] == 2) && (f.negotiated == 0 || f.negotiated == tls.VersionTLS13) {
		f.hello = append(f.hello, frame[5:]...)
		if len(f.hello) > 65536 {
			return nil, errors.New("ShadowTLS ServerHello exceeds64KiB")
		}
		if len(f.hello) >= 4 {
			size := 4 + (int(f.hello[1])<<16 | int(f.hello[2])<<8 | int(f.hello[3]))
			if len(f.hello) >= size {
				random, version, e := shadowServerHello(f.hello[:size])
				if e != nil {
					return nil, e
				}
				f.random = bytes.Clone(random)
				f.negotiated = version
				f.proof = shadowMAC(f.password, f.random)
				f.hello = nil
			}
		}
	}
	if f.version == 3 && frame[0] == 23 {
		if f.proof == nil {
			return nil, errors.New("ShadowTLS application data before ServerHello")
		}
		mask := sha256.Sum256(append([]byte(f.password), f.random...))
		body := frame[5:]
		for i := range body {
			body[i] ^= mask[i%32]
		}
		f.proof.Write(body)
		tag := shadowSum(f.proof, 4)
		out := make([]byte, len(frame)+4)
		copy(out, frame[:5])
		out[3], out[4] = byte((len(out)-5)>>8), byte(len(out)-5)
		copy(out[5:], tag)
		copy(out[9:], body)
		return out, nil
	}
	return frame, nil
}
func (f *shadowFlight) v2Auth(body []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(body) < 8 {
		return false
	}
	valid := false
	for i := 0; i < min(4, f.records); i++ {
		valid = hmac.Equal(body[:8], f.digests[i][:]) || valid
	}
	return valid
}
func (f *shadowFlight) state() ([]byte, uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Clone(f.random), f.negotiated
}
func shadowTLSResolvers(inbounds []Inbound) (out []resolverReference) {
	for _, in := range inbounds {
		if in.TLS.realityEnabled() && in.TLS.Reality.Handshake != nil {
			out = append(out, in.TLS.Reality.Handshake.DomainResolver)
		}
		if in.Handshake != nil {
			out = append(out, in.Handshake.DomainResolver)
		}
		for _, h := range in.HandshakeForServerName {
			out = append(out, h.DomainResolver)
		}
	}
	return
}
func (x ShadowTLSOptions) backend(name string, authed bool) ShadowTLSHandshake {
	for k, h := range x.HandshakeForServerName {
		if strings.EqualFold(k, name) {
			return h
		}
	}
	h := *x.Handshake
	if name != "" && (x.WildcardSNI == "all" || x.WildcardSNI == "authed" && authed) {
		h.Server = name
		h.ServerPort = 443
	}
	return h
}
func (r *Runtime) shadowHandshakeBackend(h ShadowTLSHandshake) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(r.ctx, handshakeTimeout)
	defer cancel()
	if h.DomainResolver != "" {
		options := h.DomainResolver.options()
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, options.Server)
		ctx = context.WithValue(ctx, dnsQueryOptionsKey{}, options)
	}
	c, e := r.endpoint(ctx, Outbound{Server: h.Server, ServerPort: h.ServerPort, Detour: h.Detour}, "tcp")
	if e == nil {
		c.SetDeadline(time.Now().Add(handshakeTimeout))
	}
	return c, e
}
func (r *Runtime) shadowAccept(c net.Conn, in Inbound) (net.Conn, error) {
	v := shadowVersion(in.Version)
	wire, hello, e := shadowHello(c)
	if e != nil {
		return nil, e
	}
	name, _, _ := clientHelloSNI(hello)
	if name != "" && !shadowHost(name) {
		return nil, errors.New("invalid ShadowTLS SNI")
	}
	password := in.Password
	authed := v != 3
	if v == 3 {
		for _, u := range in.Users {
			if shadowHelloAuth(hello, u.Password) {
				password = u.Password
				authed = true
				break
			}
		}
	}
	backend := in.ShadowTLSOptions.backend(name, authed)
	cover, e := r.shadowHandshakeBackend(backend)
	if e != nil {
		return nil, e
	}
	defer cover.Close()
	if e = writeAll(cover, wire); e != nil {
		return nil, e
	}
	if !authed {
		r.relay(c, cover)
		return nil, nil
	}
	flight := &shadowFlight{version: v, password: password, transcript: shadowMAC(password, nil)}
	// The cover reader always finishes (or discards) a whole record before handover.
	done := make(chan error, 1)
	go func() {
		finish := func(e error) {
			if e != nil {
				_ = c.SetReadDeadline(time.Now())
			}
			done <- e
		}
		var b [5 + shadowRecordLimit]byte
		ccs := false
		for {
			frame, e := shadowReadRecord(cover, b[:])
			if e != nil {
				finish(e)
				return
			}
			out, e := flight.process(frame)
			if e == nil {
				e = writeAll(c, out)
			}
			if e != nil {
				finish(e)
				return
			}
			if v == 1 {
				if frame[0] == 20 {
					ccs = true
				} else if ccs && frame[0] == 22 {
					finish(nil)
					return
				}
			}
		}
	}()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			cover.Close()
			<-done
		}
	}
	defer stop()
	b := make([]byte, 5+shadowRecordLimit)
	ccs := false
	attempts := 0
	var clientMAC hash.Hash
	for {
		frame, e := shadowReadRecord(c, b)
		if e != nil {
			return nil, e
		}
		if v == 1 {
			if e = writeAll(cover, frame); e != nil {
				return nil, e
			}
			if frame[0] == 20 {
				ccs = true
			} else if ccs && frame[0] == 22 {
				select {
				case e = <-done:
					stopped = true
				case <-r.ctx.Done():
					return nil, net.ErrClosed
				}
				if e != nil {
					return nil, e
				}
				c.SetDeadline(time.Now().Add(handshakeTimeout))
				return c, nil
			}
			continue
		}
		if frame[0] == 23 {
			body := frame[5:]
			if v == 2 && attempts < 16 && flight.v2Auth(body) {
				stop()
				c.SetDeadline(time.Now().Add(handshakeTimeout))
				return &shadowStream{Conn: c, version: v, readBuf: b, readPending: body[8:]}, nil
			}
			if v == 3 {
				if clientMAC == nil {
					random, version := flight.state()
					if len(random) > 0 {
						if in.StrictMode && version != tls.VersionTLS13 {
							return nil, errors.New("ShadowTLS strict mode requires TLS1.3")
						}
						clientMAC = shadowMAC(password, append(random, 'C'))
					}
				}
				if clientMAC != nil {
					next, ok := shadowProbe(clientMAC, body)
					if ok {
						next.Write(body[:4])
						random, _ := flight.state()
						stop()
						c.SetDeadline(time.Now().Add(handshakeTimeout))
						return &shadowStream{Conn: c, version: v, readBuf: b, readPending: body[4:], readMAC: next, writeMAC: shadowMAC(password, append(random, 'S'))}, nil
					}
				}
			}
			attempts++
			if attempts == 2 {
				_ = c.SetDeadline(time.Time{})
				_ = cover.SetDeadline(time.Time{})
			}
		}
		if e = writeAll(cover, frame); e != nil {
			return nil, e
		}
	}
}
func (r *Runtime) serveShadowTLS(in Inbound, c net.Conn) error {
	stream, e := r.shadowAccept(c, in)
	if e != nil || stream == nil {
		return e
	}
	for _, target := range r.config.Inbounds {
		if target.Tag == in.Detour {
			return r.serve(target, stream)
		}
	}
	return errors.New("ShadowTLS inbound detour disappeared")
}
