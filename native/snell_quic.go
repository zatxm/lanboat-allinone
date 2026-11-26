package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func snellQUICInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(b[1:])
	if version != 1 && version != 0x6b3343cf {
		return false
	}
	n := int(b[5])
	if n > 20 || 6+n >= len(b) {
		return false
	}
	m := int(b[6+n])
	if m > 20 || 7+n+m > len(b) {
		return false
	}
	return version == 1 && b[0]&0x30 == 0 || version == 0x6b3343cf && b[0]&0x30 == 0x10
}
func snellQUICSeal(password, address string, b []byte) ([]byte, error) {
	salt := quicPadding()[:16]
	// Authentication envelopes must not look like raw QUIC datagrams.
	salt[0] &^= 0x40
	return snellQUICSealSalt(password, address, b, salt)
}
func snellQUICSealSalt(password, address string, b, salt []byte) ([]byte, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	number, e := strconv.ParseUint(port, 10, 16)
	if e != nil || number == 0 || len(host) == 0 || len(host) > 255 {
		return nil, errors.New("invalid Snell QUIC destination")
	}
	plain := append([]byte{1, 1, 0, byte(len(host))}, host...)
	plain = binary.BigEndian.AppendUint16(plain, uint16(number))
	plain = append(plain, b...)
	if len(plain)+55 > 65507 {
		return nil, errors.New("Snell QUIC packet too large")
	}
	stream := newSnellConn(nil, password, "5", "", nil)
	aead, e := stream.aead(salt)
	if e != nil {
		return nil, e
	}
	header := []byte{4, 0, 0, 0, 0, byte(len(plain) >> 8), byte(len(plain))}
	var nonce [12]byte
	out := aead.Seal(salt, nonce[:], header, nil)
	nonce[0] = 1
	return aead.Seal(out, nonce[:], plain, nil), nil
}
func snellQUICOpen(password string, b []byte, replay *replayWindow) (string, []byte, error) {
	if len(b) < 61 {
		return "", nil, io.ErrUnexpectedEOF
	}
	stream := newSnellConn(nil, password, "5", "", nil)
	aead, e := stream.aead(b[:16])
	if e != nil {
		return "", nil, e
	}
	var nonce [12]byte
	header, e := aead.Open(nil, nonce[:], b[16:39], nil)
	if e != nil {
		return "", nil, e
	}
	if !bytes.Equal(header[:3], []byte{4, 0, 0}) {
		return "", nil, errors.New("invalid Snell QUIC header")
	}
	padding, size := int(binary.BigEndian.Uint16(header[3:])), int(binary.BigEndian.Uint16(header[5:]))
	if padding+size+55 != len(b) {
		return "", nil, errors.New("invalid Snell QUIC record length")
	}
	nonce[0] = 1
	plain, e := aead.Open(nil, nonce[:], b[39:], nil)
	if e != nil {
		return "", nil, e
	}
	if e = replay.add(stream.key, b[:16]); e != nil {
		return "", nil, e
	}
	plain = plain[:size]
	if len(plain) < 6 || !bytes.Equal(plain[:3], []byte{1, 1, 0}) {
		return "", nil, errors.New("invalid Snell QUIC request")
	}
	n := int(plain[3])
	if n == 0 || 4+n+2 > len(plain) {
		return "", nil, errors.New("invalid Snell QUIC hostname")
	}
	port := binary.BigEndian.Uint16(plain[4+n:])
	if port == 0 {
		return "", nil, errors.New("invalid Snell QUIC port")
	}
	payload := plain[6+n:]
	if !snellQUICInitial(payload) {
		return "", nil, errors.New("Snell UDP requires a QUIC Initial")
	}
	return portAddress(string(plain[4:4+n]), port), payload, nil
}

type snell5PacketConn struct {
	runtime                     *Runtime
	out                         Outbound
	address                     string
	ctx                         context.Context
	cancel                      context.CancelFunc
	mu, wmu                     sync.Mutex
	raw                         net.Conn
	quic                        bool
	wake                        chan struct{}
	ready                       chan struct{}
	readDeadline, writeDeadline time.Time
	err                         error
	once                        sync.Once
}

func (r *Runtime) snell5PacketClient(o Outbound, address string) (net.Conn, error) {
	if _, e := encodeAddress(address); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(r.ctx)
	return r.own(&snell5PacketConn{runtime: r, out: o, address: address, ctx: ctx, cancel: cancel, ready: make(chan struct{}), wake: make(chan struct{}, 1)})
}
func (c *snell5PacketConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if e := c.ctx.Err(); e != nil {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	raw, err := c.raw, c.err
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if raw == nil {
		ctx, cancel := context.WithTimeout(c.ctx, handshakeTimeout)
		defer cancel()
		quic := snellQUICInitial(b)
		network := "tcp"
		if quic {
			network = "udp"
		}
		raw, err = c.runtime.endpoint(ctx, c.out, network)
		if err == nil && !quic {
			if d, ok := ctx.Deadline(); ok {
				raw.SetDeadline(d)
			}
			if cfg := c.runtime.clientTLS[c.out.Tag]; cfg != nil {
				cfg, err = c.runtime.outboundTLS(ctx, c.out)
				if err == nil {
					var secured tlsStream
					secured, err = handshakeTLS(ctx, raw, cfg, c.out.TLS)
					if err == nil {
						raw = secured
					}
				}
			}
			if err == nil {
				original := raw
				raw, err = dialSnellObfs(raw, c.out)
				if err == nil {
					raw, err = snellClient(raw, c.out, c.address, true, &c.runtime.replay)
				}
				if err != nil {
					original.Close()
				}
			}
		}
		c.mu.Lock()
		if err == nil {
			if c.ctx.Err() != nil {
				raw.Close()
				err = net.ErrClosed
			} else {
				c.raw, c.quic = raw, quic
				raw.SetReadDeadline(c.readDeadline)
				raw.SetWriteDeadline(c.writeDeadline)
			}
		}
		c.err = err
		close(c.ready)
		c.mu.Unlock()
		if err != nil {
			if raw != nil {
				raw.Close()
			}
			return 0, err
		}
	}
	if c.quic && snellQUICInitial(b) {
		packet, e := snellQUICSeal(c.out.Password, c.address, b)
		if e != nil {
			return 0, e
		}
		if _, e = raw.Write(packet); e != nil {
			return 0, e
		}
		return len(b), nil
	}
	return raw.Write(b)
}
func (c *snell5PacketConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		d := c.readDeadline
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !d.IsZero() {
			timer = time.NewTimer(max(0, time.Until(d)))
			timeout = timer.C
		}
		ready := false
		var e error
		select {
		case <-c.ready:
			ready = true
		case <-c.ctx.Done():
			e = net.ErrClosed
		case <-c.wake:
		case <-timeout:
			e = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if e != nil {
			return 0, e
		}
		if ready {
			c.mu.Lock()
			raw, err := c.raw, c.err
			c.mu.Unlock()
			if err != nil {
				return 0, err
			}
			return raw.Read(b)
		}
	}
}
func (c *snell5PacketConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		if c.raw != nil {
			c.raw.Close()
		}
		c.mu.Unlock()
	})
	return nil
}
func (c *snell5PacketConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw != nil {
		return c.raw.LocalAddr()
	}
	return &net.UDPAddr{}
}
func (c *snell5PacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(c.out.Server), Port: int(c.out.ServerPort)}
}
func (c *snell5PacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	signalQUIC(c.wake)
	if c.raw != nil {
		return c.raw.SetReadDeadline(t)
	}
	return nil
}
func (c *snell5PacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.raw != nil {
		return c.raw.SetWriteDeadline(t)
	}
	return nil
}
func (c *snell5PacketConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (r *Runtime) serveSnellQUIC(in Inbound, packet net.PacketConn) {
	flows := newUDPFlows(r)
	defer flows.Close()
	type destination struct {
		address string
		at      time.Time
		cids    map[string]bool
	}
	targets := map[string]destination{}
	buffer := make([]byte, 65535)
	for {
		n, from, e := packet.ReadFrom(buffer)
		if e != nil {
			return
		}
		data := buffer[:n]
		if n < 21 {
			continue
		}
		key := from.String()
		d, exists := targets[key]
		prefix := string(data[1:min(len(data), 9)])
		if !exists || !d.cids[prefix] {
			address, plain, err := snellQUICOpen(in.Password, data, &r.replay)
			if err == nil {
				data = plain
				if !exists || address != d.address {
					d = destination{address: address, at: time.Now(), cids: map[string]bool{}}
				}
				if !exists && len(targets) >= 256 {
					for k, v := range targets {
						if time.Since(v.at) > r.udpTimeoutFor(in.Tag, udpTimeout) {
							delete(targets, k)
						}
					}
					if len(targets) >= 256 {
						continue
					}
				}
			} else if !exists || len(data) < 21 || data[0]&0x40 == 0 || snellQUICInitial(data) {
				continue
			}
			if len(d.cids) < 32 {
				d.cids[string(data[1:min(len(data), 9)])] = true
			}
		}

		d.at = time.Now()
		targets[key] = d
		q := request{origin: r.socketOrigin(from, packet.LocalAddr()), network: "udp", inbound: in.Tag, source: key, address: d.address}
		_ = flows.send(key+"/"+d.address, q, data, func(b []byte, _ string) error { _, e := packet.WriteTo(b, from); return e })
	}
}
