package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"time"
)

type shadowPlugin struct {
	version  int
	password string
	options  ShadowTLSOptions
}

// Keep only the receive traffic secret in memory to recognize late TLS1.3
// session tickets. No key material is logged, exported or written to disk.
type shadowCoverSecret struct{ secret []byte }

func (s *shadowCoverSecret) Write(b []byte) (int, error) {
	fields := bytes.Fields(b)
	if len(fields) == 3 && bytes.Equal(fields[0], []byte("SERVER_TRAFFIC_SECRET_0")) {
		secret, e := hex.DecodeString(string(fields[2]))
		if e != nil {
			return 0, e
		}
		s.secret = secret
	}
	return len(b), nil
}

// Replay only the local TLS1.2 ClientHello's entropy. No trial handshake reaches a peer.
type shadowEntropy struct {
	saved  [][]byte
	index  int
	replay bool
}

func (r *shadowEntropy) Read(b []byte) (int, error) {
	if r.replay {
		if r.index < len(r.saved) {
			p := r.saved[r.index]
			r.index++
			if len(p) != len(b) {
				return 0, errors.New("TLS ClientHello entropy layout changed")
			}
			copy(b, p)
			return len(b), nil
		}
		return rand.Read(b)
	}
	if len(b) > 4096 || len(r.saved) > 32 {
		return 0, errors.New("TLS ClientHello entropy exceeds limit")
	}
	n, e := rand.Read(b)
	r.saved = append(r.saved, bytes.Clone(b[:n]))
	return n, e
}

type shadowHelloCapture struct {
	net.Conn
	data []byte
}

func (c *shadowHelloCapture) Read([]byte) (int, error) { return 0, io.EOF }
func (c *shadowHelloCapture) Write(b []byte) (int, error) {
	if len(c.data)+len(b) > 65536 {
		return 0, errors.New("ClientHello exceeds64KiB")
	}
	c.data = append(c.data, b...)
	return len(b), nil
}
func (c *shadowHelloCapture) SetDeadline(time.Time) error      { return nil }
func (c *shadowHelloCapture) SetReadDeadline(time.Time) error  { return nil }
func (c *shadowHelloCapture) SetWriteDeadline(time.Time) error { return nil }
func (c *shadowHelloCapture) LocalAddr() net.Addr              { return streamAddr("shadowtls-probe") }
func (c *shadowHelloCapture) RemoteAddr() net.Addr             { return streamAddr("shadowtls-probe") }
func (c *shadowHelloCapture) Close() error                     { return nil }
func shadowSignedTLS12Config(ctx context.Context, cfg *tls.Config, password string) (*tls.Config, error) {
	if cfg.MaxVersion == 0 || cfg.MaxVersion > tls.VersionTLS12 {
		return nil, errors.New("signed Go ClientHello is limited to TLS1.2")
	}
	cfg = cloneTLSConfig(cfg)
	cfg.SessionTicketsDisabled = true
	cfg.ClientSessionCache = nil
	if len(cfg.CurvePreferences) == 0 {
		cfg.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	}
	entropy := new(shadowEntropy)
	cfg.Rand = entropy
	capture := new(shadowHelloCapture)
	_ = tls.Client(capture, cfg).HandshakeContext(ctx)
	_, hello, e := shadowHello(bytes.NewReader(capture.data))
	if e != nil {
		return nil, e
	}
	sid, e := shadowSession(hello)
	if e != nil {
		return nil, e
	}
	if len(entropy.saved) < 2 || !bytes.Equal(entropy.saved[1], sid) {
		return nil, errors.New("unsupported TLS ClientHello entropy layout")
	}
	clear(sid[28:])
	h := shadowMAC(password, nil)
	h.Write(hello)
	copy(entropy.saved[1][28:], shadowSum(h, 4))
	entropy.replay = true
	return cfg, nil
}

type shadowHandshakeReader struct {
	net.Conn
	version           int
	password          string
	pending           []byte
	buffer            []byte
	hello             []byte
	random            []byte
	negotiated        uint16
	verified, bad     bool
	transcript, proof hash.Hash
}

func (c *shadowHandshakeReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		if c.buffer == nil {
			c.buffer = make([]byte, 5+shadowRecordLimit)
		}
		frame, e := shadowReadRecord(c.Conn, c.buffer)
		if e != nil {
			return 0, e
		}
		if c.version == 2 {
			c.transcript.Write(frame)
		}
		if frame[0] == 22 && (len(c.hello) > 0 || frame[5] == 2) && (c.negotiated == 0 || c.negotiated == tls.VersionTLS13) {
			c.hello = append(c.hello, frame[5:]...)
			if len(c.hello) > 65536 {
				return 0, errors.New("ServerHello exceeds64KiB")
			}
			if len(c.hello) >= 4 {
				n := 4 + (int(c.hello[1])<<16 | int(c.hello[2])<<8 | int(c.hello[3]))
				if len(c.hello) >= n {
					random, version, e := shadowServerHello(c.hello[:n])
					if e != nil {
						return 0, e
					}
					c.random = bytes.Clone(random)
					c.negotiated = version
					c.proof = shadowMAC(c.password, c.random)
					c.hello = nil
				}
			}
		}
		if c.version == 3 && frame[0] == 23 {
			if c.proof == nil {
				return 0, errors.New("ShadowTLS application data before ServerHello")
			}
			next, ok := shadowProbe(c.proof, frame[5:])
			if ok {
				c.proof = next
				c.verified = true
				mask := sha256.Sum256(append([]byte(c.password), c.random...))
				body := frame[9:]
				for i := range body {
					body[i] ^= mask[i%32]
				}
				copy(frame[5:], body)
				frame = frame[:len(frame)-4]
				frame[3], frame[4] = byte((len(frame)-5)>>8), byte(len(frame)-5)
			} else {
				c.bad = true
			}
		}
		c.pending = frame
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (r *Runtime) shadowDial(ctx context.Context, o Outbound, v int, password string, options TLSOptions) (net.Conn, error) {
	raw, e := r.endpoint(ctx, o, "tcp")
	if e != nil {
		return nil, e
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		raw.SetDeadline(deadline)
	}
	cfg := r.clientTLS[o.Tag]
	if cfg == nil {
		return nil, errors.New("ShadowTLS client TLS configuration missing")
	}
	cfg, e = prepareClientTLS(ctx, cfg, options, r.resolver)
	if e != nil {
		return nil, e
	}
	cfg = cloneTLSConfig(cfg)
	cfg.SessionTicketsDisabled = true
	cfg.ClientSessionCache = nil
	if v == 1 {
		cfg.MaxVersion = tls.VersionTLS12
	}
	if v == 3 && !options.browserEnabled() && cfg.MaxVersion > 0 && cfg.MaxVersion <= tls.VersionTLS12 {
		cfg, e = shadowSignedTLS12Config(ctx, cfg, password)
		if e != nil {
			return nil, e
		}
	}
	observed := &shadowHandshakeReader{Conn: raw, version: v, password: password, transcript: shadowMAC(password, nil)}
	var coverCipher *stRecordCipher
	var coverTLS13 *stTLS13
	defer func() {
		if coverTLS13 != nil {
			clear(coverTLS13.clientSecret)
			clear(coverTLS13.serverSecret)
			clear(coverTLS13.exporter)
		}
	}()
	if options.browserEnabled() {
		signature := ""
		if v == 3 {
			signature = password
		}
		secure, err := dialBrowserTLS(ctx, observed, cfg, options, signature)
		if err != nil {
			return nil, err
		}
		switch c := secure.(type) {
		case *realityConn:
			coverTLS13 = c.tls
			if v == 2 {
				coverCipher = c.tls.serverApp
			}
		case *ocTLS12:
			clear(c.master)
		}
	} else if v == 3 && (cfg.MaxVersion == 0 || cfg.MaxVersion >= tls.VersionTLS13) {
		coverTLS13, e = shadowTLS13(ctx, observed, cfg, options, password)
		if e != nil {
			return nil, e
		}
	} else {
		var coverSecret shadowCoverSecret
		defer func() { clear(coverSecret.secret) }()
		if v == 2 {
			cfg.KeyLogWriter = &coverSecret
		}
		secured := clientTLS(observed, cfg, options)
		if e = secured.HandshakeContext(ctx); e != nil {
			return nil, e
		}
		if v == 2 && secured.ConnectionState().Version == tls.VersionTLS13 {
			suite, err := stSuite(secured.ConnectionState().CipherSuite)
			if err != nil {
				return nil, err
			}
			if len(coverSecret.secret) != suite.hash.Size() {
				return nil, errors.New("TLS1.3 cover receive secret missing")
			}
			coverCipher, e = suite.recordCipher(coverSecret.secret)
			if e != nil {
				return nil, e
			}
		}
	}
	if v == 3 && observed.negotiated == tls.VersionTLS13 && (!observed.verified || observed.bad) {
		name := cfg.ServerName
		if name == "" {
			name = options.ServerName
		}
		if name == "" {
			name = o.Server
		}
		coverTLS13.muddle(name)
		return nil, errors.New("ShadowTLS server authentication failed")
	}

	if e = ctx.Err(); e != nil {
		return nil, e
	}
	success = true
	raw.SetDeadline(time.Time{})
	if v == 1 {
		return raw, nil
	}
	conn := &shadowStream{Conn: raw, version: v, coverCipher: coverCipher}
	if v == 2 {
		conn.firstPrefix = shadowSum(observed.transcript, 8)
	} else {
		conn.readMAC = shadowMAC(password, append(bytes.Clone(observed.random), 'S'))
		conn.writeMAC = shadowMAC(password, append(bytes.Clone(observed.random), 'C'))
		if observed.verified {
			conn.handshakeMAC = observed.proof
		}
	}
	return conn, nil
}
