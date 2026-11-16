package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type ocTLS12 struct {
	writeLimit                              int
	onRekey                                 func(uint64)
	hasReadDeadline, deadlineKnown          bool
	position, size                          int
	readDeadline, socketDeadline, nextRekey time.Time
	interval                                time.Duration
	certificate                             *tls.Certificate
	frame                                   [16709]byte
	reader                                  *bufio.Reader
	enabled                                 atomic.Bool
	net.Conn
	config                             *tls.Config
	server                             bool
	readMu, writeMu, mu                sync.Mutex
	state                              tls.ConnectionState
	readKey, writeKey                  *ocTLS12Cipher
	master, clientRandom, serverRandom []byte
	clientHello, serverHello           []byte
	clientVerify, serverVerify         []byte
	pending                            *ocTLS12Handshake
	data, handshake                    []byte
	queue                              [][]byte
	queued                             int
	closed, writeClosed                bool
	secure, ems                        bool
	generation                         atomic.Uint64
}

type ocTLS12Handshake struct {
	done  chan struct{}
	err   error
	hello []byte
	timer *time.Timer
}

func newOCTLS12(raw net.Conn, cfg *tls.Config, state tls.ConnectionState, w *ocTLS12Initial) (*ocTLS12, error) {
	c := &ocTLS12{Conn: raw, config: cfg, server: w.server, state: state, master: bytes.Clone(w.master), clientRandom: bytes.Clone(w.clientRandom), serverRandom: bytes.Clone(w.serverRandom), clientHello: w.clientHello, serverHello: w.serverHello, clientVerify: w.finished[0], serverVerify: w.finished[1]}
	if len(w.localCertificate) > 0 {
		c.certificate = w.certificate
		if c.certificate == nil {
			for i := range cfg.Certificates {
				if len(cfg.Certificates[i].Certificate) > 0 && bytes.Equal(cfg.Certificates[i].Certificate[0], w.localCertificate) {
					c.certificate = &cfg.Certificates[i]
					break
				}
			}
		}
		if c.certificate == nil || len(c.certificate.Certificate) == 0 || !bytes.Equal(c.certificate.Certificate[0], w.localCertificate) {
			return nil, errors.New("CSTP TLS initial signing identity unavailable")
		}
	}
	c.readKey, c.writeKey = w.keys[1], w.keys[0]
	if c.server {
		c.readKey, c.writeKey = w.keys[0], w.keys[1]
	}
	_, ext, e := ocTLS12ParseHello(c.serverHello, false)
	if e != nil {
		return nil, e
	}
	_, c.secure = ext[0xff01]
	_, c.ems = ext[23]
	return c, nil
}
func (c *ocTLS12) Handshake() error                           { return nil }
func (c *ocTLS12) HandshakeContext(ctx context.Context) error { return ctx.Err() }
func (c *ocTLS12) NetConn() net.Conn                          { return c.Conn }
func (c *ocTLS12) ConnectionState() tls.ConnectionState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}
func (c *ocTLS12) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || !c.ems || length < 0 || length > 65535 || len(context) > 65535 {
		return nil, errors.New("invalid CSTP TLS exporter")
	}
	switch label {
	case "client finished", "server finished", "master secret", "key expansion":
		return nil, errors.New("reserved TLS exporter label")
	}
	seed := append(bytes.Clone(c.clientRandom), c.serverRandom...)
	if context != nil {
		seed = binary.BigEndian.AppendUint16(seed, uint16(len(context)))
		seed = append(seed, context...)
	}
	return ocDTLSPRF(ocTLS12Hash(c.state.CipherSuite), c.master, label, seed, length), nil
}
func (c *ocTLS12) Close() error {
	err := c.Conn.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		clear(c.master)
		if h := c.pending; h != nil {
			h.timer.Stop()
			h.err = net.ErrClosed
			close(h.done)
			c.pending = nil
		}
	}
	return err
}
func (c *ocTLS12) send(kind byte, data []byte) error {
	for len(data) > 0 {
		n := min(len(data), 16384)
		if c.writeLimit != 0 {
			n = min(n, c.writeLimit)
		}
		wire, err := c.writeKey.seal(kind, data[:n])
		if err != nil {
			return err
		}
		if err = writeAll(c.Conn, wire); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
func (c *ocTLS12) record() (byte, []byte, error) {
	if c.reader == nil {
		c.reader = bufio.NewReaderSize(c.Conn, 32<<10)
	}
	c.mu.Lock()
	err := c.setReadDeadline()
	c.mu.Unlock()
	if err != nil {
		return 0, nil, err
	}
	if c.size == 0 {
		for c.position < 5 {
			n, e := c.reader.Read(c.frame[c.position:5])
			c.position += n
			if e != nil {
				return 0, nil, e
			}
		}
		n := int(binary.BigEndian.Uint16(c.frame[3:5]))
		limit := 16408
		if c.readKey.cbc != nil {
			limit = c.readKey.cbc.key.BlockSize() + 16384 + c.readKey.cbc.mac.Size() + 256
		}
		if n > limit || n < 16 || c.frame[1] != 3 || c.frame[2] != 3 {
			return 0, nil, errors.New("invalid CSTP TLS1.2 record header")
		}
		c.size = 5 + n
	}
	for c.position < c.size {
		n, e := c.reader.Read(c.frame[c.position:c.size])
		c.position += n
		if e != nil {
			return 0, nil, e
		}
	}
	kind := c.frame[0]
	b, e := c.readKey.open(c.frame[:c.size])
	c.position, c.size = 0, 0
	return kind, b, e
}

func (c *ocTLS12) setReadDeadline() error {
	if !c.hasReadDeadline && c.nextRekey.IsZero() {
		return nil
	}
	deadline := c.readDeadline
	if c.pending == nil && !c.nextRekey.IsZero() && (deadline.IsZero() || c.nextRekey.Before(deadline)) {
		deadline = c.nextRekey
	}
	if c.deadlineKnown && deadline.Equal(c.socketDeadline) {
		return nil
	}
	c.deadlineKnown = true
	c.socketDeadline = deadline
	return c.Conn.SetReadDeadline(deadline)
}
func (c *ocTLS12) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.hasReadDeadline = true
	return c.setReadDeadline()
}
func (c *ocTLS12) SetDeadline(t time.Time) error {
	if e := c.SetReadDeadline(t); e != nil {
		return e
	}
	return c.Conn.SetWriteDeadline(t)
}
func (c *ocTLS12) scheduleRekey(interval time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.interval = interval
	c.nextRekey = time.Now().Add(interval)
}
func (c *ocTLS12) rekeyDue() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pending == nil && !c.nextRekey.IsZero() && !time.Now().Before(c.nextRekey) && (c.readDeadline.IsZero() || time.Now().Before(c.readDeadline))
}
func (c *ocTLS12) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		c.writeMu.Lock()
		c.mu.Lock()
		closed, h := c.closed || c.writeClosed, c.pending
		c.mu.Unlock()
		if closed {
			c.writeMu.Unlock()
			return total, net.ErrClosed
		}
		if h != nil {
			c.writeMu.Unlock()
			<-h.done
			if h.err != nil {
				return total, h.err
			}
			continue
		}
		n := min(len(p), 16384)
		if c.writeLimit != 0 {
			n = min(n, c.writeLimit)
		}
		err := c.send(23, p[:n])
		c.writeMu.Unlock()
		if err != nil {
			c.Close()
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (c *ocTLS12) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.writeClosed {
		return net.ErrClosed
	}
	if c.pending != nil {
		return errors.New("CSTP TLS renegotiation in progress")
	}
	c.writeClosed = true
	return c.send(21, []byte{1, 0})
}
func (c *ocTLS12) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for empty := 0; empty < 128; empty++ {
		if len(c.data) > 0 {
			n := copy(p, c.data)
			c.data = c.data[n:]
			return n, nil
		}
		c.mu.Lock()
		pending := c.pending != nil
		c.mu.Unlock()
		if !pending && len(c.queue) > 0 {
			c.data = c.queue[0]
			c.queue = c.queue[1:]
			c.queued -= len(c.data)
			continue
		}
		if c.rekeyDue() {
			c.writeMu.Lock()
			_, err := c.startRekey()
			c.writeMu.Unlock()
			if err != nil {
				c.Close()
				return 0, err
			}
		}
		kind, data, err := c.record()
		if err != nil {
			if os.IsTimeout(err) && c.rekeyDue() {
				continue
			}
			c.Close()
			return 0, err
		}
		switch kind {
		case 23:
			if len(c.handshake) > 0 {
				c.Close()
				return 0, errors.New("interleaved CSTP TLS handshake")
			}
			c.mu.Lock()
			pending = c.pending != nil
			c.mu.Unlock()
			if pending {
				if len(c.queue) >= 128 || c.queued+len(data) > 256<<10 {
					c.Close()
					return 0, errors.New("CSTP TLS pending data exceeds limit")
				}
				c.queue = append(c.queue, bytes.Clone(data))
				c.queued += len(data)
			} else {
				c.data = data
			}
		case 22:
			c.handshake = append(c.handshake, data...)
			if len(c.handshake) > 256<<10 {
				c.Close()
				return 0, errors.New("CSTP TLS handshake exceeds limit")
			}
			if len(c.handshake) < 4 || len(c.handshake) < 4+int(readUint24(c.handshake[1:4])) {
				continue
			}
			if _, err = c.begin(); err != nil {
				c.Close()
				return 0, err
			}
			c.writeMu.Lock()
			err = c.renegotiatePeer()
			c.writeMu.Unlock()
			if err != nil {
				c.Close()
				return 0, err
			}
			empty = 0
		case 21:
			if len(data) != 2 || data[0] != 1 && data[0] != 2 {
				c.Close()
				return 0, errors.New("invalid CSTP TLS alert")
			}
			if bytes.Equal(data, []byte{1, 0}) {
				c.Close()
				return 0, io.EOF
			}
			c.Close()
			return 0, fmt.Errorf("CSTP TLS alert %d", data[1])
		default:
			c.Close()
			return 0, errors.New("unexpected CSTP TLS record")
		}
	}
	c.Close()
	return 0, errors.New("too many empty CSTP TLS records")
}
func (c *ocTLS12) begin() (*ocTLS12Handshake, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.writeClosed {
		return nil, net.ErrClosed
	}
	if c.pending != nil {
		return c.pending, nil
	}
	if !c.enabled.Load() || !c.secure || !c.ems {
		return nil, fmt.Errorf("CSTP TLS rekey unavailable: authenticated=%t secure_renegotiation=%t ems=%t", c.enabled.Load(), c.secure, c.ems)
	}
	h := &ocTLS12Handshake{done: make(chan struct{})}
	h.timer = time.AfterFunc(5*time.Second, func() { c.Close() })
	c.pending = h
	return h, nil
}
func (c *ocTLS12) renegotiate(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	c.writeMu.Lock()
	h, err := c.startRekey()
	c.writeMu.Unlock()
	if err != nil {
		c.Close()
		return err
	}
	select {
	case <-h.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return h.err
	case <-ctx.Done():
		c.Close()
		return ctx.Err()
	}
}

func (c *ocTLS12) startRekey() (*ocTLS12Handshake, error) {
	c.mu.Lock()
	previous := c.pending
	c.mu.Unlock()
	h, err := c.begin()
	if err == nil && previous == nil {
		if c.server {
			err = c.send(22, stMessage(0, nil))
		} else {
			h.hello, err = c.makeClientHello()
			if err == nil {
				err = c.send(22, h.hello)
			}
		}
	}
	return h, err
}
func (c *ocTLS12) renegotiatePeer() error {
	h, err := c.begin()
	if err != nil {
		return err
	}
	m, err := c.message()
	if err != nil {
		return err
	}
	if !c.server && m[0] == 0 {
		if len(m) != 4 {
			return errors.New("invalid TLS HelloRequest")
		}
		if h.hello == nil {
			h.hello, err = c.makeClientHello()
			if err == nil {
				err = c.send(22, h.hello)
			}
			if err != nil {
				return err
			}
		}
		m, err = c.message()
		if err != nil {
			return err
		}
	}
	if c.server {
		err = c.serverRenegotiate(m, h)
	} else {
		err = c.clientRenegotiate(m, h)
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	h.timer.Stop()
	c.pending = nil
	generation := c.generation.Add(1)
	close(h.done)
	c.mu.Unlock()
	if c.onRekey != nil {
		c.onRekey(generation)
	}
	return nil
}
func (c *ocTLS12) message() ([]byte, error) {
	for empty := 0; empty < 128; empty++ {
		if len(c.handshake) >= 4 {
			n := 4 + int(readUint24(c.handshake[1:4]))
			if n > 256<<10 {
				return nil, errors.New("CSTP TLS handshake exceeds limit")
			}
			if len(c.handshake) >= n {
				m := c.handshake[:n]
				c.handshake = c.handshake[n:]
				return m, nil
			}
		}
		kind, data, err := c.record()
		if err != nil {
			return nil, err
		}
		switch kind {
		case 22:
			c.handshake = append(c.handshake, data...)
		case 23:
			if len(c.queue) >= 128 || c.queued+len(data) > 256<<10 {
				return nil, errors.New("CSTP TLS pending data exceeds limit")
			}
			if len(c.handshake) > 0 {
				return nil, errors.New("interleaved CSTP TLS handshake")
			}
			c.queue = append(c.queue, bytes.Clone(data))
			c.queued += len(data)
		default:
			return nil, errors.New("unexpected CSTP TLS renegotiation record")
		}
	}
	return nil, errors.New("too many empty CSTP TLS handshake records")
}

func ocTLS12ParseHello(body []byte, client bool) ([]byte, map[uint16][]byte, error) {
	p := stCursor{data: body}
	if p.number(2) != tls.VersionTLS12 {
		return nil, nil, errors.New("CSTP TLS renegotiation version changed")
	}
	p.take(32)
	p.vector(1)
	if client {
		p.vector(2)
		compression := p.vector(1)
		if !bytes.Equal(compression, []byte{0}) {
			return nil, nil, errors.New("TLS compression is disabled")
		}
	} else {
		p.take(2)
		if p.number(1) != 0 {
			return nil, nil, errors.New("TLS compression is disabled")
		}
	}
	start := len(body) - len(p.data)
	ext := p.vector(2)
	if e := p.end(); e != nil {
		return nil, nil, e
	}
	values, e := stExtensions(ext)
	return body[:start], values, e
}
