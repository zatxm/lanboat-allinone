package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const masqueH2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

type masqueHTTPContext struct{}

// Hide TLS-only methods so net/http detects cleartext HTTP2 prior knowledge.
type masquePlainConn struct{ net.Conn }

type masqueHTTPListener struct {
	net.Listener
	r       *Runtime
	tls     *tls.Config
	options TLSOptions
}

func (l *masqueHTTPListener) Accept() (net.Conn, error) {
	raw, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	l.r.mu.Lock()
	if l.r.closed {
		l.r.mu.Unlock()
		raw.Close()
		return nil, net.ErrClosed
	}
	l.r.workers.Add(1)
	l.r.mu.Unlock()
	c := &masqueHTTPWire{Conn: raw, ctx: l.r.ctx, decoder: masqueHPACK{limit: 4096}, session: newMasqueHTTPSession(l.r.ctx), done: make(chan struct{})}
	if l.tls != nil {
		c.tls = serverTLSConnection(raw, l.tls, l.options)
		c.Conn = c.tls
	}
	c.reader = bufio.NewReaderSize(c.Conn, 4096)
	go func() { defer l.r.workers.Done(); <-c.session.done; c.session.close(); c.session.workers.Wait() }()
	if c.tls == nil {
		return &masquePlainConn{c}, nil
	}
	return c, nil
}

// Translate Extended CONNECT only at the standard-library HTTP2 boundary.
// Go retains HPACK response coding, stream multiplexing and flow control.
type masqueHTTPWire struct {
	net.Conn
	tls          tlsConnection
	ctx          context.Context
	session      *masqueSession
	reader       *bufio.Reader
	once         sync.Once
	err          error
	h2           bool
	pending      []byte
	decoder      masqueHPACK
	writeMu      sync.Mutex
	writePending []byte
	closeOnce    sync.Once
	client       bool
	done         chan struct{}
	peerSettings chan struct{}
	settingsOnce sync.Once
	extended     atomic.Bool
	prefaceSent  bool
	frameBuffer  []byte
	stopContext  func() bool
}

func (c *masqueHTTPWire) initialize() {
	if c.client {
		c.h2 = true
		return
	}
	c.Conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if c.tls != nil {
		if c.err = c.tls.HandshakeContext(c.ctx); c.err != nil {
			return
		}
		c.h2 = c.tls.ConnectionState().NegotiatedProtocol == "h2"
	} else {
		var prefix []byte
		prefix, c.err = c.reader.Peek(3)
		if c.err != nil {
			return
		}
		c.h2 = bytes.Equal(prefix, []byte("PRI"))
	}
	if c.h2 {
		prefix := make([]byte, len(masqueH2Preface))
		_, c.err = io.ReadFull(c.reader, prefix)
		if c.err == nil && !bytes.Equal(prefix, []byte(masqueH2Preface)) {
			c.err = errors.New("invalid MASQUE HTTP2 preface")
		}
		if c.err == nil {
			c.pending = prefix
		}
	}
	c.Conn.SetDeadline(time.Now().Add(handshakeTimeout))
}
func masqueH2Frame(kind, flags byte, id uint32, payload []byte) []byte {
	out := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), kind, flags}
	out = binary.BigEndian.AppendUint32(out, id)
	return append(out, payload...)
}
func (c *masqueHTTPWire) frame() ([]byte, error) {
	var h [9]byte
	if _, e := io.ReadFull(c.reader, h[:]); e != nil {
		return nil, e
	}
	n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
	if n > 16384 {
		return nil, errors.New("MASQUE HTTP2 frame exceeds advertised size")
	}
	if cap(c.frameBuffer) < 9+n {
		c.frameBuffer = make([]byte, 9+16384)
	}
	b := c.frameBuffer[:9+n]
	copy(b, h[:])
	_, e := io.ReadFull(c.reader, b[9:])
	return b, e
}
func (c *masqueHTTPWire) headers(first []byte) ([]byte, error) {
	id := binary.BigEndian.Uint32(first[5:9])
	if id&0x7fffffff == 0 {
		return nil, errors.New("HTTP2 HEADERS on stream zero")
	}
	firstFlags := first[4]
	flags := firstFlags
	payload, e := masqueHeaderFragment(first)
	if e != nil {
		return nil, e
	}
	block := append([]byte{}, payload...)
	for flags&4 == 0 {
		next, e := c.frame()
		if e != nil {
			return nil, e
		}
		if next[3] != 9 || binary.BigEndian.Uint32(next[5:9]) != id {
			return nil, errors.New("interleaved HTTP2 header block")
		}
		flags = next[4]
		block = append(block, next[9:]...)
		if len(block) > 1<<20 {
			return nil, errors.New("compressed HTTP2 header exceeds limit")
		}
	}
	fields, e := c.decoder.decode(block)
	if e != nil {
		return nil, e
	}
	scheme := "http"
	if c.tls != nil {
		scheme = "https"
	}
	for _, field := range fields {
		if field[0] == ":scheme" && field[1] != scheme {
			return nil, errors.New("MASQUE scheme does not match connection security")
		}
	}
	block, e = masqueRewriteHeaders(fields)
	if e != nil {
		return nil, e
	}
	return masqueHeaderFrames(id, firstFlags&1, block), nil
}
func (c *masqueHTTPWire) Read(b []byte) (int, error) {
	c.once.Do(c.initialize)
	if c.err != nil {
		return 0, c.err
	}
	if !c.h2 {
		return c.reader.Read(b)
	}
	if len(b) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		frame, e := c.frame()
		if e != nil {
			return 0, e
		}
		if c.client && frame[3] == 4 && frame[4]&1 == 0 && binary.BigEndian.Uint32(frame[5:9]) == 0 {
			for p := 9; p+6 <= len(frame); p += 6 {
				if binary.BigEndian.Uint16(frame[p:p+2]) == 8 {
					c.extended.Store(binary.BigEndian.Uint32(frame[p+2:p+6]) == 1)
				}
			}
			c.settingsOnce.Do(func() { close(c.peerSettings) })
		}
		if !c.client && frame[3] == 1 {
			frame, e = c.headers(frame)
			if e != nil {
				return 0, e
			}
		}
		c.pending = frame
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *masqueHTTPWire) Write(b []byte) (int, error) {
	if c.client {
		return c.clientWrite(b)
	}
	c.once.Do(c.initialize)
	if c.err != nil {
		return 0, c.err
	}
	if !c.h2 {
		return c.Conn.Write(b)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writePending = append(c.writePending, b...)
	if len(c.writePending) > 1<<20 {
		return 0, errors.New("MASQUE HTTP2 output exceeds limit")
	}
	offset := 0
	for len(c.writePending)-offset >= 9 {
		input := c.writePending[offset:]
		n := int(input[0])<<16 | int(input[1])<<8 | int(input[2])
		if n > 1<<20-9 {
			return 0, errors.New("MASQUE HTTP2 output frame exceeds limit")
		}
		if n > len(input)-9 {
			break
		}
		frame := input[:9+n]
		if frame[3] == 4 && frame[4]&1 == 0 && binary.BigEndian.Uint32(frame[5:9]) == 0 {
			payload := append([]byte{}, frame[9:]...)
			payload = binary.BigEndian.AppendUint16(payload, 8)
			payload = binary.BigEndian.AppendUint32(payload, 1)
			frame = masqueH2Frame(4, frame[4], 0, payload)
		}
		if e := writeAll(c.Conn, frame); e != nil {
			return 0, e
		}
		offset += 9 + n
	}
	copy(c.writePending, c.writePending[offset:])
	c.writePending = c.writePending[:len(c.writePending)-offset]
	return len(b), nil
}
func (c *masqueHTTPWire) Close() error {
	c.closeOnce.Do(func() {
		c.Conn.Close()
		if c.stopContext != nil {
			c.stopContext()
		}
		close(c.done)
		if c.session != nil {
			c.session.cancel()
		}
	})
	return nil
}

func (c *masqueHTTPWire) ConnectionState() tls.ConnectionState {
	if s, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return s.ConnectionState()
	}
	return tls.ConnectionState{}
}
func newMasqueHTTP2Client(conn net.Conn, ctx context.Context) *masqueHTTPWire {
	c := &masqueHTTPWire{Conn: conn, client: true, ctx: ctx, reader: bufio.NewReaderSize(conn, 4096), decoder: masqueHPACK{limit: 4096}, peerSettings: make(chan struct{}), done: make(chan struct{})}
	c.stopContext = context.AfterFunc(ctx, func() { conn.Close() })
	return c
}
func (c *masqueHTTPWire) clientWrite(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.writePending = append(c.writePending, b...)
	if len(c.writePending) > 1<<20 {
		return 0, errors.New("MASQUE HTTP2 output exceeds limit")
	}
	offset := 0
	if !c.prefaceSent {
		if len(c.writePending) < len(masqueH2Preface) {
			return len(b), nil
		}
		if !bytes.Equal(c.writePending[:len(masqueH2Preface)], []byte(masqueH2Preface)) {
			return 0, errors.New("invalid HTTP2 client preface")
		}
		if e := writeAll(c.Conn, []byte(masqueH2Preface)); e != nil {
			return 0, e
		}
		offset = len(masqueH2Preface)
		c.prefaceSent = true
	}
	for len(c.writePending)-offset >= 9 {
		input := c.writePending[offset:]
		n := int(input[0])<<16 | int(input[1])<<8 | int(input[2])
		if n > 1<<20-9 {
			return 0, errors.New("HTTP2 output frame exceeds limit")
		}
		if len(input) < 9+n {
			break
		}
		frame := input[:9+n]
		consumed := 9 + n
		if frame[3] == 1 {
			id := binary.BigEndian.Uint32(frame[5:9])
			flags := frame[4]
			firstFlags := flags
			block, e := masqueHeaderFragment(frame)
			if e != nil {
				return 0, e
			}
			block = append([]byte{}, block...)
			complete := true
			for flags&4 == 0 {
				if len(input)-consumed < 9 {
					complete = false
					break
				}
				next := input[consumed:]
				size := int(next[0])<<16 | int(next[1])<<8 | int(next[2])
				if size > 16384 {
					return 0, errors.New("HTTP2 CONTINUATION exceeds limit")
				}
				if len(next) < 9+size {
					complete = false
					break
				}
				if next[3] != 9 || binary.BigEndian.Uint32(next[5:9]) != id {
					return 0, errors.New("interleaved HTTP2 output header")
				}
				flags = next[4]
				block = append(block, next[9:9+size]...)
				consumed += 9 + size
			}
			if !complete {
				break
			}
			fields, e := c.decoder.decode(block)
			if e != nil {
				return 0, e
			}
			block, extended, e := masqueClientHeaders(fields)
			if e != nil {
				return 0, e
			}
			if extended {
				timer := time.NewTimer(handshakeTimeout)
				select {
				case <-c.peerSettings:
				case <-c.ctx.Done():
					timer.Stop()
					return 0, c.ctx.Err()
				case <-c.done:
					timer.Stop()
					return 0, net.ErrClosed
				case <-timer.C:
					return 0, errors.New("MASQUE HTTP2 settings timeout")
				}
				timer.Stop()
				if !c.extended.Load() {
					return 0, errors.New("MASQUE peer disabled Extended CONNECT")
				}
			}
			frame = masqueHeaderFrames(id, firstFlags&1, block)
		}
		if e := writeAll(c.Conn, frame); e != nil {
			return 0, e
		}
		offset += consumed
	}
	copy(c.writePending, c.writePending[offset:])
	c.writePending = c.writePending[:len(c.writePending)-offset]
	return len(b), nil
}
func masqueHeaderFragment(frame []byte) ([]byte, error) {
	flags := frame[4]
	payload := frame[9:]
	if flags&8 != 0 {
		if len(payload) == 0 || int(payload[0]) >= len(payload) {
			return nil, errors.New("invalid HTTP2 header padding")
		}
		payload = payload[1 : len(payload)-int(payload[0])]
	}
	if flags&0x20 != 0 {
		if len(payload) < 5 {
			return nil, errors.New("truncated HTTP2 priority")
		}
		payload = payload[5:]
	}
	return payload, nil
}
func masqueHeaderFrames(id uint32, flags byte, block []byte) []byte {
	var out []byte
	kind := byte(1)
	for len(block) > 0 {
		n := min(len(block), 16384)
		end := byte(0)
		if n == len(block) {
			end = 4
		}
		out = append(out, masqueH2Frame(kind, flags|end, id, block[:n])...)
		block = block[n:]
		kind = 9
		flags = 0
	}
	if out == nil {
		out = masqueH2Frame(1, flags|4, id, nil)
	}
	return out
}

func (c *masqueHTTPWire) HandshakeContext(ctx context.Context) error {
	c.once.Do(c.initialize)
	return c.err
}
