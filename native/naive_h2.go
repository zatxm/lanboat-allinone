package native

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const naiveH2ConnectionWindow = 128 << 20
const naiveH2StreamWindow = 64 << 20

var errNaiveH2Draining = fmt.Errorf("Naive HTTP2 stream refused before application data: %w", net.ErrClosed)

type naiveH2Operation struct {
	headers [][2]string
	wire    []byte
	stream  *naiveH2Stream
	kind    byte
	count   int
	pooled  bool
	result  chan error
}

type naiveH2Session struct {
	encoder              chromiumHPACK
	encodeLimit          int
	conn                 net.Conn
	mu                   sync.Mutex
	streams              map[uint32]*naiveH2Stream
	next, peerConcurrent uint32
	peerWindow, send     int64
	peerHeader           uint32
	receive, consumed    int
	draining             bool
	err                  error
	done, space          chan struct{}
	control, data        chan *naiveH2Operation
	decoder              masqueHPACK
	onClose              func()
	stop                 func() bool
	settings             chan struct{}
	haveSettings         bool
	opening              chan struct{}
	readBuffer           []byte
	idle                 *time.Timer
	preamble             *naiveH2Stream
	bufferBudget         *naiveBufferBudget
}

func newNaiveH2Session(r *Runtime, conn net.Conn, preamble [][2]string) (*naiveH2Session, error) {
	if secure, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		state := secure.ConnectionState()
		if state.Version == tls.VersionTLS12 {
			switch state.CipherSuite {
			case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
			default:
				conn.Close()
				return nil, errors.New("TLS1.2 cipher is forbidden for Naive HTTP2")
			}
		}
	}
	m := &naiveH2Session{encoder: chromiumHPACK{limit: 4096}, encodeLimit: 4096, conn: conn, streams: map[uint32]*naiveH2Stream{}, peerConcurrent: 128, peerHeader: ^uint32(0), peerWindow: 65535, send: 65535, receive: naiveH2ConnectionWindow, done: make(chan struct{}), settings: make(chan struct{}), opening: make(chan struct{}, 1), space: make(chan struct{}, 1), control: make(chan *naiveH2Operation, 256), data: make(chan *naiveH2Operation, 32), decoder: masqueHPACK{limit: 4096}}
	m.decoder.max, m.decoder.headerLimit = 65536, 262144
	m.bufferBudget = &r.naiveBuffers
	m.next = 2
	m.preamble = &naiveH2Stream{session: m, id: 1, send: m.peerWindow, receive: naiveH2StreamWindow, localEnd: true, opened: true, discard: true, readWake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1), done: make(chan struct{})}
	m.streams[1] = m.preamble
	settings := chromiumH2Settings()
	initial := append([]byte(masqueH2Preface), masqueH2Frame(4, 0, 0, settings)...)
	initial = append(initial, masqueH2Frame(8, 0, 0, binary.BigEndian.AppendUint32(nil, naiveH2ConnectionWindow-65535))...)
	block := m.encoder.encode(preamble, m.encodeLimit)
	initial = append(initial, chromiumH2Preamble(block)...)
	conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	if err := writeAll(conn, initial); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetWriteDeadline(time.Time{})
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		conn.Close()
		return nil, net.ErrClosed
	}
	r.workers.Add(2)
	m.mu.Lock()
	m.idle = time.AfterFunc(90*time.Second, m.closeIdle)
	m.stop = context.AfterFunc(r.ctx, func() { m.fail(net.ErrClosed) })
	m.mu.Unlock()
	r.mu.Unlock()
	go func() { defer r.workers.Done(); m.writeLoop() }()
	go func() { defer r.workers.Done(); m.fail(m.readLoop()) }()
	return m, nil
}

func (m *naiveH2Session) closeIdle() {
	m.mu.Lock()
	empty := len(m.streams) == 0 && m.err == nil
	if empty {
		m.draining = true
	}
	m.mu.Unlock()
	if empty {
		m.fail(io.EOF)
	}
}

func (m *naiveH2Session) idleWhenEmpty() {
	if len(m.streams) == 0 && m.err == nil && !m.draining && m.idle != nil {
		m.idle.Reset(90 * time.Second)
	}
}

func (m *naiveH2Session) fail(err error) {
	m.mu.Lock()
	if m.err != nil {
		m.mu.Unlock()
		return
	}
	m.err = err
	if m.idle != nil {
		m.idle.Stop()
	}
	for _, s := range m.streams {
		if !s.remoteEnd {
			s.err = err
		}
		s.signalRead()
	}
	m.streams = nil
	close(m.done)
	callback := m.onClose
	m.mu.Unlock()
	m.conn.Close()
	if m.stop != nil {
		m.stop()
	}
	if callback != nil {
		callback()
	}
}

func (m *naiveH2Session) queue(op *naiveH2Operation) {
	select {
	case m.control <- op:
	case <-m.done:
	default:
		m.fail(errors.New("Naive HTTP2 control queue exceeded"))
	}
}

func (m *naiveH2Session) writeLoop() {
	defer func() {
		for {
			select {
			case op := <-m.data:
				m.finishOperation(op, net.ErrClosed)
			default:
				return
			}
		}
	}()
	for {
		var op *naiveH2Operation
		select {
		case <-m.done:
			return
		case op = <-m.control:
		default:
			select {
			case <-m.done:
				return
			case op = <-m.control:
			case op = <-m.data:
			}
		}
		m.mu.Lock()
		s := op.stream
		if s != nil && (s.closed && op.kind != 3 || s.localEnd && op.kind == 0) {
			m.mu.Unlock()
			m.refund(op)
			m.finishOperation(op, net.ErrClosed)
			continue
		}
		if op.kind == 1 && len(op.headers) > 0 {
			op.wire = chromiumH2Headers(s.id, m.encoder.encode(op.headers, m.encodeLimit))
		}
		if op.kind == 3 && s != nil {
			if !s.opened {
				m.mu.Unlock()
				continue
			}
			// Only DATA payload consumes credit; the DATA+RST wire length is48..72.
			if !s.localEnd && m.send >= 50 && s.send >= 50 {
				var random [1]byte
				for rand.Read(random[:]); random[0] >= 250; rand.Read(random[:]) {
				}
				n := 48 + int(random[0])%25 - 22
				padding := make([]byte, n)
				padding[0] = byte(n - 1)
				op.wire = append(masqueH2Frame(0, 9, s.id, padding), op.wire...)
				m.send -= int64(n)
				s.send -= int64(n)
			}
		}
		m.mu.Unlock()
		m.conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		err := writeAll(m.conn, op.wire)
		m.conn.SetWriteDeadline(time.Time{})
		if err == nil && s != nil {
			m.mu.Lock()
			if op.kind == 1 {
				s.opened = true
			}
			if op.kind == 0 && op.count == 0 {
				s.localEnd = true
			}
			m.mu.Unlock()
		}
		m.finishOperation(op, err)
		if err == nil && s != nil {
			m.retire(s)
		}
		if err != nil {
			m.fail(err)
			return
		}
	}
}

func (m *naiveH2Session) finishOperation(op *naiveH2Operation, err error) {
	if op.pooled {
		buffers.Put((*[32 * 1024]byte)(op.wire[:32*1024]))
	}
	if op.result != nil {
		op.result <- err
	}
}

func (m *naiveH2Session) refund(op *naiveH2Operation) {
	if op.count == 0 {
		return
	}
	m.mu.Lock()
	m.send += int64(op.count)
	op.stream.send += int64(op.count)
	for _, s := range m.streams {
		s.signalWrite()
	}
	m.mu.Unlock()
}

func (m *naiveH2Session) readLoop() error {
	first := true
	for {
		kind, flags, id, b, err := m.frame()
		if err != nil {
			return err
		}
		if first && (kind != 4 || flags&1 != 0) {
			return errors.New("Naive HTTP2 peer omitted initial SETTINGS")
		}
		first = false
		if err = m.receiveFrame(kind, flags, id, b); err != nil {
			return err
		}
	}
}

func (m *naiveH2Session) frame() (kind, flags byte, id uint32, body []byte, err error) {
	var h [9]byte
	if _, err = io.ReadFull(m.conn, h[:]); err != nil {
		return
	}
	n := int(h[0])<<16 | int(h[1])<<8 | int(h[2])
	if n > 16384 {
		err = errors.New("Naive HTTP2 frame exceeds advertised size")
		return
	}
	kind, flags, id = h[3], h[4], binary.BigEndian.Uint32(h[5:])&0x7fffffff
	if m.readBuffer == nil {
		m.readBuffer = make([]byte, 16384)
	}
	body = m.readBuffer[:n]
	_, err = io.ReadFull(m.conn, body)
	return
}

func (m *naiveH2Session) receiveFrame(kind, flags byte, id uint32, b []byte) error {
	switch kind {
	case 4:
		if id != 0 || len(b)%6 != 0 || flags&1 != 0 && len(b) != 0 {
			return errors.New("invalid Naive HTTP2 SETTINGS")
		}
		if flags&1 != 0 {
			return nil
		}
		m.mu.Lock()
		for len(b) != 0 {
			key, value := binary.BigEndian.Uint16(b), binary.BigEndian.Uint32(b[2:])
			b = b[6:]
			switch key {
			case 1:
				m.encodeLimit = int(min(value, 65536))
				m.encoder.resize(m.encodeLimit)
			case 2:
				m.mu.Unlock()
				return errors.New("server sent HTTP2 ENABLE_PUSH")
			case 3:
				m.peerConcurrent = min(value, 128)
			case 4:
				if value > 1<<31-1 {
					m.mu.Unlock()
					return errors.New("invalid Naive HTTP2 initial window")
				}
				for _, s := range m.streams {
					s.send += int64(value) - m.peerWindow
					if s.send > 1<<31-1 {
						m.mu.Unlock()
						return errors.New("Naive HTTP2 stream window overflow")
					}
					s.signalWrite()
				}
				m.peerWindow = int64(value)
			case 5:
				if value < 16384 || value > 1<<24-1 {
					m.mu.Unlock()
					return errors.New("invalid Naive HTTP2 maximum frame size")
				}
			case 6:
				m.peerHeader = value
			}
		}
		if !m.haveSettings {
			m.haveSettings = true
			close(m.settings)
		}
		m.mu.Unlock()
		select {
		case m.space <- struct{}{}:
		default:
		}
		m.queue(&naiveH2Operation{wire: masqueH2Frame(4, 1, 0, nil)})
	case 6:
		if id != 0 || len(b) != 8 {
			return errors.New("invalid Naive HTTP2 PING")
		}
		if flags&1 == 0 {
			m.queue(&naiveH2Operation{wire: masqueH2Frame(6, 1, 0, b)})
		}
	case 8:
		if len(b) != 4 || binary.BigEndian.Uint32(b)&0x7fffffff == 0 {
			return errors.New("invalid Naive HTTP2 WINDOW_UPDATE")
		}
		n := int64(binary.BigEndian.Uint32(b) & 0x7fffffff)
		m.mu.Lock()
		if id == 0 {
			m.send += n
			if m.send > 1<<31-1 {
				m.mu.Unlock()
				return errors.New("Naive HTTP2 connection window overflow")
			}
			for _, s := range m.streams {
				s.signalWrite()
			}
		} else if s := m.streams[id]; s != nil {
			s.send += n
			if s.send > 1<<31-1 {
				m.mu.Unlock()
				s.closeWithError(errors.New("Naive HTTP2 stream window overflow"))
				return nil
			}
			s.signalWrite()
		}
		m.mu.Unlock()
	case 1:
		if id == 0 {
			return errors.New("Naive HTTP2 HEADERS on stream0")
		}
		block, err := masqueHeaderFragment(masqueH2Frame(kind, flags, id, b))
		if err != nil {
			return err
		}
		block = append([]byte(nil), block...)
		end := flags&1 != 0
		for flags&4 == 0 {
			var next byte
			var stream uint32
			next, flags, stream, b, err = m.frame()
			if err != nil {
				return err
			}
			if next != 9 || stream != id || len(block)+len(b) > 262144 {
				return errors.New("invalid Naive HTTP2 CONTINUATION")
			}
			block = append(block, b...)
		}
		fields, err := m.decoder.decode(block)
		if err != nil {
			return err
		}
		return m.headers(id, fields, end)
	case 0:
		if id == 0 {
			return errors.New("Naive HTTP2 DATA on stream0")
		}
		n := len(b)
		if flags&8 != 0 {
			if len(b) == 0 || int(b[0]) >= len(b) {
				return errors.New("invalid Naive HTTP2 DATA padding")
			}
			b = b[1 : len(b)-int(b[0])]
		}
		m.mu.Lock()
		m.receive -= n
		if m.receive < 0 {
			m.mu.Unlock()
			return errors.New("Naive HTTP2 connection receive window exceeded")
		}
		s := m.streams[id]
		if s == nil {
			if id&1 == 0 || id > m.next {
				m.mu.Unlock()
				return errors.New("Naive HTTP2 DATA on idle stream")
			}
			m.mu.Unlock()
			m.consume(nil, n)
			return nil
		}
		if !s.ready || s.remoteEnd || s.receive < n {
			m.mu.Unlock()
			m.consume(nil, n)
			s.closeWithError(errors.New("invalid Naive HTTP2 stream DATA"))
			return nil
		}
		s.receive -= n
		if s.discard {
			s.discarded += len(b)
			s.remoteEnd = flags&1 != 0
			tooLarge := s.discarded > 8<<20
			m.mu.Unlock()
			m.consume(s, n)
			if tooLarge {
				s.closeWithError(errors.New("Naive preamble body exceeds8MiB"))
			} else {
				m.retire(s)
			}
			return nil
		}
		m.mu.Unlock()
		if err := m.bufferBudget.reserve(len(b), m.done, s.done); err != nil {
			m.mu.Lock()
			closed := s.closed
			m.mu.Unlock()
			if closed {
				m.consume(nil, n)
				return nil
			}
			return err
		}
		m.mu.Lock()
		if s.closed {
			m.mu.Unlock()
			m.bufferBudget.release(len(b))
			m.consume(nil, n)
			return nil
		}
		if len(b) > 0 {
			s.buffer.Write(b)
		}
		s.remoteEnd = flags&1 != 0
		s.signalRead()
		m.mu.Unlock()
		m.consume(s, n-len(b))
		m.retire(s)
	case 3:
		if id == 0 || len(b) != 4 {
			return errors.New("invalid Naive HTTP2 RST_STREAM")
		}
		m.mu.Lock()
		s := m.streams[id]
		complete := s != nil && s.remoteEnd && binary.BigEndian.Uint32(b) == 0
		if complete {
			s.localEnd = true
			s.signalRead()
			s.signalWrite()
		}
		m.mu.Unlock()
		if complete {
			m.retire(s)
		} else if s != nil {
			if binary.BigEndian.Uint32(b) == 7 {
				s.finish(errNaiveH2Draining)
			} else {
				s.finish(fmt.Errorf("Naive HTTP2 peer reset stream: %d", binary.BigEndian.Uint32(b)))
			}
		}
	case 7:
		if id != 0 || len(b) < 8 {
			return errors.New("invalid Naive HTTP2 GOAWAY")
		}
		last := binary.BigEndian.Uint32(b) & 0x7fffffff
		m.mu.Lock()
		m.draining = true
		var refused []*naiveH2Stream
		for id, s := range m.streams {
			if id > last {
				refused = append(refused, s)
			}
		}
		empty := len(m.streams) == 0
		m.mu.Unlock()
		for _, s := range refused {
			s.finish(errNaiveH2Draining)
		}
		if empty {
			return io.EOF
		}
	case 2:
		if id == 0 || len(b) != 5 {
			return errors.New("invalid Naive HTTP2 PRIORITY")
		}
	case 5, 9:
		return errors.New("unexpected Naive HTTP2 PUSH_PROMISE or CONTINUATION")
	}
	return nil
}

func (m *naiveH2Session) headers(id uint32, fields [][2]string, end bool) error {
	status, padded, regular := "", false, false
	reply := ""
	replySeen := false
	for _, f := range fields {
		if f[0] == "" || strings.ToLower(f[0]) != f[0] {
			return errors.New("invalid Naive HTTP2 header name")
		}
		if strings.HasPrefix(f[0], ":") {
			if regular || f[0] != ":status" || status != "" {
				return errors.New("invalid Naive HTTP2 response pseudo-header")
			}
			status = f[1]
		} else {
			regular = true
			for _, ch := range f[0] {
				if ch < 'a' || ch > 'z' {
					if ch < '0' || ch > '9' {
						if !strings.ContainsRune("!#$%&'*+-.^_`|~", ch) {
							return errors.New("invalid Naive HTTP2 header name")
						}
					}
				}
			}
			switch f[0] {
			case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
				return errors.New("forbidden Naive HTTP2 connection header")
			}
			if strings.ContainsAny(f[1], "\r\n\x00") {
				return errors.New("invalid Naive HTTP2 header value")
			}
			if f[0] == "padding" {
				padded = true
			}
			if f[0] == "padding-type-reply" {
				if replySeen {
					return errors.New("duplicate Naive padding reply")
				}
				replySeen = true
				reply = f[1]
			}
		}
	}
	m.mu.Lock()
	s := m.streams[id]
	if s == nil {
		if id&1 == 0 || id > m.next {
			m.mu.Unlock()
			return errors.New("Naive HTTP2 HEADERS on idle stream")
		}
		m.mu.Unlock()
		return nil
	}
	if !s.ready {
		code, err := strconv.Atoi(status)
		if err != nil || len(status) != 3 || code < 100 || code > 599 || code == 101 {
			m.mu.Unlock()
			return errors.New("invalid Naive HTTP2 status")
		}
		if code < 200 {
			s.informational++
			if end || s.informational > 16 {
				m.mu.Unlock()
				return errors.New("invalid Naive HTTP2 informational response")
			}
			m.mu.Unlock()
			return nil
		}
		s.status, s.padded, s.ready = code, padded, true
		if !s.discard {
			selected, err := naivePaddingReply(padded, reply)
			if err != nil {
				m.mu.Unlock()
				return err
			}
			s.padded = selected
		}
	} else if status != "" || !end {
		m.mu.Unlock()
		return errors.New("invalid Naive HTTP2 trailers")
	}
	s.remoteEnd = end
	s.signalRead()
	m.mu.Unlock()
	m.retire(s)
	return nil
}

func (m *naiveH2Session) consume(s *naiveH2Stream, n int) {
	if n == 0 {
		return
	}
	m.mu.Lock()
	if m.err != nil {
		m.mu.Unlock()
		return
	}
	m.consumed += n
	var updates []*naiveH2Operation
	if m.consumed >= naiveH2ConnectionWindow/2 {
		v := m.consumed
		m.receive += v
		m.consumed = 0
		updates = append(updates, &naiveH2Operation{wire: masqueH2Frame(8, 0, 0, binary.BigEndian.AppendUint32(nil, uint32(v)))})
	}
	if s != nil && !s.closed {
		s.consumed += n
		if s.consumed >= naiveH2StreamWindow/2 && !s.remoteEnd {
			v := s.consumed
			s.receive += v
			s.consumed = 0
			updates = append(updates, &naiveH2Operation{wire: masqueH2Frame(8, 0, s.id, binary.BigEndian.AppendUint32(nil, uint32(v)))})
		}
	}
	m.mu.Unlock()
	for _, op := range updates {
		m.queue(op)
	}
}

func (c *trustClient) naiveSession(ctx context.Context) (*naiveH2Session, error) {
	c.naiveCreate.Lock()
	defer c.naiveCreate.Unlock()
	c.mu.Lock()
	if m := c.naiveH2; m != nil {
		m.mu.Lock()
		usable := m.err == nil && !m.draining
		m.mu.Unlock()
		if usable {
			c.mu.Unlock()
			return m, nil
		}
	}
	if len(c.naiveSessions) >= 8 {
		c.mu.Unlock()
		return nil, errors.New("too many draining Naive HTTP2 sessions")
	}
	epoch := c.epoch
	c.mu.Unlock()
	conn, err := c.http.DialTLSContext(ctx, "tcp", portAddress(c.outbound.Server, c.outbound.ServerPort))
	if err != nil {
		return nil, err
	}
	m, err := newNaiveH2Session(c.runtime, conn, chromiumPreamble(c.outbound))
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.epoch != epoch || c.runtime.ctx.Err() != nil {
		c.mu.Unlock()
		m.fail(net.ErrClosed)
		return nil, net.ErrClosed
	}
	if c.naiveSessions == nil {
		c.naiveSessions = map[*naiveH2Session]struct{}{}
	}
	c.naiveSessions[m] = struct{}{}
	c.naiveH2 = m
	c.physical = conn
	m.mu.Lock()
	m.onClose = func() { c.mu.Lock(); delete(c.naiveSessions, m); c.mu.Unlock() }
	closed := m.err != nil
	m.mu.Unlock()
	if closed {
		delete(c.naiveSessions, m)
	}
	c.mu.Unlock()
	if err := m.awaitPreamble(ctx); err != nil {
		m.fail(err)
		return nil, err
	}
	return m, nil
}

func (c *trustClient) connectNaiveH2(ctx context.Context, authority string) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		conn, err := c.connectNaiveH2Once(ctx, authority)
		if !errors.Is(err, errNaiveH2Draining) {
			return conn, err
		}
	}
	return nil, errNaiveH2Draining
}

func (c *trustClient) connectNaiveH2Once(ctx context.Context, authority string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	m, err := c.naiveSession(ctx)
	if err != nil {
		return nil, err
	}
	fields := c.chromiumConnectHeaders(authority)
	size := uint32(0)
	for _, field := range fields {
		size += uint32(32 + len(field[0]) + len(field[1]))
	}
	m.mu.Lock()
	limit := m.peerHeader
	m.mu.Unlock()
	if size > limit {
		return nil, errors.New("Naive HTTP2 request headers exceed peer limit")
	}
	// Stream IDs must be opened on the wire in allocation order.
	select {
	case m.opening <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, net.ErrClosed
	}
	s, err := m.open(ctx)
	if err != nil {
		<-m.opening
		return nil, err
	}
	op := &naiveH2Operation{headers: fields, stream: s, kind: 1, result: make(chan error, 1)}
	err = s.submit(ctx, op)
	<-m.opening
	if err == nil {
		for {
			m.mu.Lock()
			ready, status, padded, streamErr := s.ready, s.status, s.padded, s.err
			m.mu.Unlock()
			if streamErr != nil {
				err = streamErr
				break
			}
			if ready {
				if status != 200 {
					err = fmt.Errorf("Naive HTTP2 CONNECT: HTTP %d", status)
					if status == 407 {
						m.fail(err)
					}
					break
				}
				conn := &httpStreamConn{reader: s, writer: s, close: s.close, closeWrite: s.closeWrite, local: m.conn.LocalAddr(), remote: streamAddr(authority)}
				if padded {
					return &naiveConn{Conn: conn}, nil
				}
				return conn, nil
			}
			select {
			case <-ctx.Done():
				err = ctx.Err()
			case <-s.done:
				err = net.ErrClosed
			case <-m.done:
				err = net.ErrClosed
			case <-s.readWake:
				continue
			}
			break
		}
	}
	s.close()
	return nil, err
}
