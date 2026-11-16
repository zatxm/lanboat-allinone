package native

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// MASQUE uses a distinct HTTP/3 connection: QUIC datagrams belong to request
// streams here, whereas Hysteria and TUIC assign their own datagram semantics.
type masqueSession struct {
	version             int
	space               chan struct{}
	q                   *quicConn
	ctx                 context.Context
	done                <-chan struct{}
	cancel              context.CancelFunc
	http                *http.Transport
	closed              bool
	next                uint64
	mu                  sync.Mutex
	flows               map[uint64]*masqueFlow
	critical            map[uint64]bool
	settings            chan struct{}
	extended, datagrams bool
	buffered            atomic.Int64
	contextBytes        atomic.Int64
	workers             sync.WaitGroup
	once                sync.Once
}

func newMasqueHTTPSession(parent context.Context) *masqueSession {
	ctx, cancel := context.WithCancel(parent)
	return &masqueSession{ctx: ctx, cancel: cancel, done: ctx.Done(), space: make(chan struct{}, 1), flows: map[uint64]*masqueFlow{}}
}
func (m *masqueSession) goWork(fn func()) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.ctx.Err() != nil {
		return false
	}
	m.workers.Add(1)
	go func() { defer m.workers.Done(); fn() }()
	return true
}
func (m *masqueSession) datagramLimit() int {
	if m.q == nil {
		return 0
	}
	return m.q.datagramLimit()
}
func newMasqueSession(q *quicConn) (*masqueSession, error) {
	if e := h3StartSettings(q.ctx, q, [][2]uint64{{0x33, 1}}); e != nil {
		q.Close()
		return nil, e
	}
	m := &masqueSession{space: make(chan struct{}, 1), q: q, ctx: q.ctx, done: q.done, flows: map[uint64]*masqueFlow{}, critical: map[uint64]bool{}, settings: make(chan struct{})}
	return m, nil
}
func (m *masqueSession) close() {
	m.once.Do(func() {
		if m.q != nil {
			m.q.Close()
		}
		if m.cancel != nil {
			m.cancel()
		}
		if m.http != nil {
			m.http.CloseIdleConnections()
		}
		m.mu.Lock()
		m.closed = true
		list := make([]*masqueFlow, 0, len(m.flows))
		for _, f := range m.flows {
			list = append(list, f)
		}
		m.mu.Unlock()
		for _, f := range list {
			f.Close()
		}
	})
}
func (m *masqueSession) start(handle func(*quicStream)) {
	m.goWork(func() {
		defer m.close()
		for {
			b, e := m.q.ReceiveDatagram(m.q.ctx)
			if e != nil {
				return
			}
			r := quicReader(b)
			id, e := r.v()
			if e != nil || id >= 1<<60 {
				return
			}
			m.mu.Lock()
			f := m.flows[id*4]
			m.mu.Unlock()
			if f != nil {
				if e = f.deliver(r, false); e != nil {
					f.Close()
				}
			}
		}
	})
	m.goWork(func() {
		defer m.close()
		slots := make(chan struct{}, 128)
		for {
			s, e := m.q.AcceptStream(m.q.ctx)
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				s.Close()
				continue
			}
			m.goWork(func() {
				defer func() { <-slots }()
				defer s.Close()
				if s.id&2 == 0 {
					if handle != nil {
						handle(s)
					} else {
						m.close()
					}
					return
				}
				s.SetReadDeadline(time.Now().Add(handshakeTimeout))
				kind, e := readQUICVar(s)
				if e != nil {
					m.close()
					return
				}
				if kind == 0 || kind == 2 || kind == 3 {
					m.mu.Lock()
					duplicate := m.critical[kind]
					m.critical[kind] = true
					m.mu.Unlock()
					if duplicate {
						m.close()
						return
					}
				}
				e = h3UniBody(s, kind, func(v map[uint64]uint64) error {
					if v[8] > 1 || v[0x33] > 1 || v[0x33] == 1 && m.q.peer.maxDatagram == 0 {
						return errors.New("invalid MASQUE HTTP3 settings")
					}
					m.mu.Lock()
					m.extended = v[8] == 1
					m.datagrams = v[0x33] == 1
					close(m.settings)
					m.mu.Unlock()
					s.SetReadDeadline(time.Time{})
					return nil
				})
				if e != nil && (kind == 0 || kind == 2 || kind == 3) {
					m.close()
				}
			})
		}
	})
}
func (m *masqueSession) waitSettings(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.q.done:
		return net.ErrClosed
	case <-m.settings:
	}
	m.mu.Lock()
	ok := m.extended
	m.mu.Unlock()
	if !ok && !m.q.server {
		return errors.New("MASQUE peer disabled Extended CONNECT")
	}
	return nil
}
func (m *masqueSession) flow(s *quicStream) (*masqueFlow, error) {
	return m.registerFlow(s, s.id, &trustH3Conn{quicStream: s})
}
func (m *masqueSession) registerFlow(s net.Conn, id uint64, body net.Conn) (*masqueFlow, error) {
	f := &masqueFlow{capsules: true, session: m, stream: s, id: id, body: body, incoming: make(chan masqueDatagram, 256), done: make(chan struct{}), notify: make(chan struct{}, 1)}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.flows) >= 128 || m.closed || m.ctx.Err() != nil {
		return nil, errors.New("MASQUE flow capacity exhausted")
	}
	m.flows[id] = f
	return f, nil
}

type masqueDatagram struct {
	data     []byte
	reliable bool
}

type masqueFlow struct {
	contexts        atomic.Pointer[masqueContexts]
	ipConfiguration *masqueIP
	capsules        bool
	via             bool
	reliableOnly    atomic.Bool
	writeBuffer     []byte
	session         *masqueSession
	stream          net.Conn
	id              uint64
	body            net.Conn
	writeMu, mu     sync.Mutex
	closed          bool
	incoming        chan masqueDatagram
	done, notify    chan struct{}
	deadline        time.Time
	control         func(uint64, []byte) error
}

func (f *masqueFlow) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	close(f.done)
	for {
		select {
		case b := <-f.incoming:
			f.session.buffered.Add(-int64(len(b.data)))
			signal(f.session.space)
		default:
			goto drained
		}
	}
drained:
	f.mu.Unlock()
	if contexts := f.contexts.Load(); contexts != nil {
		contexts.close()
	}
	f.session.mu.Lock()
	delete(f.session.flows, f.id)
	f.session.mu.Unlock()
	return f.stream.Close()
}
func (f *masqueFlow) deliver(payload []byte, reliable bool) error {
	r := quicReader(payload)
	context, e := r.v()
	if e != nil {
		return e
	}
	if state := f.contexts.Load(); state != nil {
		decoded, ok := state.decode(context, r)
		if !ok {
			return nil
		}
		r = quicReader(decoded)
	} else if context != 0 {
		return nil
	}
	if len(r) > 65535 {
		return errors.New("MASQUE datagram too large")
	}
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return nil
		}
		n := f.session.buffered.Load()
		if n+int64(len(r)) <= 4<<20 && len(f.incoming) < cap(f.incoming) {
			// A consumer or another flow can update the shared budget while this
			// flow is locked. Contention is not a full queue, even for datagrams.
			if !f.session.buffered.CompareAndSwap(n, n+int64(len(r))) {
				f.mu.Unlock()
				continue
			}
			f.incoming <- masqueDatagram{data: r, reliable: reliable}
			f.mu.Unlock()
			return nil
		}
		f.mu.Unlock()
		if !reliable {
			return nil
		}
		select {
		case <-f.session.space:
		case <-f.done:
			return net.ErrClosed
		case <-f.session.done:
			return net.ErrClosed
		}
	}
}
func (f *masqueFlow) readCapsules() error {
	defer f.Close()
	for {
		kind, e := readQUICVar(f.body)
		if e != nil {
			return e
		}
		n, e := readQUICVar(f.body)
		if e != nil {
			return e
		}
		if n > 1<<20 {
			return errors.New("MASQUE capsule exceeds limit")
		}
		contexts := f.contexts.Load()
		processing := contexts != nil && masqueKnownContextCapsule(kind)
		known := kind <= 3 || processing
		if p := f.ipConfiguration; p != nil {
			known = known || kind == masqueDNSAssign && p.acceptDNS || kind == masquePREF64 && p.acceptPREF64
		}
		if !known || kind != 0 && f.control == nil && !processing {
			if _, e = io.CopyN(io.Discard, f.body, int64(n)); e != nil {
				return e
			}
			continue
		}
		limit := uint64(65536)
		if processing {
			limit = uint64(contexts.local.mtu + 16 + 16*contexts.local.segments)
		}
		if kind == 0 {
			limit = 65535 + 8
		}
		if n > limit {
			return errors.New("MASQUE known capsule exceeds limit")
		}
		data := make([]byte, n)
		if _, e = io.ReadFull(f.body, data); e != nil {
			return e
		}
		if kind == 0 {
			e = f.deliver(data, true)
		} else if processing {
			e = contexts.handle(f, kind, data)
		} else {
			e = f.control(kind, data)
		}
		if e != nil {
			return e
		}
	}
}
func (f *masqueFlow) capsule(kind uint64, b []byte) error {
	f.writeMu.Lock()
	defer f.writeMu.Unlock()
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	h := quicVar(f.writeBuffer[:0], kind)
	h = quicVar(h, uint64(len(b)))
	h = append(h, b...)
	e := writeAll(f.body, h)
	if cap(h) <= 4096 {
		f.writeBuffer = h[:0]
	} else {
		f.writeBuffer = nil
	}
	if e != nil {
		f.Close()
	}
	return e
}
func (f *masqueFlow) Write(b []byte) (int, error) { return f.writeDatagram(b, false) }
func (f *masqueFlow) writeDatagram(b []byte, reliable bool) (int, error) {
	if len(b) > 65535 {
		return 0, errors.New("MASQUE payload exceeds limit")
	}
	f.mu.Lock()
	closed := f.closed
	f.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	originalLength := len(b)
	contextID := uint64(0)
	if state := f.contexts.Load(); state != nil {
		state.sendMu.Lock()
		defer state.sendMu.Unlock()
		var err error
		contextID, b, err = state.encode(f, b)
		if err != nil {
			return 0, err
		}
	}
	if err := f.sendDatagram(contextID, b, reliable); err != nil {
		return 0, err
	}
	return originalLength, nil
}
func (f *masqueFlow) sendDatagram(contextID uint64, b []byte, reliable bool) error {
	if f.isClosed() {
		return net.ErrClosed
	}
	m := f.session
	m.mu.Lock()
	datagrams := m.q != nil && m.datagrams && !f.via && !reliable && !f.reliableOnly.Load()
	m.mu.Unlock()
	var e error
	var header [16]byte
	headerLength := len(quicVar(quicVar(header[:0], f.id/4), contextID))
	if datagrams && len(b)+headerLength <= m.q.datagramLimit() {
		data := quicVar(nil, f.id/4)
		data = quicVar(data, contextID)
		data = append(data, b...)
		op := newQUICOperation('d', nil)
		op.data = data
		e = m.q.do(m.q.ctx, op, f.stream.(*quicStream)).err
		if errors.Is(e, errQUICDatagramSize) && f.capsules {
			e = f.capsule(0, append(quicVar(nil, contextID), b...))
		}
	} else {
		if !f.capsules {
			return errors.New("MASQUE peer requires a datagram within the QUIC path MTU")
		}
		data := append(quicVar(nil, contextID), b...)
		e = f.capsule(0, data)
	}
	if e != nil {
		f.Close()
		return e
	}
	return nil
}
func (f *masqueFlow) Read(b []byte) (int, error) {
	n, _, err := f.readPacket(b)
	return n, err
}
func (f *masqueFlow) readPacket(b []byte) (int, bool, error) {
	for {
		f.mu.Lock()
		deadline, closed := f.deadline, f.closed
		f.mu.Unlock()
		if closed {
			return 0, false, net.ErrClosed
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, false, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var packet masqueDatagram
		var e error
		select {
		case packet = <-f.incoming:
		case <-f.done:
			e = net.ErrClosed
		case <-f.session.done:
			e = net.ErrClosed
		case <-f.notify:
		case <-timeout:
			e = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if e != nil {
			return 0, false, e
		}
		if packet.data != nil {
			f.session.buffered.Add(-int64(len(packet.data)))
			signal(f.session.space)
			return copy(b, packet.data), packet.reliable, nil
		}
	}
}
func (f *masqueFlow) LocalAddr() net.Addr  { return f.stream.LocalAddr() }
func (f *masqueFlow) RemoteAddr() net.Addr { return f.stream.RemoteAddr() }
func (f *masqueFlow) SetReadDeadline(t time.Time) error {
	f.mu.Lock()
	f.deadline = t
	f.mu.Unlock()
	signal(f.notify)
	return nil
}
func (f *masqueFlow) SetWriteDeadline(t time.Time) error { return f.stream.SetWriteDeadline(t) }
func (f *masqueFlow) SetDeadline(t time.Time) error {
	f.SetReadDeadline(t)
	return f.SetWriteDeadline(t)
}
