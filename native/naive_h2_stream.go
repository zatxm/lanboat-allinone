package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

type naiveH2Stream struct {
	session                                            *naiveH2Session
	id                                                 uint32
	send                                               int64
	receive, consumed, status, informational           int
	ready, padded, opened, localEnd, remoteEnd, closed bool
	err                                                error
	buffer                                             bytes.Buffer
	readWake, writeWake, done                          chan struct{}
	writeMu                                            sync.Mutex
	retired                                            bool
	discard                                            bool
	discarded                                          int
}

func (s *naiveH2Stream) signalRead() {
	select {
	case s.readWake <- struct{}{}:
	default:
	}
}
func (s *naiveH2Stream) signalWrite() {
	select {
	case s.writeWake <- struct{}{}:
	default:
	}
}
func (s *naiveH2Stream) release() { s.buffer = bytes.Buffer{} }

func (m *naiveH2Session) open(ctx context.Context) (*naiveH2Stream, error) {
	select {
	case <-m.settings:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, net.ErrClosed
	}
	for {
		m.mu.Lock()
		if m.draining {
			m.mu.Unlock()
			return nil, errNaiveH2Draining
		}
		if m.err != nil || m.next >= 1<<31-3 {
			m.mu.Unlock()
			return nil, net.ErrClosed
		}
		if len(m.streams) < int(m.peerConcurrent) {
			if m.idle != nil {
				m.idle.Stop()
			}
			m.next += 2
			id := m.next - 1
			s := &naiveH2Stream{session: m, id: id, send: m.peerWindow, receive: naiveH2StreamWindow, readWake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1), done: make(chan struct{})}
			m.streams[id] = s
			m.mu.Unlock()
			return s, nil
		}
		m.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.done:
			return nil, net.ErrClosed
		case <-m.space:
		}
	}
}

func (s *naiveH2Stream) submit(ctx context.Context, op *naiveH2Operation) error {
	m := s.session
	select {
	case m.data <- op:
	case <-ctx.Done():
		m.refund(op)
		m.finishOperation(op, ctx.Err())
		return ctx.Err()
	case <-s.done:
		m.refund(op)
		m.finishOperation(op, net.ErrClosed)
		return net.ErrClosed
	case <-m.done:
		m.refund(op)
		m.finishOperation(op, net.ErrClosed)
		return net.ErrClosed
	}
	select {
	case err := <-op.result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return net.ErrClosed
	case <-m.done:
		return net.ErrClosed
	}
}

func (s *naiveH2Stream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	m := s.session
	for {
		m.mu.Lock()
		if s.buffer.Len() > 0 {
			n, _ := s.buffer.Read(b)
			if s.buffer.Len() == 0 && s.buffer.Cap() > 32768 {
				s.release()
			} else if s.buffer.Cap() > 65536 && s.buffer.Len() < s.buffer.Cap()/4 {
				remaining := bytes.Clone(s.buffer.Bytes())
				s.buffer = *bytes.NewBuffer(remaining)
			}
			m.mu.Unlock()
			m.bufferBudget.release(n)
			m.consume(s, n)
			return n, nil
		}
		if s.err != nil {
			err := s.err
			m.mu.Unlock()
			return 0, err
		}
		end, closed := s.remoteEnd, s.closed
		m.mu.Unlock()
		if end {
			return 0, io.EOF
		}
		if closed {
			return 0, net.ErrClosed
		}
		select {
		case <-m.done:
			continue
		case <-s.done:
			continue
		case <-s.readWake:
		}
	}
}

func (s *naiveH2Stream) Write(b []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	m := s.session
	written := 0
	for len(b) > 0 {
		m.mu.Lock()
		if s.closed || s.localEnd || m.err != nil {
			m.mu.Unlock()
			return written, net.ErrClosed
		}
		n := int(min(int64(min(len(b), 16384)), m.send, s.send))
		if n <= 0 {
			m.mu.Unlock()
			select {
			case <-s.done:
				return written, net.ErrClosed
			case <-m.done:
				return written, net.ErrClosed
			case <-s.writeWake:
				continue
			}
		}
		m.send -= int64(n)
		s.send -= int64(n)
		m.mu.Unlock()
		buf := buffers.Get().(*[32 * 1024]byte)[:]
		wire := buf[:9+n]
		wire[0], wire[1], wire[2], wire[3], wire[4] = byte(n>>16), byte(n>>8), byte(n), 0, 0
		binary.BigEndian.PutUint32(wire[5:], s.id)
		copy(wire[9:], b[:n])
		op := &naiveH2Operation{wire: wire, stream: s, kind: 0, count: n, pooled: true, result: make(chan error, 1)}
		if err := s.submit(context.Background(), op); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}

func (s *naiveH2Stream) closeWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	m := s.session
	m.mu.Lock()
	closed := s.closed || s.localEnd
	m.mu.Unlock()
	if closed {
		return nil
	}
	return s.submit(context.Background(), &naiveH2Operation{wire: masqueH2Frame(0, 1, s.id, nil), stream: s, kind: 0, result: make(chan error, 1)})
}

func (s *naiveH2Stream) finish(err error) bool {
	m := s.session
	m.mu.Lock()
	if s.closed {
		m.mu.Unlock()
		return false
	}
	s.closed = true
	s.err = err
	unread := s.buffer.Len()
	s.release()
	delete(m.streams, s.id)
	m.idleWhenEmpty()
	close(s.done)
	empty := m.draining && len(m.streams) == 0
	m.mu.Unlock()
	m.bufferBudget.release(unread)
	m.consume(nil, unread)
	select {
	case m.space <- struct{}{}:
	default:
	}
	if empty {
		m.fail(io.EOF)
	}
	return true
}

func (s *naiveH2Stream) closeWithError(err error) {
	if !s.finish(err) {
		return
	}
	s.session.mu.Lock()
	complete := s.localEnd && s.remoteEnd
	s.session.mu.Unlock()
	if complete {
		return
	}
	s.session.queue(&naiveH2Operation{stream: s, kind: 3, wire: masqueH2Frame(3, 0, s.id, []byte{0, 0, 0, 8})})
}
func (s *naiveH2Stream) close() { s.closeWithError(net.ErrClosed) }

func (s *naiveH2Stream) Close() error { s.close(); return nil }

func (m *naiveH2Session) retire(s *naiveH2Stream) {
	m.mu.Lock()
	if s.closed || s.retired || !s.localEnd || !s.remoteEnd {
		m.mu.Unlock()
		return
	}
	s.retired = true
	delete(m.streams, s.id)
	m.idleWhenEmpty()
	empty := m.draining && len(m.streams) == 0
	m.mu.Unlock()
	select {
	case m.space <- struct{}{}:
	default:
	}
	if empty {
		m.fail(io.EOF)
	}
}

var _ io.ReadWriter = (*naiveH2Stream)(nil)
