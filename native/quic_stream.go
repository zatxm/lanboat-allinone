package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type quicPiece struct {
	offset uint64
	data   []byte
}

type quicStreamStopError struct{ code uint64 }

func (e *quicStreamStopError) Error() string {
	return fmt.Sprintf("QUIC peer stopped stream: %d", e.code)
}

// A complete one-way command may be consumed before its FIN is delivered.
// Preserve errors for writes, bidirectional streams and nonzero stop codes.
func (s *quicStream) finishUni() error {
	err := s.CloseWrite()
	var stopped *quicStreamStopError
	if s.id&2 != 0 && errors.As(err, &stopped) && stopped.code == 0 {
		return nil
	}
	return err
}

type quicBuffer struct {
	position uint64
	parts    []quicPiece
}

func (b *quicBuffer) put(offset uint64, data []byte) error {
	end := offset + uint64(len(data))
	if end < offset || end >= 1<<62 {
		return errors.New("QUIC stream offset overflow")
	}
	if end <= b.position {
		return nil
	}
	if offset < b.position {
		data = data[b.position-offset:]
		offset = b.position
	}
	// Coalesce ordered arrivals in bounded chunks; large configured windows
	// must not turn every packet into a retained reassembly fragment.
	if len(b.parts) > 0 {
		p := &b.parts[len(b.parts)-1]
		if p.offset+uint64(len(p.data)) == offset && len(p.data)+len(data) <= 256<<10 {
			p.data = append(p.data, data...)
			return nil
		}
	}
	cursor := offset
	var pending []quicPiece
	for _, part := range b.parts {
		stop := part.offset + uint64(len(part.data))
		if stop <= cursor {
			continue
		}
		if part.offset >= end {
			break
		}
		if cursor < part.offset {
			n := min(part.offset, end)
			pending = append(pending, quicPiece{cursor, append([]byte{}, data[cursor-offset:n-offset]...)})
			cursor = n
		}
		overlapEnd := min(stop, end)
		if cursor < overlapEnd {
			if !bytes.Equal(data[cursor-offset:overlapEnd-offset], part.data[cursor-part.offset:overlapEnd-part.offset]) {
				return errors.New("inconsistent overlapping QUIC data")
			}
			cursor = overlapEnd
		}
	}
	if cursor < end {
		pending = append(pending, quicPiece{cursor, append([]byte{}, data[cursor-offset:]...)})
	}
	b.parts = append(b.parts, pending...)
	if len(b.parts) > 512 {
		return errors.New("QUIC reassembly fragment limit")
	}
	slices.SortFunc(b.parts, func(a, c quicPiece) int {
		if a.offset < c.offset {
			return -1
		}
		if a.offset > c.offset {
			return 1
		}
		return 0
	})
	return nil
}
func (b *quicBuffer) read(dst []byte) int {
	n := 0
	for len(b.parts) > 0 && b.parts[0].offset == b.position && len(dst) > 0 {
		part := &b.parts[0]
		k := copy(dst, part.data)
		n += k
		dst = dst[k:]
		b.position += uint64(k)
		part.offset += uint64(k)
		part.data = part.data[k:]
		if len(part.data) == 0 {
			copy(b.parts, b.parts[1:])
			b.parts[len(b.parts)-1] = quicPiece{}
			b.parts = b.parts[:len(b.parts)-1]
		}
	}
	return n
}
func signalQUIC(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

type quicOperation struct {
	kind     byte
	stream   *quicStream
	data     []byte
	n, code  uint64
	reply    chan quicResult
	canceled atomic.Bool
	accepted atomic.Int64
}
type quicResult struct {
	stream *quicStream
	n      int
	err    error
}

func newQUICOperation(kind byte, s *quicStream) *quicOperation {
	return &quicOperation{kind: kind, stream: s, reply: make(chan quicResult, 1)}
}

type quicStream struct {
	peerCancel                                                            atomic.Pointer[context.CancelFunc]
	peerCanceled                                                          atomic.Bool
	conn                                                                  *quicConn
	id                                                                    uint64
	mu, wmu                                                               sync.Mutex
	buffer                                                                quicBuffer
	highest, final, readLimit, sendOffset, sendLimit                      uint64
	consumed                                                              atomic.Uint64
	readErr, writeErr                                                     error
	finalKnown, sendFin, finAck, delivered, resetSent, stopped, appClosed bool
	readDeadline, writeDeadline                                           time.Time
	readWake, writeWake                                                   chan struct{}
	closed                                                                chan struct{}
	closeOnce                                                             sync.Once
}

func newQUICStream(c *quicConn, id uint64) *quicStream {
	local := id&1 == 0
	if c.server {
		local = !local
	}
	limit := c.peer.bidiLocal
	if local {
		limit = c.peer.bidiRemote
	}
	if id&2 != 0 {
		limit = c.peer.uni
	}
	_, window := c.receiveWindows()
	return &quicStream{conn: c, id: id, readLimit: window, sendLimit: limit, readWake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1), closed: make(chan struct{})}
}
func (s *quicStream) discardReceived() {
	old := s.consumed.Swap(s.highest)
	if s.highest > old {
		s.conn.consumed.Add(s.highest - old)
	}
	s.buffer.position = s.highest
}
func (s *quicStream) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		n := s.buffer.read(b)
		if n > 0 {
			s.consumed.Add(uint64(n))
			s.conn.consumed.Add(uint64(n))
			s.mu.Unlock()
			signalQUIC(s.conn.wake)
			return n, nil
		}
		err := s.readErr
		if err == nil && s.finalKnown && s.buffer.position == s.final {
			err = io.EOF
		}
		deadline := s.readDeadline
		s.mu.Unlock()
		if err != nil {
			return 0, err
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-s.readWake:
		case <-s.closed:
			err = net.ErrClosed
		case <-s.conn.done:
			err = s.conn.err()
		case <-timeout:
			err = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return 0, err
		}
	}
}
func (s *quicStream) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	written := 0
	for len(b) > 0 {
		n := min(len(b), 16<<10)
		op := newQUICOperation('w', s)
		op.data = append([]byte{}, b[:n]...)
		result := s.conn.do(s.conn.ctx, op, s)
		written += result.n
		if result.err != nil {
			return written, result.err
		}
		b = b[n:]
	}
	return written, nil
}
func (s *quicStream) CloseWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.conn.do(s.conn.ctx, newQUICOperation('f', s), s).err
}
func (s *quicStream) Close() error {
	s.closeOnce.Do(func() { close(s.closed); op := newQUICOperation('c', s); s.conn.do(s.conn.ctx, op, nil) })
	return nil
}
func (s *quicStream) LocalAddr() net.Addr  { return s.conn.local }
func (s *quicStream) RemoteAddr() net.Addr { return s.conn.remote }
func (s *quicStream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.mu.Unlock()
	signalQUIC(s.readWake)
	signalQUIC(s.writeWake)
	return nil
}
func (s *quicStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	signalQUIC(s.readWake)
	return nil
}
func (s *quicStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	signalQUIC(s.writeWake)
	return nil
}

type quicWriteDeadline interface {
	writeState() (time.Time, <-chan struct{}, <-chan struct{})
}

func (s *quicStream) writeState() (time.Time, <-chan struct{}, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeDeadline, s.writeWake, s.closed
}

func (c *quicConn) do(ctx context.Context, op *quicOperation, s quicWriteDeadline) quicResult {
	queue := c.ops
	var replies <-chan quicResult
	for {
		var deadline time.Time
		var changed, closed <-chan struct{}
		if s != nil {
			deadline, changed, closed = s.writeState()
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				op.canceled.Store(true)
				signalQUIC(c.wake)
				return quicResult{n: int(op.accepted.Load()), err: os.ErrDeadlineExceeded}
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var result quicResult
		var complete, replied bool
		select {
		case queue <- op:
			queue, replies = nil, op.reply
		case result = <-replies:
			complete, replied = true, true
		case <-changed:
		case <-closed:
			result = quicResult{n: int(op.accepted.Load()), err: net.ErrClosed}
			complete = true
		case <-ctx.Done():
			result = quicResult{n: int(op.accepted.Load()), err: ctx.Err()}
			complete = true
		case <-c.done:
			result = quicResult{n: int(op.accepted.Load()), err: c.err()}
			complete = true
		case <-timeout:
			result = quicResult{n: int(op.accepted.Load()), err: os.ErrDeadlineExceeded}
			complete = true
		}
		if timer != nil {
			timer.Stop()
		}
		if complete {
			if result.err != nil {
				op.canceled.Store(true)
				signalQUIC(c.wake)
				if op.kind == 'o' && queue == nil && !replied {
					go func() {
						select {
						case abandoned := <-op.reply:
							if abandoned.stream != nil {
								abandoned.stream.Close()
							}
						case <-c.done:
						}
					}()
				}
			}
			return result
		}
	}
}
func (c *quicConn) OpenStream(ctx context.Context, uni bool) (*quicStream, error) {
	select {
	case <-c.ready:
	case <-c.done:
		return nil, c.err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	op := newQUICOperation('o', nil)
	if uni {
		op.n = 1
	}
	result := c.do(ctx, op, nil)
	return result.stream, result.err
}
func (c *quicConn) AcceptStream(ctx context.Context) (*quicStream, error) {
	select {
	case s := <-c.accept:
		return s, nil
	case <-c.done:
		return nil, c.err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *quicConn) SendDatagram(ctx context.Context, data []byte) error {
	if len(data) > c.datagramLimit() {
		return errQUICDatagramSize
	}
	op := newQUICOperation('d', nil)
	op.data = append([]byte{}, data...)
	return c.do(ctx, op, nil).err
}
func (c *quicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.datagrams:
		return b, nil
	case <-c.done:
		return nil, c.err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *quicConn) Close() error { c.cancel(); <-c.done; return nil }
