package native

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const smuxBufferLimit = 4 << 20

type muxProtocol byte

const (
	muxSMUX muxProtocol = iota
	muxCool
	muxSudoku
	muxYAMUX
)

// SMUXv1 uses connection-wide backpressure; v2 additionally advertises stream credits.
type smuxSession struct {
	conn       net.Conn
	ctx        context.Context
	cancel     context.CancelFunc
	client     bool
	cool       bool
	yamux      bool
	sudoku     bool
	control    chan sudokuMuxControl
	cloak      bool
	version    byte
	mu         sync.Mutex
	streams    map[uint32]*smuxStream
	next       uint32
	peerIDs    packetWindow
	err        error
	once       sync.Once
	gate       chan struct{}
	deadlineMu sync.Mutex
	writing    atomic.Pointer[smuxStream]
	buffered   atomic.Int64
	lastRead   atomic.Int64
	idleAt     atomic.Int64
	pooled     atomic.Bool
	space      chan struct{}
	accept     chan *smuxStream
	done       chan struct{}
	tx         [16396]byte
}

func newSMUX(ctx context.Context, conn net.Conn, client bool) *smuxSession {
	return newMuxSession(ctx, conn, client, false)
}

// Mux.Cool and SMUX share bounded queues and deadlines, but use separate wire codecs.
func newMuxSession(ctx context.Context, conn net.Conn, client, cool bool) *smuxSession {
	protocol := muxSMUX
	if cool {
		protocol = muxCool
	}
	return newMuxConfigured(ctx, conn, client, protocol, 1, 10*time.Second, false)
}
func newSMUXVersion(ctx context.Context, conn net.Conn, client bool, version byte, keepalive time.Duration) *smuxSession {
	return newMuxConfigured(ctx, conn, client, muxSMUX, version, keepalive, false)
}
func newMuxConfigured(ctx context.Context, conn net.Conn, client bool, protocol muxProtocol, version byte, keepalive time.Duration, cloak bool) *smuxSession {
	ctx, cancel := context.WithCancel(ctx)
	s := &smuxSession{conn: conn, ctx: ctx, cancel: cancel, client: client, cool: protocol == muxCool, yamux: protocol == muxYAMUX, sudoku: protocol == muxSudoku, version: version, cloak: cloak, streams: map[uint32]*smuxStream{}, gate: make(chan struct{}, 1), space: make(chan struct{}, 1), accept: make(chan *smuxStream, 128), done: make(chan struct{})}
	if s.sudoku || s.yamux {
		s.control = make(chan sudokuMuxControl, 128)
	}
	if client {
		s.next = 1
	} else if s.yamux {
		s.next = 2
	}
	s.lastRead.Store(time.Now().UnixNano())
	s.idleAt.Store(time.Now().UnixNano())
	s.pooled.Store(client && (s.cool || s.sudoku))
	go func() { s.close(s.receive()) }()
	go func() {
		var ticks <-chan time.Time
		if keepalive > 0 {
			ticker := time.NewTicker(keepalive)
			defer ticker.Stop()
			ticks = ticker.C
		}
		for {
			select {
			case <-ctx.Done():
				s.close(net.ErrClosed)
				return
			case frame := <-s.control:
				if err := s.send(ctx, frame.command, frame.id, frame.data, nil); err != nil {
					s.close(err)
					return
				}
			case now := <-ticks:
				if s.pooled.Load() {
					s.mu.Lock()
					idle := len(s.streams) == 0 && now.Sub(time.Unix(0, s.idleAt.Load())) > 30*time.Second
					if idle {
						s.err = net.ErrClosed
					}
					s.mu.Unlock()
					if idle {
						s.close(net.ErrClosed)
						return
					}
				}
				if now.Sub(time.Unix(0, s.lastRead.Load())) > 120*time.Second {
					s.close(errors.New("SMUX keepalive timeout"))
					return
				}
				if err := s.send(ctx, 3, 0, nil, nil); err != nil {
					s.close(err)
					return
				}
			}
		}
	}()
	return s
}

func (s *smuxSession) close(err error) {
	s.once.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		s.mu.Lock()
		s.err = err
		streams := s.streams
		s.streams = map[uint32]*smuxStream{}
		s.mu.Unlock()
		s.cancel()
		s.conn.Close()
		close(s.done)
		for _, c := range streams {
			if errors.Is(err, net.ErrClosed) {
				c.Close()
			} else {
				c.finish(err)
			}
		}
		signal(s.space)
	})
}

func (s *smuxSession) writeSlot(ctx context.Context, c *smuxStream) (time.Time, error) {
	for {
		var deadline time.Time
		if c == nil {
			deadline = time.Now().Add(handshakeTimeout)
		}
		var notify <-chan struct{}
		if c != nil {
			c.mu.Lock()
			deadline = c.writeDeadline
			closed := c.closed
			c.mu.Unlock()
			if closed {
				return time.Time{}, net.ErrClosed
			}
			notify = c.writeNotify
		}
		if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
			deadline = d
		}
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		if s.ctx.Err() != nil {
			return time.Time{}, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return time.Time{}, os.ErrDeadlineExceeded
		}
		select {
		case s.gate <- struct{}{}:
			return deadline, nil
		default:
		}
		var timeout <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return time.Time{}, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		acquired := false
		var err error
		select {
		case s.gate <- struct{}{}:
			acquired = true
		case <-notify:
		case <-ctx.Done():
			err = ctx.Err()
		case <-s.ctx.Done():
			err = net.ErrClosed
		case <-timeout:
			err = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil {
			return time.Time{}, err
		}
		if acquired {
			return deadline, nil
		}
	}
}
func (s *smuxSession) send(ctx context.Context, cmd byte, id uint32, data []byte, c *smuxStream) error {
	return s.sendTarget(ctx, cmd, id, data, c, "")
}

func (s *smuxSession) sendTarget(ctx context.Context, cmd byte, id uint32, data []byte, c *smuxStream, target string) error {
	if len(data) > 16384 && (!s.cool || c == nil || c.network != 2 || len(data) > 65535) {
		return errors.New("SMUX write frame exceeds limit")
	}
	deadline, err := s.writeSlot(ctx, c)
	if err != nil {
		return err
	}
	defer func() {
		s.deadlineMu.Lock()
		s.writing.Store(nil)
		// A completed control write must not leave a close-on-deadline HTTP
		// carrier timer armed until the next keepalive tick.
		_ = s.conn.SetWriteDeadline(time.Time{})
		s.deadlineMu.Unlock()
		<-s.gate
	}()
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	if c != nil {
		c.mu.Lock()
		if c.closed || cmd == 2 && c.writeClosed {
			c.mu.Unlock()
			return net.ErrClosed
		}
		deadline = c.writeDeadline
		if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
			deadline = d
		}
		s.deadlineMu.Lock()
		s.writing.Store(c)
		_ = s.conn.SetWriteDeadline(deadline)
		s.deadlineMu.Unlock()
		c.mu.Unlock()
	} else {
		s.deadlineMu.Lock()
		s.writing.Store(nil)
		_ = s.conn.SetWriteDeadline(deadline)
		s.deadlineMu.Unlock()
	}
	if s.yamux {
		if err := s.sendYAMUX(cmd, id, data); err != nil {
			s.close(err)
			return err
		}
		return nil
	}
	if s.cool {
		if err := s.sendCool(cmd, id, data, c, target); err != nil {
			s.close(err)
			return err
		}
		return nil
	}
	if s.sudoku {
		if err := s.sendSudoku(cmd, id, data); err != nil {
			s.close(err)
			return err
		}
		return nil
	}
	s.tx[0], s.tx[1] = s.version, cmd
	binary.LittleEndian.PutUint16(s.tx[2:4], uint16(len(data)))
	binary.LittleEndian.PutUint32(s.tx[4:8], id)
	copy(s.tx[8:], data)
	if err := writeAll(s.conn, s.tx[:8+len(data)]); err != nil {
		s.close(err)
		return err
	}
	return nil
}

func (s *smuxSession) open(ctx context.Context) (*smuxStream, error) {
	return s.openPayload(ctx, nil)
}

func (s *smuxSession) openPayload(ctx context.Context, payload []byte) (*smuxStream, error) {
	s.mu.Lock()
	if s.err != nil {
		e := s.err
		s.mu.Unlock()
		return nil, e
	}
	if len(s.streams) >= 128 || s.next > ^uint32(0)-2 {
		s.mu.Unlock()
		return nil, errors.New("SMUX stream capacity exhausted")
	}
	id := s.next
	s.next += 2
	c := s.newStream(id)
	s.streams[id] = c
	s.mu.Unlock()
	if err := s.send(ctx, 0, id, payload, c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (s *smuxSession) receive() error {
	if s.yamux {
		return s.receiveYAMUX()
	}
	if s.sudoku {
		return s.receiveSudoku()
	}
	if s.cool {
		return s.receiveCool()
	}
	var h [8]byte
	var buffer []byte
	for {
		if _, err := io.ReadFull(s.conn, h[:]); err != nil {
			return err
		}
		s.lastRead.Store(time.Now().UnixNano())
		cmd, size, id := h[1], int(binary.LittleEndian.Uint16(h[2:4])), binary.LittleEndian.Uint32(h[4:8])
		if h[0] != s.version || cmd > 4 || cmd == 4 && (s.version != 2 || size != 8) || cmd != 2 && cmd != 4 && size != 0 {
			return errors.New("invalid SMUX header")
		}
		s.mu.Lock()
		c := s.streams[id]
		if cmd == 0 {
			peerOdd := !s.client
			peerID := uint64(id)
			if !s.cloak {
				peerID /= 2
			}
			if !s.cloak && (id&1 != 0) != peerOdd || !s.peerIDs.accept(peerID) || c != nil || len(s.streams) >= 128 {
				s.mu.Unlock()
				return errors.New("invalid SMUX stream identifier or capacity")
			}
			c = s.newStream(id)
			s.streams[id] = c
		}
		s.mu.Unlock()
		switch cmd {
		case 0:
			select {
			case s.accept <- c:
			case <-s.ctx.Done():
				return net.ErrClosed
			default:
				return errors.New("SMUX accept queue full")
			}
		case 1:
			if c != nil {
				if s.cloak {
					c.mu.Lock()
					c.writeClosed = true
					c.mu.Unlock()
				}
				c.finish(io.EOF)
			}
		case 2:
			if cap(buffer) < size {
				buffer = make([]byte, max(1024, size))
			}
			data := buffer[:size]
			if _, err := io.ReadFull(s.conn, data); err != nil {
				return err
			}
			if c != nil {
				if err := c.push(data); err != nil {
					return err
				}
			}
		case 3:
		case 4:
			if _, err := io.ReadFull(s.conn, h[:]); err != nil {
				return err
			}
			if c != nil {
				consumed, window := binary.LittleEndian.Uint32(h[:]), binary.LittleEndian.Uint32(h[4:])
				c.mu.Lock()
				invalid := kcpBefore(c.written, consumed) || window > smuxBufferLimit
				if !invalid && !kcpBefore(consumed, c.peerConsumed) {
					c.peerConsumed, c.peerWindow = consumed, window
					signal(c.writeNotify)
				}
				c.mu.Unlock()
				if invalid {
					return errors.New("invalid SMUXv2 credit")
				}
			}
		}
	}
}

type smuxStream struct {
	session                                                 *smuxSession
	id                                                      uint32
	network                                                 byte
	address                                                 string
	packetTargets                                           []string
	mu                                                      sync.Mutex
	writeMu                                                 sync.Mutex
	queue                                                   [][]byte
	bytes                                                   int
	written, peerConsumed, peerWindow, consumed, lastUpdate uint32
	yamuxWindow                                             uint32
	updated                                                 bool
	err                                                     error
	closed, writeClosed                                     bool
	readDeadline, writeDeadline                             time.Time
	notify                                                  chan struct{}
	writeNotify                                             chan struct{}
}

func (s *smuxSession) newStream(id uint32) *smuxStream {
	return &smuxStream{session: s, id: id, peerWindow: 262144, yamuxWindow: 262144, notify: make(chan struct{}, 1), writeNotify: make(chan struct{}, 1)}
}

func (c *smuxStream) push(data []byte) error { return c.pushTarget(data, c.address) }

func (c *smuxStream) pushTarget(data []byte, address string) error {
	packet := c.network == 2
	if len(data) == 0 && !packet {
		return nil
	}
	for {
		c.mu.Lock()
		if c.closed || c.err != nil {
			c.mu.Unlock()
			return nil
		}
		if len(c.queue) < 1024 && c.bytes+len(data) <= 1<<20 && c.session.buffered.Load()+int64(len(data)) <= smuxBufferLimit {
			// Coalesce tiny peer frames, so queue overhead is bounded by chunks,
			// rather than allowing millions of one-byte slice allocations.
			left := data
			if n := len(c.queue); n > 0 && !packet {
				last := c.queue[n-1]
				size := min(len(left), cap(last)-len(last))
				c.queue[n-1] = append(last, left[:size]...)
				left = left[size:]
			}
			if len(left) > 0 || packet {
				capacity := max(1024, len(left))
				if n := len(c.queue); n > 0 && !packet {
					capacity = max(capacity, min(16384, cap(c.queue[n-1])*2))
				}
				if packet {
					capacity = len(left)
					c.packetTargets = append(c.packetTargets, address)
				}
				chunk := make([]byte, len(left), capacity)
				copy(chunk, left)
				c.queue = append(c.queue, chunk)
			}
			c.bytes += len(data)
			c.session.buffered.Add(int64(len(data)))
			signal(c.notify)
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		if err := waitAny(c.session.space, c.session.ctx, time.Time{}); err != nil {
			return err
		}
	}
}
func (c *smuxStream) finish(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	signal(c.notify)
	signal(c.writeNotify)
	c.mu.Unlock()
	signal(c.session.space)
}

func (c *smuxStream) Read(p []byte) (int, error) {
	n, _, err := c.readTarget(p)
	return n, err
}

func (c *smuxStream) readTarget(p []byte) (int, string, error) {
	if len(p) == 0 {
		return 0, "", nil
	}
	for {
		c.mu.Lock()
		if len(c.queue) > 0 {
			if c.network == 2 {
				packet, address := c.queue[0], c.packetTargets[0]
				c.queue[0], c.packetTargets[0] = nil, ""
				c.queue, c.packetTargets = c.queue[1:], c.packetTargets[1:]
				c.bytes -= len(packet)
				c.session.buffered.Add(-int64(len(packet)))
				signal(c.session.space)
				c.mu.Unlock()
				if len(packet) > len(p) {
					return 0, address, io.ErrShortBuffer
				}
				return copy(p, packet), address, nil
			}
			n := copy(p, c.queue[0])
			c.queue[0] = c.queue[0][n:]
			if len(c.queue[0]) == 0 {
				c.queue[0] = nil
				c.queue = c.queue[1:]
			}
			c.bytes -= n
			c.consumed += uint32(n)
			update := (c.session.version == 2 || c.session.yamux) && (!c.updated || c.consumed-c.lastUpdate >= 32768)
			consumed := c.consumed
			delta := consumed - c.lastUpdate
			if update && c.session.yamux {
				c.yamuxWindow += delta
			}
			if update {
				c.updated = true
				c.lastUpdate = consumed
			}
			c.session.buffered.Add(-int64(n))
			signal(c.session.space)
			c.mu.Unlock()
			if update {
				var data [8]byte
				if c.session.yamux {
					binary.LittleEndian.PutUint32(data[:], delta)
				} else {
					binary.LittleEndian.PutUint32(data[:], consumed)
				}
				binary.LittleEndian.PutUint32(data[4:], 65536)
				if err := c.session.send(c.session.ctx, 4, c.id, data[:], nil); err != nil {
					c.finish(err)
				}
			}
			return n, "", nil
		}
		err, deadline := c.err, c.readDeadline
		c.mu.Unlock()
		if err != nil {
			return 0, "", err
		}
		if err = waitAny(c.notify, c.session.ctx, deadline); err != nil {
			return 0, "", err
		}
	}
}
func (c *smuxStream) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	closed := c.closed || c.writeClosed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if c.network == 2 {
		if err := c.session.send(c.session.ctx, 2, c.id, p, c); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), 16384)
		if c.session.version == 2 || c.session.yamux {
			for {
				c.mu.Lock()
				if c.closed || c.writeClosed || c.err != nil && c.err != io.EOF {
					err := c.err
					if err == nil {
						err = net.ErrClosed
					}
					c.mu.Unlock()
					return written, err
				}
				credit := int64(c.peerWindow) - int64(uint32(c.written-c.peerConsumed))
				if c.session.yamux {
					credit = int64(c.peerWindow)
				}
				d := c.writeDeadline
				if credit > 0 {
					n = min(n, int(credit))
					c.written += uint32(n)
					if c.session.yamux {
						c.peerWindow -= uint32(n)
					}
					c.mu.Unlock()
					break
				}
				c.mu.Unlock()
				if err := waitAny(c.writeNotify, c.session.ctx, d); err != nil {
					return written, err
				}
			}
		}
		if err := c.session.send(c.session.ctx, 2, c.id, p[:n], c); err != nil {
			if c.session.version == 2 || c.session.yamux {
				c.mu.Lock()
				c.written -= uint32(n)
				if c.session.yamux {
					c.peerWindow += uint32(n)
				}
				c.mu.Unlock()
			}
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
func (c *smuxStream) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	done := c.closed || c.writeClosed
	c.writeClosed = true
	c.mu.Unlock()
	if done {
		return nil
	}
	return c.session.send(c.session.ctx, 1, c.id, nil, c)
}
func (c *smuxStream) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	send := !c.writeClosed
	c.writeClosed = true
	c.session.buffered.Add(-int64(c.bytes))
	c.bytes = 0
	c.queue = nil
	c.packetTargets = nil
	c.err = net.ErrClosed
	signal(c.notify)
	signal(c.writeNotify)
	c.mu.Unlock()
	signal(c.session.space)
	s := c.session
	s.mu.Lock()
	delete(s.streams, c.id)
	if len(s.streams) == 0 {
		s.idleAt.Store(time.Now().UnixNano())
	}
	s.mu.Unlock()
	if send {
		return s.send(s.ctx, 1, c.id, nil, nil)
	}
	return nil
}
func (c *smuxStream) LocalAddr() net.Addr  { return c.session.conn.LocalAddr() }
func (c *smuxStream) RemoteAddr() net.Addr { return c.session.conn.RemoteAddr() }
func (c *smuxStream) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *smuxStream) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	signal(c.notify)
	signal(c.writeNotify)
	c.mu.Unlock()
	return nil
}
func (c *smuxStream) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.session.deadlineMu.Lock()
	if c.session.writing.Load() == c {
		_ = c.session.conn.SetWriteDeadline(t)
	}
	c.session.deadlineMu.Unlock()
	signal(c.writeNotify)
	c.mu.Unlock()
	return nil
}
