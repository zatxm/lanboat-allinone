package native

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type cloakLink struct {
	net.Conn
	websocket bool
}

// Session teardown aborts the socket; TLS close_notify can block behind an unresponsive peer.
func (l *cloakLink) Close() error {
	conn := l.Conn
	for {
		switch value := conn.(type) {
		case *websocketConn:
			conn = value.Conn
		case *bufferedConn:
			conn = value.Conn
		case *tls.Conn:
			return value.NetConn().Close()
		default:
			return conn.Close()
		}
	}
}
func (l *cloakLink) readFrame() ([]byte, error) {
	if l.websocket {
		return cloakWSRead(l.Conn)
	}
	var header [5]byte
	if _, err := io.ReadFull(l.Conn, header[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if header[0] != 23 || header[1] != 3 || header[2] != 3 || n < 22 || n > cloakWireLimit {
		return nil, errors.New("invalid Cloak application record")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(l.Conn, body)
	return body, err
}
func (l *cloakLink) writeFrame(b []byte) error {
	if l.websocket {
		_, e := l.Write(b)
		return e
	}
	return writeAll(l.Conn, shadowFrame(23, b))
}

type cloakStreamState struct {
	send, next uint64
	pending    map[uint64]cloakFrame
	link       int
	active     time.Time
	started    bool
}
type cloakMuxConn struct {
	r             *Runtime
	ctx           context.Context
	cancel        context.CancelFunc
	codec         *cloakCodec
	links         []*cloakLink
	mu, rmu       sync.Mutex
	states        map[uint32]*cloakStreamState
	finished      packetWindow
	queued        int
	current       []byte
	currentCharge int
	frames        chan cloakFrame
	errors        chan error
	workers       sync.WaitGroup
	once          sync.Once
	readDeadline  time.Time
	readErr       error
	readWake      chan struct{}
}

func newCloakMux(r *Runtime, key [32]byte, method byte, links []*cloakLink) (*cloakMuxConn, error) {
	codec, e := newCloakCodec(key, method)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(r.ctx)
	c := &cloakMuxConn{r: r, ctx: ctx, cancel: cancel, codec: codec, links: nil, states: map[uint32]*cloakStreamState{}, frames: make(chan cloakFrame, 8), errors: make(chan error, 1), readWake: make(chan struct{}, 1)}
	for _, link := range links {
		if e = c.addLink(link); e != nil {
			c.Close()
			return nil, e
		}
	}
	return c, nil
}
func (c *cloakMuxConn) addLink(link *cloakLink) error {
	c.mu.Lock()
	if c.ctx.Err() != nil || len(c.links) >= 8 {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.links = append(c.links, link)
	c.workers.Add(1)
	c.mu.Unlock()
	go c.receive(link)
	return nil
}
func (c *cloakMuxConn) reserve(n int) bool {
	if c.r.cloakBudget.Add(int64(n)) > 16<<20 {
		c.r.cloakBudget.Add(-int64(n))
		return false
	}
	return true
}
func (c *cloakMuxConn) release(n int) { c.r.cloakBudget.Add(-int64(n)) }
func (c *cloakMuxConn) receive(link *cloakLink) {
	defer c.workers.Done()
	for {
		b, e := link.readFrame()
		if e != nil {
			select {
			case c.errors <- e:
			default:
			}
			return
		}
		f, e := c.codec.open(b)
		if e != nil {
			select {
			case c.errors <- e:
			default:
			}
			return
		}
		f.charge = len(b)
		if !c.reserve(f.charge) {
			select {
			case c.errors <- errors.New("Cloak receive budget exhausted"):
			default:
			}
			return
		}
		select {
		case c.frames <- f:
		case <-c.ctx.Done():
			c.release(f.charge)
			return
		}
	}
}
func cloakSMUXFrame(b []byte, cmd byte, id uint32, payload []byte) []byte {
	b = append(b, 1, cmd)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(payload)))
	b = binary.LittleEndian.AppendUint32(b, id)
	return append(b, payload...)
}
func (c *cloakMuxConn) releaseState(state *cloakStreamState) {
	for _, f := range state.pending {
		c.release(f.charge)
		c.queued -= f.charge
	}
}
func (c *cloakMuxConn) consume(f cloakFrame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f.close == 2 {
		c.release(f.charge)
		return net.ErrClosed
	}
	state := c.states[f.id]
	if state == nil {
		if !c.finished.fresh(uint64(f.id)) || f.close != 0 {
			c.release(f.charge)
			return nil
		}
		if len(c.states) >= 128 {
			c.release(f.charge)
			return errors.New("Cloak stream capacity exceeded")
		}
		state = &cloakStreamState{pending: map[uint64]cloakFrame{}, link: int(f.id) % len(c.links), active: time.Now()}
		c.states[f.id] = state
	}
	state.active = time.Now()
	if f.seq < state.next {
		c.release(f.charge)
		return nil
	}
	if _, exists := state.pending[f.seq]; exists {
		c.release(f.charge)
		return nil
	}
	if f.seq-state.next > 256 || len(state.pending) >= 64 || c.queued+f.charge > 4<<20 {
		c.release(f.charge)
		return errors.New("Cloak reordering buffer exceeded")
	}
	state.pending[f.seq] = f
	c.queued += f.charge
	var ready []cloakFrame
	for {
		next, ok := state.pending[state.next]
		if !ok {
			break
		}
		delete(state.pending, state.next)
		state.next++
		c.queued -= next.charge
		ready = append(ready, next)
		if next.close != 0 {
			break
		}
	}
	for _, f := range ready {
		if !state.started {
			c.current = cloakSMUXFrame(c.current, 0, f.id, nil)
			state.started = true
		}
		if f.close == 1 {
			c.current = cloakSMUXFrame(c.current, 1, f.id, nil)
			c.releaseState(state)
			delete(c.states, f.id)
			c.finished.accept(uint64(f.id))
		} else if len(f.body) > 0 {
			c.current = cloakSMUXFrame(c.current, 2, f.id, f.body)
		}
		c.currentCharge += f.charge
	}
	return nil
}
func (c *cloakMuxConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for len(c.current) == 0 {
		if c.currentCharge != 0 {
			c.release(c.currentCharge)
			c.currentCharge = 0
		}
		if c.readErr != nil {
			select {
			case frame := <-c.frames:
				if err := c.consume(frame); err != nil {
					return 0, err
				}
				continue
			default:
				return 0, c.readErr
			}
		}
		c.mu.Lock()
		deadline := c.readDeadline
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		var f cloakFrame
		var err error
		received := false
		terminal := false
		select {
		case f = <-c.frames:
			received = true
		case err = <-c.errors:
			terminal = true
		case <-c.ctx.Done():
			err = net.ErrClosed
		case <-c.readWake:
		case <-timeout:
			err = os.ErrDeadlineExceeded
		}
		if timer != nil {
			timer.Stop()
		}
		if err != nil && terminal {
			c.readErr = err
			continue
		}
		if err != nil {
			return 0, err
		}
		if received {
			if e := c.consume(f); e != nil {
				return 0, e
			}
		}
	}
	n := copy(b, c.current)
	c.current = c.current[n:]
	if len(c.current) == 0 && c.currentCharge != 0 {
		c.release(c.currentCharge)
		c.currentCharge = 0
	}
	return n, nil
}
func (c *cloakMuxConn) Write(b []byte) (int, error) {
	if len(b) < 8 || b[0] != 1 || int(binary.LittleEndian.Uint16(b[2:])) != len(b)-8 {
		return 0, errors.New("invalid Cloak SMUX adapter frame")
	}
	cmd, id := b[1], binary.LittleEndian.Uint32(b[4:])
	if cmd > 2 {
		return len(b), nil
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	state := c.states[id]
	if state == nil {
		if !c.finished.fresh(uint64(id)) {
			c.mu.Unlock()
			if cmd == 1 {
				return len(b), nil
			}
			return 0, net.ErrClosed
		}
		if len(c.states) >= 128 {
			c.mu.Unlock()
			return 0, errors.New("Cloak stream capacity exceeded")
		}
		state = &cloakStreamState{pending: map[uint64]cloakFrame{}, link: int(id) % len(c.links), active: time.Now(), started: true}
		c.states[id] = state
	}
	state.active = time.Now()
	link := c.links[state.link]
	c.mu.Unlock()
	if cmd == 0 {
		return len(b), nil
	}
	payload := b[8:]
	closing := byte(0)
	if cmd == 1 {
		closing = 1
		payload = make([]byte, 16)
		rand.Read(payload)
	}
	for len(payload) > 0 {
		c.mu.Lock()
		if state.send == ^uint64(0) {
			c.mu.Unlock()
			return 0, errors.New("Cloak sequence exhausted")
		}
		seq := state.send
		state.send++
		c.mu.Unlock()
		n := min(len(payload), 16000)
		frame := c.codec.seal(cloakFrame{id: id, seq: seq, close: closing, body: payload[:n]})
		if e := link.writeFrame(frame); e != nil {
			return 0, e
		}
		payload = payload[n:]
	}
	if cmd == 1 {
		c.mu.Lock()
		if c.states[id] == state {
			c.releaseState(state)
			delete(c.states, id)
			c.finished.accept(uint64(id))
		}
		c.mu.Unlock()
	}
	return len(b), nil
}
func (c *cloakMuxConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		links := append([]*cloakLink(nil), c.links...)
		c.mu.Unlock()
		for _, l := range links {
			l.SetWriteDeadline(time.Now())
			l.Close()
		}
		c.workers.Wait()
		c.rmu.Lock()
		c.mu.Lock()
		for _, state := range c.states {
			c.releaseState(state)
		}
		c.states = nil
		if c.currentCharge != 0 {
			c.release(c.currentCharge)
			c.currentCharge = 0
		}
		c.current = nil
		c.mu.Unlock()
		for {
			select {
			case f := <-c.frames:
				c.release(f.charge)
			default:
				c.rmu.Unlock()
				return
			}
		}
	})
	return nil
}
func (c *cloakMuxConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.links[0].LocalAddr()
}
func (c *cloakMuxConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.links[0].RemoteAddr()
}
func (c *cloakMuxConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *cloakMuxConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	signal(c.readWake)
	return nil
}
func (c *cloakMuxConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	links := append([]*cloakLink(nil), c.links...)
	c.mu.Unlock()
	for _, l := range links {
		if e := l.SetWriteDeadline(t); e != nil {
			return e
		}
	}
	return nil
}
