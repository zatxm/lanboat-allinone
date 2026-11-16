package native

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// An account follows one KIP session across its HTTP upload and download sockets.
type sudokuAccount struct {
	mu       sync.Mutex
	user     *sudokuUser
	forward  *sudokuAccount
	up, down uint64
	wires    map[*sudokuWire]struct{}
	logical  net.Conn
	done     chan struct{}
	closed   bool
	finished bool
}

func newSudokuAccount() *sudokuAccount {
	return &sudokuAccount{wires: map[*sudokuWire]struct{}{}, done: make(chan struct{})}
}

func (a *sudokuAccount) wrap(c net.Conn) net.Conn {
	w := &sudokuWire{Conn: c, account: a}
	a.wires[w] = struct{}{}
	return w
}

func (a *sudokuAccount) bind(u *sudokuUser) error {
	a.mu.Lock()
	if a.closed || a.forward != nil || a.user != nil {
		a.mu.Unlock()
		return net.ErrClosed
	}
	u.mu.Lock()
	u.rollMonth(time.Now())
	if u.limit != 0 && u.used >= u.limit {
		u.mu.Unlock()
		a.mu.Unlock()
		return errSudokuQuota
	}
	u.sessions[a] = struct{}{}
	a.user = u
	u.mu.Unlock()
	up, down := a.up, a.down
	a.up, a.down = 0, 0
	a.mu.Unlock()
	return u.record(up, down)
}

func (a *sudokuAccount) add(up, down uint64) error {
	a.mu.Lock()
	f, u := a.forward, a.user
	if f == nil && u == nil {
		a.up += up
		a.down += down
	}
	a.mu.Unlock()
	if f != nil {
		return f.add(up, down)
	}
	if u != nil {
		return u.record(up, down)
	}
	return nil
}

func (a *sudokuAccount) join(target *sudokuAccount) error {
	if a == target {
		return nil
	}
	a.mu.Lock()
	if a.closed || a.user != nil || a.forward != nil {
		a.mu.Unlock()
		return net.ErrClosed
	}
	target.mu.Lock()
	if target.closed {
		target.mu.Unlock()
		a.mu.Unlock()
		return net.ErrClosed
	}
	a.forward = target
	for w := range a.wires {
		target.wires[w] = struct{}{}
	}
	a.wires = nil
	u := target.user
	if u == nil {
		target.up += a.up
		target.down += a.down
	}
	target.mu.Unlock()
	up, down := a.up, a.down
	a.up, a.down = 0, 0
	a.mu.Unlock()
	if u != nil {
		return u.record(up, down)
	}
	return nil
}

func (a *sudokuAccount) remove(w *sudokuWire) {
	a.mu.Lock()
	f := a.forward
	delete(a.wires, w)
	a.mu.Unlock()
	if f != nil {
		f.remove(w)
	}
}

func (a *sudokuAccount) Close() error {
	a.mu.Lock()
	if f := a.forward; f != nil {
		a.mu.Unlock()
		return f.Close()
	}
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	if !a.finished {
		close(a.done)
	}
	u := a.user
	logical := a.logical
	wires := make([]*sudokuWire, 0, len(a.wires))
	for w := range a.wires {
		wires = append(wires, w)
	}
	a.mu.Unlock()
	if u != nil {
		u.mu.Lock()
		delete(u.sessions, a)
		u.mu.Unlock()
	}
	for _, w := range wires {
		w.Close()
	}
	if logical != nil {
		logical.Close()
	}
	return nil
}

// A graceful application EOF still lets HTTP finish its chunks and trailers.
func (a *sudokuAccount) finish() {
	a.mu.Lock()
	if a.closed || a.finished {
		a.mu.Unlock()
		return
	}
	a.finished = true
	close(a.done)
	u := a.user
	a.mu.Unlock()
	if u != nil {
		u.mu.Lock()
		delete(u.sessions, a)
		u.mu.Unlock()
	}
}

type sudokuWire struct {
	net.Conn
	account *sudokuAccount
	once    sync.Once
}

func (c *sudokuWire) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		if e := c.account.add(uint64(n), 0); e != nil {
			c.account.Close()
			err = e
		}
	}
	return n, err
}
func (c *sudokuWire) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		if e := c.account.add(0, uint64(n)); e != nil {
			c.account.Close()
			err = e
		}
	}
	return n, err
}
func (c *sudokuWire) Close() error {
	var err error
	c.once.Do(func() { c.account.remove(c); err = c.Conn.Close() })
	return err
}
func (c *sudokuWire) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

type sudokuBandwidth struct {
	mu                            sync.Mutex
	bytesPerSecond, burst, credit float64
	at                            time.Time
}

func (b *sudokuBandwidth) init(mbps float64) {
	b.bytesPerSecond = mbps * 125000
	b.burst = min(65536, max(1, b.bytesPerSecond/10))
	b.credit, b.at = b.burst, time.Now()
}

type sudokuPayload struct {
	net.Conn
	ctx      context.Context
	account  *sudokuAccount
	user     *sudokuUser
	mu       sync.Mutex
	deadline [2]time.Time
	wake     chan struct{}
}

func newSudokuPayload(ctx context.Context, c net.Conn, a *sudokuAccount) *sudokuPayload {
	a.mu.Lock()
	u := a.user
	a.mu.Unlock()
	until := time.Now().Add(handshakeTimeout)
	return &sudokuPayload{Conn: c, ctx: ctx, account: a, user: u, deadline: [2]time.Time{until, until}, wake: make(chan struct{})}
}
func (c *sudokuPayload) wait(direction, n int) error {
	if c.user == nil {
		return errors.New("unauthenticated Sudoku payload")
	}
	b := &c.user.rate[direction]
	if b.bytesPerSecond == 0 {
		return nil
	}
	for n > 0 {
		c.mu.Lock()
		deadline, wake := c.deadline[direction], c.wake
		c.mu.Unlock()
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-c.account.done:
			return net.ErrClosed
		default:
		}
		chunk := min(n, max(1, int(b.burst)))
		b.mu.Lock()
		now = time.Now()
		b.credit = min(b.burst, b.credit+now.Sub(b.at).Seconds()*b.bytesPerSecond)
		b.at = now
		if b.credit >= float64(chunk) {
			b.credit -= float64(chunk)
			b.mu.Unlock()
			n -= chunk
			continue
		}
		delay := time.Duration((float64(chunk) - b.credit) / b.bytesPerSecond * float64(time.Second))
		b.mu.Unlock()
		if !deadline.IsZero() {
			delay = min(delay, time.Until(deadline))
		}
		timer := time.NewTimer(max(delay, time.Microsecond))
		var err error
		select {
		case <-timer.C:
		case <-wake:
		case <-c.account.done:
			err = net.ErrClosed
		case <-c.ctx.Done():
			err = c.ctx.Err()
		}
		timer.Stop()
		if err != nil {
			return err
		}
	}
	return nil
}
func (c *sudokuPayload) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		if e := c.wait(0, n); e != nil {
			c.Close()
			return 0, e
		}
	}
	return n, err
}
func (c *sudokuPayload) Write(b []byte) (int, error) {
	if err := c.wait(1, len(b)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}
func (c *sudokuPayload) Close() error { c.account.finish(); return c.Conn.Close() }
func (c *sudokuPayload) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
func (c *sudokuPayload) setDeadline(t time.Time, direction int) {
	c.mu.Lock()
	if direction < 0 {
		c.deadline = [2]time.Time{t, t}
	} else {
		c.deadline[direction] = t
	}
	close(c.wake)
	c.wake = make(chan struct{})
	c.mu.Unlock()
}
func (c *sudokuPayload) SetDeadline(t time.Time) error {
	c.setDeadline(t, -1)
	return c.Conn.SetDeadline(t)
}
func (c *sudokuPayload) SetReadDeadline(t time.Time) error {
	c.setDeadline(t, 0)
	return c.Conn.SetReadDeadline(t)
}
func (c *sudokuPayload) SetWriteDeadline(t time.Time) error {
	c.setDeadline(t, 1)
	return c.Conn.SetWriteDeadline(t)
}
