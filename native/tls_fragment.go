package native

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func (o TLSOptions) fragmentDelay() (time.Duration, error) {
	if o.FragmentFallbackDelay != "" && !o.Fragment {
		return 0, errors.New("fragment_fallback_delay requires fragment")
	}
	delay, err := optionDuration(o.FragmentFallbackDelay, 500*time.Millisecond)
	if err != nil || delay <= 0 {
		return 0, errors.New("fragment_fallback_delay must be a positive duration")
	}
	return delay, nil
}

type tlsFragmentConn struct {
	net.Conn
	writeMu    sync.Mutex
	writeErr   error
	fallback   time.Duration
	done       atomic.Bool
	closed     chan struct{}
	closeOnce  sync.Once
	deadlineMu sync.Mutex
	deadline   time.Time
	changed    chan struct{}
}

func newTLSFragmentConn(conn net.Conn, delay time.Duration) *tlsFragmentConn {
	return &tlsFragmentConn{Conn: conn, fallback: delay, closed: make(chan struct{}), changed: make(chan struct{}, 1)}
}

// Split writes inside SNI without changing any record or transcript bytes.
func tlsFragmentSplit(p []byte) (int, error) {
	if len(p) < 6 || p[0] != 22 || p[5] != 1 {
		return 0, nil
	}
	if len(p) > 1<<20 {
		return 0, errors.New("TLS fragment write exceeds1MiB")
	}
	size := int(binary.BigEndian.Uint16(p[3:5]))
	if size > len(p)-5 || size < 4 {
		return 0, errors.New("truncated TLS ClientHello record")
	}
	split := 5 + size/2
	if name, start, ok := clientHelloSNI(p[5 : 5+size]); ok && len(name) > 1 {
		split = 5 + start + len(name)/2
	}
	return min(split, 4+size), nil
}

func fragmentTCP(conn net.Conn) net.Conn {
	for {
		owned, ok := conn.(*ownedConn)
		if !ok {
			return conn
		}
		conn = owned.Conn
	}
}

func tlsFragmentRTT(conn net.Conn) time.Duration {
	conn = fragmentTCP(conn)
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return 0
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0
	}
	var rtt time.Duration
	if err = raw.Control(func(fd uintptr) { rtt = tcpFragmentRTT(fd) }); err != nil {
		return 0
	}
	return rtt
}

func tcpFragmentRTTValue(data []byte, offset int, unit time.Duration) time.Duration {
	if len(data) < offset+4 {
		return 0
	}
	return time.Duration(binary.NativeEndian.Uint32(data[offset:])) * unit
}

func (c *tlsFragmentConn) wait(delay time.Duration) error {
	until := time.Now().Add(delay)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		c.deadlineMu.Lock()
		deadline := c.deadline
		c.deadlineMu.Unlock()
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		if !now.Before(until) {
			return nil
		}
		wake := until
		if !deadline.IsZero() && deadline.Before(wake) {
			wake = deadline
		}
		timer.Reset(time.Until(wake))
		select {
		case <-c.closed:
			return net.ErrClosed
		case <-c.changed:
		case <-timer.C:
		}
	}
}

func (c *tlsFragmentConn) Write(p []byte) (int, error) {
	if c.done.Load() {
		return c.Conn.Write(p)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	split, err := tlsFragmentSplit(p)
	if err != nil {
		return 0, err
	}
	if split == 0 {
		return c.Conn.Write(p)
	}
	if tcp, ok := fragmentTCP(c.Conn).(*net.TCPConn); ok {
		if err = tcp.SetNoDelay(true); err != nil {
			return 0, err
		}
	}
	n, err := writeTLSFragment(c.Conn, p[:split])
	if err == nil {
		delay := c.fallback
		if rtt := tlsFragmentRTT(c.Conn); rtt >= 20*time.Millisecond {
			delay = 2 * rtt
		}
		err = c.wait(delay)
	}
	if err == nil {
		var tail int
		tail, err = writeTLSFragment(c.Conn, p[split:])
		n += tail
	}
	c.writeErr = err
	return n, err
}

func writeTLSFragment(w io.Writer, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
		p = p[n:]
	}
	return total, nil
}

func (c *tlsFragmentConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
func (c *tlsFragmentConn) setDeadline(t time.Time) {
	c.deadlineMu.Lock()
	c.deadline = t
	c.deadlineMu.Unlock()
	select {
	case c.changed <- struct{}{}:
	default:
	}
}
func (c *tlsFragmentConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetDeadline(t); err != nil {
		return err
	}
	c.setDeadline(t)
	return nil
}
func (c *tlsFragmentConn) SetWriteDeadline(t time.Time) error {
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.setDeadline(t)
	return nil
}
