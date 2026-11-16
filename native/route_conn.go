package native

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// Defer only routes containing sniff actions. This also works for module Dial:
// Handshake fragments are bounded and replayed unchanged after the route is selected.
type routeConn struct {
	runtime                               *Runtime
	ctx                                   context.Context
	cancel                                context.CancelFunc
	q                                     request
	once                                  sync.Once
	ready                                 chan struct{}
	mu                                    sync.Mutex
	writeMu                               sync.Mutex
	pending                               []byte
	packets                               []int
	sniffTimeout                          time.Duration
	sniffTimer                            *time.Timer
	conn                                  net.Conn
	err                                   error
	closed                                bool
	deadline, readDeadline, writeDeadline time.Time
}

func newRouteConn(r *Runtime, ctx context.Context, q request) *routeConn {
	ctx, cancel := context.WithCancel(context.WithValue(r.ctx, inboundRouteKey{}, true))
	timeout := 300 * time.Millisecond
	for _, rule := range r.rules {
		if rule.rule.Action == "sniff" && rule.rule.Timeout != "" {
			timeout, _ = optionDuration(rule.rule.Timeout, timeout)
			break
		}
	}
	return &routeConn{runtime: r, ctx: ctx, cancel: cancel, q: q, ready: make(chan struct{}), sniffTimeout: timeout}
}
func (c *routeConn) init(payload []byte, packets []int) (written int, err error) {
	c.once.Do(func() {
		q := c.q
		q.payload = payload
		ctx := c.ctx
		c.mu.Lock()
		if c.sniffTimer != nil {
			c.sniffTimer.Stop()
			c.sniffTimer = nil
		}
		deadline := c.deadline
		if !c.writeDeadline.IsZero() && (deadline.IsZero() || c.writeDeadline.Before(deadline)) {
			deadline = c.writeDeadline
		}
		c.mu.Unlock()
		if !deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline)
			defer cancel()
		}
		conn, e := c.runtime.routeResolved(ctx, q)
		c.mu.Lock()
		c.conn = conn
		if conn != nil {
			if c.closed {
				conn.Close()
				e = net.ErrClosed
			} else {
				conn.SetDeadline(c.deadline)
				if !c.readDeadline.IsZero() {
					conn.SetReadDeadline(c.readDeadline)
				}
				if !c.writeDeadline.IsZero() {
					conn.SetWriteDeadline(c.writeDeadline)
				}
			}
		}
		c.err = e
		c.mu.Unlock()
		close(c.ready)
	})
	c.pending, c.packets = nil, nil
	if c.err != nil {
		return 0, c.err
	}
	// Publish the connection before replay so concurrent reads can drain an early response.
	if c.q.network == "udp" {
		for _, size := range packets {
			var n int
			n, err = c.conn.Write(payload[written : written+size])
			written += n
			if n != size && err == nil {
				err = io.ErrShortWrite
			}
			if err != nil {
				break
			}
		}
	} else if len(payload) > 0 {
		written, err = c.conn.Write(payload)
		if written != len(payload) && err == nil {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		c.Close()
	}
	return
}

func (c *routeConn) flush() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.ready:
		return
	case <-c.ctx.Done():
		return
	default:
	}
	c.init(c.pending, c.packets)
}

func (c *routeConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	select {
	case <-c.ready:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Read(b)
	default:
	}
	timeout := c.sniffTimeout
	c.mu.Lock()
	deadline := c.readDeadline
	if deadline.IsZero() {
		deadline = c.deadline
	}
	c.mu.Unlock()
	if !deadline.IsZero() {
		timeout = min(timeout, max(0, time.Until(deadline)))
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.ready:
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-timer.C:
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		c.flush()
		select {
		case <-c.ready:
		case <-c.ctx.Done():
			return 0, c.ctx.Err()
		}
	}
	if c.err != nil {
		return 0, c.err
	}
	return c.conn.Read(b)
}
func (c *routeConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.ready:
		if c.err != nil {
			return 0, c.err
		}
		return c.conn.Write(b)
	default:
	}
	c.mu.Lock()
	closed, deadline := c.closed, c.writeDeadline
	if deadline.IsZero() {
		deadline = c.deadline
	}
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	previous := len(c.pending)
	if previous > 0 && len(b) > sniffLimit-previous {
		if _, err := c.init(c.pending, c.packets); err != nil {
			return 0, err
		}
		return c.conn.Write(b)
	}
	data := b
	if previous > 0 {
		data = append(c.pending, b...)
	}
	packets := c.packets
	if c.q.network == "udp" {
		packets = append(packets, len(b))
	}
	more := false
	if len(data) < sniffLimit && len(packets) < 32 {
		for _, rule := range c.runtime.rules {
			if rule.rule.Action == "sniff" && sniffNeedsMore(c.q.network, data, rule.rule.Sniffer) {
				more = true
				break
			}
		}
	}
	if more {
		if previous == 0 {
			data = append([]byte(nil), b...)
		}
		c.pending, c.packets = data, packets
		c.mu.Lock()
		if c.sniffTimer == nil {
			wait := c.sniffTimeout
			if !deadline.IsZero() {
				wait = min(wait, max(0, time.Until(deadline)))
			}
			c.sniffTimer = time.AfterFunc(wait, c.flush)
		}
		c.mu.Unlock()
		return len(b), nil
	}
	n, err := c.init(data, packets)
	return max(0, n-previous), err
}
func (c *routeConn) Close() error {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	if c.sniffTimer != nil {
		c.sniffTimer.Stop()
		c.sniffTimer = nil
	}
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
func (c *routeConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return routeAddr(c.q.network)
}
func (c *routeConn) RemoteAddr() net.Addr { return routeAddr(c.q.address) }
func (c *routeConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = t
	if c.conn != nil {
		return c.conn.SetDeadline(t)
	}
	return nil
}
func (c *routeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	if c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}
	return nil
}
func (c *routeConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	if c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}
	return nil
}
func (c *routeConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.ready:
	default:
		if len(c.pending) == 0 {
			return nil
		}
		if _, err := c.init(c.pending, c.packets); err != nil {
			return err
		}
	}
	if c.err != nil {
		return c.err
	}
	if v, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}

type routeAddr string

func (a routeAddr) Network() string { return "lanboat" }
func (a routeAddr) String() string  { return string(a) }
func (r *Runtime) dnsRouteConn(ctx context.Context, q request) (net.Conn, error) {
	a, b := net.Pipe()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		a.Close()
		b.Close()
		return nil, net.ErrClosed
	}
	r.workers.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.workers.Done()
		defer b.Close()
		stop := context.AfterFunc(r.ctx, func() { b.Close() })
		defer stop()
		for {
			var query []byte
			if q.network == "tcp" {
				var n [2]byte
				if _, e := io.ReadFull(b, n[:]); e != nil {
					return
				}
				query = make([]byte, binary.BigEndian.Uint16(n[:]))
				if _, e := io.ReadFull(b, query); e != nil {
					return
				}
			} else {
				query = make([]byte, 65535)
				n, e := b.Read(query)
				if e != nil {
					return
				}
				query = query[:n]
			}
			reply, e := r.ExchangeDNS(WithMetadata(r.ctx, q.metadata), query, q.inbound)
			if e != nil {
				return
			}
			if q.network == "tcp" {
				reply = append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...)
			}
			if _, e = b.Write(reply); e != nil {
				return
			}
		}
	}()
	return a, nil
}
