package native

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type snellIdleConn struct {
	stream *snellConn
	at     time.Time
}
type snellPool struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	idle     []snellIdleConn
	all      map[*snellConn]bool
	timer    *time.Timer
	closed   bool
	timeout  time.Duration
}

func (p *snellPool) arm() {
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
	if len(p.idle) == 0 || p.closed {
		return
	}
	p.timer = time.AfterFunc(max(time.Millisecond, time.Until(p.idle[0].at.Add(p.timeout))), p.expire)
}
func (p *snellPool) expire() {
	p.mu.Lock()
	for len(p.idle) > 0 && time.Since(p.idle[0].at) >= p.timeout {
		c := p.idle[0].stream
		p.idle = p.idle[1:]
		delete(p.all, c)
		c.Close()
	}
	p.arm()
	p.mu.Unlock()
}
func (p *snellPool) close() { p.clear(true) }
func (p *snellPool) clear(permanent bool) {
	p.mu.Lock()
	if permanent {
		p.closed = true
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	all := p.all
	p.all = map[*snellConn]bool{}
	p.idle = nil
	p.mu.Unlock()
	for c := range all {
		c.Close()
	}
}
func (p *snellPool) discard(s *snellConn) { p.mu.Lock(); delete(p.all, s); p.mu.Unlock(); s.Close() }
func (p *snellPool) put(s *snellConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.all[s] || len(p.idle) >= 8 {
		delete(p.all, s)
		s.Close()
		return
	}
	p.idle = append(p.idle, snellIdleConn{s, time.Now()})
	p.arm()
}
func (p *snellPool) dial(ctx context.Context, address string) (net.Conn, error) {
	for attempt := 0; attempt < 2; attempt++ {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, net.ErrClosed
		}
		var stream *snellConn
		reused := len(p.idle) > 0
		if reused {
			entry := p.idle[len(p.idle)-1]
			p.idle = p.idle[:len(p.idle)-1]
			stream = entry.stream
			p.arm()
			if time.Since(entry.at) >= p.timeout {
				delete(p.all, stream)
				stream.Close()
				stream = nil
				reused = false
			}
		}
		p.mu.Unlock()
		if stream == nil {
			raw, e := p.runtime.endpoint(ctx, p.outbound, "tcp")
			if e != nil {
				return nil, e
			}
			if d, ok := ctx.Deadline(); ok {
				raw.SetDeadline(d)
			}
			secured := raw
			if cfg := p.runtime.clientTLS[p.outbound.Tag]; cfg != nil {
				cfg, e = p.runtime.outboundTLS(ctx, p.outbound)
				if e != nil {
					raw.Close()
					return nil, e
				}
				c, err := handshakeTLS(ctx, raw, cfg, p.outbound.TLS)
				if err != nil {
					raw.Close()
					return nil, err
				}
				secured = c
			}
			secured, e = dialSnellObfs(secured, p.outbound)
			if e != nil {
				raw.Close()
				return nil, e
			}
			stream = newSnellConn(secured, p.outbound.Password, p.outbound.Version, &p.runtime.replay)
			p.mu.Lock()
			if p.closed || len(p.all) >= 128 {
				p.mu.Unlock()
				raw.Close()
				return nil, errors.New("Snell pool capacity reached or closed")
			}
			p.all[stream] = true
			p.mu.Unlock()
		}
		if d, ok := ctx.Deadline(); ok {
			stream.SetDeadline(d)
		}
		stop := context.AfterFunc(ctx, func() { stream.Close() })
		reply, e := snellClientStream(stream, p.outbound, address, false)

		stop()
		if e != nil {
			p.discard(stream)
			if reused && attempt == 0 && ctx.Err() == nil {
				continue
			}
			return nil, e
		}
		stream.SetDeadline(time.Time{})
		return p.runtime.own(&snellPooledConn{snellReplyConn: reply.(*snellReplyConn), pool: p})
	}
	return nil, net.ErrClosed
}

type snellPooledConn struct {
	*snellReplyConn
	pool            *snellPool
	readMu          sync.Mutex
	peerEOF, closed atomic.Bool
}

func (c *snellPooledConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	n, e := c.snellReplyConn.Read(b)
	if e == io.EOF {
		c.peerEOF.Store(true)
	}
	return n, e
}
func (c *snellPooledConn) Write(b []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.snellReplyConn.Write(b)
}
func (c *snellPooledConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	stream := c.snellConn
	stream.SetWriteDeadline(time.Now().Add(time.Second))
	if e := stream.CloseWrite(); e != nil {
		c.pool.discard(stream)
		return e
	}
	stream.SetReadDeadline(time.Now().Add(time.Second))
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if !c.peerEOF.Load() {
		if _, e := io.CopyN(io.Discard, c.snellReplyConn, 512<<10); e != io.EOF {
			c.pool.discard(stream)
			return nil
		}
	}
	stream.rmu.Lock()
	clean := stream.rerr == io.EOF && len(stream.pending) == 0
	if clean {
		stream.rerr = nil
	}
	stream.rmu.Unlock()
	if !clean {
		c.pool.discard(stream)
		return nil
	}
	stream.wmu.Lock()
	clean = stream.werr == nil
	if clean {
		stream.ended = false
	}
	stream.wmu.Unlock()
	if !clean {
		c.pool.discard(stream)
		return nil
	}
	stream.SetDeadline(time.Time{})
	c.pool.put(stream)
	return nil
}
