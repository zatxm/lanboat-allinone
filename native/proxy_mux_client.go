package native

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

type proxyMuxClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	current  *smuxSession
	all      []*smuxSession
}

func (p *proxyMuxClient) reset() {
	p.mu.Lock()
	all := p.all
	p.current = nil
	p.all = nil
	p.mu.Unlock()
	for _, s := range all {
		s.close(net.ErrClosed)
	}
}

func (p *proxyMuxClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cool := p.outbound.plugin == nil || !p.outbound.plugin.smux
	maxID := uint32(65535)
	if !cool {
		maxID = ^uint32(0) - 2
	}
	var s *smuxSession
	active := p.all[:0]
	limit := 128
	if plugin := p.outbound.plugin; plugin != nil && plugin.muxLimit != 0 {
		limit = plugin.muxLimit
	}
	for _, item := range p.all {
		item.mu.Lock()
		alive := item.err == nil
		available := alive && len(item.streams) < limit && item.next <= maxID
		exhausted := alive && item.next > maxID && len(item.streams) == 0
		item.mu.Unlock()
		if exhausted {
			item.close(net.ErrClosed)
			alive = false
		}
		if alive {
			active = append(active, item)
		}
		if available && s == nil {
			s = item
		}
	}
	clear(p.all[len(active):])
	p.all = active
	if s == nil {
		if len(p.all) >= 16 {
			return nil, errors.New("proxy multiplex pool capacity exhausted")
		}
		c, err := p.runtime.dialProxyTransportRaw(ctx, p.outbound)
		if err != nil {
			return nil, err
		}
		raw := c
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		switch p.outbound.Type {
		case "vmess":
			c, err = vmessClient(c, p.outbound, p.runtime.vmessUsers["out:"+p.outbound.Tag][0], "mux", "")
		case "vless":
			c, err = vlessClient(c, p.outbound, "mux", "")
		}
		stop()
		if err == nil {
			err = ctx.Err()
		}
		if err != nil {
			raw.Close()
			return nil, err
		}
		_ = c.SetDeadline(time.Time{})
		s = newMuxSession(p.runtime.ctx, c, true, cool)
		s.pooled.Store(true)
		p.current = s
		p.all = append(p.all, s)
	}
	var stream *smuxStream
	var err error
	if cool {
		stream, err = s.openCool(ctx, network, address)
	} else {
		stream, err = s.open(ctx)
	}
	if err != nil {
		return nil, err
	}
	return p.runtime.own(stream)
}
