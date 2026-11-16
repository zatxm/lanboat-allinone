package native

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

func validateQUICTransport(t Transport, tls TLSOptions) error {
	if t.xhttp3(tls) {
		return tls.validateQUICVersion()
	}
	if t.Type != "quic" {
		return nil
	}
	if !tls.Enabled {
		return errors.New("QUIC transport requires TLS")
	}
	return tls.validateQUICVersion()
}

// V2Ray's plain QUIC transport puts one proxy connection on each bidirectional
// QUIC stream. It has no HTTP/3 headers, authentication or datagram protocol.
type quicTransportClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	conn     *quicConn
	packets  map[*brookQUICPacket]struct{}
}

func (p *quicTransportClient) close() {
	p.mu.Lock()
	q := p.conn
	p.conn = nil
	packets := p.packets
	p.packets = nil
	p.mu.Unlock()
	if q != nil {
		q.Close()
	}
	for packet := range packets {
		packet.Close()
	}
}

func (p *quicTransportClient) connect(ctx context.Context) (*quicConn, error) {
	raw, err := p.runtime.endpoint(ctx, p.outbound, "udp")
	if err != nil {
		return nil, err
	}
	cfg, err := p.runtime.outboundTLS(ctx, p.outbound)
	if err != nil {
		raw.Close()
		return nil, err
	}
	cfg = cloneTLSConfig(cfg)
	if len(cfg.NextProtos) == 0 {
		cfg.NextProtos = []string{"h3"}
	}
	options := quicOptions{}
	if plugin := p.outbound.plugin; plugin != nil && plugin.hy2 {
		options = proxyQUICOptions("hysteria2", "")
	}
	if p.outbound.Type == "brook" {
		options.initial = 1300
	}
	return dialQUIC(ctx, p.runtime.ctx, raw, cfg, options)
}

func (p *quicTransportClient) session(ctx context.Context) (*quicConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.runtime.ctx.Err(); err != nil {
		return nil, err
	}
	q := p.conn
	if q != nil {
		select {
		case <-q.done:
			q = nil
		default:
		}
	}
	if q == nil {
		var err error
		q, err = p.connect(ctx)
		if err != nil {
			return nil, err
		}
		go func() {
			if p.outbound.plugin != nil && p.outbound.plugin.hy2 {
				receiveHY2TransportStreams(q)
				return
			}
			defer q.Close()
			for {
				s, err := q.AcceptStream(q.ctx)
				if err != nil {
					return
				}
				s.Close()
			}
		}()
		if plugin := p.outbound.plugin; plugin != nil && plugin.hy2 {
			session := quicProxySession{conn: q}
			if err = session.authenticateHY2(ctx, Outbound{Password: plugin.password}); err != nil {
				q.Close()
				return nil, err
			}
		}
		p.conn = q
	}
	return q, nil
}

func (p *quicTransportClient) dial(ctx context.Context) (net.Conn, error) {
	if p.outbound.Type == "brook" {
		owner, err := p.brookConnection(ctx)
		if err != nil {
			return nil, err
		}
		s, err := owner.conn.OpenStream(ctx, false)
		if err != nil {
			owner.Close()
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			s.SetDeadline(deadline)
		}
		return &brookQUICStream{quicStream: s, owner: owner}, nil
	}
	q, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	s, err := q.OpenStream(ctx, false)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		s.SetDeadline(deadline)
	}
	if plugin := p.outbound.plugin; plugin != nil && plugin.hy2 {
		if err := writeAll(s, quicVar(nil, 0x401)); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

func (r *Runtime) serveQUICTransport(in Inbound, q *quicConn) error {
	var workers sync.WaitGroup
	defer workers.Wait()
	defer q.Close()
	var auth chan struct{}
	var once sync.Once
	if in.plugin != nil && in.plugin.hy2 {
		auth = make(chan struct{})
		if err := h3Start(q.ctx, q); err != nil {
			return err
		}
	}
	if in.Type == "brook" {
		workers.Go(func() { r.serveBrookQUICPackets(in, q) })
	}
	slots := make(chan struct{}, 128)
	for {
		s, err := q.AcceptStream(q.ctx)
		if err != nil {
			return err
		}
		if s.id&2 != 0 && (in.plugin == nil || !in.plugin.hy2) {
			s.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			s.Close()
			continue
		}
		workers.Go(func() {
			defer func() { <-slots }()
			defer s.Close()
			s.SetDeadline(time.Now().Add(handshakeTimeout))
			if in.plugin != nil && in.plugin.hy2 {
				_ = r.serveHY2Transport(in, q, s, auth, &once)
			} else {
				_ = r.serveProtocol(in, s, q.remote.String())
			}
		})
	}
}
