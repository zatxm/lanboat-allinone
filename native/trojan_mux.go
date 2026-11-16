package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type trojanMuxClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	current  *smuxSession
}

func (p *trojanMuxClient) reset() {
	p.mu.Lock()
	s := p.current
	p.current = nil
	p.mu.Unlock()
	if s != nil {
		s.close(net.ErrClosed)
	}
}

func (p *trojanMuxClient) session(ctx context.Context) (*smuxSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.current; s != nil {
		select {
		case <-s.done:
			p.current = nil
		default:
			return s, nil
		}
	}
	c, err := p.runtime.dialProxyTransport(ctx, p.outbound)
	if err != nil {
		return nil, err
	}
	transport := c
	stop := context.AfterFunc(ctx, func() { transport.Close() })
	defer stop()
	if p.outbound.Shadowsocks != nil && p.outbound.Shadowsocks.Enabled {
		c = &ssConn{Conn: c, key: p.runtime.keys["out:"+p.outbound.Tag], replay: &p.runtime.replay, lineSalt: p.outbound.Transport.Type == ""}
	}
	sum := sha256.Sum224([]byte(p.outbound.Password))
	a, _ := encodeAddress("mux.lanboat:443")
	header := append([]byte(hex.EncodeToString(sum[:])+"\r\n"), 127)
	header = append(header, a...)
	header = append(header, 13, 10)
	if err = writeAll(c, header); err == nil {
		err = ctx.Err()
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	s := newSMUX(p.runtime.ctx, c, true)
	p.current = s
	return s, nil
}
func (p *trojanMuxClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	a, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	s, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	c, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	cmd := byte(1)
	if network == "udp" {
		cmd = 3
	}
	if err = writeAll(c, append([]byte{cmd}, a...)); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	var conn net.Conn = c
	if network == "udp" {
		conn = &streamPacketConn{Conn: c, address: address, trojan: true}
	}
	return p.runtime.own(conn)
}

func (r *Runtime) serveTrojanMux(c net.Conn, q request) error {
	_ = c.SetDeadline(time.Time{})
	s := newSMUX(r.ctx, c, false)
	var workers sync.WaitGroup
	defer func() { s.close(net.ErrClosed); workers.Wait() }()
	for {
		select {
		case stream := <-s.accept:
			workers.Go(func() {
				defer stream.Close()
				_ = stream.SetReadDeadline(time.Now().Add(handshakeTimeout))
				var cmd [1]byte
				if _, err := io.ReadFull(stream, cmd[:]); err != nil {
					return
				}
				address, err := readAddress(stream)
				if err != nil {
					return
				}
				if cmd[0] == 1 {
					if _, err = encodeAddress(address); err != nil {
						return
					}
				}
				job := q
				job.address = address
				_ = stream.SetDeadline(time.Time{})
				if cmd[0] == 3 {
					job.network = "udp"
					_ = r.serveStreamPackets(stream, job, true)
					return
				}
				if cmd[0] != 1 {
					return
				}
				remote, err := r.routeDial(s.ctx, job)
				if err != nil {
					return
				}
				stop := context.AfterFunc(s.ctx, func() { remote.Close() })
				defer stop()
				r.relay(stream, remote)
			})
		case <-s.done:
			s.mu.Lock()
			err := s.err
			s.mu.Unlock()
			if err == nil {
				err = errors.New("Trojan multiplex session closed")
			}
			return err
		}
	}
}
