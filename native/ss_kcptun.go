package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type kcptunOptions struct {
	crypt                                        *kcpCrypt
	code                                         *kcpRS
	server                                       string
	port                                         uint16
	mtu, sendWindow, receiveWindow, dscp, resend int
	interval, keepalive, expire                  time.Duration
	nodelay, congestion, compress                bool
	version                                      byte
}

func prepareKCPPlugin(values map[string]string, tls TLSOptions, inbound bool) (*ssPlugin, error) {
	if tls.Enabled {
		return nil, errors.New("kcptun does not use TLS")
	}
	o := &kcptunOptions{mtu: 1350, sendWindow: 1024, receiveWindow: 1024, interval: 40 * time.Millisecond, resend: 2, keepalive: 10 * time.Second, version: 1}
	mode := values["mode"]
	if mode == "" {
		mode = "fast"
	}
	switch mode {
	case "normal":
		o.interval = 50 * time.Millisecond
		o.resend = 0
		o.congestion = true
	case "fast":
	case "fast2":
		o.interval = 30 * time.Millisecond
		o.nodelay = true
	case "fast3":
		o.interval = 20 * time.Millisecond
		o.nodelay = true
	case "custom":
		o.nodelay = true
	default:
		return nil, fmt.Errorf("invalid kcptun mode %q", mode)
	}
	data, parity := 10, 3
	for name, value := range values {
		switch name {
		case "key", "crypt", "mode":
		case "nocomp":
			v, e := strconv.ParseBool(value)
			if value == "" {
				v = true
				e = nil
			}
			if e != nil {
				return nil, errors.New("invalid kcptun nocomp")
			}
			o.compress = !v
		case "server":
			if inbound || value == "" || len(value) > 253 || strings.ContainsAny(value, " /?#\\\t\r\n") {
				return nil, errors.New("invalid kcptun server")
			}
			if net.ParseIP(value) == nil && strings.ContainsAny(value, "[]:@") {
				return nil, errors.New("invalid kcptun server")
			}
			o.server = value
		case "port", "mtu", "sndwnd", "rcvwnd", "datashard", "parityshard", "dscp", "keepalive", "autoexpire", "version", "nodelay", "interval", "resend", "nc":
			n, e := strconv.Atoi(value)
			if e != nil || n < 0 {
				return nil, fmt.Errorf("invalid kcptun %s", name)
			}
			switch name {
			case "port":
				if inbound || n < 1 || n > 65535 {
					return nil, errors.New("kcptun port must be1-65535")
				}
				o.port = uint16(n)
			case "mtu":
				if n < 128 || n > 1500 {
					return nil, errors.New("kcptun MTU must be128-1500")
				}
				o.mtu = n
			case "sndwnd", "rcvwnd":
				if n < 1 || n > 4096 {
					return nil, errors.New("kcptun windows must be1-4096")
				}
				if name == "sndwnd" {
					o.sendWindow = n
				} else {
					o.receiveWindow = n
				}
			case "datashard", "parityshard":
				if n > 128 {
					return nil, errors.New("kcptun shard counts must be0-128")
				}
				if name == "datashard" {
					data = n
				} else {
					parity = n
				}
			case "dscp":
				if n > 63 {
					return nil, errors.New("kcptun DSCP must be0-63")
				}
				o.dscp = n
			case "version":
				if n != 1 && n != 2 {
					return nil, errors.New("kcptun version must be1 or2")
				}
				o.version = byte(n)
			case "keepalive", "autoexpire":
				if n > 86400*365 {
					return nil, errors.New("kcptun duration exceeds one year")
				}
				if name == "keepalive" {
					o.keepalive = time.Duration(n) * time.Second
				} else {
					o.expire = time.Duration(n) * time.Second
				}
			default:
				if mode != "custom" {
					return nil, fmt.Errorf("kcptun %s requires custom mode", name)
				}
				switch name {
				case "interval":
					if n < 10 || n > 5000 {
						return nil, errors.New("kcptun interval must be10-5000ms")
					}
					o.interval = time.Duration(n) * time.Millisecond
				case "resend":
					if n > 32 {
						return nil, errors.New("kcptun resend must be0-32")
					}
					o.resend = n
				case "nodelay", "nc":
					if n > 1 {
						return nil, errors.New("kcptun nodelay/nc must be0 or1")
					}
					if name == "nodelay" {
						o.nodelay = n == 1
					} else {
						o.congestion = n == 0
					}
				}
			}
		default:
			return nil, fmt.Errorf("unsupported kcptun option %q", name)
		}
	}
	var err error
	method := values["crypt"]
	if method == "" {
		method = "aes"
	}
	o.crypt, err = newKCPCrypt(method, values["key"])
	if err != nil {
		return nil, err
	}
	if data+parity > 255 {
		return nil, errors.New("kcptun FEC shard total must be at most255")
	}
	if data != 0 && parity != 0 {
		o.code = newKCPRS(data, parity)
	}
	return &ssPlugin{kcp: o}, nil
}

type kcptunClient struct {
	r       *Runtime
	o       Outbound
	mu      sync.Mutex
	session *smuxSession
	born    time.Time
	retired []*smuxSession
}

func (p *kcptunClient) dial(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	live := p.retired[:0]
	for _, s := range p.retired {
		s.mu.Lock()
		idle := len(s.streams) == 0
		closed := s.err != nil
		s.mu.Unlock()
		if idle || closed {
			s.close(net.ErrClosed)
		} else {
			live = append(live, s)
		}
	}
	clear(p.retired[len(live):])
	p.retired = live
	options := p.o.plugin.kcp
	if s := p.session; s != nil {
		s.mu.Lock()
		closed := s.err != nil
		s.mu.Unlock()
		expired := options.expire > 0 && time.Since(p.born) >= options.expire
		if closed {
			p.session = nil
		} else if expired {
			if len(p.retired) >= 8 {
				return nil, errors.New("kcptun expired session capacity reached")
			}
			p.retired = append(p.retired, s)
			p.session = nil
		}
	}
	if p.session == nil {
		raw, err := p.r.dialKCP(ctx, p.o, options)
		if err != nil {
			return nil, err
		}
		var conn net.Conn = raw
		if options.compress {
			conn = &kcpSnappyConn{Conn: raw}
		}
		p.session = newSMUXVersion(p.r.ctx, conn, true, options.version, options.keepalive)
		p.born = time.Now()
	}
	return p.session.open(ctx)
}
func (p *kcptunClient) reset() {
	p.mu.Lock()
	sessions := append(p.retired, p.session)
	p.retired = nil
	p.session = nil
	p.mu.Unlock()
	for _, s := range sessions {
		if s != nil {
			s.close(net.ErrClosed)
		}
	}
}
func (r *Runtime) serveKCPTUN(in Inbound, c net.Conn, source string, o *kcptunOptions) error {
	_ = c.SetDeadline(time.Time{})
	if o.compress {
		c = &kcpSnappyConn{Conn: c}
	}
	s := newSMUXVersion(r.ctx, c, false, o.version, o.keepalive)
	var workers sync.WaitGroup
	defer func() { s.close(net.ErrClosed); workers.Wait() }()
	for {
		select {
		case stream := <-s.accept:
			workers.Go(func() {
				defer stream.Close()
				_ = stream.SetDeadline(time.Now().Add(handshakeTimeout))
				_ = r.serveProtocol(in, stream, source)
			})
		case <-s.done:
			s.mu.Lock()
			err := s.err
			s.mu.Unlock()
			return err
		}
	}
}
func (r *Runtime) closeKCP(wait bool) {
	r.kcpMu.Lock()
	conns := make([]*kcpConn, 0, len(r.kcpConns))
	for c := range r.kcpConns {
		conns = append(conns, c)
	}
	r.kcpMu.Unlock()
	for _, c := range conns {
		c.abort(net.ErrClosed)
	}
	if wait {
		for _, c := range conns {
			c.workers.Wait()
		}
	}
}
