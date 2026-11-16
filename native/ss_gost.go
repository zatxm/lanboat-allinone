package native

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func prepareGOSTPlugin(options map[string]string, tls TLSOptions, inbound bool) (*ssPlugin, error) {
	mode := options["mode"]
	if mode == "" {
		mode = "mws"
	}
	var websocket, secure, multiplex bool
	switch mode {
	case "mws":
		websocket, multiplex = true, true
	case "mwss":
		websocket, secure, multiplex = true, true, true
	case "mtls":
		secure, multiplex = true, true
	case "ws":
		websocket = true
	case "wss":
		websocket, secure = true, true
	case "tls":
		secure = true
	default:
		return nil, fmt.Errorf("unsupported GOST plugin mode %q", mode)
	}
	p := &ssPlugin{gost: true, smux: multiplex, mux: multiplex, tls: tls}
	for name, value := range options {
		switch name {
		case "mode", "host", "sni":
		case "path":
			if !websocket {
				return nil, errors.New("GOST path requires a WebSocket mode")
			}
		case "server":
			if inbound {
				return nil, errors.New("GOST server endpoint is an outbound option")
			}
			if value == "" || !validHTTPHost(value) || strings.ContainsAny(value, "[]:@\\") || len(value) > 253 {
				if ip := net.ParseIP(value); ip == nil {
					return nil, errors.New("invalid GOST plugin server address")
				}
			}
			p.server = value
		case "port":
			if inbound {
				return nil, errors.New("GOST port is an outbound option")
			}
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				return nil, errors.New("GOST plugin port must be1-65535")
			}
			p.port = uint16(port)
		case "skip-cert-verify":
			if inbound {
				return nil, errors.New("GOST skip-cert-verify is an outbound option")
			}
			value, err := strconv.ParseBool(value)
			if err != nil {
				return nil, errors.New("invalid GOST skip-cert-verify")
			}
			p.tls.Insecure = value
		case "cert":
			p.tls.CertificatePath = value
		case "key":
			if !inbound {
				return nil, errors.New("GOST key is an inbound option")
			}
			p.tls.KeyPath = value
		default:
			return nil, fmt.Errorf("unsupported GOST plugin option %q", name)
		}
	}
	if !secure && (p.tls.Enabled || p.tls.Insecure || options["cert"] != "" || options["key"] != "" || options["sni"] != "") {
		return nil, errors.New("GOST TLS options require tls, mtls, wss or mwss mode")
	}
	p.tls.Enabled = secure
	if sni := options["sni"]; sni != "" {
		if !validHTTPHost(sni) || len(sni) > 253 {
			return nil, errors.New("invalid GOST SNI")
		}
		p.tls.ServerName = sni
	}
	if p.tls.ServerName == "" {
		p.tls.ServerName = options["host"]
	}
	if p.tls.ServerName == "" {
		p.tls.ServerName = p.server
	}
	if websocket {
		path := options["path"]
		if path == "" {
			path = "/ws"
		}
		p.transport = Transport{Type: "ws", Path: path, Host: options["host"]}
		if err := p.transport.validate(); err != nil {
			return nil, err
		}
	} else if options["host"] != "" && !validHTTPHost(options["host"]) {
		return nil, errors.New("invalid GOST Host")
	}
	if _, err := p.tls.config(inbound, p.tls.ServerName); err != nil {
		return nil, err
	}
	return p, nil
}

func (r *Runtime) serveSMUXPlugin(in Inbound, c net.Conn, source string) error {
	_ = c.SetDeadline(time.Time{})
	s := newSMUX(r.ctx, c, false)
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
