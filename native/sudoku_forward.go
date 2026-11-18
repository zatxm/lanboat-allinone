package native

import (
	"context"
	"errors"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// SudokuWebSocketForward exposes a public sudoku-tcp-v1 route as a local TCP port.
type SudokuWebSocketForward struct {
	listener net.Listener
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
}

func (f *SudokuWebSocketForward) Addr() net.Addr { return f.listener.Addr() }
func (f *SudokuWebSocketForward) Close() error   { f.cancel(); return f.Wait() }
func (f *SudokuWebSocketForward) Wait() error    { <-f.done; return f.err }

// ForwardSudokuWebSocket uses the runtime's direct resolver and TLS validation.
// URL paths identify published services;they are not authentication credentials.
func (r *Runtime) ForwardSudokuWebSocket(ctx context.Context, listen, endpoint string, options TLSOptions) (*SudokuWebSocketForward, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.realityEnabled() {
		return nil, errors.New("public Sudoku WebSocket forwarding uses standard TLS,not Reality")
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") || !validHTTPHost(u.Host) || u.User != nil || u.Fragment != "" {
		return nil, errors.New("Sudoku WebSocket endpoint requires a ws:// or wss:// URL without credentials or fragment")
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return nil, errors.New("missing Sudoku WebSocket host")
	}
	if port == "" {
		port = "80"
		if u.Scheme == "wss" {
			port = "443"
		}
	}
	address := net.JoinHostPort(host, port)
	if _, err = encodeAddress(address); err != nil {
		return nil, err
	}
	localHost, _, err := net.SplitHostPort(listen)
	if err != nil || localHost == "" {
		return nil, errors.New("Sudoku WebSocket forward requires an explicit listen host and port")
	}
	options.Enabled = u.Scheme == "wss"
	config, err := options.config(false, host)
	if err != nil {
		return nil, err
	}
	if config != nil {
		config.NextProtos = []string{"http/1.1"}
	}
	l, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	child, cancel := context.WithCancel(r.ctx)
	stopParent := context.AfterFunc(ctx, cancel)
	stopListener := context.AfterFunc(child, func() { l.Close() })
	f := &SudokuWebSocketForward{listener: l, cancel: cancel, done: make(chan struct{})}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		stopParent()
		stopListener()
		cancel()
		l.Close()
		return nil, net.ErrClosed
	}
	r.workers.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.workers.Done()
		defer close(f.done)
		defer stopParent()
		defer stopListener()
		defer l.Close()
		var workers sync.WaitGroup
		defer func() { cancel(); workers.Wait() }()
		var active atomic.Int32
		for {
			local, err := l.Accept()
			if err != nil {
				if child.Err() == nil {
					f.err = err
				}
				return
			}
			if active.Add(1) > 128 {
				active.Add(-1)
				local.Close()
				continue
			}
			workers.Go(func() {
				defer active.Add(-1)
				defer local.Close()
				stopLocal := context.AfterFunc(child, func() { local.Close() })
				defer stopLocal()
				dial, done := context.WithTimeout(child, handshakeTimeout)
				defer done()
				raw, err := r.direct(dial, "tcp", address)
				if err != nil {
					logDebug(r.logger, err, "sudoku: WebSocket forward dial")
					return
				}
				defer raw.Close()
				stopRaw := context.AfterFunc(child, func() { raw.Close() })
				defer stopRaw()
				deadline, _ := dial.Deadline()
				raw.SetDeadline(deadline)
				conn := raw
				if config != nil {
					secured := clientTLS(raw, config, options)
					if err = secured.HandshakeContext(dial); err != nil {
						logDebug(r.logger, err, "sudoku: WebSocket forward TLS")
						return
					}
					conn = secured
				}
				transport := Transport{Type: "ws", Path: u.RequestURI(), Host: u.Host, websocketProtocol: sudokuTCPSubprotocol}
				ws, err := dialTransportHandshake(conn, Outbound{Server: host, Transport: transport}, nil)
				if err != nil {
					logDebug(r.logger, err, "sudoku: WebSocket forward upgrade")
					return
				}
				done()
				raw.SetDeadline(time.Time{})
				r.relay(local, ws)
			})
		}
	}()
	return f, nil
}
