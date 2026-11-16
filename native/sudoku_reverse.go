package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type SudokuReverse struct {
	Listen   string               `json:"listen,omitempty"`
	ClientID string               `json:"client_id,omitempty"`
	Routes   []SudokuReverseRoute `json:"routes,omitempty"`
}

type SudokuReverseRoute struct {
	Path        string `json:"path"`
	Target      string `json:"target"`
	StripPrefix *bool  `json:"strip_prefix,omitempty"`
	HostHeader  string `json:"host_header,omitempty"`
}

const sudokuReverseMaxRegistration = 16384

func (p *SudokuReverse) validate(client bool) error {
	if p == nil {
		return nil
	}
	if len(p.ClientID) > 128 || strings.ContainsAny(p.ClientID, "\x00\r\n") {
		return errors.New("invalid Sudoku reverse client identifier")
	}
	if client {
		if p.Listen != "" || len(p.Routes) == 0 || len(p.Routes) > 64 {
			return errors.New("Sudoku reverse outbound requires1-64 routes and no listen address")
		}
		seen := make(map[string]bool, len(p.Routes))
		for i := range p.Routes {
			route := &p.Routes[i]
			route.Path = strings.TrimSpace(route.Path)
			if route.Path != "" {
				route.Path = path.Clean("/" + strings.TrimPrefix(route.Path, "/"))
			}
			route.Target = strings.TrimSpace(route.Target)
			route.HostHeader = strings.TrimSpace(route.HostHeader)
			if seen[route.Path] || len(route.Path) > 256 || strings.ContainsAny(route.Path, "\x00\r\n\t ?#\\<>\"'`&") {
				return errors.New("invalid or duplicate Sudoku reverse path")
			}
			seen[route.Path] = true
			address, err := encodeAddress(route.Target)
			if err != nil {
				return errors.New("invalid Sudoku reverse target")
			}
			// Match the exact address form decoded from incoming KIP opens.
			route.Target, _ = readAddress(bytes.NewReader(address))
			if route.HostHeader != "" && !validHTTPHost(route.HostHeader) {
				return errors.New("invalid Sudoku reverse Host header")
			}
		}
		if body, _ := json.Marshal(p); len(body) > sudokuReverseMaxRegistration {
			return errors.New("Sudoku reverse registration exceeds16384 bytes")
		}
	} else {
		host, port, err := net.SplitHostPort(p.Listen)
		n, portErr := strconv.Atoi(port)
		if err != nil || portErr != nil || n < 0 || n > 65535 || host == "" || len(p.Routes) != 0 || p.ClientID != "" {
			return errors.New("Sudoku TCP reverse inbound requires an explicit listen host and port,without routes or client_id")
		}
	}
	return nil
}

func parseSudokuReverse(body []byte) (SudokuReverse, error) {
	var p SudokuReverse
	if len(body) > sudokuReverseMaxRegistration {
		return p, errors.New("oversized Sudoku reverse registration")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, errors.New("invalid Sudoku reverse registration")
	}
	if d.Decode(new(any)) != io.EOF {
		return p, errors.New("extra Sudoku reverse registration data")
	}
	return p, p.validate(true)
}

type sudokuReverseServer struct {
	r         *Runtime
	listener  net.Listener
	mu        sync.Mutex
	current   *smuxSession
	target    string
	routes    map[string]*sudokuReverseHTTPRoute
	sessions  int
	bodySlots chan struct{}
	active    atomic.Int32
}

func (r *Runtime) serveSudokuReverse(tag string, conn net.Conn, body []byte) error {
	p, err := parseSudokuReverse(body)
	if err != nil {
		return err
	}
	server := r.sudokuReverseServers[tag]
	if server == nil {
		return errors.New("Sudoku reverse entry is disabled")
	}
	server.mu.Lock()
	if server.sessions >= 64 || len(server.routes)+len(p.Routes) > 256 {
		server.mu.Unlock()
		return errors.New("Sudoku reverse entry publication limit")
	}
	for _, route := range p.Routes {
		if route.Path == "" && server.current != nil || server.routes[route.Path] != nil {
			server.mu.Unlock()
			return errors.New("Sudoku reverse route is already registered")
		}
	}
	conn.SetDeadline(time.Time{})
	s := newMuxConfigured(r.ctx, conn, true, muxSudoku, 1, 15*time.Second, false)
	// A reverse link is a persistent publication,not an idle outbound pool.
	s.pooled.Store(false)
	if server.routes == nil {
		server.routes = make(map[string]*sudokuReverseHTTPRoute)
	}
	for _, route := range p.Routes {
		if route.Path == "" {
			server.current, server.target = s, route.Target
		} else {
			server.routes[route.Path] = server.newHTTPRoute(route, s)
		}
	}
	server.sessions++
	server.mu.Unlock()
	defer s.close(net.ErrClosed)
	defer func() {
		server.mu.Lock()
		if server.current == s {
			server.current, server.target = nil, ""
		}
		for prefix, route := range server.routes {
			if route.session == s {
				delete(server.routes, prefix)
			}
		}
		server.sessions--
		server.mu.Unlock()
	}()
	<-s.done
	return nil
}

func (p *sudokuReverseServer) run() {
	defer p.r.workers.Done()
	httpEntry := newSudokuReverseHTTPListener(p.listener.Addr())
	httpServer := p.httpServer()
	httpDone := make(chan struct{})
	go func() { defer close(httpDone); _ = httpServer.Serve(httpEntry) }()
	defer func() { httpEntry.Close(); httpServer.Close(); <-httpDone }()
	for {
		raw, err := p.listener.Accept()
		if err != nil {
			return
		}
		if p.active.Add(1) > 128 {
			p.active.Add(-1)
			raw.Close()
			continue
		}
		conn, err := p.r.own(&sudokuReverseEntryConn{Conn: raw, owner: p})
		if err != nil {
			continue
		}
		p.r.workers.Add(1)
		go func() {
			defer p.r.workers.Done()
			conn = p.dispatchHTTP(conn, httpEntry)
			if conn == nil {
				return
			}
			defer conn.Close()
			p.mu.Lock()
			s, target := p.current, p.target
			p.mu.Unlock()
			if s == nil {
				return
			}
			ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
			defer cancel()
			address, _ := encodeAddress(target)
			stream, err := s.openPayload(ctx, address)
			if err != nil {
				return
			}
			p.r.relay(conn, stream)
		}()
	}
}

type sudokuReverseClient struct {
	r       *Runtime
	out     Outbound
	mu      sync.Mutex
	cancel  context.CancelFunc
	current *smuxSession
	wake    chan struct{}
	raw     net.Conn
	stopped bool
}

func (p *sudokuReverseClient) reset() {
	p.mu.Lock()
	cancel, raw := p.cancel, p.raw
	p.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if raw != nil {
		raw.Close()
	}
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

func (p *sudokuReverseClient) run() {
	defer p.r.workers.Done()
	delay := 250 * time.Millisecond
	for p.r.ctx.Err() == nil {
		started := time.Now()
		err := p.session()
		p.mu.Lock()
		stopped := p.stopped
		p.mu.Unlock()
		if stopped || p.r.ctx.Err() != nil {
			return
		}
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled) {
			p.r.logger.Debug("Sudoku reverse link ended", zap.String("outbound", p.out.Tag), zap.Error(err))
		}
		if time.Since(started) >= time.Second {
			delay = 250 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-p.r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		case <-p.wake:
			timer.Stop()
		}
		delay = min(delay*2, 10*time.Second)
	}
}

func (p *sudokuReverseClient) stop() {
	p.mu.Lock()
	p.stopped = true
	raw := p.raw
	p.mu.Unlock()
	p.reset()
	if ready, ok := raw.(*sudokuHTTPReady); ok {
		if client, ok := ready.Conn.(*sudokuHTTPClient); ok {
			// Withdraw while DNS and configured detours are still available.
			<-client.withdrawn
		}
	}
}

// SudokuReverseAddress reports the TCP publication entry,including an assigned
// ephemeral port. New does not bind it; it becomes available after Start.
func (r *Runtime) SudokuReverseAddress(tag string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if server := r.sudokuReverseServers[tag]; server != nil {
		return server.listener.Addr().String()
	}
	return ""
}

func (p *sudokuReverseClient) session() error {
	ctx, cancel := context.WithCancel(p.r.ctx)
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		cancel()
		return net.ErrClosed
	}
	p.cancel = cancel
	p.mu.Unlock()
	defer cancel()
	options := *p.out.Sudoku
	options.packedUplink = true
	options.tables = make([]*SudokuOptions, len(p.out.Sudoku.tables))
	for i, variant := range p.out.Sudoku.tables {
		copy := *variant
		copy.packedUplink = true
		options.tables[i] = &copy
	}
	out := p.out
	out.Sudoku = &options
	handshake, stopHandshake := context.WithTimeout(ctx, handshakeTimeout)
	defer stopHandshake()
	raw, err := p.r.dialProxyTransport(handshake, out)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.raw = raw
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.raw = nil; p.mu.Unlock() }()
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	deadline := context.AfterFunc(handshake, func() { raw.Close() })
	defer deadline()
	conn, selected, err := sudokuHandshake(raw, &options, 15)
	if err == nil && selected&8 == 0 {
		err = errors.New("Sudoku peer did not negotiate reverse connections")
	}
	if err == nil {
		body, _ := json.Marshal(options.Reverse)
		err = sudokuMessage(conn, 0x13, body)
	}
	if err != nil {
		return err
	}
	if !deadline() || handshake.Err() != nil {
		return context.DeadlineExceeded
	}
	stopHandshake()
	conn.SetDeadline(time.Time{})
	s := newMuxConfigured(ctx, conn, false, muxSudoku, 1, 15*time.Second, false)
	targets := make(map[string]bool, len(options.Reverse.Routes))
	for _, route := range options.Reverse.Routes {
		targets[route.Target] = true
	}
	p.mu.Lock()
	p.current = s
	p.mu.Unlock()
	var workers sync.WaitGroup
	defer func() {
		s.close(net.ErrClosed)
		workers.Wait()
		p.mu.Lock()
		p.current = nil
		p.mu.Unlock()
	}()
	for {
		select {
		case stream := <-s.accept:
			workers.Go(func() {
				defer stream.Close()
				if !targets[stream.address] {
					_ = s.sudokuControl(4, stream.id, "destination not published")
					s.sudokuAbort(stream)
					return
				}
				dial, done := context.WithTimeout(s.ctx, handshakeTimeout)
				remote, err := p.r.direct(dial, "tcp", stream.address)
				done()
				if err != nil {
					_ = s.sudokuControl(4, stream.id, "destination unavailable")
					s.sudokuAbort(stream)
					return
				}
				closeRemote := context.AfterFunc(s.ctx, func() { remote.Close() })
				defer closeRemote()
				p.r.relay(stream, remote)
			})
		case <-s.done:
			s.mu.Lock()
			err := s.err
			s.mu.Unlock()
			return err
		}
	}
}
