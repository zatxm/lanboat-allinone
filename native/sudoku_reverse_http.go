package native

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

const sudokuTCPSubprotocol = "sudoku-tcp-v1"
const sudokuReverseCookie = "sudoku_rev_prefix"

type sudokuReverseHTTPRoute struct {
	SudokuReverseRoute
	session *smuxSession
	proxy   *httputil.ReverseProxy
}

func sudokuReversePath(path, prefix string) bool {
	return prefix == "/" || path == prefix || strings.HasPrefix(path, prefix+"/")
}

func (p *sudokuReverseServer) newHTTPRoute(route SudokuReverseRoute, s *smuxSession) *sudokuReverseHTTPRoute {
	r := &sudokuReverseHTTPRoute{SudokuReverseRoute: route, session: s}
	strip := route.StripPrefix == nil || *route.StripPrefix
	r.proxy = &httputil.ReverseProxy{
		Rewrite: func(q *httputil.ProxyRequest) {
			q.SetURL(&url.URL{Scheme: "http", Host: route.Target})
			if strip && route.Path != "/" {
				q.Out.URL.Path = strings.TrimPrefix(q.In.URL.Path, route.Path)
				if q.Out.URL.Path == "" {
					q.Out.URL.Path = "/"
				}
				q.Out.URL.RawPath = ""
			}
			q.Out.Host = q.In.Host
			if route.HostHeader != "" {
				q.Out.Host = route.HostHeader
			} else if host, _, _ := net.SplitHostPort(route.Target); net.ParseIP(host) == nil {
				q.Out.Host = route.Target
			}
			// Client-supplied forwarding headers must not impersonate a trusted edge.
			q.SetXForwarded()
			q.Out.Header.Del("X-Forwarded-Prefix")
			if route.Path != "/" {
				q.Out.Header.Set("X-Forwarded-Prefix", route.Path)
			}
			if strip && route.Path != "/" {
				q.Out.Header.Del("Accept-Encoding")
			}
		},
		Transport: &http.Transport{
			Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
			ResponseHeaderTimeout: handshakeTimeout, MaxResponseHeaderBytes: 64 << 10,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return r.dial(ctx)
			},
		},
		FlushInterval: 50 * time.Millisecond,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			if !strip || route.Path == "/" || resp.StatusCode == http.StatusSwitchingProtocols {
				return nil
			}
			sudokuReverseHeaders(resp, route.Path)
			if sudokuReverseBodyType(resp) == "" {
				return nil
			}
			select {
			case p.bodySlots <- struct{}{}:
			case <-resp.Request.Context().Done():
				return resp.Request.Context().Err()
			}
			if err := sudokuReverseBody(resp, route.Path); err != nil {
				<-p.bodySlots
				return err
			}
			// Keep the slot until the downstream finishes or disconnects,not just
			// until rewriting ends;slow readers otherwise retain unbounded buffers.
			resp.Body = &sudokuReverseResponseBody{ReadCloser: resp.Body, slots: p.bodySlots}
			return nil
		},
		ErrorLog: zap.NewStdLog(p.r.logger),
	}
	return r
}

type sudokuReverseResponseBody struct {
	io.ReadCloser
	slots chan struct{}
	once  sync.Once
}

func (b *sudokuReverseResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { <-b.slots })
	return err
}

func (r *sudokuReverseHTTPRoute) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	address, _ := encodeAddress(r.Target)
	return r.session.openPayload(ctx, address)
}

func (p *sudokuReverseServer) matchHTTP(path string) *sudokuReverseHTTPRoute {
	var best *sudokuReverseHTTPRoute
	for prefix, route := range p.routes {
		if sudokuReversePath(path, prefix) && (best == nil || len(prefix) > len(best.Path)) {
			best = route
		}
	}
	return best
}

func (p *sudokuReverseServer) httpServer() *http.Server {
	return &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return p.r.ctx },
		ErrorLog: zap.NewStdLog(p.r.logger)}
}

func (p *sudokuReverseServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p.r.mu.Lock()
	if p.r.closed {
		p.r.mu.Unlock()
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	p.r.workers.Add(1)
	p.r.mu.Unlock()
	defer p.r.workers.Done()
	p.mu.Lock()
	route := p.matchHTTP(req.URL.Path)
	if route == nil {
		if ref, err := url.Parse(req.Referer()); err == nil && strings.EqualFold(ref.Host, req.Host) {
			route = p.matchHTTP(ref.Path)
		}
	}
	if route == nil {
		if c, err := req.Cookie(sudokuReverseCookie); err == nil {
			if prefix, err := url.PathUnescape(c.Value); err == nil {
				route = p.routes[prefix]
			}
		}
	}
	p.mu.Unlock()
	if route == nil {
		http.NotFound(w, req)
		return
	}
	if !sudokuReversePath(req.URL.Path, route.Path) {
		req.URL.Path = route.Path + req.URL.Path
		req.URL.RawPath = ""
	}
	upgrade := headerToken(req.Header.Get("Connection"), "upgrade") && strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
	if req.URL.Path == route.Path {
		for _, value := range req.Header.Values("Sec-WebSocket-Protocol") {
			for token := range strings.SplitSeq(value, ",") {
				if upgrade && strings.TrimSpace(token) == sudokuTCPSubprotocol {
					p.serveWebSocket(w, req, route)
					return
				}
			}
		}
		if !upgrade && route.Path != "/" && (req.Method == "GET" || req.Method == "HEAD") {
			u := *req.URL
			u.Path += "/"
			u.RawPath = ""
			http.Redirect(w, req, u.String(), http.StatusPermanentRedirect)
			return
		}
	}
	route.proxy.ServeHTTP(w, req)
}

func (p *sudokuReverseServer) serveWebSocket(w http.ResponseWriter, req *http.Request, route *sudokuReverseHTTPRoute) {
	key := req.Header.Get("Sec-WebSocket-Key")
	decoded, err := base64.StdEncoding.DecodeString(key)
	if req.Method != "GET" || req.ProtoMajor != 1 || err != nil || len(decoded) != 16 || req.Header.Get("Sec-WebSocket-Version") != "13" || req.ContentLength > 0 || len(req.TransferEncoding) != 0 {
		http.Error(w, "invalid WebSocket handshake", http.StatusBadRequest)
		return
	}
	if origin := req.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !strings.EqualFold(u.Host, req.Host) {
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
	}
	remote, err := route.dial(req.Context())
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer remote.Close()
	conn, buffered, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	_, err = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + websocketAccept(key) + "\r\nSec-WebSocket-Protocol: " + sudokuTCPSubprotocol + "\r\n\r\n")
	if err == nil {
		err = buffered.Flush()
	}
	if err == nil {
		p.r.relay(&websocketConn{Conn: &bufferedConn{Conn: conn, reader: buffered.Reader}}, remote)
	}
}

// Only sniff when HTTP routes exist;raw-only publications remain opaque and
// server-first protocols keep their immediate connection behavior.
func (p *sudokuReverseServer) dispatchHTTP(c net.Conn, l *sudokuReverseHTTPListener) net.Conn {
	p.mu.Lock()
	hasHTTP := len(p.routes) != 0
	p.mu.Unlock()
	if !hasHTTP {
		return c
	}
	reader := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	prefix, err := reader.Peek(4)
	c.SetReadDeadline(time.Time{})
	buffered := &bufferedConn{Conn: c, reader: reader}
	if err != nil {
		return buffered
	}
	switch string(prefix) {
	case "GET ", "POST", "HEAD", "PUT ", "PATC", "DELE", "OPTI", "CONN", "TRAC":
	default:
		return buffered
	}
	select {
	case l.conns <- buffered:
	case <-l.done:
		c.Close()
	}
	return nil
}

type sudokuReverseHTTPListener struct {
	address net.Addr
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
}

func newSudokuReverseHTTPListener(a net.Addr) *sudokuReverseHTTPListener {
	return &sudokuReverseHTTPListener{address: a, conns: make(chan net.Conn), done: make(chan struct{})}
}
func (l *sudokuReverseHTTPListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *sudokuReverseHTTPListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}
func (l *sudokuReverseHTTPListener) Addr() net.Addr { return l.address }

type sudokuReverseEntryConn struct {
	net.Conn
	owner *sudokuReverseServer
	once  sync.Once
}

func (c *sudokuReverseEntryConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.owner.active.Add(-1) })
	return err
}
func (c *sudokuReverseEntryConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }
