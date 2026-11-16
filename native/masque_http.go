package native

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (m *masqueSession) nextID() uint64 { m.mu.Lock(); defer m.mu.Unlock(); m.next++; return m.next }
func (c *masqueClient) openHTTP(ctx context.Context, m *masqueSession, protocol, path, authority string) (*masqueFlow, error) {
	if m.version == 1 {
		return c.openHTTP1(ctx, m, protocol, path, authority)
	}
	requestCtx, cancel := context.WithCancel(m.ctx)
	if tag, ok := ctx.Value(dnsBootstrapKey{}).(string); ok {
		requestCtx = context.WithValue(requestCtx, dnsBootstrapKey{}, tag)
	}
	if options, ok := ctx.Value(dnsQueryOptionsKey{}).(resolverOptions); ok {
		requestCtx = context.WithValue(requestCtx, dnsQueryOptionsKey{}, options)
	}
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	reader, writer := io.Pipe()
	scheme := "http"
	if c.outbound.TLS.Enabled {
		scheme = "https"
	}
	u := scheme + "://" + portAddress(c.outbound.Server, c.outbound.ServerPort) + path
	if path == "" {
		u += "/"
	}
	method := "CONNECT"
	if protocol != "" {
		method = "POST"
	}
	req, e := http.NewRequestWithContext(requestCtx, method, u, reader)
	if e != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, e
	}
	req.Host = authority
	if protocol != "" {
		req.Header.Set(masqueProtocolHeader, protocol)
		req.Header.Set("Capsule-Protocol", "?1")
		if c.outbound.DatagramContexts {
			req.Header.Set(masqueContextsHeader, masqueContextsAdvertisement(protocol))
		}
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.outbound.Username+":"+c.outbound.Password))
	req.Header.Set("Proxy-Authorization", auth)
	if protocol != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("User-Agent", "")
	for name, values := range c.outbound.Headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	response, e := m.http.RoundTrip(req)
	if e == nil && (response.ProtoMajor != 2 || response.StatusCode < 200 || response.StatusCode > 299) {
		e = masqueStatusError(response.StatusCode)
	}
	if e == nil && protocol != "" && response.Header.Get("Capsule-Protocol") != "?1" {
		e = errors.New("MASQUE response did not negotiate capsules")
	}
	if e == nil {
		e = ctx.Err()
	}
	if e != nil {
		cancel()
		reader.Close()
		writer.Close()
		if response != nil {
			response.Body.Close()
		}
		return nil, e
	}
	conn := &httpStreamConn{reader: response.Body, writer: writer, closeWrite: writer.Close, local: streamAddr("masque-http2"), remote: streamAddr(authority)}
	conn.close = func() { cancel(); reader.Close(); writer.Close(); response.Body.Close() }
	f, e := m.registerFlow(conn, m.nextID(), conn)
	if e != nil {
		conn.Close()
		return nil, e
	}
	if c.outbound.DatagramContexts && protocol != "" {
		f.negotiateContexts(protocol, response.Header.Get(masqueContextsHeader), false)
	}
	return f, nil
}
func (c *masqueClient) openHTTP1(ctx context.Context, m *masqueSession, protocol, path, authority string) (*masqueFlow, error) {
	raw, e := c.runtime.endpoint(ctx, c.outbound, "tcp")
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	stopSession := context.AfterFunc(m.ctx, func() { raw.Close() })
	defer stopSession()
	deadline := time.Now().Add(handshakeTimeout)
	if d, yes := ctx.Deadline(); yes && d.Before(deadline) {
		deadline = d
	}
	raw.SetDeadline(deadline)
	transport := raw
	if c.outbound.TLS.Enabled {
		cfg, e := c.runtime.outboundTLS(ctx, c.outbound)
		if e != nil {
			return nil, e
		}
		cfg = masqueTLSConfig(cfg)
		cfg.NextProtos = []string{"http/1.1"}
		secure := clientTLS(raw, cfg, c.outbound.TLS)
		if e = secure.HandshakeContext(ctx); e != nil {
			return nil, e
		}
		transport = secure
	}
	method, target := "CONNECT", authority
	if protocol != "" {
		method = "GET"
		target = path
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(c.outbound.Username+":"+c.outbound.Password))
	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n", method, target, authority, auth)
	if protocol != "" {
		fmt.Fprintf(&request, "Authorization: %s\r\nConnection: Upgrade\r\nUpgrade: %s\r\nCapsule-Protocol: ?1\r\n", auth, protocol)
		if c.outbound.DatagramContexts {
			fmt.Fprintf(&request, "%s: %s\r\n", masqueContextsHeader, masqueContextsAdvertisement(protocol))
		}
	}
	for name, values := range c.outbound.Headers {
		for _, value := range values {
			fmt.Fprintf(&request, "%s: %s\r\n", name, value)
		}
	}
	request.WriteString("\r\n")
	if e = writeAll(transport, []byte(request.String())); e != nil {
		return nil, e
	}
	reader := bufio.NewReaderSize(transport, 4096)
	header, e := readHTTPHeader(reader)
	if e != nil {
		return nil, e
	}
	response, e := http.ReadResponse(bufio.NewReader(strings.NewReader(string(header))), &http.Request{Method: method})
	if e != nil {
		return nil, e
	}
	if protocol != "" {
		if response.StatusCode != 101 || !headerToken(response.Header.Get("Connection"), "upgrade") || response.Header.Get("Upgrade") != protocol || response.Header.Get("Capsule-Protocol") != "?1" {
			return nil, masqueStatusError(response.StatusCode)
		}
	} else if response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, masqueStatusError(response.StatusCode)
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	raw.SetDeadline(time.Time{})
	conn := &bufferedConn{Conn: transport, reader: reader}
	f, e := m.registerFlow(conn, m.nextID(), conn)
	if e != nil {
		return nil, e
	}
	ok = true
	if c.outbound.DatagramContexts && protocol != "" {
		f.negotiateContexts(protocol, response.Header.Get(masqueContextsHeader), false)
	}
	return f, nil
}

func (r *Runtime) serveMasqueHTTP(in Inbound, w http.ResponseWriter, req *http.Request) {
	if !in.masqueServes(req.ProtoMajor) {
		w.WriteHeader(505)
		return
	}
	wire, ok := req.Context().Value(masqueHTTPContext{}).(*masqueHTTPWire)
	if !ok {
		http.Error(w, "invalid transport", 500)
		return
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.workers.Add(1)
	r.mu.Unlock()
	defer r.workers.Done()
	protocol := req.Header.Get(masqueProtocolHeader)
	method := req.Method
	if req.ProtoMajor == 2 && protocol != "" {
		if method != "POST" {
			http.Error(w, "invalid method", 400)
			return
		}
		method = "CONNECT"
	}
	if req.ProtoMajor == 1 {
		protocol = ""
		if req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
			http.Error(w, "request body not allowed", 400)
			return
		}
		if req.Method == "GET" && headerToken(req.Header.Get("Connection"), "upgrade") {
			protocol = req.Header.Get("Upgrade")
			method = "CONNECT"
		} else if req.Method != "CONNECT" {
			http.Error(w, "invalid method", 405)
			return
		}
	}
	h := map[string]string{":method": method, ":protocol": protocol, ":authority": req.Host, "authorization": req.Header.Get("Authorization"), "proxy-authorization": req.Header.Get("Proxy-Authorization"), "capsule-protocol": req.Header.Get("Capsule-Protocol"), "via": req.Header.Get("Via"), masqueContextsHeader: req.Header.Get(masqueContextsHeader)}
	if protocol != "" {
		h[":scheme"] = "http"
		if wire.tls != nil {
			h[":scheme"] = "https"
		}
		h[":path"] = req.URL.RequestURI()
	}
	controller := http.NewResponseController(w)
	var conn net.Conn
	var hijacked net.Conn
	var response *masqueResponse
	local, remote := httpStreamAddresses(req)
	if req.ProtoMajor == 2 {
		response = &masqueResponse{writer: flushingWriter{w: w, controller: controller}, controller: controller}
		s := &httpStreamConn{reader: req.Body, writer: response, local: local, remote: remote, readDeadline: response.setReadDeadline, writeDeadline: response.setWriteDeadline}
		s.close = func() { req.Body.Close(); _ = response.setWriteDeadline(time.Now()) }
		defer func() {
			if protocol == "" {
				response.finish()
				s.Close()
			} else {
				s.Close()
				response.finish()
			}
		}()
		conn = s
	} else {
		// Delay the hijack until validation and route establishment have succeeded.
		conn = &masqueUpgradeConn{remote: remote, local: local}
	}
	respond := func(status int) error {
		if status == 407 {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Lanboat"`)
		}
		if status != 200 {
			// Rejection is a complete HTTP response. Do not let flow cleanup
			// turn its queued headers into an INTERNAL_ERROR deadline reset.
			if response != nil {
				response.finish()
			}
			w.WriteHeader(status)
			return controller.Flush()
		}
		if protocol != "" {
			w.Header().Set("Capsule-Protocol", "?1")
			if in.DatagramContexts {
				if value := masqueContextsResponse(protocol, req.Header.Get(masqueContextsHeader)); value != "" {
					w.Header().Set(masqueContextsHeader, value)
				}
			}
		}
		if req.ProtoMajor == 2 {
			w.WriteHeader(200)
			return controller.Flush()
		}
		raw, buffer, e := controller.Hijack()
		if e != nil {
			return e
		}
		hijacked = raw
		upgrade := conn.(*masqueUpgradeConn)
		upgrade.Conn = &bufferedConn{Conn: raw, reader: buffer.Reader}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			raw.Close()
			return net.ErrClosed
		}
		r.connections[raw] = struct{}{}
		r.mu.Unlock()
		if protocol == "" {
			e = writeAll(raw, []byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		} else {
			extra := ""
			if value := w.Header().Get(masqueContextsHeader); value != "" {
				extra = masqueContextsHeader + ": " + value + "\r\n"
			}
			e = writeAll(raw, []byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+protocol+"\r\nCapsule-Protocol: ?1\r\n"+extra+"\r\n"))
		}
		return e
	}
	defer func() {
		if hijacked != nil {
			conn.Close()
			r.mu.Lock()
			delete(r.connections, hijacked)
			r.mu.Unlock()
		}
	}()
	state := wire.ConnectionState()
	r.serveMasqueConnect(in, wire.session, conn, conn, wire.session.nextID(), h, state, respond)
}

// A failed HTTP1 request is never hijacked and never accesses its body stream.
type masqueUpgradeConn struct {
	net.Conn
	remote, local net.Addr
}

func (c *masqueUpgradeConn) LocalAddr() net.Addr  { return c.local }
func (c *masqueUpgradeConn) RemoteAddr() net.Addr { return c.remote }
func (c *masqueUpgradeConn) Close() error {
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}
func (c *masqueUpgradeConn) SetDeadline(t time.Time) error {
	if c.Conn != nil {
		return c.Conn.SetDeadline(t)
	}
	return nil
}
func (c *masqueUpgradeConn) CloseWrite() error {
	if c.Conn != nil {
		if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
			return half.CloseWrite()
		}
	}
	return nil
}

// Keep response access inside the handler lifetime, including asynchronous IP workers.
type masqueResponse struct {
	mu         sync.RWMutex
	finished   bool
	writer     flushingWriter
	controller *http.ResponseController
}

func (s *masqueResponse) Write(b []byte) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.finished {
		return 0, net.ErrClosed
	}
	return s.writer.Write(b)
}
func (s *masqueResponse) setReadDeadline(t time.Time) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.finished {
		return net.ErrClosed
	}
	return s.controller.SetReadDeadline(t)
}
func (s *masqueResponse) setWriteDeadline(t time.Time) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.finished {
		return net.ErrClosed
	}
	return s.controller.SetWriteDeadline(t)
}
func (s *masqueResponse) finish() { s.mu.Lock(); s.finished = true; s.mu.Unlock() }
