package native

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

func (r *Runtime) newHTTPTransport(o Outbound) *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(o.TLS.Enabled)
	protocols.SetUnencryptedHTTP2(!o.TLS.Enabled)
	return &http.Transport{
		Protocols: protocols, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 16, IdleConnTimeout: 90 * time.Second,
		HTTP2:                 &http.HTTP2Config{StrictMaxConcurrentRequests: true, MaxReceiveBufferPerConnection: 1 << 20, MaxReceiveBufferPerStream: 128 << 10, WriteByteTimeout: handshakeTimeout},
		ResponseHeaderTimeout: handshakeTimeout, MaxResponseHeaderBytes: 65536,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := r.endpoint(ctx, o, "tcp")
			if err == nil {
				conn = httpHealthConnection(conn, o.Transport)
			}
			return conn, err
		},
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			raw, err := r.endpoint(ctx, o, "tcp")
			if err != nil {
				return nil, err
			}
			cfg, err := r.outboundTLS(ctx, o)
			if err != nil {
				raw.Close()
				return nil, err
			}
			cfg = cloneTLSConfig(cfg)
			if o.Type == "masque" {
				cfg = masqueTLSConfig(cfg)
			}
			cfg.NextProtos = []string{"h2"}
			conn, err := handshakeTLS(ctx, raw, cfg, o.TLS)
			if err != nil {
				raw.Close()
				return nil, err
			}
			if conn.ConnectionState().NegotiatedProtocol != "h2" {
				conn.Close()
				return nil, errors.New("server did not negotiate HTTP/2")
			}
			return httpHealthConnection(conn, o.Transport), nil
		},
	}
}

func (r *Runtime) dialHTTPTransport(ctx context.Context, o Outbound) (net.Conn, error) {
	requestCtx, cancel := context.WithCancel(r.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	reader, writer := io.Pipe()
	path := o.Transport.httpPath()
	u, _ := url.ParseRequestURI(path)
	u.Scheme = "http"
	if o.TLS.Enabled {
		u.Scheme = "https"
	}
	u.Host = portAddress(o.Server, o.ServerPort)
	method := o.Transport.Method
	if method == "" {
		method = "PUT"
	}
	if o.Transport.Type == "grpc" {
		method = "POST"
	}
	request, err := http.NewRequestWithContext(requestCtx, method, u.String(), reader)
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, err
	}
	request.Header.Set("Content-Type", "application/octet-stream")
	if o.Transport.Type == "grpc" {
		request.Header.Set("Content-Type", "application/grpc")
		request.Header.Set("Te", "trailers")
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "")
	for key, values := range o.Transport.Headers {
		if strings.EqualFold(key, "Host") && len(values) > 0 {
			request.Host = values[0]
			continue
		}
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	if o.Transport.Host != "" {
		request.Host = o.Transport.Host
	}
	body := &httpResponseBody{ready: make(chan struct{})}
	go func() {
		defer close(body.ready)
		body.response, body.err = r.httpClients[o.Tag].RoundTrip(request)
		if body.err == nil {
			response := body.response
			if response.ProtoMajor != 2 || response.StatusCode != 200 {
				body.err = errors.New("HTTP/2 proxy stream rejected")
			}
			if o.Transport.Type == "grpc" && !strings.HasPrefix(response.Header.Get("Content-Type"), "application/grpc") {
				body.err = errors.New("invalid gRPC content type")
			}
		}
		if body.err != nil {
			cancel()
			reader.CloseWithError(body.err)
			writer.CloseWithError(body.err)
			if body.response != nil {
				body.response.Body.Close()
			}
		}
	}()
	c := &httpStreamConn{reader: body, writer: writer, closeWrite: writer.Close, local: streamAddr("http2-client"), remote: streamAddr(u.Host)}
	c.close = func() { cancel(); reader.Close(); writer.Close(); body.Close() }
	if err := ctx.Err(); err != nil {
		c.Close()
		return nil, err
	}
	if o.Transport.Type == "grpc" {
		return &grpcConn{Conn: c, status: func() string {
			<-body.ready
			if body.response == nil {
				return ""
			}
			return body.response.Trailer.Get("Grpc-Status")
		}}, nil
	}
	return c, nil
}

type httpResponseBody struct {
	ready    chan struct{}
	response *http.Response
	err      error
}

func (b *httpResponseBody) Read(p []byte) (int, error) {
	<-b.ready
	if b.err != nil {
		return 0, b.err
	}
	return b.response.Body.Read(p)
}
func (b *httpResponseBody) Close() error {
	<-b.ready
	if b.response != nil {
		return b.response.Body.Close()
	}
	return nil
}

type plainHTTPConn struct {
	net.Conn
	reader  *bufio.Reader
	client  bool
	headers map[string]headerValues
	once    sync.Once
	err     error
}

func (c *plainHTTPConn) Read(p []byte) (int, error) {
	if c.client {
		c.once.Do(func() {
			header, err := readHTTPHeader(c.reader)
			if err != nil {
				c.err = err
				return
			}
			response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(header))), &http.Request{Method: "PUT"})
			if err != nil {
				c.err = err
				return
			}
			if response.StatusCode != 200 {
				c.err = errors.New("HTTP stream rejected: " + response.Status + "; encoding=" + strings.Join(response.TransferEncoding, ","))
			}
		})
		if c.err != nil {
			return 0, c.err
		}
	}
	// This transport switches to raw bytes after the header, even if a peer leaves a chunked header behind.
	return c.reader.Read(p)
}
func (c *plainHTTPConn) Write(p []byte) (int, error) {
	if !c.client {
		c.once.Do(func() {
			var header strings.Builder
			header.WriteString("HTTP/1.1 200 OK\r\n")
			for key, values := range c.headers {
				for _, value := range values {
					header.WriteString(key + ": " + value + "\r\n")
				}
			}
			header.WriteString("\r\n")
			c.err = writeAll(c.Conn, []byte(header.String()))
		})
		if c.err != nil {
			return 0, c.err
		}
	}
	return c.Conn.Write(p)
}
func (c *plainHTTPConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (r *Runtime) newHTTPServer(in Inbound) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(in.TLS.Enabled)
	protocols.SetUnencryptedHTTP2(!in.TLS.Enabled)
	server := &http.Server{Protocols: protocols, TLSConfig: r.serverTLS[in.Tag], ReadHeaderTimeout: handshakeTimeout, MaxHeaderBytes: 65536, IdleTimeout: 90 * time.Second, ErrorLog: zap.NewStdLog(r.logger.Named("http2")), HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 128, MaxReceiveBufferPerConnection: 1 << 20, MaxReceiveBufferPerStream: 128 << 10, WriteByteTimeout: handshakeTimeout}}
	if in.Transport.isHTTP() {
		server.IdleTimeout, _ = time.ParseDuration(in.Transport.IdleTimeout)
		// A zero idle_timeout means no idle eviction, including the Server's
		// otherwise implicit fallback to ReadHeaderTimeout.
		if server.IdleTimeout == 0 {
			server.IdleTimeout = -1
		}
	}
	if server.TLSConfig != nil {
		server.TLSConfig = cloneTLSConfig(server.TLSConfig)
		server.TLSConfig.NextProtos = slices.Clone(server.TLSConfig.NextProtos)
		for _, protocol := range []string{"h2", "http/1.1"} {
			if !slices.Contains(server.TLSConfig.NextProtos, protocol) {
				server.TLSConfig.NextProtos = append(server.TLSConfig.NextProtos, protocol)
			}
		}
	}
	server.ConnState = func(c net.Conn, state http.ConnState) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if state == http.StateNew {
			if r.closed || len(r.connections) >= 4096 {
				c.Close()
				return
			}
			r.connections[c] = struct{}{}
		} else if state == http.StateClosed || state == http.StateHijacked {
			delete(r.connections, c)
		}
	}
	if in.Type == "masque" {
		in.connection.http2(server.HTTP2)
		if settings := in.connection; settings != nil && settings.idle >= 0 {
			server.IdleTimeout = settings.idle
			if server.IdleTimeout == 0 {
				server.IdleTimeout = -1
			}
		}
		server.HTTP2.MaxReadFrameSize = 16384
		protocols.SetHTTP1(in.masqueServes(1))
		protocols.SetHTTP2(in.TLS.Enabled && in.masqueServes(2))
		protocols.SetUnencryptedHTTP2(!in.TLS.Enabled && in.masqueServes(2))
		if in.TLS.Enabled {
			server.TLSConfig = cloneTLSConfig(r.serverTLS[in.Tag])
			server.TLSConfig.NextProtos = nil
			if in.masqueServes(2) {
				server.TLSConfig.NextProtos = append(server.TLSConfig.NextProtos, "h2")
			}
			if in.masqueServes(1) {
				server.TLSConfig.NextProtos = append(server.TLSConfig.NextProtos, "http/1.1")
			}
		}
		server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
			if plain, ok := c.(*masquePlainConn); ok {
				c = plain.Conn
			}
			return context.WithValue(ctx, masqueHTTPContext{}, c)
		}
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.serveMasqueHTTP(in, w, req) })
		return server
	}
	if in.Transport.Type == "xhttp" {
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server.Handler = r.xhttpServers[in.Tag]
		return server
	}
	if in.Type == "trusttunnel" || in.Type == "naive" {
		protocols.SetHTTP1(in.naiveFrontend != nil)
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { r.serveTrustHTTP(in, w, req) })
		return server
	}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := in.Transport.httpPath()
		method := in.Transport.Method
		if method == "" {
			method = "PUT"
		}
		if in.Transport.Type == "grpc" {
			method = "POST"
		}
		validPath := req.URL.RequestURI() == path
		if in.Transport.Type == "http" {
			validPath = strings.HasPrefix(req.URL.RequestURI(), path)
		}
		if req.ProtoMajor != 2 || req.Method != method || !validPath || in.Transport.Host != "" && req.Host != in.Transport.Host {
			http.NotFound(w, req)
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
		controller := http.NewResponseController(w)
		w.Header().Set("Content-Type", "application/octet-stream")
		for key, values := range in.Transport.Headers {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		if in.Transport.Type == "grpc" {
			if !strings.HasPrefix(req.Header.Get("Content-Type"), "application/grpc") {
				http.Error(w, "invalid gRPC content type", 415)
				return
			}
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			defer w.Header().Set("Grpc-Status", "0")
		}
		w.WriteHeader(200)
		if err := controller.Flush(); err != nil {
			return
		}
		local, remote := httpStreamAddresses(req)
		c := &httpStreamConn{reader: req.Body, writer: &flushingWriter{w: w, controller: controller}, local: local, remote: remote, readDeadline: controller.SetReadDeadline, writeDeadline: controller.SetWriteDeadline}
		c.close = func() { req.Body.Close(); _ = controller.SetWriteDeadline(time.Now()) }
		_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
		var conn net.Conn = c
		if in.Transport.Type == "grpc" {
			conn = &grpcConn{Conn: c}
		}
		if err := r.serveProtocol(in, conn, req.RemoteAddr); err != nil && !errors.Is(err, io.EOF) && r.ctx.Err() == nil {
			r.logger.Debug("HTTP/2 stream ended", zap.String("inbound", in.Tag), zap.Error(err))
		}
		c.Close()
	})
	return server
}

type streamAddr string

func httpStreamAddresses(req *http.Request) (net.Addr, net.Addr) {
	local, _ := req.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if local == nil {
		local = streamAddr("")
	}
	peer, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		return local, streamAddr("")
	}
	if local.Network() == "udp" {
		return local, net.UDPAddrFromAddrPort(peer)
	}
	return local, net.TCPAddrFromAddrPort(peer)
}

func (streamAddr) Network() string  { return "tcp" }
func (a streamAddr) String() string { return string(a) }

type flushingWriter struct {
	w          http.ResponseWriter
	controller *http.ResponseController
}

func (w *flushingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil {
		err = w.controller.Flush()
	}
	return n, err
}

type httpStreamConn struct {
	reader                          io.ReadCloser
	writer                          io.Writer
	closeWrite                      func() error
	close                           func()
	local, remote                   net.Addr
	readDeadline, writeDeadline     func(time.Time) error
	mu                              sync.Mutex
	writeMu                         sync.Mutex
	readTimer, writeTimer           *time.Timer
	readGeneration, writeGeneration uint64
	closeOnce                       sync.Once
	closed, expired                 bool
}

func (c *httpStreamConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	return n, c.result(err)
}
func (c *httpStreamConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	n, err := c.writer.Write(p)
	return n, c.result(err)
}
func (c *httpStreamConn) result(err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil && c.expired {
		return os.ErrDeadlineExceeded
	}
	return err
}
func (c *httpStreamConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		c.closeOnce.Do(c.closeWrites)
		return nil
	}
	c.closed = true
	if c.readTimer != nil {
		c.readTimer.Stop()
	}
	if c.writeTimer != nil {
		c.writeTimer.Stop()
	}
	c.mu.Unlock()
	c.closeOnce.Do(c.closeWrites)
	return nil
}

// A nested HTTP/2 writer may outlive its carrier unless Close waits for writes.
func (c *httpStreamConn) closeWrites() {
	c.close()
	c.writeMu.Lock()
	c.writeMu.Unlock()
}
func (c *httpStreamConn) CloseWrite() error {
	if c.closeWrite != nil {
		return c.closeWrite()
	}
	return nil
}
func (c *httpStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *httpStreamConn) RemoteAddr() net.Addr { return c.remote }
func (c *httpStreamConn) SetReadDeadline(t time.Time) error {
	if c.readDeadline != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			return net.ErrClosed
		}
		return c.readDeadline(t)
	}
	return c.deadline(t, &c.readTimer, &c.readGeneration)
}
func (c *httpStreamConn) SetWriteDeadline(t time.Time) error {
	if c.writeDeadline != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.closed {
			return net.ErrClosed
		}
		return c.writeDeadline(t)
	}
	return c.deadline(t, &c.writeTimer, &c.writeGeneration)
}
func (c *httpStreamConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}
func (c *httpStreamConn) deadline(t time.Time, timer **time.Timer, generation *uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	if *timer != nil {
		(*timer).Stop()
	}
	*generation += 1
	current := *generation
	if t.IsZero() {
		*timer = nil
		return nil
	}
	*timer = time.AfterFunc(time.Until(t), func() {
		c.mu.Lock()
		if c.closed || *generation != current {
			c.mu.Unlock()
			return
		}
		c.expired = true
		c.mu.Unlock()
		c.Close()
	})
	return nil
}
