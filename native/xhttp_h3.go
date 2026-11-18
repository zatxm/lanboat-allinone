package native

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

func (e *xHTTPEntry) h3Session(ctx context.Context) (*quicConn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, io.ErrClosedPipe
	}
	if q := e.quic; q != nil {
		select {
		case <-q.done:
			e.quic = nil
		default:
			return q, nil
		}
	}
	p := e.pool
	raw, err := p.r.endpoint(ctx, p.o, "udp")
	if err != nil {
		return nil, err
	}
	cfg, err := prepareClientTLS(ctx, p.cfg, p.o.TLS, p.r.resolver)
	if err != nil {
		raw.Close()
		return nil, err
	}
	cfg = cloneTLSConfig(cfg)
	cfg.NextProtos = []string{"h3"}
	period := p.o.Transport.XMux.HKeepAlivePeriod
	if period == 0 {
		period = 10
	}
	q, err := dialQUIC(ctx, p.r.ctx, raw, cfg, p.o.QUICReceiveWindows.apply(quicOptions{keepAlive: time.Duration(period) * time.Second}))
	if err != nil {
		raw.Close()
		return nil, err
	}
	if err = h3Start(ctx, q); err != nil {
		q.Close()
		return nil, err
	}
	e.quic = q
	go dnsQUICPeerStreams(q, true)
	return q, nil
}

type xH3Body struct {
	*trustH3Conn
	stop    func() bool
	request io.ReadCloser
	once    sync.Once
}

func (b *xH3Body) Close() error {
	b.once.Do(func() {
		b.stop()
		b.quicStream.Close()
		if b.request != nil {
			b.request.Close()
		}
	})
	return nil
}
func (e *xHTTPEntry) roundTripH3(req *http.Request) (*http.Response, error) {
	q, err := e.h3Session(req.Context())
	if err != nil {
		return nil, err
	}
	return roundTripH3(q, req)
}

func roundTripH3(q *quicConn, req *http.Request) (*http.Response, error) {
	for key, values := range req.Header {
		if err := validateHTTPHeader(key, values); err != nil {
			return nil, err
		}
		switch strings.ToLower(key) {
		case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
			return nil, errors.New("HTTP3 forbids connection-specific headers")
		case "te":
			if !strings.EqualFold(strings.Join(values, ","), "trailers") {
				return nil, errors.New("HTTP3 TE must be trailers")
			}
		}
	}
	s, err := q.OpenStream(req.Context(), false)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(req.Context(), func() {
		s.Close()
		if req.Body != nil {
			req.Body.Close()
		}
	})
	body := &xH3Body{trustH3Conn: &trustH3Conn{quicStream: s}, stop: stop, request: req.Body}
	if d, ok := req.Context().Deadline(); ok {
		s.SetDeadline(d)
	}
	authority := req.Host
	if authority == "" {
		authority = req.URL.Host
	}
	headers := [][2]string{{":method", req.Method}, {":scheme", req.URL.Scheme}, {":authority", authority}, {":path", req.URL.RequestURI()}}
	for key, values := range req.Header {
		if strings.EqualFold(key, "Content-Length") {
			continue
		}
		separator := ", "
		if strings.EqualFold(key, "Cookie") {
			separator = "; "
		}
		if len(values) > 0 {
			headers = append(headers, [2]string{strings.ToLower(key), strings.Join(values, separator)})
		}
	}
	if req.ContentLength > 0 {
		headers = append(headers, [2]string{"content-length", strconv.FormatInt(req.ContentLength, 10)})
	}
	if err = h3WriteFrame(s, 1, h3Encode(headers)); err != nil {
		body.Close()
		return nil, err
	}
	go func() {
		var err error
		if req.Body != nil {
			_, err = io.Copy(body.trustH3Conn, req.Body)
			req.Body.Close()
		}
		if err == nil {
			err = h3FinishRequest(s)
		}
		if err != nil {
			// A peer may stop uploads after replying; keep its response readable.
			s.CloseWrite()
		}
	}()
	var h map[string]string
	var responseHeaders http.Header
	for informational := 0; ; informational++ {
		responseHeaders = make(http.Header)
		h, err = h3Status(s, responseHeaders)
		if err != nil {
			body.Close()
			return nil, err
		}
		code, _ := strconv.Atoi(h[":status"])
		if len(h[":status"]) != 3 {
			code = 0
		}
		if code >= 200 {
			break
		}
		if code < 100 || code == 101 || informational >= 16 {
			body.Close()
			return nil, errors.New("invalid XHTTP HTTP3 status")
		}
	}
	code, err := strconv.Atoi(h[":status"])
	if err != nil || code < 200 || code > 599 {
		body.Close()
		return nil, errors.New("invalid XHTTP HTTP3 status")
	}
	length := int64(-1)
	if values, ok := responseHeaders["Content-Length"]; ok {
		v := values[0]
		length, err = strconv.ParseInt(v, 10, 64)
		if err != nil || v == "" || strings.Trim(v, "0123456789") != "" || length < 0 {
			body.Close()
			return nil, errors.New("invalid HTTP3 content length")
		}
	}
	for key := range h {
		if strings.HasPrefix(key, ":") && key != ":status" {
			body.Close()
			return nil, errors.New("invalid HTTP3 response pseudo-header")
		}
	}
	response := &http.Response{StatusCode: code, Status: strconv.Itoa(code) + " " + http.StatusText(code), Proto: "HTTP/3.0", ProtoMajor: 3, Header: responseHeaders, Body: body, ContentLength: length, Request: req}
	return response, nil
}

type xH3Writer struct {
	stream  *trustH3Conn
	header  http.Header
	written bool
	err     error
}

type xH3RequestBody struct{ *trustH3Conn }

func (b *xH3RequestBody) Close() error { return b.SetReadDeadline(time.Now()) }

func (w *xH3Writer) Header() http.Header { return w.header }
func (w *xH3Writer) WriteHeader(code int) {
	if w.written {
		return
	}
	w.written = true
	headers := [][2]string{{":status", strconv.Itoa(code)}}
	for key, values := range w.header {
		for _, value := range values {
			headers = append(headers, [2]string{strings.ToLower(key), value})
		}
	}
	w.err = h3WriteFrame(w.stream.quicStream, 1, h3Encode(headers))
}
func (w *xH3Writer) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(200)
	}
	if w.err != nil {
		return 0, w.err
	}
	return w.stream.Write(b)
}
func (w *xH3Writer) FlushError() error {
	if !w.written {
		w.WriteHeader(200)
	}
	return w.err
}
func (w *xH3Writer) SetReadDeadline(t time.Time) error  { return w.stream.SetReadDeadline(t) }
func (w *xH3Writer) SetWriteDeadline(t time.Time) error { return w.stream.SetWriteDeadline(t) }
func (w *xH3Writer) EnableFullDuplex() error            { return nil }
func (r *Runtime) serveXHTTPQUIC(in Inbound, q *quicConn) error {
	return serveHTTP3(q, r.xhttpServers[in.Tag])
}

func serveHTTP3(q *quicConn, handler http.Handler) error {
	defer q.Close()
	if e := h3Start(q.ctx, q); e != nil {
		return e
	}
	var workers sync.WaitGroup
	defer workers.Wait()
	defer q.Close()
	serverCtx := context.WithValue(q.ctx, http.ServerContextKey, &http.Server{Handler: handler})
	slots := make(chan struct{}, 128)
	for {
		s, e := q.AcceptStream(q.ctx)
		if e != nil {
			return e
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
			// Standard HTTP handlers use ErrAbortHandler to reset a truncated response.
			defer func() {
				if v := recover(); v != nil && v != http.ErrAbortHandler {
					panic(v)
				}
			}()
			if s.id&2 != 0 {
				if e := h3Uni(s); e != nil {
					q.cancel()
				}
				return
			}
			s.SetDeadline(time.Now().Add(handshakeTimeout))
			kind, b, e := h3ReadFrame(s)
			if e != nil || kind != 1 {
				return
			}
			h, e := h3Decode(b)
			if e != nil {
				return
			}
			w := &xH3Writer{stream: &trustH3Conn{quicStream: s}, header: make(http.Header)}
			u, e := url.ParseRequestURI(h[":path"])
			connect := h[":method"] == "CONNECT"
			if connect && h[":scheme"] == "" && h[":path"] == "" {
				u, e = &url.URL{Host: h[":authority"]}, nil
			}
			if e != nil || u.IsAbs() || !connect && h[":scheme"] != "https" || connect && (h[":scheme"] != "" || h[":path"] != "") || h[":authority"] == "" || h[":protocol"] != "" {
				w.WriteHeader(400)
				s.CloseWrite()
				return
			}
			ctx, cancel := context.WithCancel(serverCtx)
			defer cancel()
			s.peerCancel.Store(&cancel)
			if s.peerCanceled.Load() {
				cancel()
			}
			defer s.peerCancel.Store(nil)
			ctx = context.WithValue(ctx, http.LocalAddrContextKey, q.local)
			requestURI := u.RequestURI()
			if connect {
				requestURI = h[":authority"]
			}
			req := (&http.Request{Method: h[":method"], URL: u, RequestURI: requestURI, Proto: "HTTP/3.0", ProtoMajor: 3, Host: h[":authority"], Header: make(http.Header), Body: &xH3RequestBody{&trustH3Conn{quicStream: s}}, RemoteAddr: q.remote.String(), ContentLength: -1, TLS: &q.state}).WithContext(ctx)
			for key, value := range h {
				if !strings.HasPrefix(key, ":") {
					req.Header.Set(key, value)
				}
			}
			if v := req.Header.Get("Content-Length"); v != "" {
				n, e := strconv.ParseInt(v, 10, 64)
				if e != nil || n < 0 {
					w.WriteHeader(400)
					s.CloseWrite()
					return
				}
				req.ContentLength = n
			}
			s.SetDeadline(time.Time{})
			handler.ServeHTTP(w, req)
			if !w.written {
				w.WriteHeader(200)
			}
			s.CloseWrite()
		})
	}
}
