package native

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type http3Transport struct {
	runtime  *Runtime
	options  HTTPClientOptions
	fallback *http.Transport
}

func (t *http3Transport) CloseIdleConnections() { t.fallback.CloseIdleConnections() }

func (t *http3Transport) session(req *http.Request) (*quicConn, bool, error) {
	options := t.options.TLS
	options.Enabled = true
	config, err := options.config(false, req.URL.Hostname())
	if err != nil {
		return nil, false, err
	}
	config, err = prepareClientTLS(req.Context(), config, options, t.runtime.resolver)
	if err != nil {
		return nil, false, err
	}
	config = masqueTLSConfig(config)
	config.NextProtos = []string{"h3"}
	address := req.URL.Host
	if req.URL.Port() == "" {
		address = net.JoinHostPort(req.URL.Hostname(), "443")
	}
	timeout := handshakeTimeout
	if !t.options.DisableVersionFallback {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()
	raw, err := t.fallback.DialContext(ctx, "udp", address)
	if err != nil {
		return nil, true, err
	}
	q, err := dialQUIC(ctx, t.runtime.ctx, raw, config)
	if err != nil {
		var ech *tls.ECHRejectionError
		return nil, masqueCanFallback(err) && !errors.As(err, &ech), err
	}
	if err = h3Start(ctx, q); err != nil {
		q.Close()
		return nil, true, err
	}
	go dnsQUICPeerStreams(q, true)
	return q, false, nil
}

func (t *http3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" && !t.options.DisableVersionFallback {
		return t.fallback.RoundTrip(req)
	}
	if req.URL.Scheme != "https" {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, errors.New("HTTP3 requires an https URL")
	}
	q, retry, err := t.session(req)
	if err != nil {
		// Fall back before sending HTTP only; never replay a POST after an error.
		if retry && !t.options.DisableVersionFallback && req.Context().Err() == nil && t.runtime.ctx.Err() == nil {
			return t.fallback.RoundTrip(req)
		}
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	r := req.Clone(req.Context())
	compressed := r.Header.Get("Accept-Encoding") == "" && r.Header.Get("Range") == "" && r.Method != "HEAD"
	if compressed {
		r.Header.Set("Accept-Encoding", "gzip")
	}
	if _, ok := r.Header["User-Agent"]; !ok {
		r.Header.Set("User-Agent", "Go-http-client/3.0")
	}
	stop := context.AfterFunc(req.Context(), func() { q.Close() })
	response, err := roundTripH3(q, r)
	if err != nil {
		stop()
		q.Close()
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, err
	}
	body := &http3ResponseBody{Reader: response.Body, stream: response.Body, q: q, stop: stop}
	response.Body = body
	response.TLS = &q.state
	length := response.ContentLength
	if req.Method == "HEAD" || response.StatusCode == 204 || response.StatusCode == 304 {
		length = 0
	}
	if length >= 0 {
		body.Reader = &http3LengthReader{Reader: body.Reader, remaining: length}
	}
	if compressed && strings.EqualFold(response.Header.Get("Content-Encoding"), "gzip") {
		reader, err := gzip.NewReader(body.Reader)
		if err != nil {
			body.Close()
			return nil, err
		}
		body.Reader = reader
		response.Header.Del("Content-Encoding")
		response.Header.Del("Content-Length")
		response.ContentLength, response.Uncompressed = -1, true
	}
	return response, nil
}

type http3LengthReader struct {
	io.Reader
	remaining int64
}

func (r *http3LengthReader) Read(b []byte) (int, error) {
	n, err := r.Reader.Read(b)
	r.remaining -= int64(n)
	if r.remaining < 0 {
		return n, errors.New("HTTP3 response exceeds content length")
	}
	if err == io.EOF && r.remaining != 0 {
		err = io.ErrUnexpectedEOF
	}
	return n, err
}

// Downloads are infrequent: release QUIC with the body instead of retaining a pool.
type http3ResponseBody struct {
	io.Reader
	stream io.ReadCloser
	q      *quicConn
	stop   func() bool
	once   sync.Once
}

func (b *http3ResponseBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err != nil {
		b.Close()
	}
	return n, err
}

func (b *http3ResponseBody) Close() error {
	b.once.Do(func() {
		b.stop()
		b.stream.Close()
		b.q.Close()
	})
	return nil
}
