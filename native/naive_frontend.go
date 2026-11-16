package native

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"go.uber.org/zap"
)

type naiveFrontend struct {
	proxy     *httputil.ReverseProxy
	transport *http.Transport
	slots     chan struct{}
}

func parseNaiveFrontend(kind, address string) (*url.URL, error) {
	if address == "" {
		return nil, nil
	}
	u, err := url.Parse(address)
	if err != nil || kind != "naive" || u.Scheme != "http" && u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawQuery != "" {
		return nil, errors.New("naive_frontend requires a Naive inbound and an HTTP(S) origin without credentials,query or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid naive_frontend port")
		}
	}
	return u, nil
}

func (r *Runtime) newNaiveFrontend(address string) *naiveFrontend {
	target, _ := parseNaiveFrontend("naive", address)
	transport := &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 16, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: handshakeTimeout, ResponseHeaderTimeout: handshakeTimeout, MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
			defer cancel()
			return r.direct(ctx, network, address)
		},
	}
	p := &naiveFrontend{transport: transport, slots: make(chan struct{}, 32)}
	p.proxy = &httputil.ReverseProxy{
		Transport: transport,
		ErrorLog:  zap.NewStdLog(r.logger.Named("naive_frontend")),
		Rewrite: func(q *httputil.ProxyRequest) {
			q.SetURL(target)
			q.Out.Host = target.Host
			q.SetXForwarded()
			q.Out.Header.Del("Forwarded")
			q.Out.Header.Del("Proxy-Authorization")
			q.Out.Header.Del("Padding")
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Proxy-Authenticate")
			resp.Header.Del("Proxy-Authorization")
			resp.Header.Del("Padding")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "Bad Gateway", 502) },
	}
	return p
}

func (p *naiveFrontend) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Never turn an unauthenticated CONNECT into a second forward proxy.
	if req.Method == "CONNECT" {
		http.NotFound(w, req)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "Service Unavailable", 503)
		return
	}
	p.proxy.ServeHTTP(w, req)
}
