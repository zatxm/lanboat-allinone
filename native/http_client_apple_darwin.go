//go:build darwin && cgo

package native

/*
#cgo CFLAGS: -x objective-c -fobjc-arc -fblocks
#cgo LDFLAGS: -framework Foundation -framework Security -framework Network -framework CoreWLAN
#include <stdlib.h>
#include "http_client_apple.h"
*/
import "C"

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/cgo"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

type appleHTTPTransport struct {
	runtime                       *Runtime
	options                       HTTPClientOptions
	source                        RuleSet
	mu                            sync.Mutex
	session                       unsafe.Pointer
	proxy                         *http.Server
	listener                      net.Listener
	user, password, authorization string
	plain                         *http.Transport
}
type appleHTTPExchange struct {
	mu                       sync.Mutex
	session                  unsafe.Pointer
	request                  *http.Request
	options                  TLSOptions
	reader                   *io.PipeReader
	writer                   *io.PipeWriter
	headers                  chan *http.Response
	done                     chan struct{}
	complete                 bool
	stopRequest, stopRuntime func() bool
	handle                   cgo.Handle
}
type appleHTTPBody struct {
	*io.PipeReader
	exchange *appleHTTPExchange
}

func (b *appleHTTPBody) Close() error { b.exchange.cancel(); return b.PipeReader.Close() }

func newAppleHTTPTransport(r *Runtime, o HTTPClientOptions, s RuleSet) (httpClientTransport, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	var secret [32]byte
	rand.Read(secret[:])
	t := &appleHTTPTransport{runtime: r, options: o, source: s, listener: listener, user: "lanboat", password: hex.EncodeToString(secret[:])}
	t.authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(t.user+":"+t.password))
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		tag := o.Detour
		if tag == "" {
			tag = s.DownloadDetour
		}
		if tag != "" {
			return r.dialOutbound(ctx, tag, network, address)
		}
		if len(s.HTTPClient) == 0 && len(r.config.HTTPClients) == 0 && r.config.Route.DefaultHTTPClient == "" {
			return r.dialOutbound(ctx, r.config.Route.Final, network, address)
		}
		return r.directWithOptions(ctx, o.DialOptions, network, address)
	}
	t.plain = &http.Transport{Proxy: nil, DialContext: dial, MaxIdleConnsPerHost: 4}
	t.proxy = &http.Server{ReadHeaderTimeout: handshakeTimeout, MaxHeaderBytes: 65536, Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if subtle.ConstantTimeCompare([]byte(req.Header.Get("Proxy-Authorization")), []byte(t.authorization)) != 1 {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Lanboat Apple transport"`)
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		req.Header.Del("Proxy-Authorization")
		if req.Method == "CONNECT" {
			upstream, err := dial(req.Context(), "tcp", req.Host)
			if err != nil {
				http.Error(w, "proxy connection failed", 502)
				return
			}
			downstream, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				upstream.Close()
				return
			}
			defer downstream.Close()
			defer upstream.Close()
			if _, err = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			if buffer.Flush() != nil {
				return
			}
			done := make(chan struct{})
			go func() {
				io.Copy(upstream, buffer)
				if half, ok := upstream.(interface{ CloseWrite() error }); ok {
					half.CloseWrite()
				}
				close(done)
			}()
			io.Copy(downstream, upstream)
			downstream.Close()
			upstream.Close()
			<-done
			return
		}
		if req.URL.Scheme != "http" || req.URL.User != nil {
			http.Error(w, "invalid proxy request", 400)
			return
		}
		clone := req.Clone(req.Context())
		clone.RequestURI = ""
		stripProxyHeaders(clone.Header)
		response, err := t.plain.RoundTrip(clone)
		if err != nil {
			http.Error(w, "proxy request failed", 502)
			return
		}
		defer response.Body.Close()
		for key, values := range response.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	})}
	go t.proxy.Serve(listener)

	return t, nil
}
func (t *appleHTTPTransport) CloseIdleConnections() {
	t.mu.Lock()
	session := t.session
	t.session = nil
	if t.listener != nil {
		t.proxy.Close()
		t.listener.Close()
		t.listener = nil
	}
	t.mu.Unlock()
	if session != nil {
		C.lanboat_apple_finish(session)
	}
	t.plain.CloseIdleConnections()
}
func (t *appleHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Hostname() == "" || req.URL.User != nil || req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return nil, errors.New("Apple HTTP request requires HTTP(S) without URL credentials")
	}
	if t.options.TLS.ServerName != "" && !strings.EqualFold(t.options.TLS.ServerName, req.URL.Hostname()) {
		return nil, errors.New("Apple TLS server_name must match request host")
	}
	if req.Host != "" && !strings.EqualFold(req.Host, req.URL.Host) {
		return nil, errors.New("Apple HTTP Host must match request URL")
	}
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(req.Body, (8<<20)+1))
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(body) > 8<<20 {
			return nil, errors.New("Apple HTTP request body exceeds8MiB")
		}
	}
	headers := map[string]string{}
	for key, values := range req.Header {
		separator := ", "
		if strings.EqualFold(key, "Cookie") {
			separator = "; "
		}
		headers[key] = strings.Join(values, separator)
	}
	encoded, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	if t.runtime.ctx.Err() != nil {
		t.mu.Unlock()
		return nil, net.ErrClosed
	}
	if t.session == nil {
		if t.listener == nil {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.mu.Unlock()
				return nil, err
			}
			t.listener = listener
			t.proxy = &http.Server{ReadHeaderTimeout: handshakeTimeout, MaxHeaderBytes: 65536, Handler: t.proxy.Handler}
			go t.proxy.Serve(listener)
		}
		user, password := C.CString(t.user), C.CString(t.password)
		minimum, maximum := C.int(tls.VersionTLS12), C.int(tls.VersionTLS13)
		versions := map[string]uint16{"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12, "1.3": tls.VersionTLS13}
		if value := versions[t.options.TLS.MinVersion]; value != 0 {
			minimum = C.int(value)
		}
		if value := versions[t.options.TLS.MaxVersion]; value != 0 {
			maximum = C.int(value)
		}
		t.session = C.lanboat_apple_session(C.int(t.listener.Addr().(*net.TCPAddr).Port), user, password, minimum, maximum)
		C.free(unsafe.Pointer(user))
		C.free(unsafe.Pointer(password))
	}
	session := t.session
	C.lanboat_apple_retain(session)
	t.mu.Unlock()
	reader, writer := io.Pipe()
	exchange := &appleHTTPExchange{session: session, request: req, options: t.options.TLS, reader: reader, writer: writer, headers: make(chan *http.Response, 1), done: make(chan struct{})}
	exchange.handle = cgo.NewHandle(exchange)
	exchange.mu.Lock()
	exchange.stopRequest = context.AfterFunc(req.Context(), exchange.cancel)
	exchange.stopRuntime = context.AfterFunc(t.runtime.ctx, exchange.cancel)
	url, method, h := C.CString(req.URL.String()), C.CString(req.Method), C.CString(string(encoded))
	var data unsafe.Pointer
	if len(body) > 0 {
		data = unsafe.Pointer(&body[0])
	}
	C.lanboat_apple_start(session, C.uintptr_t(exchange.handle), url, method, h, data, C.size_t(len(body)))
	C.free(unsafe.Pointer(url))
	C.free(unsafe.Pointer(method))
	C.free(unsafe.Pointer(h))
	exchange.mu.Unlock()
	select {
	case response := <-exchange.headers:
		return response, nil
	case <-exchange.done:
		select {
		case response := <-exchange.headers:
			return response, nil
		default:
		}
		return nil, errors.New("Apple HTTP request failed before response headers")
	case <-req.Context().Done():
		exchange.cancel()
		return nil, req.Context().Err()
	}
}
func (e *appleHTTPExchange) cancel() {
	e.reader.CloseWithError(context.Canceled)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.complete {
		C.lanboat_apple_cancel(e.session, C.uintptr_t(e.handle))
	}
}

//export lanboatAppleHeaders
func lanboatAppleHeaders(handle C.uintptr_t, status C.int, data *C.char, size C.size_t) {
	e := cgo.Handle(handle).Value().(*appleHTTPExchange)
	var fields map[string]any
	if size > 65536 || json.Unmarshal(C.GoBytes(unsafe.Pointer(data), C.int(size)), &fields) != nil {
		e.cancel()
		return
	}
	header := http.Header{}
	for key, value := range fields {
		header.Set(key, fmt.Sprint(value))
	}
	length := int64(-1)
	if n, err := strconv.ParseInt(header.Get("Content-Length"), 10, 64); err == nil && n >= 0 {
		length = n
	}
	response := &http.Response{StatusCode: int(status), Status: strconv.Itoa(int(status)) + " " + http.StatusText(int(status)), Header: header, Body: &appleHTTPBody{PipeReader: e.reader, exchange: e}, ContentLength: length, Request: e.request, Proto: "HTTP"}
	select {
	case e.headers <- response:
	default:
		e.cancel()
	}
}

//export lanboatAppleData
func lanboatAppleData(handle C.uintptr_t, data unsafe.Pointer, size C.size_t) C.int {
	e := cgo.Handle(handle).Value().(*appleHTTPExchange)
	if size > 16<<20 {
		return 0
	}
	if _, err := e.writer.Write(unsafe.Slice((*byte)(data), int(size))); err != nil {
		return 0
	}
	return 1
}

//export lanboatAppleDone
func lanboatAppleDone(handle C.uintptr_t, code C.int) {
	e := cgo.Handle(handle).Value().(*appleHTTPExchange)
	e.mu.Lock()
	e.complete = true
	e.stopRequest()
	e.stopRuntime()
	e.mu.Unlock()
	var err error
	if code != 0 {
		err = fmt.Errorf("Apple HTTP request failed (%d)", int(code))
	}
	e.writer.CloseWithError(err)
	close(e.done)
	C.lanboat_apple_release(e.session)
	e.handle.Delete()
}

//export lanboatAppleTrust
func lanboatAppleTrust(handle C.uintptr_t, data unsafe.Pointer, size C.size_t) C.int {
	e := cgo.Handle(handle).Value().(*appleHTTPExchange)
	if size > 4<<20 {
		return 0
	}
	raw := C.GoBytes(data, C.int(size))
	state := tls.ConnectionState{ServerName: e.request.URL.Hostname()}
	for len(raw) > 0 {
		if len(raw) < 4 {
			return 0
		}
		n := int(binary.BigEndian.Uint32(raw))
		raw = raw[4:]
		if n > len(raw) || n == 0 {
			return 0
		}
		cert, err := x509.ParseCertificate(raw[:n])
		if err != nil {
			return 0
		}
		state.PeerCertificates = append(state.PeerCertificates, cert)
		raw = raw[n:]
	}
	options := e.options
	options.Enabled = true
	config, err := options.config(false, e.request.URL.Hostname())
	if err != nil {
		return 0
	}
	if !config.InsecureSkipVerify && verifyTLSChain(state, config.RootCAs, e.request.URL.Hostname(), false) != nil {
		return 0
	}
	if config.VerifyConnection != nil && config.VerifyConnection(state) != nil {
		return 0
	}
	return 1
}
func appleNetworkMetadata(ctx context.Context, m *Metadata) {
	if ctx.Err() != nil {
		return
	}
	value := C.lanboat_apple_network()
	if value == nil {
		return
	}
	defer C.free(unsafe.Pointer(value))
	var result struct {
		SSID, BSSID            string
		Expensive, Constrained bool
	}
	if json.Unmarshal([]byte(C.GoString(value)), &result) != nil {
		return
	}
	if m.NetworkType == "wifi" {
		if result.SSID != "" {
			m.WiFiSSID = result.SSID
		}
		if result.BSSID != "" {
			m.WiFiBSSID = result.BSSID
		}
	}
	m.NetworkIsExpensive = result.Expensive
	m.NetworkIsConstrained = result.Constrained
}
