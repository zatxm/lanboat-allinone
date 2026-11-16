package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func xhttpPair(t *testing.T, kind, mode string, version int, x XHTTPOptions) (*Runtime, *Runtime) {
	t.Helper()
	in := testInbound(t, kind)
	x.Mode = mode
	in.Transport = Transport{Type: "xhttp", Path: "/test-x", XHTTPOptions: x}
	if version > 1 {
		in.TLS = certificate(t)
		if version == 3 {
			in.TLS.ALPN = []string{"h3"}
		}
	} else {
		in.TLS = TLSOptions{}
	}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	o.Transport = in.Transport
	if version > 1 {
		o.TLS = TLSOptions{Enabled: true, Insecure: true}
		if version == 3 {
			o.TLS.ALPN = []string{"h3"}
		}
	}
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{o}})
}
func TestXHTTPIndependent(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, mode := range []string{"auto", "packet-up", "stream-up", "stream-one"} {
			t.Run(strconv.Itoa(version)+"/"+mode, func(t *testing.T) {
				_, c := xhttpPair(t, "vless", mode, version, XHTTPOptions{})
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				c.resetNetworkTransports()
				assertTCP(t, c)
			})
		}
	}
}
func TestXHTTPProtocols(t *testing.T) {
	for _, kind := range []string{"vmess", "trojan", "shadowsocks", "relay"} {
		t.Run(kind, func(t *testing.T) {
			_, c := xhttpPair(t, kind, "stream-one", 2, XHTTPOptions{})
			assertTCP(t, c)
			if kind != "shadowsocks" {
				sizes := []int{1, 4096, 60000}
				if kind == "vmess" {
					sizes = []int{1, 4096, 16000}
				}
				assertUDPSizes(t, c, sizes)
			}
		})
	}
}
func TestXHTTPPlacements(t *testing.T) {
	for _, place := range []string{"path", "query", "header", "cookie"} {
		for _, data := range []string{"body", "header", "cookie"} {
			t.Run(place+"/"+data, func(t *testing.T) {
				x := XHTTPOptions{SessionPlacement: place, SeqPlacement: place, UplinkDataPlacement: data, UplinkChunkSize: "128", ScMinPostsIntervalMs: "0"}
				_, c := xhttpPair(t, "vless", "packet-up", 1, x)
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{511, 60000})
			})
		}
	}
	for _, place := range []string{"queryInHeader", "query", "header", "cookie"} {
		for _, method := range []string{"repeat-x", "tokenish"} {
			t.Run("padding/"+place+"/"+method, func(t *testing.T) {
				_, c := xhttpPair(t, "vless", "packet-up", 2, XHTTPOptions{XPaddingObfsMode: true, XPaddingPlacement: place, XPaddingMethod: method, XPaddingKey: "pad", XPaddingHeader: "X-Test-Pad", XPaddingBytes: "100-101"})
				assertTCP(t, c)
			})
		}
	}
}
func TestXHTTPWire(t *testing.T) {
	for _, place := range []string{"path", "query", "header", "cookie"} {
		for _, data := range []string{"body", "header", "cookie"} {
			x := XHTTPOptions{Mode: "packet-up", SessionPlacement: place, SeqPlacement: place, UplinkDataPlacement: data, UplinkChunkSize: "8"}.normalized()
			o := Outbound{Server: "example.com", ServerPort: 80, Transport: Transport{Type: "xhttp", Path: "/x", XHTTPOptions: x}}
			sequence := uint64(27)
			request, e := x.request(context.Background(), o, "/x/", "random-id", &sequence, nil)
			if e != nil {
				t.Fatal(e)
			}
			request.Method = "POST"
			payload := bytes.Repeat([]byte{0, 1, 2, 255}, 100)
			x.putData(request, payload)
			session, seq, e := o.Transport.xhttpFields(request)
			if e != nil || session != "random-id" || seq == nil || *seq != sequence {
				t.Fatal(place, data, session, seq, e)
			}
			var got []byte
			if data == "body" {
				got, e = io.ReadAll(request.Body)
			} else {
				got, e = x.dataHeaders(request, len(payload))
			}
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatal(place, data, e)
			}
			if !x.checkPadding(request) {
				t.Fatal("padding")
			}
		}
	}
	for _, method := range []string{"repeat-x", "tokenish"} {
		for _, n := range []int{1, 2, 10, 100, 1000} {
			p := xPadding(n, method)
			if xPaddingLength(p, method) != n {
				t.Fatal(n, method, len(p))
			}
		}
	}
}
func TestXHTTPConcurrent(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		t.Run(mode, func(t *testing.T) {
			_, c := xhttpPair(t, "vless", mode, 2, XHTTPOptions{XMux: XHTTPMux{MaxConcurrency: "2", CMaxReuseTimes: "3", HMaxRequestTimes: "5", HMaxReusableSecs: "1"}, ScMinPostsIntervalMs: "0"})
			address := echoUDP(t)
			var wg sync.WaitGroup
			for i := range 12 {
				wg.Go(func() {
					conn, e := c.Dial(context.Background(), "udp", address)
					if e != nil {
						t.Error(e)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					for range 6 {
						want := bytes.Repeat([]byte{byte(i)}, 4096)
						if _, e = conn.Write(want); e != nil {
							t.Error(e)
							return
						}
						got := make([]byte, 8192)
						n, e := conn.Read(got)
						if e != nil || !bytes.Equal(want, got[:n]) {
							t.Error(n, e)
							return
						}
					}
				})
			}
			wg.Wait()
		})
	}
}
func TestXHTTPConfig(t *testing.T) {
	base := Transport{Type: "xhttp", Path: "/x"}
	for _, change := range []func(*Transport){func(t *Transport) { t.Mode = "bad" }, func(t *Transport) { t.XPaddingBytes = "0" }, func(t *Transport) { t.XPaddingBytes = "200-100" }, func(t *Transport) { t.Mode = "stream-up"; t.UplinkDataPlacement = "cookie" }, func(t *Transport) { t.SessionPlacement = "path"; t.SeqPlacement = "header" }, func(t *Transport) { t.Path = "/path?query=x" }, func(t *Transport) { t.SessionKey = "Cookie\r\nx" }, func(t *Transport) { t.XPaddingHeader = "Content-Length" }, func(t *Transport) { t.XMux.MaxConcurrency = "2"; t.XMux.MaxConnections = "2" }, func(t *Transport) { t.ScMaxBufferedPosts = 129 }} {
		copy := base
		change(&copy)
		if e := copy.validate(); e == nil {
			t.Fatal("invalid XHTTP option accepted", copy)
		}
	}
	for _, raw := range []string{`1`, `"1-3"`, `"0-0"`} {
		var value xRange
		if e := json.Unmarshal([]byte(raw), &value); e != nil {
			t.Fatal(e)
		}
		if _, _, e := value.bounds(0, 0); e != nil {
			t.Fatal(e)
		}
	}
}
func TestXHTTPServerBounds(t *testing.T) {
	r := newTestRuntime(t, Config{})
	in := testInbound(t, "vless")
	in.Transport = Transport{Type: "xhttp", Path: "/x", XHTTPOptions: XHTTPOptions{Mode: "packet-up", ScMaxEachPostBytes: "64", ScMaxBufferedPosts: 2}}
	server := newXHTTPServer(r, in)
	defer server.close()
	x := in.Transport.XHTTPOptions.normalized()
	makeRequest := func(id string, seq uint64, body []byte) *http.Request {
		req, e := x.request(context.Background(), Outbound{Server: "example.com", ServerPort: 80}, "/x/", id, &seq, nil)
		if e != nil {
			t.Fatal(e)
		}
		req.Method = "POST"
		x.putData(req, body)
		return req
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, makeRequest("test", 1, []byte("second")))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, makeRequest("test", 0, []byte("first")))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	p := server.sessions["test"]
	b := make([]byte, 11)
	if _, e := io.ReadFull(p, b); e != nil || string(b) != "firstsecond" {
		t.Fatal(string(b), e)
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, makeRequest("test", 0, []byte("replay")))
	if w.Code != 400 {
		t.Fatal("accepted replay", w.Code)
	}
	w = httptest.NewRecorder()
	server.ServeHTTP(w, makeRequest("large", 0, make([]byte, 65)))
	if w.Code != 400 {
		t.Fatal("accepted oversized", w.Code)
	}
	if server.buffered.Load() != 0 {
		t.Fatal("leaked packet budget", server.buffered.Load())
	}
	server.buffered.Store(xHTTPBudget)
	w = httptest.NewRecorder()
	server.ServeHTTP(w, makeRequest("budget", 0, []byte{1}))
	if w.Code != 400 || server.buffered.Load() != xHTTPBudget {
		t.Fatal("global packet budget was bypassed or miscounted", w.Code, server.buffered.Load())
	}
	server.buffered.Store(0)
	for i := range 512 {
		if _, e := server.session(strconv.Itoa(i)); e != nil {
			t.Fatal(e)
		}
	}
	for _, mode := range []string{"packet-up", "stream-up", "stream-one"} {
		server.x.Mode = mode
		x := server.x
		var session string
		if mode != "stream-one" {
			session = "overflow"
		}
		req, e := x.request(context.Background(), Outbound{Server: "example.com", ServerPort: 80}, in.Transport.xhttpPath(), session, nil, strings.NewReader("handshake"))
		if e != nil {
			t.Fatal(e)
		}
		if mode == "packet-up" {
			seq := uint64(0)
			req, e = x.request(context.Background(), Outbound{Server: "example.com", ServerPort: 80}, in.Transport.xhttpPath(), session, &seq, strings.NewReader("handshake"))
			if e != nil {
				t.Fatal(e)
			}
		}
		w = httptest.NewRecorder()
		server.ServeHTTP(w, req)
		if w.Code != 503 {
			t.Fatal(mode, "bypassed session limit", w.Code)
		}
	}
	server.close()
	if len(server.sessions) != 0 {
		t.Fatal("retained closed sessions")
	}
}
func TestXHTTPCancellation(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			server, c := xhttpPair(t, "vless", "stream-up", version, XHTTPOptions{})
			conn, e := c.Dial(context.Background(), "udp", echoUDP(t))
			if e != nil {
				t.Fatal(e)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			if _, e = conn.Read(make([]byte, 1)); !os.IsTimeout(e) {
				t.Fatal(e)
			}
			conn.Close()
			c.Close()
			deadline := time.Now().Add(2 * time.Second)
			for {
				state := server.xhttpServers["server"]
				state.mu.Lock()
				n := len(state.sessions)
				state.mu.Unlock()
				if n == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("session retained after cancellation", n)
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}

func TestXHTTPDownloadSplit(t *testing.T) {
	for _, mode := range []string{"packet-up", "stream-up"} {
		t.Run(mode, func(t *testing.T) {
			in := testInbound(t, "vless")
			in.TLS = certificate(t)
			in.Transport = Transport{Type: "xhttp", Path: "/split", XHTTPOptions: XHTTPOptions{Mode: mode}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			address := server.Address("server")
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			go func() {
				for {
					client, e := listener.Accept()
					if e != nil {
						return
					}
					go func() {
						backend, e := net.Dial("tcp", address)
						if e != nil {
							client.Close()
							return
						}
						defer client.Close()
						defer backend.Close()
						done := make(chan struct{})
						go func() { io.Copy(backend, client); backend.Close(); close(done) }()
						io.Copy(client, backend)
						client.Close()
						<-done
					}()
				}
			}()
			o := testOutbound(t, in, address)
			o.Transport = in.Transport
			o.Transport.DownloadTargetHost = "127.0.0.1"
			o.Transport.DownloadTargetPort = uint16(listener.Addr().(*net.TCPAddr).Port)
			o.Transport.DownloadHTTPHost = "download.example"
			o.Transport.DownloadServerName = "example.com"
			o.Transport.DownloadTLS = &TLSOptions{Enabled: true, Certificate: in.TLS.Certificate}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 511, 60000})
			if c.xhttpClients["proxy"].up == c.xhttpClients["proxy"].down {
				t.Fatal("download did not use its own pool")
			}
		})
	}
}
func TestXHTTPPoolLimits(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			_, r := xhttpPair(t, "vless", "packet-up", version, XHTTPOptions{XMux: XHTTPMux{MaxConnections: "1"}})
			p := r.xhttpClients["proxy"].up
			first, e := p.acquire(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if version == 1 {
				ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
				defer cancel()
				if _, e = p.acquire(ctx); e == nil {
					t.Fatal("H1 reused an occupied pair")
				}
			} else {
				second, e := p.acquire(context.Background())
				if e != nil || second != first {
					t.Fatal("max_connections", e)
				}
				second.release()
			}
			first.release()
			p.mu.Lock()
			for _, e := range p.entries {
				e.retired = true
			}
			p.mu.Unlock()
			next, e := p.acquire(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			p.mu.Lock()
			n := len(p.entries)
			p.mu.Unlock()
			if n != 1 {
				t.Fatal("retired pool leaked", n)
			}
			next.release()
		})
	}
	for _, m := range []XHTTPMux{{}, {MaxConcurrency: "0", MaxConnections: "0-0"}} {
		if !m.defaults() {
			t.Fatal("all-zero XMUX must use defaults")
		}
	}
}

func TestXHTTPMethodsAndHeaders(t *testing.T) {
	for _, method := range []string{"PUT", "PATCH", "GET", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			x := XHTTPOptions{UplinkHTTPMethod: method, ScMinPostsIntervalMs: "0", NoGRPCHeader: true, NoSSEHeader: true}
			if method == "GET" {
				x.UplinkDataPlacement = "header"
			}
			_, c := xhttpPair(t, "vless", "packet-up", 2, x)
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
	for _, disabled := range []bool{false, true} {
		x := XHTTPOptions{Mode: "stream-one", NoGRPCHeader: disabled}.normalized()
		request, e := x.request(context.Background(), Outbound{Server: "example.com", ServerPort: 80}, "/a%2fb/", "", nil, strings.NewReader("body"))
		if e != nil {
			t.Fatal(e)
		}
		if (request.Header.Get("Content-Type") == "") != disabled || !request.Close {
			t.Fatal("stream header/connection", request.Header, request.Close)
		}
		if request.URL.Path != "/a%2fb/" {
			t.Fatal("literal path changed", request.URL)
		}
	}
}
func TestXHTTPKeepAlive(t *testing.T) {
	_, r := xhttpPair(t, "vless", "stream-up", 2, XHTTPOptions{ScStreamUpServerSecs: "1"})
	c, e := r.Dial(context.Background(), "udp", echoUDP(t))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	time.Sleep(1100 * time.Millisecond)
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("after keepalive"))
	b := make([]byte, 32)
	n, e := c.Read(b)
	if e != nil || string(b[:n]) != "after keepalive" {
		t.Fatal(n, e)
	}
	for _, period := range []int{-1, 1} {
		_, r := xhttpPair(t, "vless", "stream-one", 3, XHTTPOptions{XMux: XHTTPMux{HKeepAlivePeriod: period}})
		c, e := r.Dial(context.Background(), "udp", echoUDP(t))
		if e != nil {
			t.Fatal(e)
		}
		pool := r.xhttpClients["proxy"].up
		pool.mu.Lock()
		entry := pool.entries[0]
		pool.mu.Unlock()
		entry.mu.Lock()
		q := entry.quic
		entry.mu.Unlock()
		if q == nil || q.keepAlive != time.Duration(period)*time.Second {
			t.Fatal("QUIC keepalive option was ignored")
		}
		c.Close()
	}
}

func TestXHTTPHalfClose(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, mode := range []string{"stream-up", "stream-one"} {
			t.Run(strconv.Itoa(version)+"/"+mode, func(t *testing.T) {
				_, r := xhttpPair(t, "vless", mode, version, XHTTPOptions{})
				listener, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer listener.Close()
				go func() {
					c, e := listener.Accept()
					if e != nil {
						return
					}
					defer c.Close()
					b, e := io.ReadAll(c)
					if e == nil {
						c.Write(b)
					}
				}()
				c, e := r.Dial(context.Background(), "tcp", listener.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				want := bytes.Repeat([]byte("halfclose"), 1000)
				if _, e = c.Write(want); e != nil {
					t.Fatal(e)
				}
				if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
					t.Fatal(e)
				}
				got, e := io.ReadAll(c)
				if e != nil || !bytes.Equal(got, want) {
					t.Fatal("stream halfclose", len(got), e)
				}
			})
		}
	}
}
func FuzzXHTTPFields(f *testing.F) {
	f.Add([]byte("/x/session-id/0"), []byte("x-data-0"), []byte("AQID"))
	f.Add([]byte("/bad"), []byte("x-data-99"), []byte("%%%"))
	f.Fuzz(func(t *testing.T, path, key, value []byte) {
		if len(path)+len(key)+len(value) > 65536 {
			return
		}
		req, e := http.NewRequest("POST", "http://example.test/", nil)
		if e != nil {
			t.Fatal(e)
		}
		req.URL.Path = string(path)
		req.Header.Set(string(key), string(value))
		x := XHTTPOptions{Mode: "packet-up", UplinkDataPlacement: "header"}.normalized()
		transport := Transport{Type: "xhttp", Path: "/x", XHTTPOptions: x}
		session, seq, e := transport.xhttpFields(req)
		if e == nil && (len(session) > 128 || seq != nil && session == "") {
			t.Fatal("invalid fields accepted")
		}
		b, e := x.dataHeaders(req, 4096)
		if e == nil && len(b) > 4096 {
			t.Fatal("unbounded decoded payload")
		}
		x.checkPadding(req)
	})
}
