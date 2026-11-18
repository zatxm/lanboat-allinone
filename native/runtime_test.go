package native

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const testUUID = "2b2d59c9-a4e1-4efa-a694-12b6f063093c"

func newTestRuntime(t *testing.T, config Config) *Runtime {
	t.Helper()
	for _, options := range [][]Outbound{config.Outbounds, config.Endpoints} {
		for i := range options {
			if options[i].Type == "tailscale" && options[i].TaildropDirectory == "" {
				options[i].TaildropDirectory = t.TempDir()
			}
		}
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	core, logs := observer.New(zap.DebugLevel)
	r, err := New(context.Background(), data, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			for _, entry := range logs.All() {
				t.Log(entry.Message, entry.ContextMap())
			}
		}
	})
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func certificate(t *testing.T) TLSOptions {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	pair := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return TLSOptions{Enabled: true, Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))}, Key: []string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))}}
}

func testInbound(t *testing.T, kind string) Inbound {
	t.Helper()
	in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1"}
	switch kind {
	case "mixed", "socks", "http", "relay":
		in.Users = []User{{Username: "client", Password: "private"}}
	case "brook":
		in.Password = "private"
	case "shadowsocks":
		in.Method = "aes-256-gcm"
		in.Password = "private"
	case "trojan", "anytls":
		in.Users = []User{{Password: "private"}}
		in.TLS = certificate(t)
	case "vless", "vmess":
		in.Users = []User{{UUID: testUUID}}
	}
	return in
}

func testOutbound(t *testing.T, in Inbound, address string) Outbound {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	var port uint16
	if _, err := fmt.Sscan(portText, &port); err != nil {
		t.Fatal(err)
	}
	kind := in.Type
	if kind == "mixed" {
		kind = "socks"
	}
	out := Outbound{Type: kind, Tag: "proxy", Server: host, ServerPort: port, Username: "client", Password: "private", Method: in.Method, UUID: testUUID}
	if in.TLS.Enabled {
		out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Insecure: true}
	}
	return out
}

func echoUDP(t *testing.T) string {
	t.Helper()
	conn, err := (ListenOptions{}).listenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// Concurrent protocol tests send sixteen 8KiB packets before the reader runs.
	if err := conn.(*net.UDPConn).SetReadBuffer(1 << 20); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := conn.ReadFrom(b)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(b[:n], from)
		}
	}()
	return conn.LocalAddr().String()
}

func assertTCP(t *testing.T, client *Runtime, excludedPorts ...uint16) {
	t.Helper()
	assertTCPTimeout(t, client, 5*time.Second, excludedPorts...)
}

func assertTCPTimeout(t *testing.T, client *Runtime, timeout time.Duration, excludedPorts ...uint16) {
	t.Helper()
	want := strings.Repeat("independent Lanboat transfer\n", 10000)
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if auth := req.Header.Get("Proxy-Authorization"); auth != "" {
			t.Error("proxy credentials reached origin")
		}
		_, _ = io.WriteString(w, want)
	}))
	// Deferred ACME listeners must not be stolen by this test origin's port0 bind.
	for slices.Contains(excludedPorts, uint16(origin.Listener.Addr().(*net.TCPAddr).Port)) {
		origin.Listener.Close()
		var err error
		origin.Listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
	}
	origin.Start()
	defer origin.Close()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return client.Dial(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, Timeout: timeout}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || string(got) != want {
		t.Fatalf("TCP transfer: %d bytes, %v", len(got), err)
	}
}

func assertUDP(t *testing.T, client *Runtime) {
	assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
}

func assertUDPSizes(t *testing.T, client *Runtime, sizes []int) {
	assertUDPAddress(t, client, sizes, echoUDP(t))
}

func assertUDPAddress(t *testing.T, client *Runtime, sizes []int, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	for _, size := range sizes {
		want := bytes.Repeat([]byte{byte(size)}, size)
		if _, err := c.Write(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 65535)
		n, err := c.Read(got)
		if err != nil || !bytes.Equal(want, got[:n]) {
			t.Fatalf("UDP packet size %d: got %d, %v", size, n, err)
		}
	}
}

func TestIndependentProtocolMatrix(t *testing.T) {
	for _, kind := range []string{"mixed", "socks", "http", "shadowsocks", "trojan", "vless", "anytls", "relay"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			if kind != "http" {
				assertUDP(t, client)
			}
		})
	}
}

func TestShadowsocksCiphers(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Method = method
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDP(t, client)
		})
	}
}

func TestAuthenticationNeverFallsBack(t *testing.T) {
	for _, kind := range []string{"socks", "http", "shadowsocks", "trojan", "vless", "vmess", "anytls", "relay", "brook"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Password = "wrong-password"
			out.UUID = "00000000-0000-4000-8000-000000000000"
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			var accessed int
			var mu sync.Mutex
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { mu.Lock(); accessed++; mu.Unlock(); w.WriteHeader(200) }))
			defer origin.Close()
			transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return client.Dial(ctx, n, a) }}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: time.Second}).Get(origin.URL)
			if err == nil {
				response.Body.Close()
				t.Fatal("wrong authentication succeeded")
			}
			mu.Lock()
			defer mu.Unlock()
			if accessed != 0 {
				t.Fatal("failed authentication bypassed proxy")
			}
		})
	}
}

func TestHTTPForwardingCredentialsAndBody(t *testing.T) {
	in := testInbound(t, "http")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	want := strings.Repeat("body", 20000)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			t.Error("hop headers reached origin")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(data)
	}))
	defer origin.Close()
	proxy, _ := url.Parse("http://client:private@" + server.Address("server"))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequest("POST", origin.URL, strings.NewReader(want))
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "secret")
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || string(got) != want {
		t.Fatalf("forward body mismatch: %d, %v", len(got), err)
	}
}

func TestRoutingAndDetour(t *testing.T) {
	in := testInbound(t, "socks")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	proxy := testOutbound(t, in, server.Address("server"))
	proxy.Tag = "front"
	innerIn := testInbound(t, "shadowsocks")
	inner := newTestRuntime(t, Config{Inbounds: []Inbound{innerIn}})
	out := testOutbound(t, innerIn, inner.Address("server"))
	out.Detour = "front"
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out, proxy, {Type: "block", Tag: "blocked"}}, Route: Route{Final: "proxy", Rules: []Rule{{Domain: []string{"blocked.example"}, Outbound: "blocked"}}}})
	assertTCP(t, client)
	assertUDP(t, client)
	if c, err := client.Dial(context.Background(), "tcp", "blocked.example:80"); err == nil {
		c.Close()
		t.Fatal("blocked route succeeded")
	}
}

func TestCloseInterruptsSessions(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() { c, _ := listener.Accept(); accepted <- c }()
	client := newTestRuntime(t, Config{})
	c, err := client.Dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	peer := <-accepted
	defer peer.Close()
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection survived runtime.Close")
	}
	if c, err := client.Dial(context.Background(), "tcp", listener.Addr().String()); err == nil {
		c.Close()
		t.Fatal("closed runtime accepted a new session")
	}
}

func TestRuntimeConcurrentClose(t *testing.T) {
	r := newTestRuntime(t, Config{})
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	closeLogger := r.closeLogger
	r.closeLogger = func() { close(started); <-release; closeLogger() }
	done := make(chan struct{}, 9)
	go func() { r.Close(); done <- struct{}{} }()
	<-started
	for range 8 {
		go func() { r.Close(); done <- struct{}{} }()
	}
	select {
	case <-done:
		t.Fatal("concurrent Close returned before shutdown completed")
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	for range 9 {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("concurrent Close deadlocked")
		}
	}
}

func TestZapLogger(t *testing.T) {
	core, observed := observer.New(zap.InfoLevel)
	raw, _ := json.Marshal(Config{Inbounds: []Inbound{{Type: "mixed", Tag: "local", Listen: "127.0.0.1"}}})
	r, err := New(context.Background(), raw, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	logs := observed.All()
	if len(logs) != 1 || !strings.HasPrefix(logs[0].Message, "inbound/mixed[local]: tcp server started at 127.0.0.1:") {
		t.Fatalf("unexpected zap output: %+v", logs)
	}
}
