//go:build linux

package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestKernelTLSLinux(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_KERNEL_TLS_CHILD") != "1" {
		if os.Getenv("LANBOAT_TEST_KERNEL_TLS_VM") != "1" {
			t.Skip("run scripts/test-kernel-tls.sh for isolated real-kernel validation")
		}
		if runtime.GOARCH != "amd64" {
			t.Fatal("kernel VM harness needs amd64")
		}
		cmd := exec.Command("bash", filepath.Join("..", "scripts", "test-kernel-tls.sh"))
		b, e := cmd.CombinedOutput()
		t.Log(string(b))
		if e != nil {
			t.Fatal(e)
		}
		return
	}
	before, e := os.ReadFile("/proc/net/tls_stat")
	if e != nil {
		t.Fatal(e)
	}
	t.Log(string(before))
	for _, mode := range []string{"tx", "rx", "both"} {
		for _, side := range []string{"client", "server", "both"} {
			t.Run(mode+"/"+side, func(t *testing.T) { testKernelTLSHandshake(t, mode, side) })
		}
		for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
			t.Run(fmt.Sprintf("%s/key-update/%04x", mode, id), func(t *testing.T) { testKernelTLSKeys(t, mode, id) })
		}
	}
	for _, kind := range []string{"socks", "trojan", "anytls", "relay", "vmess", "vless", "brook"} {
		t.Run("proxy/"+kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = certificate(t)
			in.TLS.KernelTX, in.TLS.KernelRX = true, true
			if kind == "brook" {
				in.Transport = Transport{Type: "ws", Path: "/brook"}
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Transport = in.Transport
			out.TLS.KernelTX, out.TLS.KernelRX = true, true
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
			assertTCP(t, client)
		})
	}
	for _, tr := range []string{"ws", "httpupgrade", "grpc", "http", "xhttp"} {
		t.Run("transport/"+tr, func(t *testing.T) {
			in := testInbound(t, "vless")
			in.TLS = certificate(t)
			in.TLS.KernelTX, in.TLS.KernelRX = true, true
			in.Transport = Transport{Type: tr, Path: "/kernel"}
			if tr == "grpc" {
				in.Transport.Path = ""
				in.Transport.ServiceName = "kernel"
			}
			if tr == "xhttp" {
				in.Transport.XHTTPOptions.Mode = "stream-one"
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Transport, out.TLS.KernelTX, out.TLS.KernelRX = in.Transport, true, true
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
	for _, kind := range []string{"naive", "trusttunnel", "masque"} {
		t.Run("http2/"+kind, func(t *testing.T) {
			in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", HTTPVersion: 2, Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
			if kind == "naive" {
				in.Network, in.HTTPVersion = "tcp", 0
			}
			in.TLS.KernelTX, in.TLS.KernelRX = true, true
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.HTTPVersion = 2
			if kind == "naive" {
				out.HTTPVersion = 0
			}
			out.TLS.KernelTX, out.TLS.KernelRX = true, true
			if kind == "masque" {
				out.Mode = "ip"
			}
			if kind == "naive" {
				out.UDPOverTCP = true
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
	for _, tr := range []string{"", "grpc", "xhttp"} {
		t.Run("reality/"+tr, func(t *testing.T) {
			so, co := realityFixture(t)
			so.KernelTX, so.KernelRX, co.KernelTX, co.KernelRX = true, true, true, true
			in := testInbound(t, "vless")
			in.TLS = so
			if tr != "" {
				in.Transport = Transport{Type: tr, Path: "/kernel"}
			}
			if tr == "grpc" {
				in.Transport.Path = ""
				in.Transport.ServiceName = "kernel"
			}
			if tr == "xhttp" {
				in.Transport.XHTTPOptions.Mode = "stream-one"
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Transport, out.TLS = in.Transport, co
			assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{out}}))
		})
	}
	t.Run("ech", func(t *testing.T) {
		f := newMutualTLSFixture(t)
		config, key := testECHPair(t)
		in := testInbound(t, "trojan")
		in.TLS = testECHServer(t, f, key)
		in.TLS.KernelTX, in.TLS.KernelRX = true, true
		s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		s.serverTLS[in.Tag].VerifyConnection = requireECH
		o := testOutbound(t, in, s.Address("server"))
		o.TLS = testECHClient(f, config)
		o.TLS.KernelTX, o.TLS.KernelRX = true, true
		assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{o}}))
	})
	t.Run("close-notify", func(t *testing.T) {
		f := newMutualTLSFixture(t)
		a, b := kernelTLSTCPPair(t)
		so, co := f.server(), f.client()
		so.KernelTX, so.KernelRX = true, true
		sc, e := so.config(true, "")
		if e != nil {
			t.Fatal(e)
		}
		cc, e := co.config(false, "example.com")
		if e != nil {
			t.Fatal(e)
		}
		s := serverTLSConnection(b, sc, so)
		c := tls.Client(a, cc)
		done := make(chan error, 1)
		go func() { done <- s.Handshake() }()
		if e := c.Handshake(); e != nil {
			t.Fatal(e)
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		if e := s.Close(); e != nil {
			t.Fatal(e)
		}
		if e := s.Close(); e != nil {
			t.Fatal("repeated close", e)
		}
		if _, e := io.ReadAll(c); e != nil {
			t.Fatal("close_notify lost", e)
		}
	})
	t.Run("controller", func(t *testing.T) {
		in := testInbound(t, "trojan")
		in.TLS.KernelTX, in.TLS.KernelRX = true, true
		s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, ExternalController: "127.0.0.1:0"})
		o := testOutbound(t, in, s.Address("server"))
		o.TLS.KernelTX, o.TLS.KernelRX = true, true
		assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{o}}))
		if s.controller.up.Load() < 100 || s.controller.down.Load() < 100 {
			t.Fatal("offload lost controller traffic")
		}
	})
	for _, kind := range []string{"tls", "https"} {
		t.Run("dns/"+kind, func(t *testing.T) {
			var address string
			if kind == "tls" {
				in := Inbound{Type: "dns", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t)}
				in.TLS.KernelTX, in.TLS.KernelRX = true, true
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"kernel.test": {"192.0.2.7"}}}}}})
				address = s.Address("server")
			} else {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					if req.ProtoMajor != 2 {
						t.Error("DoH lost HTTP2")
					}
					q, e := io.ReadAll(req.Body)
					if e != nil {
						t.Error(e)
						return
					}
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(dnsAnswer(q))
				}))
				s.EnableHTTP2 = true
				s.StartTLS()
				defer s.Close()
				address = s.Listener.Addr().String()
			}
			host, port, _ := net.SplitHostPort(address)
			n, _ := strconv.ParseUint(port, 10, 16)
			c := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: kind, Tag: "resolver", Server: host, ServerPort: uint16(n), TLS: TLSOptions{Insecure: true, KernelTX: true, KernelRX: true}}}}})
			ips, e := c.LookupIP(context.Background(), "kernel.test")
			if e != nil || len(ips) == 0 {
				t.Fatal(ips, e)
			}
		})
	}
	t.Run("download", func(t *testing.T) {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.ProtoMajor != 2 {
				t.Error("downloader lost HTTP2")
			}
			io.WriteString(w, "rules")
		}))
		s.EnableHTTP2 = true
		s.StartTLS()
		defer s.Close()
		r := newTestRuntime(t, Config{})
		c, tr, e := r.ruleHTTPClient(RuleSet{HTTPClient: clientReference(`{"tls":{"kernel_tx":true,"kernel_rx":true,"insecure":true}}`)})
		if e != nil {
			t.Fatal(e)
		}
		defer tr.CloseIdleConnections()
		res, e := c.Get(s.URL)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, e := io.ReadAll(res.Body)
		if e != nil || string(b) != "rules" {
			t.Fatal(string(b), e)
		}
	})
	after, e := os.ReadFile("/proc/net/tls_stat")
	if e != nil {
		t.Fatal(e)
	}
	t.Log(string(after))
	for _, name := range []string{"TlsTxSw", "TlsRxSw", "TlsTxRekeyOk", "TlsRxRekeyOk"} {
		found := false
		for _, line := range strings.Split(string(after), "\n") {
			var key string
			var n int
			if _, e := fmt.Sscan(line, &key, &n); e == nil && key == name && n > 0 {
				found = true
			}
		}
		if !found {
			t.Fatalf("kernel counter %s did not increment", name)
		}
	}
}

func testKernelTLSHandshake(t *testing.T, mode, side string) {
	f := newMutualTLSFixture(t)
	a, b := kernelTLSTCPPair(t)
	account := &controller{}
	a = &controllerWireConn{Conn: a, c: account}
	so, co := f.server(), f.client()
	so.KernelTX, so.KernelRX = mode != "rx", mode != "tx"
	co.KernelTX, co.KernelRX = so.KernelTX, so.KernelRX
	sc, e := so.config(true, "")
	if e != nil {
		t.Fatal(e)
	}
	cc, e := co.config(false, "example.com")
	if e != nil {
		t.Fatal(e)
	}
	if side == "client" {
		so.KernelTX, so.KernelRX = false, false
	}
	if side == "server" {
		co.KernelTX, co.KernelRX = false, false
	}
	s := serverTLSConnection(b, sc, so)
	c := clientTLS(a, cc, co)
	done := make(chan error, 1)
	go func() { done <- s.HandshakeContext(context.Background()) }()
	if e := c.Handshake(); e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if len(c.ConnectionState().VerifiedChains) == 0 || len(s.ConnectionState().VerifiedChains) == 0 {
		t.Fatal("mTLS lost")
	}
	go func() {
		_, e := io.Copy(s, s)
		if e == nil {
			e = s.CloseWrite()
		}
		done <- e
	}()
	payload := bytes.Repeat([]byte("kernel encrypted record!"), 20000)
	write := make(chan error, 1)
	go func() {
		_, e := c.Write(payload)
		if e == nil {
			e = c.CloseWrite()
		}
		write <- e
	}()
	got, e := io.ReadAll(c)
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip=%d err=%v", len(got), e)
	}
	if e := <-write; e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if account.wireUp.Load() < int64(len(payload)) || account.wireDown.Load() < int64(len(payload)) {
		t.Fatal("kernel socket bypassed wire accounting")
	}
}

func testKernelTLSKeys(t *testing.T, mode string, id uint16) {
	a, b := kernelTLSTCPPair(t)
	suite, e := stSuite(id)
	if e != nil {
		t.Fatal(e)
	}
	makeConn := func(raw net.Conn, server bool) *realityConn {
		own, peer := bytes.Repeat([]byte{1}, suite.hash.Size()), bytes.Repeat([]byte{2}, suite.hash.Size())
		if server {
			own, peer = peer, own
		}
		tx, _ := suite.recordCipher(own)
		rx, _ := suite.recordCipher(peer)
		return &realityConn{Conn: raw, server: server, tls: &stTLS13{conn: raw, suite: suite, clientSecret: own, serverSecret: peer, clientApp: tx, serverApp: rx, state: tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}}}
	}
	c, s := makeConn(a, false), makeConn(b, true)
	c.kernel, e = installKernelTLS(a, c.tls, mode != "rx", mode != "tx")
	if e != nil {
		t.Fatal(e)
	}
	s.kernel, e = installKernelTLS(b, s.tls, mode != "rx", mode != "tx")
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := io.Copy(s, s)
		if e == nil {
			e = s.CloseWrite()
		}
		done <- e
	}()
	write := make(chan error, 1)
	go func() {
		for range 3 {
			c.writeMu.Lock()
			e := c.updateWriteKey()
			c.writeMu.Unlock()
			if e != nil {
				write <- e
				return
			}
			if _, e = c.Write([]byte("updated key")); e != nil {
				write <- e
				return
			}
		}
		write <- c.CloseWrite()
	}()
	got, e := io.ReadAll(c)
	if e != nil || string(got) != strings.Repeat("updated key", 3) {
		t.Fatalf("keyupdate data=%q err=%v", got, e)
	}
	if e := <-write; e != nil {
		t.Fatal(e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
