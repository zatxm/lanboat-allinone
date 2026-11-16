package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func masqueEndpointRuntime(t *testing.T, endpoint map[string]any) *Runtime {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"endpoints": []any{endpoint}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(); err != nil {
		r.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func masqueEndpointServer(t *testing.T, versions any) *Runtime {
	t.Helper()
	return masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": versions, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": certificate(t), "path": "/vpn/{target}/{ipproto}/"})
}

func masqueEndpointClient(t *testing.T, server *Runtime, version int, strict bool) *Runtime {
	t.Helper()
	host, port, err := net.SplitHostPort(server.Address("server"))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := shadowPort(port)
	return masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "username": "client", "password": "private", "version": version, "disable_version_fallback": strict, "tls": TLSOptions{Enabled: true, Insecure: true}, "path": "/vpn/{target}/{ipproto}/", "headers": map[string]any{"X-Application": "lanboat", "X-Multi": []string{"one", "two"}}})
}

func TestMasqueEndpointVersions(t *testing.T) {
	for _, versions := range [][]int{{1}, {2}, {3}, {1, 2}, {1, 3}, {2, 3}, {1, 2, 3}} {
		t.Run(fmt.Sprint(versions), func(t *testing.T) {
			s := masqueEndpointServer(t, versions)
			for _, version := range versions {
				t.Run(fmt.Sprint(version), func(t *testing.T) {
					c := masqueEndpointClient(t, s, version, true)
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 4096, 60000})
					assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
					p := c.masqueClients["proxy"].ip.Load()
					if got := p.addresses(); len(got) != 2 || got[0] != netip.MustParseAddr("10.44.0.2") || got[1] != netip.MustParseAddr("fd44::2") {
						t.Fatal("incorrect client addresses", got)
					}
					c.resetNetworkTransports()
					assertTCP(t, c)
				})
			}
		})
	}
}

func TestMasqueVersionFallback(t *testing.T) {
	for _, pair := range [][2]int{{3, 2}, {3, 1}, {2, 1}} {
		t.Run(fmt.Sprint(pair), func(t *testing.T) {
			s := masqueEndpointServer(t, pair[1])
			c := masqueEndpointClient(t, s, pair[0], false)
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096, 60000})
			client := c.masqueClients["proxy"]
			client.mu.Lock()
			m := client.session
			got := m.version
			client.mu.Unlock()
			if got != pair[1] {
				t.Fatal("incorrect fallback", got)
			}
			assertTCP(t, c)
			client.mu.Lock()
			same := client.session == m
			client.mu.Unlock()
			if !same {
				t.Fatal("fallback session not reused")
			}
			c.resetNetworkTransports()
			assertTCP(t, c)
		})
	}
	t.Run("blocked-udp", func(t *testing.T) {
		s := masqueEndpointServer(t, 1)
		blackhole, err := net.ListenPacket("udp", s.Address("server"))
		if err != nil {
			t.Fatal(err)
		}
		defer blackhole.Close()
		c := masqueEndpointClient(t, s, 3, false)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, err := c.Dial(ctx, "tcp", relayEchoTCP(t))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		if _, err = conn.Write([]byte("fallback")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len("fallback"))
		if _, err = io.ReadFull(conn, got); err != nil || string(got) != "fallback" {
			t.Fatal(string(got), err)
		}
		if c.masqueClients["proxy"].session.version != 1 {
			t.Fatal("did not fall back past blocked UDP")
		}
	})
	t.Run("disabled", func(t *testing.T) {
		s := masqueEndpointServer(t, 1)
		c := masqueEndpointClient(t, s, 2, true)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if conn, err := c.Dial(ctx, "tcp", relayEchoTCP(t)); err == nil {
			conn.Close()
			t.Fatal("disabled fallback succeeded")
		}
		if c.masqueClients["proxy"].session.version != 2 {
			t.Fatal("unexpected downgrade")
		}
	})
	t.Run("canceled", func(t *testing.T) {
		s := masqueEndpointServer(t, 1)
		c := masqueEndpointClient(t, s, 3, false)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.Dial(ctx, "tcp", "127.0.0.1:1"); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	for _, version := range []int{1, 2} {
		t.Run(fmt.Sprintf("udp-first/%d", version), func(t *testing.T) {
			s := masqueEndpointServer(t, version)
			c := masqueEndpointClient(t, s, 3, false)
			c.masqueClients["proxy"].outbound.Mode = "udp"
			assertUDPSizes(t, c, []int{1, 4096, 60000})
			assertTCP(t, c)
		})
	}
}

func TestMasqueFallbackErrors(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 407, 429, 500, 502, 503} {
		if masqueCanFallback(fmt.Errorf("wrapped: %w", masqueStatusError(code))) {
			t.Fatal("retrying rejection", code)
		}
	}
	for _, code := range []int{421, 501, 505} {
		if !masqueCanFallback(masqueStatusError(code)) {
			t.Fatal("not retrying unsupported transport", code)
		}
	}
	for _, err := range []error{&tls.CertificateVerificationError{Err: errors.New("invalid")}, x509.UnknownAuthorityError{}, x509.CertificateInvalidError{}, x509.HostnameError{Host: "invalid"}} {
		if masqueCanFallback(fmt.Errorf("wrapped: %w", err)) {
			t.Fatal("retrying certificate failure", err)
		}
	}
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := masqueEndpointServer(t, []int{1, 2, 3})
			c := masqueEndpointClient(t, s, version, false)
			c.masqueClients["proxy"].outbound.Password = "wrong"
			if conn, err := c.Dial(context.Background(), "tcp", relayEchoTCP(t)); err == nil {
				conn.Close()
				t.Fatal("bad credentials accepted")
			}
			if c.masqueClients["proxy"].session.version != version {
				t.Fatal("authentication failure caused downgrade")
			}
		})
	}
}

func TestMasqueFallbackCertificates(t *testing.T) {
	for _, version := range []int{2, 3} {
		for _, pin := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/pin-%t", version, pin), func(t *testing.T) {
				s := masqueEndpointServer(t, []int{1, 2, 3})
				host, port, _ := net.SplitHostPort(s.Address("server"))
				n, _ := shadowPort(port)
				options := TLSOptions{Enabled: true, ServerName: "localhost"}
				if pin {
					options.Insecure = true
					options.CertificatePublicKeySHA256 = []string{base64.StdEncoding.EncodeToString(make([]byte, 32))}
				}
				c := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "username": "client", "password": "private", "version": version, "tls": options})
				if conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
					conn.Close()
					t.Fatal("invalid certificate accepted")
				}
				m := c.masqueClients["proxy"].session
				if version == 3 && m != nil || version == 2 && (m == nil || m.version != 2) {
					t.Fatal("certificate failure caused version fallback")
				}
			})
		}
	}
}

func TestMasqueEndpointRoutes(t *testing.T) {
	s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 2, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "advertise_routes": []string{"127.0.0.1/32", "127.0.0.1/32", "10.0.0.0/8"}, "tls": certificate(t)})
	host, port, _ := net.SplitHostPort(s.Address("server"))
	n, _ := shadowPort(port)
	c := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "version": 2, "tls": TLSOptions{Enabled: true, Insecure: true}})
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 4096})
	p := c.masqueClients["proxy"].ip.Load()
	if err := p.writePacket(makeUDPPacket(p.addresses()[0], netip.MustParseAddr("192.0.2.1"), 1234, 53, []byte{1})); err != ErrRejected {
		t.Fatal("client ignored route restriction", err)
	}
	// Bypass the client's announced-route check: the server must independently
	// reject packets outside the advertised prefixes rather than trust its peer.
	sink, err := net.ListenPacket("udp", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	_, sp, _ := net.SplitHostPort(sink.LocalAddr().String())
	pn, _ := shadowPort(sp)
	if _, err = p.flow.Write(makeUDPPacket(p.addresses()[0], netip.MustParseAddr("127.0.0.2"), 1234, pn, []byte{42})); err != nil {
		t.Fatal(err)
	}
	sink.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err = sink.ReadFrom(make([]byte, 128)); !os.IsTimeout(err) {
		t.Fatal("server allowed forbidden route", err)
	}
}

func TestMasqueEndpointConfig(t *testing.T) {
	base := `{"endpoints":[{"type":"masque-client","tag":"proxy","server":"127.0.0.1","server_port":443,"tls":{"enabled":true},%s}]}`
	for _, field := range []string{`"version":4`, `"version":[1,2]`, `"system":true,"name":"bad/name"`, `"name":"tun0"`, `"advertise_routes":["bad"]`, `"path":"/vpn/{wrong}/"`, `"headers":{"Authorization":"x"}`, `"headers":{"X-Test":"x\r\nInjected: true"}`, `"users":[{"username":"a","password":"b"}]`, `"unknown":true`} {
		if _, err := Parse([]byte(fmt.Sprintf(base, field))); err == nil {
			t.Fatal("invalid endpoint accepted", field)
		}
	}
	for _, version := range []string{`0`, `1`, `2`, `3`} {
		if _, err := Parse([]byte(fmt.Sprintf(base, `"version":`+version))); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []string{`[]`, `["10.44.0.1/32"]`, `["::/0"]`, `["10.0.0.1/24","10.1.0.1/24"]`, `["::ffff:10.0.0.1/120"]`} {
		if _, err := Parse([]byte(`{"endpoints":[{"type":"masque-server","address":` + address + `,"tls":{"enabled":true,"certificate_path":"/tmp/no-cert","key_path":"/tmp/no-key"}}]}`)); err == nil {
			t.Fatal(address)
		}
	}
	for _, headers := range []map[string]headerValues{{"X-Test": {"ok"}, "x-test": {"bad"}}, {"Transfer-Encoding": {"chunked"}}, {"X-Test": {strings.Repeat("x", 16385)}}} {
		if validateMasqueHeaders(headers) == nil {
			t.Fatal("unsafe headers accepted")
		}
	}
	var config Config
	for range 2 {
		if err := (masqueEndpointOptions{Type: "masque-server", Address: []string{"10.44.0.1/24"}}).appendTo(&config); err != nil {
			t.Fatal(err)
		}
	}
	if config.Inbounds[0].Tag == "" || config.Inbounds[0].Tag == config.Inbounds[1].Tag {
		t.Fatal("unnamed endpoints overlap")
	}
	if err := (masqueEndpointOptions{Type: "masque-server", Tag: config.Inbounds[0].Tag, Address: []string{"10.44.0.1/24"}}).appendTo(&config); err == nil {
		t.Fatal("duplicate endpoint tag accepted")
	}
}

func TestMasqueHTTP1ExtraHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.Header.Clone(); w.WriteHeader(407) }))
	defer s.Close()
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	n, _ := shadowPort(port)
	c := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "masque", Tag: "proxy", Server: host, ServerPort: n, HTTPVersion: 1, TLS: TLSOptions{Enabled: true, Insecure: true}, MasqueOptions: MasqueOptions{Headers: map[string]headerValues{"X-Multi": {"one", "two"}}}}}})
	if conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("expected rejection")
	}
	h := <-seen
	if got := h.Values("X-Multi"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatal(got)
	}
}

func TestMasqueEndpointOnDemand(t *testing.T) {
	s := masqueEndpointServer(t, []int{1, 2, 3})
	host, port, _ := net.SplitHostPort(s.Address("server"))
	n, _ := shadowPort(port)
	c := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "username": "client", "password": "private", "path": "/vpn/{target}/{ipproto}/", "on_demand": true, "tls": TLSOptions{Enabled: true, Insecure: true}})
	assertTCP(t, c)
	client := c.masqueClients["proxy"]
	client.mu.Lock()
	old := client.session
	client.mu.Unlock()
	if err := c.DisconnectMasque("proxy"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.done:
	default:
		t.Fatal("old session retained")
	}
	assertTCP(t, c)
	client.mu.Lock()
	same := client.session == old
	client.mu.Unlock()
	if same {
		t.Fatal("session not rebuilt")
	}
	if err := c.DisconnectMasque("missing"); err == nil {
		t.Fatal("missing endpoint accepted")
	}
	regular := masqueEndpointClient(t, s, 2, true)
	if err := regular.DisconnectMasque("proxy"); err == nil {
		t.Fatal("non-demand endpoint disconnected")
	}
	c.Close()
	if err := c.DisconnectMasque("proxy"); err == nil {
		t.Fatal("closed runtime accepted")
	}
}

func FuzzMasqueEndpoint(f *testing.F) {
	f.Add([]byte(`{"endpoints":[{"type":"masque-client","server":"localhost","server_port":8080,"version":2}]}`))
	f.Add([]byte(`{"endpoints":[{"type":"masque-client","server":"localhost","server_port":443,"tls":{"enabled":true}}]}`))
	f.Add([]byte(`{"endpoints":{"type":"masque-server","version":[1,2],"address":"10.44.0.1/24"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 32768 {
			return
		}
		_, endpoints, _ := extractNativeEndpoints(b)
		var config Config
		for _, endpoint := range endpoints.masque {
			_ = endpoint.appendTo(&config)
			_ = validateMasqueHeaders(endpoint.Headers)
		}
	})
}
