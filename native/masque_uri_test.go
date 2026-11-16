package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestMasqueURITemplates(t *testing.T) {
	for _, template := range []string{"/vpn/{target}/{ipproto}/", "/vpn?t={target}&p={ipproto}", "/vpn{?target,ipproto}", "/vpn?user=bob{&target,ipproto}", "/vpn/{target,ipproto}"} {
		t.Run(template, func(t *testing.T) {
			compiled, err := compileMasqueURI(template)
			if err != nil {
				t.Fatal(err)
			}
			if scope, status := compiled.match(compiled.wildcard); status != 0 || scope.protocol != 256 || scope.prefix.IsValid() || scope.target != "" {
				t.Fatal(scope, status)
			}
			path := strings.ReplaceAll(compiled.wildcard, "*", "%2A")
			if _, status := compiled.match(path); status != 0 {
				t.Fatal("escaped wildcard rejected", status)
			}
		})
	}
	template, err := compileMasqueURI("/vpn{?target,ipproto}")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path, prefix, host string
		protocol           uint16
		status             int
	}{
		{"/vpn", "", "", 256, 0},
		{"/vpn?target=192.0.2.0%2F24", "192.0.2.0/24", "", 256, 0},
		{"/vpn?ipproto=017", "", "", 17, 0},
		{"/vpn?target=2001%3Adb8%3A%3A%2f32&ipproto=6", "2001:db8::/32", "", 6, 0},
		{"/vpn?target=192.0.2.1&ipproto=6", "192.0.2.1/32", "", 6, 0},
		{"/vpn?target=proxy.example.&ipproto=17", "", "proxy.example.", 17, 0},
		{"/vpn?target=192.0.2.1%2F24", "", "", 0, 400},
		{"/vpn?target=192.0.2.0%2F33", "", "", 0, 400},
		{"/vpn?target=2001:db8::", "", "", 0, 400},
		{"/vpn?target=fe80%3A%3A1%25lo", "", "", 0, 400},
		{"/vpn?target=%00host", "", "", 0, 400},
		{"/vpn?target=%252F", "", "", 0, 400},
		{"/vpn?target=bad%2Fhost", "", "", 0, 400},
		{"/vpn?target=-bad.test", "", "", 0, 400},
		{"/vpn?target=bad..test", "", "", 0, 400},
		{"/vpn?target=%xy", "", "", 0, 400},
		{"/vpn?ipproto=256", "", "", 0, 400},
		{"/vpn?ipproto=-1", "", "", 0, 400},
		{"/vpn?ipproto=0006", "", "", 0, 400},
		{"/vpn?ipproto=0", "", "", 0, 400},
		{"/vpn?ipproto=44", "", "", 0, 400},
		{"/vpn?ipproto=6&ipproto=17", "", "", 0, 404},
		{"/vpn?target=", "", "", 0, 404},
		{"/wrong", "", "", 0, 404},
	} {
		t.Run(test.path, func(t *testing.T) {
			scope, status := template.match(test.path)
			if status != test.status {
				t.Fatal(scope, status)
			}
			if status == 0 && (scope.protocol != test.protocol || scope.target != test.host || scope.prefix.IsValid() != (test.prefix != "") || test.prefix != "" && scope.prefix.String() != test.prefix) {
				t.Fatal(scope)
			}
		})
	}
	repeated, err := compileMasqueURI("/vpn/{target}/{target}/{ipproto}")
	if err != nil {
		t.Fatal(err)
	}
	if _, status := repeated.match("/vpn/192.0.2.1/192.0.2.2/17"); status != 400 {
		t.Fatal("conflicting scopes accepted", status)
	}
	for _, path := range []string{"//host/path", "https://host/path", "/vpn/{wrong}", "/vpn/{+target}", "/vpn/{#target}", "/vpn/{.target}", "/vpn/{/target}", "/vpn/{;target}", "/vpn/{target:3}", "/vpn/{target*}", "/vpn/{target,target}", "/vpn/{target", "/vpn/}", "/vpn#fragment", "/vpn?bad=%gg", "/空", "/with space", "/" + strings.Repeat("a", 2048)} {
		if _, err := compileMasqueURI(path); err == nil {
			t.Fatal("invalid template accepted", path)
		}
	}
}

func TestMasqueScopeRoutes(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"scope.test": {"192.0.2.1", "2001:db8::1"}}}}, Final: "hosts"}})
	for _, test := range []struct {
		scope    masqueScope
		allowed  []string
		assigned []string
		want     []string
	}{
		{scope: masqueScope{target: "scope.test"}, want: []string{"192.0.2.1/32", "2001:db8::1/128"}},
		{scope: masqueScope{target: "scope.test"}, allowed: []string{"192.0.2.0/24"}, want: []string{"192.0.2.1/32"}},
		{scope: masqueScope{target: "scope.test"}, assigned: []string{"10.44.0.2/32"}, want: []string{"192.0.2.1/32"}},
		{scope: masqueScope{prefix: netip.MustParsePrefix("192.0.2.0/24")}, allowed: []string{"192.0.2.128/25", "192.0.2.128/25", "198.51.100.0/24"}, want: []string{"192.0.2.128/25"}},
		{scope: masqueScope{prefix: netip.MustParsePrefix("192.0.2.0/24")}, allowed: []string{"0.0.0.0/0"}, want: []string{"192.0.2.0/24"}},
		{scope: masqueScope{prefix: netip.MustParsePrefix("192.0.2.0/24")}, allowed: []string{"198.51.100.0/24"}},
		{scope: masqueScope{prefix: netip.MustParsePrefix("2001:db8::/32")}, assigned: []string{"10.44.0.2/32"}},
	} {
		var allowed []netip.Prefix
		for _, prefix := range test.allowed {
			allowed = append(allowed, netip.MustParsePrefix(prefix))
		}
		routes, err := test.scope.routes(context.Background(), r, allowed, test.assigned)
		if len(test.want) == 0 {
			if !errors.Is(err, ErrRejected) {
				t.Fatal("empty intersection accepted", routes, err)
			}
			continue
		}
		if err != nil || len(routes) != len(test.want) {
			t.Fatal(routes, err)
		}
		for _, prefix := range test.want {
			if !slices.Contains(routes, netip.MustParsePrefix(prefix)) {
				t.Fatal(routes)
			}
		}
	}
}

func TestMasqueScopedDNSAndICMP(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), MasqueOptions: MasqueOptions{URI: "/vpn{?target,ipproto}"}}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"scope.test": {"127.0.0.1", "::1"}}}}, Final: "hosts"}, Route: Route{Rules: []Rule{{Network: []string{"icmp"}, Action: "reject", Method: "reply"}}}})
			out := testOutbound(t, in, s.Address("server"))
			out.URI = "/vpn?target=scope.test&ipproto=17"
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertUDPSizes(t, c, []int{1, 4096})
			assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
			p := c.masqueClients["proxy"].ip.Load()
			for _, address := range []string{"127.0.0.1", "::1"} {
				ip := netip.MustParseAddr(address)
				echo := []byte{8, 0, 0, 0, 0, 1, 0, 7, 9, 8, 7}
				want := byte(0)
				if ip.Is6() {
					echo[0], want = 128, 129
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				reply, err := p.stack.exchangeICMP(ctx, ip, echo, 64)
				cancel()
				if err != nil || len(reply.data) < 8 || reply.data[0] != want {
					t.Fatal("ICMP was incorrectly excluded from UDP scope", address, err)
				}
			}
			out.URI = "/vpn?target=missing.test&ipproto=17"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			_, err := bad.masqueClients["proxy"].ipSession(context.Background())
			var status masqueStatusError
			if !errors.As(err, &status) || status != 502 {
				t.Fatal("DNS failure did not fail the request", err)
			}
		})
	}
}

func masqueScopedClient(t *testing.T, s *Runtime, version int, path string) *Runtime {
	t.Helper()
	host, port, _ := net.SplitHostPort(s.Address("server"))
	n, _ := shadowPort(port)
	return masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "version": version, "disable_version_fallback": true, "path": path, "tls": TLSOptions{Enabled: true, Insecure: true}})
}

func TestMasqueScopedRequests(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, paths := range [][2]string{{"/vpn/{target}/{ipproto}/", "/vpn/127.0.0.0%2F8/17/"}, {"/vpn{?target,ipproto}", "/vpn?target=127.0.0.0%2F8&ipproto=17"}, {"/vpn?t={target}&p={ipproto}", "/vpn?t=127.0.0.0%2F8&p=17"}} {
			t.Run(fmt.Sprint(version)+paths[0], func(t *testing.T) {
				s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "path": paths[0], "tls": certificate(t)})
				c := masqueScopedClient(t, s, version, paths[1])
				assertUDPSizes(t, c, []int{1, 4096, 60000})
				p := c.masqueClients["proxy"].ip.Load()
				p.mu.Lock()
				routes := append([]masqueRoute(nil), p.routes...)
				p.mu.Unlock()
				if len(routes) != 1 || routes[0].protocol != 17 || routes[0].first != netip.MustParseAddr("127.0.0.0") || routes[0].last != netip.MustParseAddr("127.255.255.255") {
					t.Fatal("unscoped route advertisement", routes)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				if conn, err := c.Dial(ctx, "tcp", relayEchoTCP(t)); err == nil {
					conn.Close()
					t.Fatal("TCP accepted through UDP scope")
				}
				// Even a peer bypassing its local advertised-route check is filtered
				// by the server after IPv6 extension traversal and reassembly.
				p.mu.Lock()
				p.haveRoutes = false
				p.mu.Unlock()
				ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel2()
				if conn, err := c.Dial(ctx2, "tcp", relayEchoTCP(t)); err == nil {
					conn.Close()
					t.Fatal("server trusted client protocol validation")
				}
				assertUDPSizes(t, c, []int{511})
			})
		}
	}
}

func TestMasqueScopedIPv6AndReassembly(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"fd44::1/64"}, "path": "/vpn/{target}/{ipproto}/", "tls": certificate(t)})
			c := masqueScopedClient(t, s, version, "/vpn/%3A%3A1/17/")
			assertUDPAddress(t, c, []int{1, 4096, 60000}, masqueEcho(t, "udp", "[::1]:0"))
			p := c.masqueClients["proxy"].ip.Load()
			sink, err := net.ListenPacket("udp", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			port := uint16(sink.LocalAddr().(*net.UDPAddr).Port)
			packet := makeUDPPacket(p.addresses()[0], netip.MustParseAddr("::1"), 32000, port, []byte("extensions"))
			withOptions := append(append(append([]byte(nil), packet[:40]...), 17, 0, 0, 0, 0, 0, 0, 0), packet[40:]...)
			withOptions[6] = 60
			binary.BigEndian.PutUint16(withOptions[4:], uint16(len(withOptions)-40))
			if _, err = p.flow.Write(withOptions); err != nil {
				t.Fatal(err)
			}
			sink.SetReadDeadline(time.Now().Add(time.Second))
			b := make([]byte, 32)
			n, _, err := sink.ReadFrom(b)
			if err != nil || string(b[:n]) != "extensions" {
				t.Fatal("extension traversal failed", err)
			}
			// A TCP-only session must not forward fragmented UDP, even though
			// the fragment's outer Next Header number is44 rather than17.
			blocked := masqueScopedClient(t, s, version, "/vpn/%3A%3A1/6/")
			ip, err := blocked.masqueClients["proxy"].ipSession(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			large := makeUDPPacket(ip.addresses()[0], netip.MustParseAddr("::1"), 32001, port, make([]byte, 4000))
			if err = writeIPFragments(large, 1280, 33, func(data []byte) error { _, e := ip.flow.Write(data); return e }); err != nil {
				t.Fatal(err)
			}
			sink.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, _, err = sink.ReadFrom(b); !os.IsTimeout(err) {
				t.Fatal("fragmented UDP bypassed TCP scope", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := blocked.Dial(ctx, "tcp", masqueEcho(t, "tcp", "[::1]:0"))
			if err != nil {
				t.Fatal("scoped TCP rejected", err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			want := "scoped IPv6 TCP"
			if _, err = io.WriteString(conn, want); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(want))
			if _, err = io.ReadFull(conn, got); err != nil || string(got) != want {
				t.Fatal("scoped TCP echo failed", err)
			}
		})
	}
}

func TestMasqueScopeErrors(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"10.44.0.1/24"}, "advertise_routes": []string{"127.0.0.1/32"}, "path": "/vpn/{target}/{ipproto}/", "tls": certificate(t)})
			for path, want := range map[string]int{"/vpn/127.0.0.1/999/": 400, "/vpn/192.0.2.0%2F24/17/": 403, "/vpn/%3A%3A1/17/": 403, "/vpn/127.0.0.1%2F8/17/": 400, "/other": 404} {
				c := masqueScopedClient(t, s, version, path)
				_, err := c.masqueClients["proxy"].ipSession(context.Background())
				var status masqueStatusError
				if !errors.As(err, &status) || status != masqueStatusError(want) {
					t.Fatal(path, err)
				}
			}
		})
	}
}

type masqueRejectedResponse struct {
	*httptest.ResponseRecorder
	expired int
}

func (w *masqueRejectedResponse) SetWriteDeadline(t time.Time) error {
	if !t.IsZero() {
		w.expired++
	}
	return nil
}

func TestMasqueRejectedHTTP2Deadline(t *testing.T) {
	r := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 2, "address": []string{"10.44.0.1/24"}, "path": "/vpn/{target}/{ipproto}/", "tls": certificate(t)})
	for path, want := range map[string]int{"/vpn/127.0.0.1/999/": 400, "/other": 404} {
		req := httptest.NewRequest("POST", "https://localhost"+path, nil)
		req.ProtoMajor, req.ProtoMinor = 2, 0
		req.Header.Set(masqueProtocolHeader, "connect-ip")
		req.Header.Set("Capsule-Protocol", "?1")
		conn := &sudokuBufferConn{Buffer: new(bytes.Buffer)}
		session := newMasqueHTTPSession(r.ctx)
		defer session.close()
		wire := &masqueHTTPWire{Conn: conn, tls: tls.Server(conn, &tls.Config{}), session: session}
		req = req.WithContext(context.WithValue(req.Context(), masqueHTTPContext{}, wire))
		w := &masqueRejectedResponse{ResponseRecorder: httptest.NewRecorder()}
		r.serveMasqueHTTP(r.config.Inbounds[0], w, req)
		if w.Code != want {
			t.Fatal(w.Code, want)
		}
		if w.expired != 0 {
			t.Fatal("rejection cleanup expired HTTP2 writer before response completed", w.expired)
		}
	}
}

func FuzzMasqueURI(f *testing.F) {
	f.Add("/vpn/{target}/{ipproto}/", "/vpn/192.0.2.0%2F24/17/")
	f.Add("/vpn{?target,ipproto}", "/vpn?target=%3A%3A1&ipproto=6")
	f.Fuzz(func(t *testing.T, template, path string) {
		compiled, err := compileMasqueURI(template)
		if err == nil {
			_, _ = compiled.match(path)
		}
	})
}
