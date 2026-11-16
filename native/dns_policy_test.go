package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSPolicyFakeIPRoutingAndReject(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "fakeip route reached real origin") }))
	defer origin.Close()
	cfg := Config{DNS: DNSConfig{Final: "real", Servers: []DNSServer{{Type: "fakeip", Tag: "fake"}, {Type: "hosts", Tag: "real", Predefined: map[string][]string{"service.example": {"127.0.0.1"}}}}, Rules: []DNSRule{{Rule: Rule{Domain: []string{"service.example"}}, Server: "fake"}, {Rule: Rule{DomainSuffix: []string{"blocked.example"}, Action: "reject"}}}}}
	runtime := newTestRuntime(t, cfg)
	ips, err := runtime.LookupIP(context.Background(), "service.example")
	if err != nil || len(ips) != 2 {
		t.Fatal(ips, err)
	}
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	for _, ip := range ips {
		parsed, _ := netip.AddrFromSlice(ip)
		if !runtime.resolver.isFake(parsed) {
			t.Fatal("expected FakeIP", ip)
		}
		conn, err := runtime.Dial(context.Background(), "tcp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: service.example\r\nConnection: close\r\n\r\n")
		response, err := io.ReadAll(conn)
		conn.Close()
		if err != nil || !strings.Contains(string(response), "fakeip route reached real origin") {
			t.Fatalf("fake route: %s %v", response, err)
		}
	}
	if _, err := runtime.LookupIP(context.Background(), "blocked.example"); err != ErrRejected {
		t.Fatal("DNS reject bypassed", err)
	}
	if _, err := runtime.Dial(context.Background(), "tcp", "198.18.99.99:443"); err == nil {
		t.Fatal("unknown FakeIP was sent directly")
	}
	query, _ := makeDNSQuery("blocked.example", 1)
	response, err := runtime.ExchangeDNS(context.Background(), query, "dns")
	if err != nil || response[3]&15 != 5 {
		t.Fatal("DNS wire reject", err)
	}
}
func TestDNSBootstrapHTTPSAndPolicyCacheIsolation(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host[:len("dns.bootstrap.test")] != "dns.bootstrap.test" {
			t.Error("bootstrap changed HTTP Host")
		}
		query, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsAnswer(query))
	}))
	defer upstream.Close()
	_, portText, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	port, _ := strconv.ParseUint(portText, 10, 16)
	cfg := Config{DNS: DNSConfig{Final: "remote", Servers: []DNSServer{{Type: "hosts", Tag: "bootstrap", Predefined: map[string][]string{"dns.bootstrap.test": {"127.0.0.1"}}}, {Type: "https", Tag: "remote", Server: "dns.bootstrap.test", ServerPort: uint16(port), DomainResolver: "bootstrap", TLS: TLSOptions{Insecure: true}}, {Type: "hosts", Tag: "a", Predefined: map[string][]string{"private.test": {"192.0.2.1"}}}, {Type: "hosts", Tag: "b", Predefined: map[string][]string{"private.test": {"192.0.2.2"}}}}, Rules: []DNSRule{{Rule: Rule{Inbound: []string{"a"}}, Server: "a"}, {Rule: Rule{Inbound: []string{"b"}}, Server: "b"}}}}
	runtime := newTestRuntime(t, cfg)
	ips, err := runtime.LookupIP(context.Background(), "data.test")
	if err != nil || len(ips) != 2 {
		t.Fatal("DoH bootstrap", ips, err)
	}
	for _, tag := range []string{"a", "b", "a", "b"} {
		query, _ := makeDNSQuery("private.test", 1)
		reply, err := runtime.ExchangeDNS(context.Background(), query, tag)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := parseDNSReply(query, reply)
		want := "192.0.2.1"
		if tag == "b" {
			want = "192.0.2.2"
		}
		if err != nil || len(got) != 1 || got[0].String() != want {
			t.Fatal("DNS policy caches mixed", got, err)
		}
	}
}
func TestDNSListenersTCPUDP(t *testing.T) {
	cfg := Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: "127.0.0.1"}}, DNS: DNSConfig{Final: "hosts", Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"local.test": {"192.0.2.7"}}}}}}
	runtime := newTestRuntime(t, cfg)
	for _, network := range []string{"udp", "tcp"} {
		conn, err := net.Dial(network, runtime.Address("dns"))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		query, _ := makeDNSQuery("local.test", 1)
		if network == "tcp" {
			writeAll(conn, binary.BigEndian.AppendUint16(nil, uint16(len(query))))
		}
		writeAll(conn, query)
		var reply []byte
		if network == "tcp" {
			var size [2]byte
			if _, err := io.ReadFull(conn, size[:]); err != nil {
				t.Fatal(err)
			}
			reply = make([]byte, int(binary.BigEndian.Uint16(size[:])))
			_, err = io.ReadFull(conn, reply)
		} else {
			reply = make([]byte, 4096)
			var n int
			n, err = conn.Read(reply)
			reply = reply[:n]
		}
		conn.Close()
		if err != nil {
			t.Fatal(network, err)
		}
		ips, _, err := parseDNSReply(query, reply)
		if err != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.7") {
			t.Fatal(network, ips, err)
		}
	}
}
func TestFakePoolDoesNotReplaceActiveMappings(t *testing.T) {
	pool, err := newFakePool(DNSServer{Inet4Range: "198.18.0.0/30"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	first, err := pool.allocate("first.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.allocate("second.test", 1); err == nil {
		t.Fatal("pool replaced a live mapping")
	}
	if pool.byIP[first].host != "first.test" {
		t.Fatal("FakeIP changed destination")
	}
}
func TestDNSQueryTypeNames(t *testing.T) {
	var rule DNSRule
	if err := json.Unmarshal([]byte(`{"query_type":["A","AAAA",65],"server":"dns"}`), &rule); err != nil || len(rule.QueryType) != 3 || rule.QueryType[1] != 28 {
		t.Fatal(rule, err)
	}
}

func TestDNSDetourDoesNotBypassFailedAuthentication(t *testing.T) {
	var requests atomic.Int32
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(req.Host, "dns.detour.test:") {
			t.Error("DoH Host changed", req.Host)
		}
		query, _ := io.ReadAll(req.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsAnswer(query))
	}))
	defer origin.Close()
	_, portText, _ := net.SplitHostPort(origin.Listener.Addr().String())
	port, _ := strconv.ParseUint(portText, 10, 16)
	proxy := newTestRuntime(t, Config{Inbounds: []Inbound{testInbound(t, "socks")}})
	out := testOutbound(t, Inbound{Type: "socks"}, proxy.Address("server"))
	cfg := Config{Outbounds: []Outbound{out}, DNS: DNSConfig{Final: "remote", Servers: []DNSServer{{Type: "hosts", Tag: "bootstrap", Predefined: map[string][]string{"dns.detour.test": {"127.0.0.1"}}}, {Type: "https", Tag: "remote", Server: "dns.detour.test", ServerPort: uint16(port), DomainResolver: "bootstrap", Detour: "proxy", TLS: TLSOptions{Insecure: true}}}}}
	client := newTestRuntime(t, cfg)
	if ips, err := client.LookupIP(context.Background(), "resolved.test"); err != nil || len(ips) != 2 {
		t.Fatal(ips, err)
	}
	if requests.Load() == 0 || proxy.Stats().Uplink == 0 {
		t.Fatal("DNS did not cross the configured proxy")
	}
	before := requests.Load()
	cfg.Outbounds[0].Password = "wrong"
	denied := newTestRuntime(t, cfg)
	if _, err := denied.LookupIP(context.Background(), "rejected.test"); err == nil {
		t.Fatal("DNS ignored failed proxy authentication")
	}
	if requests.Load() != before {
		t.Fatal("DNS bypassed proxy and reached origin directly")
	}
}
