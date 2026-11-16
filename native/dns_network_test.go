package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSNetworkDiscovery(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		scutil     bool
		ips, names []string
	}{
		{"resolv", "nameserver 192.0.2.53 # a\nnameserver ::ffff:192.0.2.53\nnameserver fe80::53%eth0\nsearch old.example\ndomain replaced.example\nsearch CORP.example. lab.example ; comment\nnameserver invalid\n", false, []string{"192.0.2.53", "fe80::53"}, []string{"corp.example", "lab.example"}},
		{"scutil", "resolver #1\n search domain[0] : corp.example\n nameserver[0] : 2001:db8::53\n nameserver[1] : 127.0.0.1\nresolver #2\n nameserver[0] : 2001:db8::53\n domain : not-a-search-domain\n search domain[0] : LAB.example.\n", true, []string{"2001:db8::53", "127.0.0.1"}, []string{"corp.example", "lab.example"}},
		{"bad", "nameserver 0.0.0.0\nnameserver ff02::1\nsearch bad..example -bad.example .\n", false, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := parseDNSNetwork(strings.NewReader(tc.text), tc.scutil)
			var ips []string
			for _, ip := range s.addresses {
				ips = append(ips, ip.String())
			}
			if !reflect.DeepEqual(ips, tc.ips) || !reflect.DeepEqual(s.domains, tc.names) {
				t.Fatal(s)
			}
		})
	}
}

func TestDNSNetworkConditions(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule Rule
		want bool
	}{
		{"v4", Rule{DNSServerAddress: map[string][]string{"local": {"192.0.2.0/24"}}}, true},
		{"v6", Rule{DNSServerAddress: map[string][]string{"vpn": {"2001:db8::/32"}}}, true},
		{"and-tags", Rule{DNSServerAddress: map[string][]string{"local": {"10.0.0.0/8"}, "vpn": {"2001:db8::53"}}}, false},
		{"empty-filter", Rule{DNSServerAddress: map[string][]string{"missing": {}}}, true},
		{"search", Rule{DNSSearchDomain: map[string][]string{"vpn": {"CORP.example."}}}, true},
		{"not-suffix", Rule{DNSSearchDomain: map[string][]string{"vpn": {"example"}}}, false},
		{"and-fields", Rule{DNSServerAddress: map[string][]string{"local": {"192.0.2.53"}}, DNSSearchDomain: map[string][]string{"vpn": {"wrong.example"}}}, false},
		{"invert", Rule{DNSServerAddress: map[string][]string{"local": {"10.0.0.0/8"}}, Invert: true}, true},
		{"missing", Rule{DNSSearchDomain: map[string][]string{"missing": {"corp.example"}}}, false},
		{"logical", Rule{Type: "logical", Mode: "and", Rules: []Rule{{DNSSearchDomain: map[string][]string{"vpn": {"corp.example"}}}, {DNSServerAddress: map[string][]string{"local": {"192.0.2.53"}}}}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.rule.Outbound = "direct"
			rules, err := compileRoute(Route{Final: "direct", Rules: []Rule{tc.rule}}, map[string]Outbound{"direct": {Type: "direct"}})
			if err != nil {
				t.Fatal(err)
			}
			q := request{network: "tcp", address: "203.0.113.9:80", metadata: Metadata{DNSServerAddress: map[string][]netip.Addr{"local": {netip.MustParseAddr("192.0.2.53")}, "vpn": {netip.MustParseAddr("2001:db8::53")}}, DNSSearchDomain: map[string][]string{"vpn": {"corp.example"}}}}
			if rules[0].matches(q) != tc.want {
				t.Fatal("unexpected match", tc.want)
			}
			q.dns, q.queryType, q.preMatch = true, 1, true
			if rules[0].matches(q) != tc.want || rules[0].preMatchNeedsData(q) {
				t.Fatal("DNS/pre-match changed network condition")
			}
		})
	}
}

func TestDNSNetworkValidation(t *testing.T) {
	for _, condition := range []string{
		`"dns_server_address":{"missing":"192.0.2.0/24"}`,
		`"dns_server_address":{"local":"bad-prefix"}`,
		`"dns_server_address":{"":"192.0.2.53"}`,
	} {
		data := []byte(`{"dns":{"servers":[{"type":"local","tag":"local"}]},"route":{"rules":[{` + condition + `,"action":"reject"}]}}`)
		if _, err := Parse(data); err == nil {
			t.Fatal("invalid condition accepted", condition)
		}
	}
	if _, err := Parse([]byte(`{"dns":{"servers":[{"type":"udp","tag":"static","server":"192.0.2.53"}]},"route":{"rules":[{"dns_server_address":{"static":"192.0.2.0/24"},"action":"reject"}]}}`)); err == nil {
		t.Fatal("static DNS transport accepted as discovered configuration")
	}
	for _, rules := range [][]Rule{{{DNSSearchDomain: map[string][]string{"local": {"example"}}}}, {{Type: "logical", Mode: "and", Rules: []Rule{{DNSServerAddress: map[string][]string{"local": {"192.0.2.53"}}}}}}} {
		if _, err := compileRuleSet(rules); err == nil {
			t.Fatal("network condition accepted in headless rules")
		}
	}
}

func TestDNSNetworkRuntime(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "local", Tag: "local"}, {Type: "hosts", Tag: "fallback", Predefined: map[string][]string{"network.test": {"192.0.2.8"}}}}, Final: "fallback", Rules: []DNSRule{{Rule: Rule{DNSSearchDomain: map[string][]string{"local": {"corp.example"}}, Action: "predefined"}, Answer: []string{"network.test. 60 IN A 192.0.2.9"}}}}, Route: Route{Rules: []Rule{{DNSServerAddress: map[string][]string{"local": {"192.0.2.0/24"}}, Action: "reject"}}}})
	var reads atomic.Int32
	r.resolver.localNetwork.read = func() dnsNetworkState {
		reads.Add(1)
		return dnsNetworkState{addresses: []netip.Addr{netip.MustParseAddr("192.0.2.53")}, domains: []string{"corp.example"}}
	}
	q, _ := makeDNSQuery("network.test", 1)
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			for range 20 {
				reply, err := r.ExchangeDNS(context.Background(), q, "")
				ips, _, parseErr := parseDNSReply(q, reply)
				if err != nil || parseErr != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
					t.Error("network policy", err, parseErr, ips)
				}
			}
		})
	}
	workers.Wait()
	if reads.Load() != 1 {
		t.Fatal("discovery repeated per query", reads.Load())
	}
	if _, err := r.Dial(context.Background(), "tcp", "192.0.2.100:80"); !errors.Is(err, ErrRejected) {
		t.Fatal("route ignored discovered DNS", err)
	}
	metadata := Metadata{DNSServerAddress: map[string][]netip.Addr{"local": {}}, DNSSearchDomain: map[string][]string{"local": {}}}
	reply, err := r.ExchangeDNS(WithMetadata(context.Background(), metadata), q, "")
	ips, _, parseErr := parseDNSReply(q, reply)
	if err != nil || parseErr != nil || len(ips) != 1 || ips[0].String() != "192.0.2.8" || len(metadata.DNSServerAddress["local"]) != 0 {
		t.Fatal("explicit empty snapshot ignored or mutated", err, parseErr, ips)
	}
	r.resolver.localNetwork.mu.Lock()
	r.resolver.localNetwork.read = func() dnsNetworkState { return dnsNetworkState{} }
	r.resolver.localNetwork.mu.Unlock()
	r.resolver.localNetwork.invalidate()
	reply, err = r.ExchangeDNS(context.Background(), q, "")
	ips, _, parseErr = parseDNSReply(q, reply)
	if err != nil || parseErr != nil || len(ips) != 1 || ips[0].String() != "192.0.2.8" {
		t.Fatal("withdrew system configuration but retained match", err, parseErr, ips)
	}
	cache := &r.resolver.localNetwork
	cache.mu.Lock()
	cache.next = time.Now().Add(-time.Second)
	cache.mu.Unlock()
	_ = cache.snapshot()
}

func TestDNSNetworkMasque(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			config := masqueTestDNS("192.0.2.53:53", "")
			in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, TLS: certificate(t), Users: []User{{Username: "client", Password: "private"}}, MasqueOptions: MasqueOptions{DNS: []MasqueDNSConfiguration{config}}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Tag, out.HTTPVersion, out.AcceptDNS = "proxy", version, true
			out.Mode = "ip"
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}, DNS: DNSConfig{Servers: []DNSServer{{Type: "masque", Tag: "assigned", Endpoint: "proxy"}, {Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"network.test": {"192.0.2.8"}}}}, Final: "hosts", Rules: []DNSRule{{Rule: Rule{Action: "predefined", DNSServerAddress: map[string][]string{"assigned": {"192.0.2.0/24"}}, DNSSearchDomain: map[string][]string{"assigned": {"corp.example"}}}, Answer: []string{"network.test. 60 IN A 192.0.2.9"}}}}, Route: Route{Rules: []Rule{{DNSServerAddress: map[string][]string{"assigned": {"192.0.2.53"}}, Action: "reject"}}}})
			if ips := masqueDNSQuery(t, client, "network.test", 1); len(ips) != 1 || ips[0].String() != "192.0.2.8" {
				t.Fatal("unconnected metadata", ips)
			}
			state := masqueWaitNetwork(t, client, true, false)
			// Session establishment holds this mutex during I/O; metadata must not.
			client.masqueClients["proxy"].mu.Lock()
			read := make(chan dnsNetworkState, 1)
			go func() { read <- client.resolver.dnsNetwork("assigned") }()
			select {
			case got := <-read:
				if len(got.addresses) != 1 {
					t.Error("missing connected snapshot")
				}
			case <-time.After(time.Second):
				t.Error("metadata blocked behind endpoint I/O")
			}
			client.masqueClients["proxy"].mu.Unlock()
			if ips := masqueDNSQuery(t, client, "network.test", 1); len(ips) != 1 || ips[0].String() != "192.0.2.9" {
				t.Fatal("assigned metadata", ips)
			}
			if _, err := client.Dial(context.Background(), "tcp", "192.0.2.100:80"); !errors.Is(err, ErrRejected) {
				t.Fatal("route metadata", err)
			}
			if err := server.PublishMasqueConfiguration(context.Background(), "server", nil, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := client.WaitMasqueConfiguration(ctx, "proxy", state.Version); err != nil {
				t.Fatal(err)
			}
			if ips := masqueDNSQuery(t, client, "network.test", 1); len(ips) != 1 || ips[0].String() != "192.0.2.8" {
				t.Fatal("withdrawn metadata", ips)
			}
			client.masqueClients["proxy"].reset()
			if got := client.resolver.dnsNetwork("assigned"); len(got.addresses)+len(got.domains) != 0 {
				t.Fatal("closed session metadata retained")
			}
		})
	}
}

func TestDNSNetworkLocalCache(t *testing.T) {
	backend := func(text string) *Runtime {
		return newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: "127.0.0.1"}}, DNS: DNSConfig{Rules: []DNSRule{{Rule: Rule{Action: "predefined"}, Answer: []string{`network.test. 300 IN TXT "` + text + `"`}}}}})
	}
	one, two := backend("first"), backend("second")
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "local", Tag: "local"}}}})
	query, _ := makeDNSQuery("network.test", 16)
	for _, tc := range []struct{ server, text string }{{one.Address("dns"), "first"}, {two.Address("dns"), "second"}} {
		r.resolver.mu.Lock()
		r.resolver.systemServers = []string{tc.server}
		r.resolver.mu.Unlock()
		for range 2 {
			reply, err := r.ExchangeDNS(context.Background(), query, "")
			if err != nil {
				t.Fatal(err)
			}
			rr, err := dnsRecords(reply)
			if err != nil || len(rr[0]) != 1 || string(rr[0][0].data[1:]) != tc.text {
				t.Fatal("cache reused across system DNS change", rr, err)
			}
		}
	}
	cache := dnsNetworkCache{read: func() dnsNetworkState { return dnsNetworkState{domains: []string{"one.example"}} }}
	a := cache.snapshot()
	cache.mu.Lock()
	cache.read = func() dnsNetworkState { return dnsNetworkState{domains: []string{"two.example"}} }
	cache.mu.Unlock()
	cache.invalidate()
	b := cache.snapshot()
	if a.key == b.key || a.domains[0] != "one.example" {
		t.Fatal("search domain cache isolation or immutable snapshot")
	}
}

func TestDNSNetworkSystemWire(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "local", Tag: "local"}}}})
	r.resolver.localNetwork.read = func() dnsNetworkState {
		return dnsNetworkState{servers: []string{"192.0.2.1:53", "[2001:db8::53]:53"}, addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::53")}}
	}
	var calls atomic.Int32
	var workers sync.WaitGroup
	r.resolver.tunnelDial = func(ctx context.Context, server DNSServer, network string) (net.Conn, error) {
		calls.Add(1)
		a, b := net.Pipe()
		workers.Go(func() {
			defer b.Close()
			if server.Server == "192.0.2.1" {
				io.Copy(io.Discard, b) // A silent nameserver must leave time for the next one.
				return
			}
			if server.Server != "2001:db8::53" || network != "udp" || server.ServerPort != 53 {
				t.Error("incorrect discovered DNS endpoint", server, network)
				return
			}
			query := make([]byte, 4096)
			n, err := b.Read(query)
			if err != nil {
				t.Error(err)
				return
			}
			reply, err := predefinedDNS(query[:n], DNSRule{Answer: []string{`network.test. 60 IN TXT "discovered DNS"`}})
			if err != nil {
				t.Error(err)
				return
			}
			b.Write(reply)
		})
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	query, _ := makeDNSQuery("network.test", 16)
	reply, err := r.ExchangeDNS(ctx, query, "")
	workers.Wait()
	rr, parseErr := dnsRecords(reply)
	if err != nil || parseErr != nil || len(rr[0]) != 1 || calls.Load() != 2 {
		t.Fatal("discovered DNS wire/failover", err, parseErr, calls.Load())
	}
}

func FuzzDNSNetwork(f *testing.F) {
	f.Add([]byte("nameserver 192.0.2.53\nsearch corp.example\n"), false)
	f.Add([]byte("nameserver[0] : 2001:db8::53\nsearch domain[0] : corp.example\n"), true)
	f.Fuzz(func(t *testing.T, b []byte, scutil bool) {
		s := parseDNSNetwork(strings.NewReader(string(b)), scutil)
		for _, ip := range s.addresses {
			if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() {
				t.Fatal(ip)
			}
		}
		for _, name := range s.domains {
			if !masqueDomain(name, false) || name != canonicalDomain(name) {
				t.Fatal(name)
			}
		}
	})
}
