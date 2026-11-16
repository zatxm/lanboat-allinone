package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOpenConnectDNSHeaders(t *testing.T) {
	if h := (OpenConnectOptions{SearchDomains: []string{"corp.test", "lab.test"}}).dnsHeaders(); len(h["X-CSTP-Default-Domain"]) != 1 || h["X-CSTP-Default-Domain"][0] != "corp.test lab.test" {
		t.Fatal("search domains must share one space-delimited header", h)
	}
	h := http.Header{"X-CSTP-DNS": {"192.0.2.53", "2001:db8::53", "192.0.2.53"}, "X-CSTP-Default-Domain": {"CORP.test. lab.test"}, "X-CSTP-Split-DNS": {"private.test,.branch.test", "private.test"}, "X-CSTP-Tunnel-All-DNS": {"true"}}
	c, err := ocParseDNS(h)
	if err != nil || len(c.servers) != 2 || !slices.Equal(c.search, []string{"corp.test", "lab.test"}) || !slices.Equal(c.split, []string{"private.test", "branch.test"}) || !c.all {
		t.Fatal(c, err)
	}
	for _, host := range []string{"corp.test", "sub.corp.test", "host.private.test", "branch.test"} {
		if !c.matches(host) {
			t.Fatal("domain did not match", host)
		}
	}
	for _, host := range []string{"notprivate.test", "private.test.evil", "external.test"} {
		if c.matches(host) {
			t.Fatal("suffix boundary ignored", host)
		}
	}
	for _, h := range []http.Header{
		{"X-CSTP-DNS": {"bad"}}, {"X-CSTP-DNS": {"0.0.0.0"}}, {"X-CSTP-DNS": {"ff02::1"}}, {"X-CSTP-DNS": {"::ffff:192.0.2.53"}}, {"X-CSTP-DNS": {"fe80::1%eth0"}},
		{"X-CSTP-Default-Domain": {"bad..test"}}, {"X-CSTP-Split-DNS": {"corp.test\r\nX-Test: a"}}, {"X-CSTP-Split-DNS": {"*.test"}}, {"X-CSTP-Tunnel-All-DNS": {"maybe"}},
	} {
		if _, err := ocParseDNS(h); err == nil {
			t.Fatal("invalid DNS configuration accepted", h)
		}
	}
	for _, name := range []string{"X-CSTP-DNS", "X-CSTP-Split-DNS", "X-CSTP-Default-Domain"} {
		var values []string
		for i := range 129 {
			v := fmt.Sprintf("d%d.test", i)
			if name == "X-CSTP-DNS" {
				v = fmt.Sprintf("192.0.2.%d", i+1)
			}
			values = append(values, v)
		}
		if _, err := ocParseDNS(http.Header{name: values}); err == nil {
			t.Fatal("accepted oversized DNS configuration", name)
		}
	}
}

// Both listeners share the port and serve real DNS wire messages. The VPN
// server rewrites port53 to this fixture, so the host never needs port53.
func ocDNSFixture(t *testing.T, fixedPort ...uint16) (uint16, func() []string) {
	t.Helper()
	host, portText := "127.0.0.1", "0"
	if len(fixedPort) > 0 {
		host, portText = "", fmt.Sprint(fixedPort[0])
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, portText))
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	udp, err := net.ListenPacket("udp", portAddress(host, port))
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); udp.Close() })
	var mu sync.Mutex
	var seen []string
	answer := func(q []byte, network string) []byte {
		host, end, _, err := dnsQuestion(q)
		if err != nil {
			return nil
		}
		mu.Lock()
		seen = append(seen, network+":"+host)
		mu.Unlock()
		if host == "silent.corp.test" {
			return nil
		}
		if strings.HasPrefix(host, "trunc.") && network == "udp" {
			b := dnsResponse(q, end, nil, 0, 0)
			b[2] |= 2
			return b
		}
		if host == "host.corp.test" || strings.HasPrefix(host, "missing.") {
			return dnsResponse(q, end, nil, 0, 3)
		}
		var records []string
		_, _, typ, _ := dnsQuestion(q)
		switch typ {
		case 1:
			records = []string{host + ". 60 IN A 192.0.2.42"}
		case 28:
			records = []string{host + ". 60 IN AAAA 2001:db8::42"}
		case 16:
			records = []string{host + `. 60 IN TXT "private-value"`}
		case 15:
			records = []string{host + ". 60 IN MX 10 mail.lab.test."}
		}
		b, _ := predefinedDNS(q, DNSRule{Answer: records})
		return b
	}
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			if reply := answer(b[:n], "udp"); reply != nil {
				udp.WriteTo(reply, a)
			}
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(c, size[:]); err != nil {
					return
				}
				q := make([]byte, int(binary.BigEndian.Uint16(size[:])))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				if reply := answer(q, "tcp"); reply != nil {
					writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(reply))))
					writeAll(c, reply)
				}
			}()
		}
	}()
	return port, func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(seen) }
}

func ocDNSPair(t *testing.T, options OpenConnectOptions, dtls bool, servers []DNSServer, rules []DNSRule) (*Runtime, *Runtime, func() []string) {
	t.Helper()
	port, seen := ocDNSFixture(t)
	options.DisableDTLS = !dtls
	in := Inbound{Type: "openconnect", Tag: "vpn", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Username: "u", Password: "p"}}, OpenConnectOptions: options}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Rules: []Rule{{IPCIDR: []string{"192.0.2.1/32"}, Action: "reject", Method: "drop"}, {Port: []uint16{53}, OverrideAddress: "127.0.0.1", OverridePort: port, Outbound: "direct"}}}})
	h, p, _ := net.SplitHostPort(s.Address("vpn"))
	var n uint16
	fmt.Sscan(p, &n)
	client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "vpn", Server: h, ServerPort: n, Username: "u", Password: "p", TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: OpenConnectOptions{DisableDTLS: !dtls}}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny"}, DNS: DNSConfig{Servers: servers, Rules: rules, Timeout: "2s"}})
	return s, client, seen
}

func ocDNSQuery(t *testing.T, r *resolver, host string, typ uint16, code byte) []byte {
	t.Helper()
	q, err := makeDNSQuery(host, typ)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.exchangePolicy(context.Background(), q, false)
	if err != nil {
		t.Fatal(host, err)
	}
	if _, _, _, err = validateDNSQuestionResponse(q, b); err != nil || b[3]&15 != code {
		t.Fatalf("%s response: %x %v", host, b, err)
	}
	return b
}

func TestOpenConnectDNSIndependent(t *testing.T) {
	for _, dtls := range []bool{false, true} {
		t.Run(fmt.Sprintf("dtls=%v", dtls), func(t *testing.T) {
			_, c, seen := ocDNSPair(t, OpenConnectOptions{DNS: []string{"192.0.2.53", "2001:db8::53"}, SearchDomains: []string{"corp.test", "lab.test"}, SplitDNS: []string{"private.test"}}, dtls, []DNSServer{{Type: "openconnect", Tag: "dns", Endpoint: "vpn", AcceptDefaultResolvers: true, AcceptSearchDomain: true}}, nil)
			if dtls {
				tunnel, err := c.ocClients["vpn"].session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				ocWaitDTLS(t, tunnel)
			}
			for _, host := range []string{"www.corp.test", "sub.private.test", "trunc.corp.test"} {
				ocDNSQuery(t, c.resolver, host, 1, 0)
			}
			for _, host := range []string{"external.test", "notprivate.test", "private.test.evil"} {
				ocDNSQuery(t, c.resolver, host, 1, 3)
			}
			for _, typ := range []uint16{1, 28, 16, 15} {
				b := ocDNSQuery(t, c.resolver, "host", typ, 0)
				rr, err := dnsRecords(b)
				if err != nil || len(rr[0]) != 2 || rr[0][0].typ != 5 || rr[0][1].typ != typ {
					t.Fatal("expanded search response", rr, err)
				}
			}
			ocDNSQuery(t, c.resolver, "missing", 1, 3)
			queries := seen()
			if !slices.Contains(queries, "tcp:trunc.corp.test") || slices.Contains(queries, "udp:external.test") || slices.Contains(queries, "udp:missing") {
				t.Fatal("DNS routing/fallback", queries)
			}
		})
	}
}

func TestOpenConnectDNSDefaultResolvers(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		accept, all, split, search bool
		code                       byte
	}{
		{"no-opt-in", false, false, false, false, 3}, {"default", true, false, false, false, 0}, {"split-only", true, false, true, false, 3}, {"search-only", true, false, false, true, 3}, {"all-opt-in", true, true, true, true, 0}, {"all-without-opt-in", false, true, true, true, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := OpenConnectOptions{DNS: []string{"192.0.2.53"}, TunnelAllDNS: tc.all}
			if tc.split {
				o.SplitDNS = []string{"corp.test"}
			}
			if tc.search {
				o.SearchDomains = []string{"corp.test"}
			}
			_, c, seen := ocDNSPair(t, o, false, []DNSServer{{Type: "openconnect", Tag: "dns", Endpoint: "vpn", AcceptDefaultResolvers: tc.accept}}, nil)
			ocDNSQuery(t, c.resolver, "external.test", 1, tc.code)
			if (len(seen()) > 0) != (tc.code == 0) {
				t.Fatal("unexpected upstream query", seen())
			}
		})
	}
}

func TestOpenConnectDNSCacheAndNetwork(t *testing.T) {
	_, c, seen := ocDNSPair(t, OpenConnectOptions{DNS: []string{"192.0.2.53"}, SearchDomains: []string{"corp.test"}}, false, []DNSServer{{Type: "openconnect", Tag: "dns", Endpoint: "vpn"}}, nil)
	if s := c.resolver.dnsNetwork("dns"); len(s.addresses)+len(s.domains) > 0 {
		t.Fatal("metadata opened tunnel")
	}
	ocDNSQuery(t, c.resolver, "www.corp.test", 1, 0)
	count := len(seen())
	ocDNSQuery(t, c.resolver, "www.corp.test", 1, 0)
	if len(seen()) != count {
		t.Fatal("cache did not coalesce")
	}
	c.ocClients["vpn"].gate <- struct{}{}
	done := make(chan dnsNetworkState, 1)
	go func() { done <- c.resolver.dnsNetwork("dns") }()
	select {
	case s := <-done:
		if len(s.addresses) != 1 || s.addresses[0].String() != "192.0.2.53" || !slices.Equal(s.domains, []string{"corp.test"}) {
			t.Error(s)
		}
	case <-time.After(time.Second):
		t.Error("metadata blocked behind reconnect")
	}
	q, _ := makeDNSQuery("www.corp.test", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	if _, err := c.resolver.exchangePolicy(ctx, q, false); err == nil {
		t.Error("blocked handshake ignored query cancellation")
	}
	cancel()
	<-c.ocClients["vpn"].gate
	c.resetNetworkTransports()
	if s := c.resolver.dnsNetwork("dns"); len(s.addresses)+len(s.domains) > 0 {
		t.Fatal("closed tunnel retained metadata")
	}
	ocDNSQuery(t, c.resolver, "www.corp.test", 1, 0)
	if len(seen()) != count+1 {
		t.Fatal("reconnect reused prior DNS cache", seen())
	}
	q, _ = makeDNSQuery("silent.corp.test", 1)
	ctx, cancel = context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, err := c.resolver.exchangePolicy(ctx, q, false); err == nil {
		t.Fatal("silent DNS server ignored cancellation")
	}
}

func TestOpenConnectDNSPreferences(t *testing.T) {
	servers := []DNSServer{{Type: "hosts", Tag: "public", Predefined: map[string][]string{"external.test": {"192.0.2.99"}}}, {Type: "openconnect", Tag: "vpn-dns", Endpoint: "vpn", AcceptSearchDomain: true}}
	rules := []DNSRule{{Rule: Rule{PreferredBy: []string{"vpn-dns"}}, Server: "vpn-dns"}, {Rule: Rule{PreferredBy: []string{"public"}}, Server: "public"}}
	s, c, seen := ocDNSPair(t, OpenConnectOptions{DNS: []string{"192.0.2.53"}, SearchDomains: []string{"corp.test", "lab.test"}, SplitDNS: []string{"private.test"}}, false, servers, rules)
	for _, host := range []string{"www.corp.test", "host.private.test", "host"} {
		ocDNSQuery(t, c.resolver, host, 1, 0)
	}
	b := ocDNSQuery(t, c.resolver, "external.test", 1, 0)
	q, _ := makeDNSQuery("external.test", 1)
	copy(q[:2], b[:2])
	ips, _, err := parseDNSReply(q, b)
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.99" {
		t.Fatal(ips, err)
	}
	if slices.Contains(seen(), "udp:external.test") {
		t.Fatal("public domain sent through split DNS")
	}
	// A lost VPN must not let even a cached private answer bypass authentication.
	s.Close()
	c.ocClients["vpn"].tunnel.Load().close()
	q, _ = makeDNSQuery("www.corp.test", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := c.resolver.exchangePolicy(ctx, q, false); err == nil {
		t.Fatal("closed tunnel returned cached private DNS")
	}
}

func TestOpenConnectDNSFailover(t *testing.T) {
	for _, servers := range [][]string{{"2001:db8::53"}, {"192.0.2.1", "2001:db8::53"}} {
		_, c, seen := ocDNSPair(t, OpenConnectOptions{DNS: servers, SplitDNS: []string{"corp.test"}}, false, []DNSServer{{Type: "openconnect", Tag: "dns", Endpoint: "vpn"}}, nil)
		q, _ := makeDNSQuery("www.corp.test", 1)
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		b, err := c.resolver.exchangePolicy(ctx, q, false)
		cancel()
		if err != nil {
			t.Fatal(servers, err)
		}
		if _, _, _, err := validateDNSQuestionResponse(q, b); err != nil || !slices.Contains(seen(), "udp:www.corp.test") {
			t.Fatal(err, seen())
		}
	}
}

func TestOpenConnectDNSValidation(t *testing.T) {
	base := `{"outbounds":[{"type":"openconnect","tag":"vpn","server":"vpn.test","server_port":443,"username":"u","password":"p","tls":{"enabled":true}}],"dns":{"servers":[{"type":"openconnect","tag":"dns","endpoint":"vpn","accept_default_resolvers":true,"accept_search_domain":true}]}}`
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		strings.Replace(base, `"endpoint":"vpn"`, `"endpoint":"missing"`, 1),
		strings.Replace(base, `"endpoint":"vpn"`, `"endpoint":"vpn","server":"192.0.2.53"`, 1),
		strings.Replace(base, `"endpoint":"vpn"`, `"endpoint":"vpn","detour":"vpn"`, 1),
		strings.Replace(base, `"endpoint":"vpn"`, `"endpoint":"vpn","tls":{"insecure":true}`, 1),
		strings.Replace(base, `"server":"vpn.test"`, `"server":"vpn.test","domain_resolver":"dns"`, 1),
		strings.Replace(base, `"server":"vpn.test"`, `"server":"vpn.test","dns":["192.0.2.53"]`, 1),
		`{"dns":{"servers":[{"type":"hosts","tag":"h","accept_search_domain":true}]}}`,
		`{"dns":{"rules":[{"preferred_by":"unknown","action":"reject"}]}}`,
		`{"route":{"rules":[{"preferred_by":"unknown","action":"reject"}]}}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("invalid DNS configuration accepted", bad)
		}
	}
	if _, err := compileRuleSet([]Rule{{PreferredBy: []string{"dns"}}}); err == nil {
		t.Fatal("preferred_by allowed in headless rule set")
	}
	if _, err := newResolver(DNSConfig{Servers: []DNSServer{{Type: "openconnect", Tag: "dns", Endpoint: "vpn"}}}); err == nil {
		t.Fatal("DNS transport allowed without runtime")
	}
	in := Inbound{Type: "openconnect", Tag: "vpn", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Username: "u", Password: "p"}}, OpenConnectOptions: OpenConnectOptions{DNS: []string{"192.0.2.53"}, SearchDomains: []string{"corp.test"}, SplitDNS: []string{"corp.test"}, TunnelAllDNS: true}}
	raw, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
	config, err := Parse(raw)
	if err != nil || !slices.Equal(config.Inbounds[0].OpenConnectOptions.DNS, in.OpenConnectOptions.DNS) {
		t.Fatal("inbound push options did not survive JSON", string(raw), err)
	}
}

func TestOpenConnectDNSSearchWire(t *testing.T) {
	query, _ := makeDNSQuery("host", 1)
	expanded, _ := makeDNSQuery("host.corp.test", 1)
	reply, _ := predefinedDNS(expanded, DNSRule{Answer: []string{"host.corp.test. 300 IN A 192.0.2.42"}, NS: []string{"corp.test. 50 IN SOA ns.corp.test. hostmaster.corp.test. 1 2 3 4 5"}})
	// Preserve OPT's UDP payload class when rebuilding a question of new length.
	binary.BigEndian.PutUint16(reply[10:], 1)
	reply = append(reply, 0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0)
	b, err := ocSearchReply(query, reply, "host.corp.test")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := validateDNSQuestionResponse(query, b); err != nil {
		t.Fatal(err)
	}
	rr, err := dnsRecords(b)
	if err != nil || rr[2][0].class != 4096 || rr[0][0].typ != 5 || rr[1][0].typ != 6 {
		t.Fatal(rr, err)
	}
	ips, _, err := parseDNSReply(query, b)
	if err != nil || !slices.Equal(ips, []netip.Addr{netip.MustParseAddr("192.0.2.42")}) {
		t.Fatal(ips, err)
	}
	// DNS A responses commonly compress owner names back into the question.
	_, end, _, _ := dnsQuestion(expanded)
	compressed := dnsResponse(expanded, end, []netip.Addr{netip.MustParseAddr("192.0.2.43")}, 60, 0)
	b, err = ocSearchReply(query, compressed, "host.corp.test")
	if err != nil {
		t.Fatal(err)
	}
	ips, _, err = parseDNSReply(query, b)
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.43" {
		t.Fatal(ips, err)
	}
}

func FuzzOpenConnectDNS(f *testing.F) {
	f.Add("192.0.2.53", "corp.test lab.test", "private.test")
	f.Add("2001:db8::53", "", "a.test,b.test")
	f.Fuzz(func(t *testing.T, ip, search, split string) {
		if len(ip)+len(search)+len(split) > 65536 {
			return
		}
		c, err := ocParseDNS(http.Header{"X-CSTP-DNS": {ip}, "X-CSTP-Default-Domain": {search}, "X-CSTP-Split-DNS": {split}})
		if err == nil && (len(c.servers) > 128 || len(c.search) > 128 || len(c.split) > 128) {
			t.Fatal("capacity exceeded")
		}
	})
}
