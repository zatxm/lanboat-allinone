package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestModernConfigScalarsAndRemovedGeoIP(t *testing.T) {
	data := []byte(`{"outbounds":[{"type":"direct"}],"dns":{"servers":[{"type":"local"}]},"route":{"rule_set":[{"tag":"inline","rules":[{"domain_suffix":"example.org"}]}],"rules":[{"rule_set":"inline","action":"route","outbound":"outbound-0"}]}}`)
	cfg, e := Parse(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(cfg.Route.Rules[0].RuleSet) != 1 || cfg.DNS.Servers[0].Tag != "dns-0" {
		t.Fatal(cfg)
	}
	for _, route := range []string{`"geoip":{"path":"geoip.db"}`, `"rule_data":{"auto_update":true}`, `"rules":[{"geoip":"cn","outbound":"direct"}]`} {
		if _, e := Parse([]byte(`{"route":{` + route + `}}`)); e == nil {
			t.Fatal("removed geoip/rule_data accepted", route)
		}
	}
}
func TestModernSelectorAndURLTest(t *testing.T) {
	t.Run("selection", func(t *testing.T) {
		echo := tcpEcho(t)
		r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "selector", Tag: "group", Outbounds: []string{"direct", "deny"}, InterruptExistConnections: true}, {Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "group"}})
		c, e := r.Dial(context.Background(), "tcp", echo)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		if _, e = c.Write([]byte("x")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 1)
		if _, e = io.ReadFull(c, b); e != nil {
			t.Fatal(e)
		}
		if e = r.SelectOutbound("group", "deny"); e != nil {
			t.Fatal(e)
		}
		c.SetReadDeadline(time.Now().Add(time.Second))
		if _, e = c.Read(b); e == nil {
			t.Fatal("old inbound connection was not interrupted")
		}
		if _, e = r.Dial(context.Background(), "tcp", echo); e == nil {
			t.Fatal("selector bypassed block")
		}
	})
	t.Run("urltest", func(t *testing.T) {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
		defer target.Close()
		proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			time.Sleep(80 * time.Millisecond)
			up, e := net.Dial("tcp", req.Host)
			if e != nil {
				w.WriteHeader(502)
				return
			}
			defer up.Close()
			conn, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				return
			}
			defer conn.Close()
			io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
			done := make(chan struct{})
			go func() { io.Copy(up, conn); close(done) }()
			io.Copy(conn, up)
			conn.Close()
			<-done
		}))
		defer proxy.Close()
		host, port := splitTestAddress(t, strings.TrimPrefix(proxy.URL, "http://"))
		zero := uint16(0)
		r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "urltest", Tag: "auto", Outbounds: []string{"slow", "fast"}, URL: target.URL, Tolerance: &zero, Interval: "1h"}, {Type: "http", Tag: "slow", Server: host, ServerPort: port}, {Type: "direct", Tag: "fast"}}, Route: Route{Final: "auto"}})
		result, e := r.URLTest(context.Background(), "auto")
		if e != nil {
			t.Fatal(e)
		}
		selected, _ := r.SelectedOutbound("auto")
		if len(result) != 2 || selected != "fast" {
			t.Fatal(result, selected)
		}
	})
	t.Run("cycle", func(t *testing.T) {
		_, e := Parse([]byte(`{"outbounds":[{"type":"selector","tag":"a","outbounds":["b"]},{"type":"selector","tag":"b","outbounds":["a"]}]}`))
		if e == nil {
			t.Fatal("group cycle accepted")
		}
	})
}
func splitTestAddress(t *testing.T, address string) (string, uint16) {
	t.Helper()
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		t.Fatal(e)
	}
	p, e := net.LookupPort("tcp", port)
	if e != nil {
		t.Fatal(e)
	}
	return host, uint16(p)
}
func TestModernRouteActionsAndSniff(t *testing.T) {
	echo := tcpEcho(t)
	host, port := splitTestAddress(t, echo)
	rules := []Rule{{Action: "sniff", Sniffer: []string{"http"}}, {Domain: []string{"route.test"}, Action: "route-options", OverrideAddress: host, OverridePort: port}, {Domain: []string{"route.test"}, Outbound: "direct"}, {Action: "reject"}}
	r := newTestRuntime(t, Config{Route: Route{Rules: rules}})
	c, e := r.Dial(context.Background(), "tcp", "192.0.2.99:1")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	want := []byte("GET / HTTP/1.1\r\nHost: route.test\r\n\r\n")
	if _, e = c.Write(want); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(want))
	if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, want) {
		t.Fatal(e, string(got))
	}
	c2, e := r.Dial(context.Background(), "tcp", echo)
	if e != nil {
		t.Fatal(e)
	}
	defer c2.Close()
	if _, e = c2.Write([]byte("GET / HTTP/1.1\r\nHost: rejected.test\r\n\r\n")); e == nil {
		t.Fatal("sniff policy bypassed")
	}
	t.Run("resolve", func(t *testing.T) {
		r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"route.test": {host}}}}}, Route: Route{Rules: []Rule{{Action: "resolve", Server: "hosts", Strategy: "ipv4_only"}, {Action: "route-options", OverridePort: port}, {IPCIDR: []string{host + "/32"}, Outbound: "direct"}, {Action: "reject"}}}})
		c, e := r.Dial(context.Background(), "tcp", "route.test:1")
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
	})
	t.Run("dns-hijack", func(t *testing.T) {
		r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"dns.test": {"192.0.2.7"}}}}}, Route: Route{Rules: []Rule{{Port: []uint16{53}, Action: "hijack-dns"}}}})
		c, e := r.Dial(context.Background(), "tcp", "192.0.2.1:53")
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		query, _ := makeDNSQuery("dns.test", 1)
		if e = writeAll(c, append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)); e != nil {
			t.Fatal(e)
		}
		var size [2]byte
		if _, e = io.ReadFull(c, size[:]); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, binary.BigEndian.Uint16(size[:]))
		io.ReadFull(c, reply)
		ips, _, e := parseDNSReply(query, reply)
		if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.7" {
			t.Fatal(ips, e)
		}
	})
}
func TestModernDNSActions(t *testing.T) {
	cfg := Config{DNS: DNSConfig{ReverseMapping: true, Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"modern.test": {"10.0.0.7"}}}}, Rules: []DNSRule{{Rule: Rule{Domain: []string{"txt.test"}, Action: "predefined"}, Answer: []string{`txt.test. 60 IN TXT "hello world"`}}, {Rule: Rule{Action: "evaluate"}, Server: "hosts", Tag: "candidate"}, {Rule: Rule{MatchResponse: "candidate", IPCIDR: []string{"10.0.0.0/8"}, Action: "respond"}}}}}
	r := newTestRuntime(t, cfg)
	query, _ := makeDNSQuery("txt.test", 16)
	reply, e := r.ExchangeDNS(context.Background(), query, "")
	if e != nil {
		t.Fatal(e)
	}
	sections, e := dnsRecords(reply)
	if e != nil || len(sections[0]) != 1 || string(sections[0][0].data) != "\x0bhello world" {
		t.Fatal(sections, e)
	}
	query, _ = makeDNSQuery("modern.test", 1)
	reply, e = r.ExchangeDNS(context.Background(), query, "")
	if e != nil {
		t.Fatal(e)
	}
	ips, _, e := parseDNSReply(query, reply)
	if e != nil || len(ips) != 1 || ips[0].String() != "10.0.0.7" {
		t.Fatal(ips, e)
	}
}
func TestModernDNSWireCacheECSAndOptimistic(t *testing.T) {
	var calls atomic.Int32
	var validECS atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		query, _ := io.ReadAll(req.Body)
		sections, e := dnsRecords(query)
		if e == nil && len(sections[2]) == 1 && bytes.Contains(sections[2][0].data, []byte{0, 8, 0, 7, 0, 1, 24, 0, 192, 0, 2}) {
			validECS.Store(true)
		}
		_, end, _, _ := dnsQuestion(query)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(dnsResponse(query, end, []netip.Addr{netip.MustParseAddr("192.0.2.7")}, 1, 0))
	}))
	defer server.Close()
	host, port := splitTestAddress(t, strings.TrimPrefix(server.URL, "https://"))
	r := newTestRuntime(t, Config{DNS: DNSConfig{ClientSubnet: "192.0.2.0/24", Optimistic: optimisticOptions{Enabled: true}, Servers: []DNSServer{{Type: "https", Tag: "secure", Server: host, ServerPort: port, TLS: TLSOptions{Insecure: true}}}}})
	query, _ := makeDNSQuery("cache.test", 1)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := append([]byte(nil), query...)
			binary.BigEndian.PutUint16(q, uint16(i))
			reply, e := r.ExchangeDNS(context.Background(), q, "")
			if e != nil || binary.BigEndian.Uint16(reply) != uint16(i) {
				t.Errorf("identity %d: %v", i, e)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || !validECS.Load() {
		t.Fatal("coalescing/ECS", calls.Load(), validECS.Load())
	}
	r.resolver.mu.Lock()
	for _, element := range r.resolver.wireCache {
		entry := element.Value.(*dnsWireEntry)
		entry.until = time.Now().Add(-time.Second)
		entry.inserted = time.Now().Add(-2 * time.Second)
	}
	r.resolver.mu.Unlock()
	if _, e := r.ExchangeDNS(context.Background(), query, ""); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() != 2 {
		t.Fatal("optimistic did not refresh", calls.Load())
	}
}
func TestModernSRS15FixturesAndAdGuard(t *testing.T) {
	fields := []string{"process_name", "process_path", "process_path_regex", "package_name", "package_name_regex", "wifi_ssid", "wifi_bssid", "network_type", "network_is_expensive", "network_is_constrained", "network_interface_address", "default_interface_address"}
	for _, name := range fields {
		t.Run(name, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join("testdata/srs15", name+".srs"))
			if e != nil {
				t.Fatal(e)
			}
			rules, e := readSRS(b)
			if e != nil {
				t.Fatal(e)
			}
			snap, e := compileRuleSet(rules)
			if e != nil {
				t.Fatal(e)
			}
			q := request{network: "tcp", address: "example.org:443", metadata: Metadata{ProcessName: "curl", ProcessPath: "/bin/curl", PackageName: "com.test", NetworkType: "wifi", WiFiSSID: "wifi", WiFiBSSID: "00:11:22:33:44:55", NetworkIsExpensive: true, NetworkIsConstrained: true, NetworkInterfaceAddress: map[string][]netip.Addr{"wifi": {netip.MustParseAddr("192.0.2.1")}}, DefaultInterfaceAddress: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}}
			if !snap.rules[0].matches(q) {
				t.Fatal("reference SRS did not match metadata")
			}
		})
	}
	for _, name := range []string{"adguard-suffix", "adguard-wildcard", "adguard-except", "adguard-regex"} {
		t.Run(name, func(t *testing.T) {
			b, e := os.ReadFile(filepath.Join("testdata/srs15", name+".srs"))
			if e != nil {
				t.Fatal(e)
			}
			rules, e := readSRS(b)
			if e != nil {
				t.Fatal(e)
			}
			snap, e := compileRuleSet(rules)
			if e != nil {
				t.Fatal(e)
			}
			domain := map[string]string{"adguard-suffix": "ads.example", "adguard-wildcard": "adserver.example", "adguard-except": "bad.example.com", "adguard-regex": "ads12.example"}[name]
			q := request{address: domain + ":443"}
			if !snap.rules[0].matches(q) {
				t.Fatal("official AdGuard fixture did not match", domain)
			}
		})
	}
	rules, e := ConvertAdGuard([]byte("||example.com^\n@@||safe.example.com^\n||ads*.example^\n"))
	if e != nil {
		t.Fatal(e)
	}
	snap, e := compileRuleSet(rules)
	if e != nil {
		t.Fatal(e)
	}
	for host, want := range map[string]bool{"bad.example.com": true, "safe.example.com": false, "ads1.example": true, "other.test": false} {
		got := false
		for _, r := range snap.rules {
			got = got || r.matches(request{address: host + ":443"})
		}
		if got != want {
			t.Fatal(host, got, want)
		}
	}
}
func TestModernSRSCompilerOfficial15(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		reference = "../.cache/sing-box-1.15.0-alpha.13/sing-box"
	}
	if _, e := os.Stat(reference); e != nil {
		t.Fatal("sing-box1.15 reference required", e)
	}
	source := []byte(`{"version":5,"rules":[{"domain_suffix":"example.org","ip_cidr":["192.0.2.0/24","2001:db8::/32"],"package_name_regex":"com.*","network_interface_address":{"wifi":"192.0.2.0/24"}}]}`)
	data, e := CompileRuleSet(source, "source")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.srs")
	os.WriteFile(path, data, 0600)
	output, e := exec.Command(reference, "rule-set", "decompile", "-o", filepath.Join(dir, "rules.json"), path).CombinedOutput()
	if e != nil {
		t.Fatal(e, string(output))
	}
	var decoded struct {
		Version int    `json:"version"`
		Rules   []Rule `json:"rules"`
	}
	b, _ := os.ReadFile(filepath.Join(dir, "rules.json"))
	if e = decodeOptions(b, &decoded); e != nil || len(decoded.Rules) != 1 || len(decoded.Rules[0].PackageNameRegex) != 1 {
		t.Fatal(string(b), e)
	}
}

func tcpEcho(t *testing.T) string {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

func TestModernRuleSetHTTPAndLocalReload(t *testing.T) {
	t.Run("credential-isolation", func(t *testing.T) {
		var leaked atomic.Bool
		dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
			if q.Header.Get("X-API-Key") != "" {
				leaked.Store(true)
			}
			io.WriteString(w, `{"version":5,"rules":[{"domain":"remote.test"}]}`)
		}))
		defer dest.Close()
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { http.Redirect(w, q, dest.URL, 302) }))
		defer origin.Close()
		headers := map[string]headerValues{"X-API-Key": {"private"}}
		r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{{Tag: "download", Headers: headers}}, Experimental: ExperimentalOptions{CacheFile: CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "cache.db")}}, Route: Route{RuleSet: []RuleSet{{Type: "remote", Tag: "remote", URL: origin.URL, Format: "source"}}, Rules: []Rule{{Domain: []string{"remote.test"}, Action: "reject"}}}})
		if leaked.Load() {
			t.Fatal("custom credential leaked across origins")
		}
		s := r.config.Route.RuleSet[0]
		first := r.ruleSetCachePath(s)
		r.config.HTTPClients[0].Headers = map[string]headerValues{"X-API-Key": {"another"}}
		second := r.ruleSetCachePath(s)
		if first == second {
			t.Fatal("authenticated rule caches were shared")
		}
		if _, e := os.Stat(first); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("watch-local", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rules.json")
		os.WriteFile(path, []byte(`{"version":5,"rules":[{"domain":"one.test"}]}`), 0600)
		r := newTestRuntime(t, Config{Route: Route{RuleSet: []RuleSet{{Type: "local", Tag: "local", Path: path}}, Rules: []Rule{{RuleSet: []string{"local"}, Action: "reject"}}}})
		if _, e := r.Dial(context.Background(), "tcp", "one.test:443"); e != ErrRejected {
			t.Fatal(e)
		}
		os.WriteFile(path, []byte(`{"version":5,"rules":[{"domain":"two.test"}]}`), 0600)
		deadline := time.Now().Add(3 * time.Second)
		for !r.ruleSets["local"].matches(request{address: "two.test:443"}) && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !r.ruleSets["local"].matches(request{address: "two.test:443"}) {
			t.Fatal("local rule update was not published")
		}
		os.WriteFile(path, []byte("invalid"), 0600)
		time.Sleep(1100 * time.Millisecond)
		if !r.ruleSets["local"].matches(request{address: "two.test:443"}) {
			t.Fatal("bad reload replaced working rules")
		}
	})
}
func TestModernDNSHostsAndFakePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts")
	os.WriteFile(path, []byte("192.0.2.7 from-file.test\n"), 0600)
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", HostsPaths: []string{path}}}}})
	ips, e := r.LookupIP(context.Background(), "from-file.test")
	if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.7" {
		t.Fatal(ips, e)
	}
	cfg := Config{Experimental: ExperimentalOptions{CacheFile: CacheFileOptions{Enabled: true, Path: filepath.Join(t.TempDir(), "cache.db"), StoreFakeIP: true}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "fakeip", Tag: "fake"}}}}
	first := newTestRuntime(t, cfg)
	ips, e = first.LookupIP(context.Background(), "persistent.test")
	if e != nil || len(ips) == 0 {
		t.Fatal(ips, e)
	}
	first.Close()
	second := newTestRuntime(t, cfg)
	for _, ip := range ips {
		host, ok := second.resolver.reverseFake(netip.MustParseAddr(ip.String()))
		if !ok || host != "persistent.test" {
			t.Fatal("FakeIP mapping lost", ip, host)
		}
	}
}

func TestModernUDPRouteSniffAndDialLifetime(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"sniff.test": {"192.0.2.9"}}}}}, Route: Route{Rules: []Rule{{Action: "sniff", Sniffer: []string{"dns"}}, {Protocol: []string{"dns"}, Action: "hijack-dns"}, {Action: "reject"}}}})
	ctx, cancel := context.WithCancel(context.Background())
	conn, e := r.Dial(ctx, "udp", "192.0.2.10:5353")
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	query, _ := makeDNSQuery("sniff.test", 1)
	if _, e = conn.Write(query); e != nil {
		t.Fatal(e)
	}
	reply := make([]byte, 4096)
	n, e := conn.Read(reply)
	if e != nil {
		t.Fatal(e)
	}
	ips, _, e := parseDNSReply(query, reply[:n])
	if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
		t.Fatal(ips, e)
	}
	if _, e = r.Dial(ctx, "tcp", "192.0.2.1:443"); e != context.Canceled {
		t.Fatal("canceled Dial accepted", e)
	}
}

func TestModernTLSAndQUICSniff(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		tls.Client(client, &tls.Config{ServerName: "sniff.example", InsecureSkipVerify: true}).Handshake()
	}()
	var header [5]byte
	if _, e := io.ReadFull(server, header[:]); e != nil {
		t.Fatal(e)
	}
	hello := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, e := io.ReadFull(server, hello); e != nil {
		t.Fatal(e)
	}
	server.Close()
	<-done
	protocol, domain := sniffPacket("tcp", append(header[:], hello...), nil)
	if protocol != "tls" || domain != "sniff.example" {
		t.Fatal(protocol, domain)
	}
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	_, key, e := quicInitialKeys(dcid, false)
	if e != nil {
		t.Fatal(e)
	}
	payload := quicVar([]byte{6, 0}, uint64(len(hello)))
	payload = append(payload, hello...)
	packet := sealQUICPacket(payload, dcid, dcid, nil, 0, 0, false, key)
	protocol, domain = sniffPacket("udp", packet, nil)
	if protocol != "quic" || domain != "sniff.example" {
		t.Fatal(protocol, domain)
	}
	packet[len(packet)-1] ^= 1
	if protocol, _ := sniffPacket("udp", packet, nil); protocol != "" {
		t.Fatal("tampered QUIC classified", protocol)
	}
}

func TestModernSystemDNSNonAddressRecords(t *testing.T) {
	packets, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer packets.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		n, from, e := packets.ReadFrom(b)
		if e != nil {
			return
		}
		reply, e := predefinedDNS(b[:n], DNSRule{Answer: []string{`txt.test. 30 IN TXT "system resolver"`}})
		if e == nil {
			packets.WriteTo(reply, from)
		}
	}()
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "local", Tag: "local"}}}})
	r.resolver.systemServers = []string{packets.LocalAddr().String()}
	query, _ := makeDNSQuery("txt.test", 16)
	reply, e := r.ExchangeDNS(context.Background(), query, "")
	if e != nil {
		t.Fatal(e)
	}
	records, e := dnsRecords(reply)
	if e != nil || len(records[0]) != 1 || string(records[0][0].data) != "\x0fsystem resolver" {
		t.Fatal(records, e)
	}
	<-done
}

func TestModernDNSRecordBoundariesAndFakeTTL(t *testing.T) {
	query, _ := makeDNSQuery("null.test", 15)
	reply, e := predefinedDNS(query, DNSRule{Answer: []string{"null.test. 60 IN MX 0 ."}})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = dnsRecords(reply); e != nil {
		t.Fatal("root-name MX failed", e)
	}
	query, _ = makeDNSQuery("txt.test", 16)
	reply, e = predefinedDNS(query, DNSRule{Answer: []string{`txt.test. 60 IN TXT "two  spaces"`}})
	if e != nil {
		t.Fatal(e)
	}
	records, e := dnsRecords(reply)
	if e != nil || string(records[0][0].data) != "\x0btwo  spaces" {
		t.Fatal(records, e)
	}
	ttl := uint32(1800)
	r := newTestRuntime(t, Config{DNS: DNSConfig{DisableExpire: true, Servers: []DNSServer{{Type: "fakeip", Tag: "fake"}}, Rules: []DNSRule{{Server: "fake", RewriteTTL: &ttl}}}})
	query, _ = makeDNSQuery("lifetime.test", 1)
	reply, e = r.ExchangeDNS(context.Background(), query, "")
	if e != nil {
		t.Fatal(e)
	}
	ips, _, e := parseDNSReply(query, reply)
	if e != nil || len(ips) != 1 {
		t.Fatal(ips, e)
	}
	pool := r.resolver.pools["fake"]
	pool.mu.Lock()
	entry := pool.byIP[ips[0]]
	if time.Until(entry.until) < 30*time.Minute {
		t.Fatal("FakeIP mapping shorter than advertised TTL")
	}
	entry.until = time.Now().Add(-time.Second)
	pool.byIP[ips[0]] = entry
	pool.mu.Unlock()
	if _, e = r.ExchangeDNS(context.Background(), query, ""); e != nil {
		t.Fatal(e)
	}
	if _, ok := r.resolver.reverseFake(ips[0]); !ok {
		t.Fatal("returning a stale FakeIP mapping")
	}
}

func TestModernDNSActionTimeoutOverride(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		time.Sleep(70 * time.Millisecond)
		query, _ := io.ReadAll(q.Body)
		_, end, _, _ := dnsQuestion(query)
		w.Write(dnsResponse(query, end, []netip.Addr{netip.MustParseAddr("192.0.2.7")}, 60, 0))
	}))
	defer server.Close()
	host, port := splitTestAddress(t, strings.TrimPrefix(server.URL, "https://"))
	r := newTestRuntime(t, Config{DNS: DNSConfig{Timeout: "10ms", Servers: []DNSServer{{Type: "https", Tag: "dns", Server: host, ServerPort: port, TLS: TLSOptions{Insecure: true}}}, Rules: []DNSRule{{Rule: Rule{Timeout: "1s"}, Server: "dns"}}}})
	ips, e := r.LookupIP(context.Background(), "timeout.test")
	if e != nil || len(ips) != 1 {
		t.Fatal("action timeout was clamped to the global timeout", ips, e)
	}
}

func TestModernDNSCacheCannotBypassFamilyPolicy(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"family.test": {"2001:db8::7"}}}}, Rules: []DNSRule{{Rule: Rule{Inbound: []string{"ipv4"}, Strategy: "ipv4_only"}, Server: "hosts"}}}})
	query, _ := makeDNSQuery("family.test", 28)
	reply, e := r.ExchangeDNS(context.Background(), query, "dual")
	if e != nil || binary.BigEndian.Uint16(reply[6:]) != 1 {
		t.Fatal("failed to populate IPv6 answer", e)
	}
	reply, e = r.ExchangeDNS(context.Background(), query, "ipv4")
	if e != nil || binary.BigEndian.Uint16(reply[6:]) != 0 {
		t.Fatal("cache bypassed ipv4_only policy", e)
	}
}

func TestModernDomainTreeMatchesReferenceSemantics(t *testing.T) {
	domains := []string{"exact.test", "EXACT.TEST", "域名.example"}
	suffixes := []string{"example.org", ".subonly.test"}
	tree := buildDomainTree(domains, suffixes)
	for host, want := range map[string]bool{"exact.test": true, "sub.exact.test": false, "example.org": true, "sub.example.org": true, "notexample.org": false, "subonly.test": false, "sub.subonly.test": true, "域名.example": true, "other.test": false} {
		if got := tree.match(host); got != want {
			t.Fatal(host, got, want)
		}
	}
	source := []byte(`{"version":5,"rules":[{"domain":["exact.test","域名.example"],"domain_suffix":["example.org",".subonly.test"]}]}`)
	data, e := CompileRuleSet(source, "source")
	if e != nil {
		t.Fatal(e)
	}
	rules, e := readSRS(data)
	if e != nil {
		t.Fatal(e)
	}
	for _, host := range []string{"exact.test", "sub.exact.test", "example.org", "sub.example.org", "subonly.test", "sub.subonly.test", "域名.example"} {
		if rules[0].domains.match(host) != tree.match(host) {
			t.Fatal("SRS domain trie mismatch", host)
		}
	}
}
