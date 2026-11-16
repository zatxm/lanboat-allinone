package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tsDNSFixture(t *testing.T, config tsDNSConfig) (*Runtime, *tailscaleClient) {
	t.Helper()
	r := newTestRuntime(t, Config{})
	ctx, cancel := context.WithCancel(r.ctx)
	c := &tailscaleClient{r: r, ctx: ctx, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{}), self: tsNode{ID: 1, Name: "native.test.ts.net.", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}, nodes: map[int64]tsNode{2: {ID: 2, Name: "peer.test.ts.net.", Key: "peer", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32"), netip.MustParsePrefix("fd7a:115c:a1e0::2/128")}}}}
	c.once.Do(func() {})
	c.readyOnce.Do(func() { close(c.ready) })
	close(c.done)
	r.tailscaleClients["ts"] = c
	tsDNSPublish(t, c, config)
	r.resolver.Close()
	var err error
	r.resolver, err = newResolver(DNSConfig{Timeout: "1s", Servers: []DNSServer{{Type: "tailscale", Tag: "dns", Endpoint: "ts", AcceptSearchDomain: true, AcceptDefaultResolvers: true}}}, r)
	if err != nil {
		t.Fatal(err)
	}
	return r, c
}
func tsDNSPublish(t *testing.T, c *tailscaleClient, config tsDNSConfig) {
	t.Helper()
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.dnsConfig = config
	old := c.publishDNSLocked()
	c.mu.Unlock()
	if old != nil {
		old.close()
	}
}

func TestTailscaleDNSMagic(t *testing.T) {
	r, c := tsDNSFixture(t, tsDNSConfig{Proxied: true, Domains: []string{"test.ts.net"}, Routes: map[string][]*tsDNSResolver{"test.ts.net": nil}, ExtraRecords: []tsDNSRecord{{Name: "extra.test.ts.net", Value: "192.0.2.9"}}})
	for _, host := range []string{"native.test.ts.net", "peer.test.ts.net", "peer", "extra.test.ts.net"} {
		b := ocDNSQuery(t, r.resolver, host, 1, 0)
		rr, err := dnsRecords(b)
		if err != nil || len(rr[0]) == 0 {
			t.Fatal(host, rr, err)
		}
	}
	for _, host := range []string{tsDNSReverse(netip.MustParseAddr("100.64.0.2")), tsDNSReverse(netip.MustParseAddr("fd7a:115c:a1e0::2"))} {
		b := ocDNSQuery(t, r.resolver, host, 12, 0)
		rr, _ := dnsRecords(b)
		if len(rr[0]) != 1 || rr[0][0].typ != 12 {
			t.Fatal(host, rr)
		}
	}
	ocDNSQuery(t, r.resolver, "unknown.test.ts.net", 1, 3)
	ocDNSQuery(t, r.resolver, "88.99.64.100.in-addr.arpa", 12, 3)
	ocDNSQuery(t, r.resolver, tsDNSReverse(netip.MustParseAddr("fd7a:115c:a1e0::99")), 12, 3)
	ocDNSQuery(t, r.resolver, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa", 12, 3)
	ocDNSQuery(t, r.resolver, "peer.test.ts.net", 16, 0)
	c.mu.Lock()
	n := c.nodes[2]
	n.Expired = true
	c.nodes[2] = n
	c.mu.Unlock()
	tsDNSPublish(t, c, c.dnsConfig)
	ocDNSQuery(t, r.resolver, "peer.test.ts.net", 1, 3)
	state := r.resolver.dnsNetwork("dns")
	if !slices.Equal(state.domains, []string{"test.ts.net"}) {
		t.Fatal(state)
	}
	c.fail(errTSAuth)
	if state := r.resolver.dnsNetwork("dns"); len(state.domains)+len(state.addresses) > 0 {
		t.Fatal("failed identity retained DNS metadata")
	}
	q, _ := makeDNSQuery("extra.test.ts.net", 1)
	if _, err := r.resolver.exchangePolicy(context.Background(), q, false); err == nil {
		t.Fatal("revoked identity used cached DNS")
	}
}

func TestTailscaleDNSExitServer(t *testing.T) {
	c := tsDropTestClient(t, t.TempDir())
	c.o.AdvertiseExitNode = true
	if err := c.applyMap([]byte(`{"Node":{"User":1,"Addresses":["100.64.0.1/32"],"AllowedIPs":["0.0.0.0/0","::/0"]},"PacketFilter":[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}],"DNSConfig":{"ExitNodeFilteredSet":["blocked.test",".children.test"]}}`)); err != nil {
		t.Fatal(err)
	}
	c.r.resolver.Close()
	var err error
	c.r.resolver, err = newResolver(DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "h", Predefined: map[string][]string{"allowed.test": {"192.0.2.42"}, "children.test": {"192.0.2.43"}}}}}, c.r)
	if err != nil {
		t.Fatal(err)
	}
	request := func(host, method, source, origin string) *httptest.ResponseRecorder {
		t.Helper()
		q, _ := makeDNSQuery(host, 1)
		path := "http://peer/dns-query"
		var body *bytes.Reader
		if method == "GET" {
			path += "?dns=" + base64.RawURLEncoding.EncodeToString(q)
			body = bytes.NewReader(nil)
		} else {
			body = bytes.NewReader(q)
		}
		r := httptest.NewRequest(method, path, body)
		r.RemoteAddr = source
		r.Header.Set("Content-Type", "application/dns-message")
		r.Header.Set("Origin", origin)
		r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: int(c.peerAPI.port)}))
		w := httptest.NewRecorder()
		c.peerAPI.ServeHTTP(w, r)
		return w
	}
	for _, method := range []string{"GET", "POST"} {
		w := request("allowed.test", method, "100.64.0.3:1234", "")
		if w.Code != 200 || w.Body.Bytes()[3]&15 != 0 {
			t.Fatal(method, w.Code, w.Body.String())
		}
	}
	for _, host := range []string{"blocked.test", "sub.children.test"} {
		w := request(host, "POST", "100.64.0.2:1234", "")
		if w.Code != 200 || w.Body.Bytes()[3]&15 != 3 {
			t.Fatal(host, w.Code, w.Body.String())
		}
	}
	if w := request("children.test", "GET", "100.64.0.2:1234", ""); w.Code != 200 || w.Body.Bytes()[3]&15 != 0 {
		t.Fatal("suffix filter included apex", w.Code)
	}
	for _, tc := range []struct{ source, origin string }{{"100.64.0.88:1", ""}, {"100.64.0.2:1", "https://browser.test"}} {
		if w := request("allowed.test", "GET", tc.source, tc.origin); w.Code != 403 {
			t.Fatal("unauthorized DNS", w.Code)
		}
	}
	if err := c.applyMap([]byte(`{"PacketFilter":[]}`)); err != nil {
		t.Fatal(err)
	}
	if w := request("allowed.test", "POST", "100.64.0.2:1234", ""); w.Code != 403 {
		t.Fatal("Taildrop permission opened DNS", w.Code)
	}
}

func TestTailscaleDNSExitReference(t *testing.T) {
	url, dec, input := startTSReference(t, false)
	r := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), Hostname: "dns-exit", AdvertiseExitNode: true, ForceDERP: true}}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "h", Predefined: map[string][]string{"exit-resolved.test": {"192.0.2.42"}}}}}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := r.TailscaleStatus(ctx, "ts"); err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(input)
	if err := enc.Encode(map[string]string{"op": "approve", "hostname": "dns-exit"}); err != nil {
		t.Fatal(err)
	}
	var approved struct{ Routes []string }
	if err := dec.Decode(&approved); err != nil || len(approved.Routes) != 2 {
		t.Fatal(approved, err)
	}
	c := r.tailscaleClient("ts")
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		c.mu.Lock()
		ok := slices.Contains(c.self.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
		c.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := enc.Encode(map[string]string{"op": "dns-query", "address": "exit-resolved.test", "data": "A"}); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Wire  []byte
		Error string
	}
	if err := dec.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Error != "" || len(result.Wire) < 12 {
		t.Fatal(result)
	}
	rr, err := dnsRecords(result.Wire)
	if err != nil || len(rr[0]) != 1 || !bytes.Equal(rr[0][0].data, []byte{192, 0, 2, 42}) {
		t.Fatal(rr, err, result.Error)
	}
}

func TestTailscaleDNSRouting(t *testing.T) {
	port, seen := ocDNSFixture(t)
	a := &tsDNSResolver{Addr: portAddress("127.0.0.1", port)}
	r, c := tsDNSFixture(t, tsDNSConfig{Domains: []string{"corp.test", "lab.test"}, Routes: map[string][]*tsDNSResolver{"corp.test": {a}, "lab.test": {a}, "local.corp.test": nil}, Resolvers: []*tsDNSResolver{a}})
	for _, host := range []string{"www.corp.test", "outside.test", "host", "trunc.corp.test"} {
		ocDNSQuery(t, r.resolver, host, 1, 0)
	}
	ocDNSQuery(t, r.resolver, "unknown.local.corp.test", 1, 3)
	if !slices.Contains(seen(), "tcp:trunc.corp.test") || slices.Contains(seen(), "udp:unknown.local.corp.test") {
		t.Fatal(seen())
	}
	s := r.resolver.servers["dns"]
	s.AcceptDefaultResolvers = false
	r.resolver.servers["dns"] = s
	ocDNSQuery(t, r.resolver, "not-corp.test", 1, 3)
	r.resolver.preferredTags = []string{"dns"}
	for _, tc := range []struct {
		host string
		want bool
	}{{"www.corp.test", true}, {"corp.test.evil", false}, {"host", true}, {"outside.test", false}} {
		p, err := r.resolver.dnsPreferences(context.Background(), tc.host)
		if err != nil || slices.Contains(p, "dns") != tc.want {
			t.Fatal(tc, p, err)
		}
	}
	state := r.resolver.dnsNetwork("dns")
	if len(state.addresses) != 1 || state.addresses[0].String() != "127.0.0.1" {
		t.Fatal(state)
	}
	c.mu.Lock()
	done := make(chan dnsNetworkState, 1)
	go func() { done <- r.resolver.dnsNetwork("dns") }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("passive metadata waited for control map lock")
	}
	c.mu.Unlock()
}

func TestTailscaleDNSUpdates(t *testing.T) {
	config := tsDNSConfig{Proxied: true, Domains: []string{"test.ts.net"}, ExtraRecords: []tsDNSRecord{{Name: "record.test.ts.net", Value: "192.0.2.1"}}}
	r, c := tsDNSFixture(t, config)
	b := ocDNSQuery(t, r.resolver, "record.test.ts.net", 1, 0)
	if !slices.Equal(b[len(b)-4:], []byte{192, 0, 2, 1}) {
		t.Fatal(b)
	}
	first := c.dns.Load()
	tsDNSPublish(t, c, config)
	if c.dns.Load() != first {
		t.Fatal("unchanged DNS map rebuilt pools")
	}
	config.ExtraRecords = []tsDNSRecord{{Name: "record.test.ts.net", Value: "192.0.2.2"}}
	tsDNSPublish(t, c, config)
	if first.ctx.Err() == nil {
		t.Fatal("old snapshot stayed active")
	}
	b = ocDNSQuery(t, r.resolver, "record.test.ts.net", 1, 0)
	if !slices.Equal(b[len(b)-4:], []byte{192, 0, 2, 2}) {
		t.Fatal("old DNS cache", b)
	}
	config.ExtraRecords = []tsDNSRecord{{Name: "record.test.ts.net", Value: "192.0.2.1"}}
	tsDNSPublish(t, c, config)
	if first.key == c.dns.Load().key {
		t.Fatal("restored config reused old cache epoch")
	}
	c.mu.Lock()
	n := c.nodes[2]
	n.KeyExpiry = time.Now().Add(35 * time.Millisecond)
	c.nodes[2] = n
	c.mu.Unlock()
	tsDNSPublish(t, c, config)
	ocDNSQuery(t, r.resolver, "peer.test.ts.net", 1, 0)
	time.Sleep(45 * time.Millisecond)
	ocDNSQuery(t, r.resolver, "peer.test.ts.net", 1, 3)
	tsDNSPublish(t, c, tsDNSConfig{})
	s := r.resolver.servers["dns"]
	s.AcceptDefaultResolvers = false
	r.resolver.servers["dns"] = s
	ocDNSQuery(t, r.resolver, "record.test.ts.net", 1, 3)
}

func TestTailscaleDNSValidation(t *testing.T) {
	base := `{"endpoints":[{"type":"tailscale","tag":"ts"}],"dns":{"servers":[{"type":"tailscale","tag":"dns","endpoint":"ts","accept_search_domain":true,"accept_default_resolvers":true}],"rules":[{"preferred_by":"dns","server":"dns"}]},"route":{"default_domain_resolver":"dns"}}`
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(base, `"endpoint":"ts"`, `"endpoint":"missing"`, 1), strings.Replace(base, `"endpoint":"ts"`, `"endpoint":"ts","detour":"ts"`, 1), strings.Replace(base, `"tag":"ts"`, `"tag":"ts","domain_resolver":"dns"`, 1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatal("invalid DNS config accepted", bad)
		}
	}
	for _, r := range []string{"bad", "0.0.0.0", "ff02::1", "127.0.0.1:0", "http://u:p@dns.test/", "https://dns.test/#x", "tls://dns.test", "http://0.0.0.0/", "https://[ff02::1]/", "https://bad..test/"} {
		if (tsDNSConfig{Resolvers: []*tsDNSResolver{{Addr: r}}}).validate() == nil {
			t.Fatal("invalid resolver accepted", r)
		}
	}
	for _, v := range []tsDNSConfig{{Domains: []string{"bad..test"}}, {Resolvers: []*tsDNSResolver{nil}}, {ExtraRecords: []tsDNSRecord{{Name: "a.test", Value: "bad"}}}, {Routes: map[string][]*tsDNSResolver{"corp.test": nil, "CORP.test.": nil}}, {Resolvers: []*tsDNSResolver{{Addr: "https://dns.test", BootstrapResolution: []netip.Addr{netip.MustParseAddr("0.0.0.0")}}}}} {
		if v.validate() == nil {
			t.Fatal("invalid DNS map accepted", v)
		}
	}
}

func TestTailscaleDNSBounds(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".test"
	config := tsDNSConfig{}
	for range 2048 {
		config.ExtraRecords = append(config.ExtraRecords, tsDNSRecord{Name: name, Value: "192.0.2.42"})
	}
	r, _ := tsDNSFixture(t, config)
	b := ocDNSQuery(t, r.resolver, name, 1, 0)
	if len(b) > 65535 || b[2]&2 == 0 {
		t.Fatal("oversized MagicDNS response", len(b))
	}
	if _, err := dnsRecords(b); err != nil {
		t.Fatal("truncated response corrupted", err)
	}
}

func TestTailscaleDNSNoPlainHTTPLeak(t *testing.T) {
	var calls atomic.Int32
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer host.Close()
	r, _ := tsDNSFixture(t, tsDNSConfig{Resolvers: []*tsDNSResolver{{Addr: host.URL + "/dns-query"}}})
	q, _ := makeDNSQuery("private.corp.test", 1)
	if _, err := r.resolver.exchangePolicy(context.Background(), q, false); err == nil {
		t.Fatal("plaintext resolver outside WireGuard accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("private DNS query leaked to host HTTP listener")
	}
	// A removed peer's private address must not fall back to an OS socket.
	for _, address := range []string{"100.64.0.88", "fd7a:115c:a1e0::88"} {
		c := r.tailscaleClient("ts")
		s := c.dns.Load()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := s.dial(ctx, tsDNSResolver{}, DNSServer{Type: "udp", Server: address, ServerPort: 53}, "udp")
		if err == nil || strings.Contains(err.Error(), "context canceled") {
			t.Fatal("private resolver reached direct dial", address, err)
		}
	}
}

func TestTailscaleDNSReference(t *testing.T) {
	t.Setenv("LANBOAT_TS_DNS", "1")
	url, dec, input := startTSReference(t, false)
	o := Outbound{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), Hostname: "dns-native", ForceDERP: true}}
	r := newTestRuntime(t, Config{Outbounds: []Outbound{o}, DNS: DNSConfig{Servers: []DNSServer{{Type: "tailscale", Tag: "dns", Endpoint: "ts", AcceptSearchDomain: true, AcceptDefaultResolvers: true}}, Timeout: "5s"}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := r.TailscaleStatus(ctx, "ts"); err != nil {
		t.Fatal(err)
	}
	c := r.tailscaleClient("ts")
	deadline := time.Now().Add(5 * time.Second)
	peer := ""
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, n := range c.nodes {
			if strings.HasPrefix(n.Name, "reference.") {
				peer = n.Addresses[0].Addr().String()
			}
		}
		c.mu.Unlock()
		if peer != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if peer == "" {
		t.Fatal("reference peer missing")
	}
	enc := json.NewEncoder(input)
	via := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), Hostname: "dns-via-exit", ExitNode: "reference", ForceDERP: true}}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "tailscale", Tag: "dns", Endpoint: "ts", AcceptDefaultResolvers: true}}, Timeout: "5s"}})
	if _, err := via.TailscaleStatus(ctx, "ts"); err != nil {
		t.Fatal(err)
	}
	viaClient := via.tailscaleClient("ts")
	// Establish the official WG peer before pushing its deterministic DNS service.
	warm, err := viaClient.dial(ctx, "tcp", net.JoinHostPort(peer, "8080"))
	if err != nil {
		t.Fatal(err)
	}
	warm.Close()
	if err := enc.Encode(map[string]any{"op": "dns-exit", "hostname": "dns-via-exit", "dns": tsDNSConfig{Resolvers: []*tsDNSResolver{{Addr: "192.0.2.53"}}}}); err != nil {
		t.Fatal(err)
	}
	var ack struct{ OK bool }
	if err := dec.Decode(&ack); err != nil || !ack.OK {
		t.Fatal(ack, err)
	}
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if service, err := viaClient.exitDNS(); err == nil && strings.Contains(service.Addr, ":5354/") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A selected exit must resolve at its PeerAPI; this unreachable list must not leak.
	ocDNSQuery(t, via.resolver, "www.lab.test", 1, 0)
	// Administrators may explicitly retain a tailnet resolver while using an exit.
	tsDNSPublish(t, viaClient, tsDNSConfig{Resolvers: []*tsDNSResolver{{Addr: net.JoinHostPort(peer, "5353"), UseWithExitNode: true}}})
	ocDNSQuery(t, via.resolver, "kept.corp.test", 16, 0)
	push := func(config tsDNSConfig) {
		t.Helper()
		if err := enc.Encode(map[string]any{"op": "dns", "hostname": "dns-native", "dns": config}); err != nil {
			t.Fatal(err)
		}
		var result struct{ OK bool }
		if err := dec.Decode(&result); err != nil || !result.OK {
			t.Fatal(result, err)
		}
		until := time.Now().Add(3 * time.Second)
		want, _ := json.Marshal(config)
		for time.Now().Before(until) {
			state := c.dns.Load()
			got, _ := json.Marshal(state.config)
			if string(got) == string(want) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("DNS map update not applied")
	}
	classic := &tsDNSResolver{Addr: net.JoinHostPort(peer, "5353")}
	config := tsDNSConfig{Proxied: true, Domains: []string{"test.ts.net", "corp.test"}, Routes: map[string][]*tsDNSResolver{"test.ts.net": nil, "corp.test": {classic}}, Resolvers: []*tsDNSResolver{classic}, ExtraRecords: []tsDNSRecord{{Name: "extra.test.ts.net", Value: "192.0.2.8"}}}
	push(config)
	for _, typ := range []uint16{1, 28} {
		ocDNSQuery(t, r.resolver, "reference.test.ts.net", typ, 0)
		ocDNSQuery(t, r.resolver, "reference", typ, 0)
	}
	for _, host := range []string{"www.corp.test", "trunc.corp.test", "outside.test"} {
		for _, typ := range []uint16{1, 28, 16} {
			ocDNSQuery(t, r.resolver, host, typ, 0)
		}
	}
	ocDNSQuery(t, r.resolver, "missing.test.ts.net", 1, 3)
	config.Routes["corp.test"] = []*tsDNSResolver{{Addr: "http://" + net.JoinHostPort(peer, "5354") + "/dns-query"}}
	push(config)
	ocDNSQuery(t, r.resolver, "www.corp.test", 16, 0)
	config.ExtraRecords = []tsDNSRecord{{Name: "extra.test.ts.net", Value: "192.0.2.9"}}
	push(config)
	b := ocDNSQuery(t, r.resolver, "extra.test.ts.net", 1, 0)
	if !slices.Equal(b[len(b)-4:], []byte{192, 0, 2, 9}) {
		t.Fatal("stale controller record", b)
	}
	push(tsDNSConfig{})
	s := r.resolver.servers["dns"]
	s.AcceptDefaultResolvers = false
	r.resolver.servers["dns"] = s
	ocDNSQuery(t, r.resolver, "extra.test.ts.net", 1, 3)
}

func FuzzTailscaleDNS(f *testing.F) {
	f.Add(`{"Proxied":true,"Routes":{"corp.test":[{"Addr":"192.0.2.53"}]}}`)
	f.Add(`{"Resolvers":[{"Addr":"https://dns.test/dns-query","BootstrapResolution":["192.0.2.53"]}]}`)
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 1<<20 {
			return
		}
		var c tsDNSConfig
		if json.Unmarshal([]byte(text), &c) != nil {
			return
		}
		if c.validate() != nil {
			return
		}
		for _, list := range append([][]*tsDNSResolver{c.Resolvers, c.FallbackResolvers}, slices.Collect(maps.Values(c.Routes))...) {
			for _, r := range list {
				if _, err := tsDNSService(*r); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
