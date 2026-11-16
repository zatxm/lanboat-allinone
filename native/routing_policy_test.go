package native

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

func TestRoutingORGroupsAndDeferredDNS(t *testing.T) {
	cfg := Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "reject"}}, Route: Route{Final: "direct", RuleSet: []RuleSet{{Type: "inline", Tag: "ip", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}}}}}, Rules: []Rule{{Domain: []string{"no-dns.invalid"}, IPCIDR: []string{"192.0.2.0/24"}, Port: []uint16{443}, PortRange: []string{"8000:"}, Action: "reject"}, {Domain: []string{"source-match.invalid"}, RuleSet: []string{"ip"}, RuleSetIPCIDRMatchSource: true, Action: "reject"}}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "empty"}}}}
	r := newTestRuntime(t, cfg)
	for _, address := range []string{"no-dns.invalid:443", "no-dns.invalid:8080", "192.0.2.15:443"} {
		if _, err := r.Dial(context.Background(), "tcp", address); err != ErrRejected {
			t.Fatal("OR group or deferred DNS", address, err)
		}
	}
	rule := r.rules[1]
	if rule.evaluate(request{address: "source-match.invalid:80", source: "203.0.113.1:123"}) != matchYes {
		t.Fatal("single default set fields were not merged")
	}
	if rule.evaluate(request{address: "other.invalid:80", source: "192.0.2.10:123"}) != matchYes {
		t.Fatal("rule_set IP did not use source")
	}
	if rule.evaluate(request{address: "other.invalid:80", source: "203.0.113.1:123"}) != matchNo {
		t.Fatal("rule_set source mismatch")
	}
	logical := Rule{Type: "logical", Mode: "and", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}}, {IPCIDR: []string{"198.51.100.0/24"}, Invert: true}}, Action: "reject"}
	rules, err := compileRoute(Route{Final: "direct", Rules: []Rule{logical}}, r.outbounds)
	if err != nil {
		t.Fatal(err)
	}
	q := request{address: "unresolved.invalid:80"}
	if rules[0].evaluate(q) != matchUnknown {
		t.Fatal("logical unresolved IP evaluated as false")
	}
	q.ips = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	if rules[0].evaluate(q) != matchYes {
		t.Fatal("resolved logical result")
	}
}

func TestDNSResponseIPFilterTTLAndHosts(t *testing.T) {
	zero, custom := uint32(0), uint32(3600)
	cfg := Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "a", Predefined: map[string][]string{"Filter.Test.": {"192.0.2.10"}}}, {Type: "hosts", Tag: "b", Predefined: map[string][]string{"filter.test": {"203.0.113.10"}}}, {Type: "fakeip", Tag: "fake"}}, Final: "b", Rules: []DNSRule{{Rule: Rule{Domain: []string{"filter.test"}, IPCIDR: []string{"198.51.100.0/24"}}, Server: "a"}, {Rule: Rule{Inbound: []string{"no-cache"}}, Server: "a", RewriteTTL: &zero}, {Rule: Rule{Inbound: []string{"custom-ttl"}}, Server: "a", RewriteTTL: &custom}, {Rule: Rule{Domain: []string{"fake.test"}}, Server: "fake", RewriteTTL: &custom}}}}
	r := newTestRuntime(t, cfg)
	for _, in := range []string{"", "no-cache", "custom-ttl", ""} {
		query, _ := makeDNSQuery("filter.test", 1)
		reply, err := r.ExchangeDNS(context.Background(), query, in)
		if err != nil {
			t.Fatal(err)
		}
		ips, ttl, err := parseDNSReply(query, reply)
		want := "203.0.113.10"
		if in != "" {
			want = "192.0.2.10"
		}
		if err != nil || len(ips) != 1 || ips[0].String() != want {
			t.Fatal(in, ips, err)
		}
		if in == "no-cache" && ttl != 0 || in == "custom-ttl" && ttl < 3598 {
			t.Fatal("TTL policy caches mixed", in, ttl)
		}
	}
	ips, ttl, err := r.resolver.queryAnswer(context.Background(), "fake.test", 1, false, "")
	if err != nil || ttl < 3598 || len(ips) != 1 {
		t.Fatal(ips, ttl, err)
	}
	if entry := r.resolver.pools["fake"].byIP[ips[0]]; time.Until(entry.until) < time.Duration(ttl)*time.Second {
		t.Fatal("FakeIP expires before its DNS TTL")
	}
	for _, raw := range []string{`{"dns":{"servers":[{"type":"hosts","tag":"hosts","predefined":{"a.test":["invalid"]}}]}}`, `{"dns":{"servers":[{"type":"udp","tag":"a","server":"dns.test","domain_resolver":"fake"},{"type":"fakeip","tag":"fake"}]}}`} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("invalid DNS config accepted", raw)
		}
	}
	encoded, _ := json.Marshal(cfg)
	if !json.Valid(encoded) {
		t.Fatal("configuration did not encode")
	}
}
