package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const neighborTestMAC = "02:11:22:33:44:55"

func TestNeighborRuleSemantics(t *testing.T) {
	for _, item := range []struct {
		name         string
		rule         Rule
		hits, misses []Metadata
	}{
		{"mac", Rule{SourceMACAddress: []string{"02-11-22-33-44-55"}}, []Metadata{{SourceMACAddress: neighborTestMAC}}, []Metadata{{}, {SourceMACAddress: "02:11:22:33:44:56"}, {WiFiBSSID: neighborTestMAC}}},
		{"hostname", Rule{SourceHostname: []string{"NAS"}}, []Metadata{{SourceHostname: "nas."}}, []Metadata{{}, {SourceHostname: "nas.example"}, {Domain: "nas"}}},
		{"and", Rule{SourceMACAddress: []string{neighborTestMAC}, SourceHostname: []string{"nas"}}, []Metadata{{SourceMACAddress: neighborTestMAC, SourceHostname: "nas"}}, []Metadata{{SourceMACAddress: neighborTestMAC}, {SourceHostname: "nas"}}},
	} {
		t.Run(item.name, func(t *testing.T) {
			item.rule.Outbound = "direct"
			rules, err := compileRoute(Route{Final: "direct", Rules: []Rule{item.rule}}, map[string]Outbound{"direct": {Type: "direct"}})
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range item.hits {
				if !rules[0].matches(request{metadata: m}) {
					t.Fatal("missed", m)
				}
			}
			for _, m := range item.misses {
				if rules[0].matches(request{metadata: m}) {
					t.Fatal("matched", m)
				}
			}
			item.rule.Invert = true
			rules, err = compileRoute(Route{Final: "direct", Rules: []Rule{item.rule}}, map[string]Outbound{"direct": {Type: "direct"}})
			if err != nil {
				t.Fatal(err)
			}
			q := request{preMatch: true}
			if rules[0].matches(q) || !rules[0].preMatchNeedsData(q) {
				t.Fatal("unknown neighbor decided inverted pre-match")
			}
		})
	}
	for _, raw := range []string{
		`{"route":{"rules":[{"source_mac_address":"bad","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"source_mac_address":"01:00:5e:00:00:01","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"source_hostname":"","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"source_hostname":"bad name","outbound":"direct"}]}}`,
		`{"route":{"dhcp_lease_files":[""]}}`,
		`{"dns":{"servers":[{"type":"local","tag":"dns","neighbor_domain":["lan"]}]}}`,
		`{"dns":{"servers":[{"type":"hosts","tag":"dns","neighbor_domain":[".lan"]}]}}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("invalid neighbor setting accepted", raw)
		}
	}
	if _, err := Parse([]byte(`{"route":{"find_neighbor":true,"dhcp_lease_files":"/tmp/test.leases","rules":[{"source_mac_address":"02:11:22:33:44:55","source_hostname":"nas","outbound":"direct"}]},"dns":{"servers":[{"type":"local","tag":"dns","neighbor_domain":".lan"}]}}`)); err != nil {
		t.Fatal("scalar compatibility", err)
	}
}

func TestNeighborLeases(t *testing.T) {
	now := time.Unix(1900000000, 0)
	future := now.Add(time.Hour).Unix()
	ip := netip.MustParseAddr("192.0.2.2")
	for _, item := range []struct {
		name, data string
		ip         netip.Addr
		mac, host  string
	}{
		{"dnsmasq", fmt.Sprintf("%d %s 192.0.2.2 NAS *\n", future, neighborTestMAC), ip, neighborTestMAC, "nas"},
		{"dnsmasq-duid", fmt.Sprintf("%d 00:03:00:01:02:11:22:33:44:55 fd00::2 nas *\n", future), netip.MustParseAddr("fd00::2"), neighborTestMAC, "nas"},
		{"odhcpd-hosts", "# DHCP generated hosts\nfd00::2 nas nas.lan\n", netip.MustParseAddr("fd00::2"), "", "nas"},
		{"kea4", fmt.Sprintf("address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n192.0.2.2,%s,,3600,%d,1,1,1,nas,0\n", neighborTestMAC, future), ip, neighborTestMAC, "nas"},
		{"kea6", fmt.Sprintf("address,duid,valid_lifetime,expire,lease_type,hostname,hwaddr,state\nfd00::2,00:03:00:01:02:11:22:33:44:55,3600,%d,0,nas,,0\n", future), netip.MustParseAddr("fd00::2"), neighborTestMAC, "nas"},
		{"isc4", fmt.Sprintf("lease 192.0.2.2 {\n ends epoch %d;\n binding state active;\n hardware ethernet %s;\n client-hostname \"NAS\";\n}\n", future, neighborTestMAC), ip, neighborTestMAC, "nas"},
		{"isc4-date", fmt.Sprintf("lease 192.0.2.2 { ends 3 %s; hardware ethernet %s; client-hostname \"nas\"; }", now.Add(time.Hour).UTC().Format("2006/01/02 15:04:05"), neighborTestMAC), ip, neighborTestMAC, "nas"},
		{"isc6", fmt.Sprintf("ia-na \"\\000\\003\\000\\001\\002\\021\\042\\063\\104\\125\" { client-hostname \"nas\"; iaaddr fd00::2 { binding state active; ends epoch %d; } }", future), netip.MustParseAddr("fd00::2"), neighborTestMAC, "nas"},
		{"apple", fmt.Sprintf("{\n name=nas\n ip_address=192.0.2.2\n hw_address=1,%s\n lease=0x%x\n}\n", neighborTestMAC, future), ip, neighborTestMAC, "nas"},
	} {
		t.Run(item.name, func(t *testing.T) {
			state := parseNeighborLeases([]byte(item.data), now)
			e, ok := state[item.ip]
			if !ok || e.mac != item.mac || e.hostname != item.host || !e.valid(now) {
				t.Fatal(state)
			}
		})
	}
	for name, data := range map[string]string{
		"expired":             fmt.Sprintf("%d %s 192.0.2.2 nas *\n", now.Unix()-1, neighborTestMAC),
		"kea-reclaimed":       fmt.Sprintf("address,hwaddr,valid_lifetime,expire,hostname,state\n192.0.2.2,%s,3600,%d,nas,2\n", neighborTestMAC, future),
		"kea-pd":              fmt.Sprintf("address,valid_lifetime,expire,hostname,lease_type\nfd00::2,3600,%d,nas,2\n", future),
		"isc-freed":           fmt.Sprintf("lease 192.0.2.2 { ends epoch %d; binding state free; client-hostname \"nas\"; }", future),
		"isc-truncated":       "lease 192.0.2.2 { ends never; client-hostname \"nas\";",
		"kea-truncated":       "address,hwaddr,expire,hostname\n192.0.2.2,foo,1234\n",
		"overlong-line":       strings.Repeat("x", 65537),
		"hosts-comment":       "192.0.2.2 # hidden\n",
		"kea-overlong-header": "address," + strings.Repeat("hwaddr,", 10000) + "hostname\n",
		"apple-over-cap":      "{\nname=nas\nip_address=192.0.2.2\nlease=0x7fffffff\n}\n" + strings.Repeat("{}", neighborLimit),
		"apple-many-fields":   "{\nname=nas\nip_address=192.0.2.2\nlease=0x7fffffff\n" + strings.Repeat("name=nas\n", 33) + "}\n",
		"over-limit":          strings.Repeat("x", neighborLeaseBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if got := parseNeighborLeases([]byte(data), now); len(got) != 0 {
				t.Fatal(got)
			}
		})
	}
	active := fmt.Sprintf("lease 192.0.2.2 { ends epoch %d; client-hostname \"nas\"; }", future)
	freed := "lease 192.0.2.2 { ends never; binding state free; }"
	if len(parseNeighborLeases([]byte(active+freed), now)) != 0 {
		t.Fatal("old ISC lease survived newer free record")
	}
}

func TestNeighborCacheAndLifetime(t *testing.T) {
	var reads atomic.Int32
	c := neighborCache{read: func(context.Context, []string) neighborSnapshot {
		reads.Add(1)
		return neighborSnapshot{byIP: map[netip.Addr]neighborEntry{netip.MustParseAddr("192.0.2.2"): {mac: neighborTestMAC, hostname: "nas"}}}
	}}
	var workers sync.WaitGroup
	for range 32 {
		workers.Go(func() {
			for range 32 {
				if len(c.snapshot(context.Background(), nil).byIP) != 1 {
					t.Error("lost snapshot")
				}
			}
		})
	}
	workers.Wait()
	if reads.Load() != 1 {
		t.Fatal("uncoalesced neighbor refresh", reads.Load())
	}
	c.invalidate()
	c.snapshot(context.Background(), nil)
	if reads.Load() != 2 {
		t.Fatal("did not invalidate")
	}
	time.Sleep(1100 * time.Millisecond)
	c.snapshot(context.Background(), nil)
	if reads.Load() != 3 {
		t.Fatal("on-demand snapshot did not refresh automatically")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if len(c.snapshot(ctx, nil).byIP) != 0 {
		t.Fatal("cancelled query reused identity")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "leases")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d %s 192.0.2.2 nas *\n", time.Now().Add(time.Hour).Unix(), neighborTestMAC)), 0600); err != nil {
		t.Fatal(err)
	}
	r := newTestRuntime(t, Config{Route: Route{FindNeighbor: true, DHCPLeaseFiles: []string{path}}})
	q := request{source: "192.0.2.2:1234"}
	r.enrichNeighbor(context.Background(), &q)
	if q.metadata.SourceMACAddress != neighborTestMAC || q.metadata.SourceHostname != "nas" {
		t.Fatal(q.metadata)
	}
	q.metadata = Metadata{SourceMACAddress: "02:ff:ff:ff:ff:ff"}
	r.enrichNeighbor(context.Background(), &q)
	if q.metadata.SourceHostname != "" {
		t.Fatal("supplied MAC inherited another device hostname")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	r.neighbors.invalidate()
	q.metadata = Metadata{}
	r.enrichNeighbor(context.Background(), &q)
	if q.metadata.SourceHostname != "" || q.metadata.SourceMACAddress != "" {
		t.Fatal("deleted lease retained identity")
	}
}

func TestNeighborRuleSetHotReload(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{RuleSet: []string{"devices"}, Outbound: "direct"}}, RuleSet: []RuleSet{{Type: "inline", Tag: "devices", Rules: []Rule{{Domain: []string{"never.test"}}}}}}})
	var reads int
	r.neighbors.read = func(context.Context, []string) neighborSnapshot {
		reads++
		return neighborSnapshot{byIP: map[netip.Addr]neighborEntry{netip.MustParseAddr("192.0.2.2"): {mac: neighborTestMAC, hostname: "nas"}}}
	}
	q := request{network: "tcp", address: "203.0.113.1:443", source: "192.0.2.2:1234"}
	r.routeTarget(context.Background(), q)
	if reads != 0 || r.needsMetadata(neighborFields) {
		t.Fatal("neighbor discovery ran without rules")
	}
	raw := []byte(`{"version":4,"rules":[{"type":"logical","mode":"and","rules":[{"source_mac_address":"02:11:22:33:44:55"},{"source_hostname":"nas"}]}]}`)
	items, err := parseRuleSet(raw, "source")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := compileRuleSet(items)
	if err != nil {
		t.Fatal(err)
	}
	r.publishRuleSet(r.ruleSets["devices"], snapshot)
	matched, tag, err := r.routeTarget(context.Background(), q)
	if err != nil || tag != "direct" || matched.metadata.SourceHostname != "nas" || reads != 1 {
		t.Fatal(tag, err, matched.metadata, reads)
	}
	if _, err := CompileRuleSet(raw, "source"); err == nil {
		t.Fatal("SRS silently dropped neighbor conditions")
	}
	snapshot, err = compileRuleSet([]Rule{{Domain: []string{"never.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	r.publishRuleSet(r.ruleSets["devices"], snapshot)
	r.neighbors.invalidate()
	r.routeTarget(context.Background(), q)
	if reads != 1 || r.needsMetadata(neighborFields) {
		t.Fatal("neighbor discovery continued after rule removal")
	}
}

func TestNeighborUDPMappingIdentityIsolation(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{SourceMACAddress: []string{neighborTestMAC}, SourceHostname: []string{"nas"}, Outbound: "direct"}}}})
	flows := newUDPFlows(r)
	defer flows.Close()
	q := request{address: echoUDP(t), metadata: Metadata{SourceMACAddress: neighborTestMAC, SourceHostname: "nas"}}
	reply := func([]byte, string) error { return nil }
	if err := flows.send("same-source", q, []byte("allow"), reply); err != nil {
		t.Fatal(err)
	}
	for _, m := range []Metadata{{SourceMACAddress: "02:11:22:33:44:56", SourceHostname: "nas"}, {SourceMACAddress: neighborTestMAC, SourceHostname: "other"}, {}} {
		q.metadata = m
		if err := flows.send("same-source", q, []byte("deny"), reply); !errors.Is(err, ErrRejected) {
			t.Fatal("another device inherited an allowed UDP flow", err)
		}
	}
}

func TestNeighborLocalDNS(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "leases")
	write := func(ip string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(fmt.Sprintf("0 %s %s nas *\n0 %s fd00::2 nas *\n", neighborTestMAC, ip, neighborTestMAC)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("192.0.2.2")
	r := newTestRuntime(t, Config{Route: Route{DHCPLeaseFiles: []string{p}}, DNS: DNSConfig{ReverseMapping: true, Servers: []DNSServer{{Type: "local", Tag: "local", NeighborDomain: []string{".", ".lan"}}}, Final: "local"}})
	query := func(name string, typ uint16) ([]netip.Addr, byte) {
		t.Helper()
		q, err := makeDNSQuery(name, typ)
		if err != nil {
			t.Fatal(err)
		}
		b, err := r.ExchangeDNS(context.Background(), q, "")
		if err != nil {
			t.Fatal(err)
		}
		ips, _, err := parseDNSReply(q, b)
		if err != nil && b[3]&15 == 0 {
			t.Fatal(err)
		}
		return ips, b[3] & 15
	}
	for _, name := range []string{"nas", "nas.lan", "NAS.LAN"} {
		ips, code := query(name, 1)
		if code != 0 || len(ips) != 1 || ips[0].String() != "192.0.2.2" {
			t.Fatal(ips, code)
		}
		ips, code = query(name, 28)
		if code != 0 || len(ips) != 1 || ips[0].String() != "fd00::2" {
			t.Fatal(ips, code)
		}
	}
	if _, code := query("missing.lan", 1); code != 3 {
		t.Fatal("missing neighbor leaked upstream", code)
	}
	r.resolver.mu.Lock()
	reverse := r.resolver.reverse[netip.MustParseAddr("192.0.2.2")]
	r.resolver.mu.Unlock()
	if reverse.host != "nas.lan" {
		t.Fatal("neighbor answer skipped reverse mapping", reverse)
	}
	qTTL, _ := makeDNSQuery("nas.lan", 1)
	ttl := uint32(7)
	reply, err := r.resolver.exchangeDNSOn(context.Background(), "local", qTTL, DNSRule{RewriteTTL: &ttl}, false)
	if err != nil {
		t.Fatal(err)
	}
	sections, err := dnsRecords(reply)
	if err != nil || len(sections[0]) != 1 || sections[0][0].ttl != ttl {
		t.Fatal("neighbor answer skipped TTL rewrite", sections, err)
	}
	write("192.0.2.3")
	r.neighbors.invalidate()
	if ips, _ := query("nas.lan", 1); len(ips) != 1 || ips[0].String() != "192.0.2.3" {
		t.Fatal("stale DNS wire cache", ips)
	}
	server := r.resolver.servers["local"]
	q, _ := makeDNSQuery("a.b.lan", 1)
	host, end, typ, _ := dnsQuestion(q)
	if _, handled, err := r.resolver.neighborDNS(context.Background(), server, q, host, end, typ); handled || err != nil {
		t.Fatal("multi-label name intercepted", handled, err)
	}
	q, _ = makeDNSQuery("nas.lan", 16)
	host, end, typ, _ = dnsQuestion(q)
	if _, handled, err := r.resolver.neighborDNS(context.Background(), server, q, host, end, typ); handled || err != nil {
		t.Fatal("non-IP request intercepted", handled, err)
	}
}

func TestNeighborLeaseConflicts(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i, name := range []string{"first", "second"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("0 "+neighborTestMAC+" 192.0.2.2 "+name+" *\n"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
		if i == 1 {
			s := readNeighbors(context.Background(), paths)
			if !s.byIP[netip.MustParseAddr("192.0.2.2")].ambiguous || !s.byMAC[neighborTestMAC].ambiguous {
				t.Fatal("conflicting hostname attributed", s)
			}
		}
	}
}

func BenchmarkNeighborMetadataMatch(b *testing.B) {
	rules, err := compileRoute(Route{Final: "direct", Rules: []Rule{{SourceMACAddress: []string{neighborTestMAC}, SourceHostname: []string{"nas"}, Outbound: "direct"}}}, map[string]Outbound{"direct": {Type: "direct"}})
	if err != nil {
		b.Fatal(err)
	}
	q := request{network: "tcp", address: "203.0.113.1:443", source: "192.0.2.2:1234", metadata: Metadata{SourceMACAddress: neighborTestMAC, SourceHostname: "nas"}}
	b.ReportAllocs()
	for b.Loop() {
		if !rules[0].matches(q) {
			b.Fatal("not matched")
		}
	}
}

func FuzzNeighborLeases(f *testing.F) {
	for _, data := range []string{"0 02:11:22:33:44:55 192.0.2.2 nas *\n", "lease 192.0.2.2 { ends never; }", "address,hwaddr,expire,hostname\n", "{\nlease=0x7fffffff\n}\n"} {
		f.Add([]byte(data))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		state := parseNeighborLeases(b, time.Now())
		if len(state) > neighborLimit {
			t.Fatal("unbounded leases")
		}
		if _, err := json.Marshal(state); err != nil {
			t.Fatal(err)
		}
	})
}
