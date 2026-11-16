package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func patchDNSTTLParsed(reply, query []byte, age uint32) {
	copy(reply[:2], query[:2])
	sections, err := dnsRecords(reply)
	if err != nil {
		panic(err)
	}
	for _, records := range sections {
		for _, rr := range records {
			if rr.typ != 41 {
				ttl := uint32(0)
				if rr.ttl > age {
					ttl = rr.ttl - age
				}
				binary.BigEndian.PutUint32(reply[rr.ttlOffset:], ttl)
			}
		}
	}
}
func cachedDNSFixtures(t testing.TB) [][]byte {
	t.Helper()
	query, _ := makeDNSQuery("cache.test", 1)
	mixed, err := predefinedDNS(query, DNSRule{Answer: []string{"cache.test. 120 CNAME target.test.", "target.test. 60 A 192.0.2.1"}, NS: []string{"test. 4294967295 SOA ns.test. hostmaster.test. 1 2 3 4 5"}, Extra: []string{"ns.test. 30 AAAA 2001:db8::1", "test. 20 MX 10 mail.test."}})
	if err != nil {
		t.Fatal(err)
	}
	withOPT := bytes.Clone(mixed)
	binary.BigEndian.PutUint16(withOPT[10:], binary.BigEndian.Uint16(withOPT[10:])+1)
	withOPT = append(withOPT, 0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 0)
	large := dnsResponse(query, len(query), nil, 0, 0)
	binary.BigEndian.PutUint16(large[6:], 1)
	large = append(large, 0xc0, 12, 0xfd, 0xe8, 0, 1, 0xff, 0xff, 0xff, 0xff)
	large = binary.BigEndian.AppendUint16(large, 60000)
	large = append(large, bytes.Repeat([]byte{0xc0, 12, 0, 255}, 15000)...)
	return [][]byte{dnsAnswer(query), mixed, withOPT, large, dnsResponse(query, len(query), nil, 0, 3)}
}
func TestCachedDNSTTLMatchesParser(t *testing.T) {
	query := []byte{0x12, 0x34}
	for i, wire := range cachedDNSFixtures(t) {
		for _, age := range []uint32{0, 1, 30, 120, ^uint32(0)} {
			expected, actual := bytes.Clone(wire), bytes.Clone(wire)
			patchDNSTTLParsed(expected, query, age)
			patchDNSReply(actual, query, age)
			if !bytes.Equal(actual, expected) {
				t.Fatalf("TTL patch differs for fixture%d age%d", i, age)
			}
		}
	}
}
func TestDNSQueryOwnership(t *testing.T) {
	for _, ecs := range []string{"", "192.0.2.0/24"} {
		r := newTestRuntime(t, Config{DNS: DNSConfig{ClientSubnet: ecs, Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"cache.test": {"192.0.2.1"}}}}}})
		query, _ := makeDNSQuery("cache.test", 1)
		original := bytes.Clone(query)
		for range 2 {
			reply, err := r.ExchangeDNS(context.Background(), query, "")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(query, original) {
				t.Fatal("DNS modified caller query")
			}
			ip, _, err := parseDNSReply(query, reply)
			if err != nil || len(ip) != 1 || ip[0] != netip.MustParseAddr("192.0.2.1") {
				t.Fatal(ip, err)
			}
			clear(reply)
		}
	}
}
func TestDNSDoHBodyOwnership(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "https", Tag: "https", Server: "dns.test"}}}})
	query, _ := makeDNSQuery("cache.test", 1)
	original := bytes.Clone(query)
	var body io.ReadCloser
	r.resolver.clients["https"].Transport = acmeTestRoundTrip(func(req *http.Request) (*http.Response, error) {
		body = req.Body
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(dnsAnswer(original)))}, nil
	})
	if _, err := r.ExchangeDNS(context.Background(), query, ""); err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	clear(query)
	data, err := io.ReadAll(body)
	if err != nil || !bytes.Equal(data, original) {
		t.Fatal("HTTP transport retained caller storage", err)
	}
}
func TestDNSCachedAgeAndAsyncOwnership(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Optimistic: optimisticOptions{Enabled: true}, Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"cache.test": {"192.0.2.1"}}}}}})
	query, _ := makeDNSQuery("cache.test", 1)
	original := bytes.Clone(query)
	ttl := uint32(30)
	options := DNSRule{RewriteTTL: &ttl}
	_, err := r.resolver.exchangeDNSOn(context.Background(), "hosts", query, options, false)
	if err != nil {
		t.Fatal(err)
	}
	r.resolver.mu.Lock()
	for _, item := range r.resolver.wireCache {
		e := item.Value.(*dnsWireEntry)
		e.inserted = time.Now().Add(-5 * time.Second)
	}
	r.resolver.mu.Unlock()
	binary.BigEndian.PutUint16(query, 1234)
	reply, err := r.resolver.exchangeDNSOn(context.Background(), "hosts", query, options, false)
	if err != nil {
		t.Fatal(err)
	}
	records, err := dnsRecords(reply)
	if err != nil || records[0][0].ttl != 25 || binary.BigEndian.Uint16(reply) != 1234 {
		t.Fatal("cached age or ID", records, err)
	}
	r.resolver.mu.Lock()
	for _, item := range r.resolver.wireCache {
		item.Value.(*dnsWireEntry).until = time.Now().Add(-time.Second)
	}
	r.resolver.mu.Unlock()
	_, err = r.resolver.exchangeDNSOn(context.Background(), "hosts", query, options, false)
	if err != nil {
		t.Fatal(err)
	}
	clear(query)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		r.resolver.mu.Lock()
		fresh := false
		for _, item := range r.resolver.wireCache {
			fresh = time.Now().Before(item.Value.(*dnsWireEntry).until)
		}
		r.resolver.mu.Unlock()
		if fresh {
			reply, err = r.resolver.exchangeDNSOn(context.Background(), "hosts", original, options, false)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = parseDNSReply(original, reply); err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("optimistic refresh retained caller storage or failed")
}
func FuzzCachedDNSTTL(f *testing.F) {
	for _, wire := range cachedDNSFixtures(f) {
		f.Add(wire, uint32(60))
	}
	f.Fuzz(func(t *testing.T, wire []byte, age uint32) {
		if len(wire) > 65535 {
			return
		}
		if _, err := dnsRecords(wire); err != nil {
			return
		}
		query := []byte{0xab, 0xcd}
		expected, actual := bytes.Clone(wire), bytes.Clone(wire)
		patchDNSTTLParsed(expected, query, age)
		patchDNSReply(actual, query, age)
		if !bytes.Equal(actual, expected) {
			t.Fatal("cached TTL differs from validated parser")
		}
	})
}
