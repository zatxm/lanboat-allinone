package native

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSStoreRestoresWireResponses(t *testing.T) {
	var hits atomic.Int32
	server := dnsTestUpstream(t, "up", func(ctx context.Context, q []byte) []byte { hits.Add(1); return dnsTestReply(q, "192.0.2.71") })
	cfg := Config{DNS: DNSConfig{ReverseMapping: true, Servers: []DNSServer{server}}, Experimental: ExperimentalOptions{CacheFile: CacheFileOptions{Enabled: true, StoreDNS: true, CacheID: "one", Path: filepath.Join(t.TempDir(), "cache.db")}}}
	first := newTestRuntime(t, cfg)
	q, _ := makeDNSQuery("saved.test", 1)
	reply, e := first.ExchangeDNS(context.Background(), q, "")
	if e != nil {
		t.Fatal(e)
	}
	path := first.resolver.dnsStorePath()
	first.Close()
	stat, e := os.Stat(path)
	if e != nil || stat.Mode().Perm() != 0600 {
		t.Fatal(stat, e)
	}
	second := newTestRuntime(t, cfg)
	q[0], q[1] = 4, 9
	restored, e := second.ExchangeDNS(context.Background(), q, "")
	if e != nil || hits.Load() != 1 || !bytes.Equal(restored[:2], q[:2]) {
		t.Fatal("cache did not survive restart", hits.Load(), e)
	}
	ips, _, err := parseDNSReply(q, restored)
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.71" || len(reply) != len(restored) {
		t.Fatal("response changed", ips, err)
	}
	if entry, ok := second.resolver.reverse[netip.MustParseAddr("192.0.2.71")]; !ok || entry.host != "saved.test" {
		t.Fatal("reverse mapping not restored", entry, ok)
	}
	second.Close()
	cfg.Experimental.CacheFile.CacheID = "two"
	third := newTestRuntime(t, cfg)
	if _, e = third.ExchangeDNS(context.Background(), q, ""); e != nil || hits.Load() != 2 {
		t.Fatal("cache ID isolation", hits.Load(), e)
	}
	third.Close()
	cfg.Experimental.CacheFile.CacheID = "one"
	cfg.DNS.DisableCache = true
	fourth := newTestRuntime(t, cfg)
	if _, e = fourth.ExchangeDNS(context.Background(), q, ""); e != nil || hits.Load() != 3 {
		t.Fatal("config isolation", hits.Load(), e)
	}
}
func TestDNSStoreFlushTriggers(t *testing.T) {
	for _, threshold := range []bool{false, true} {
		t.Run(map[bool]string{false: "interval", true: "buffer"}[threshold], func(t *testing.T) {
			server := dnsTestUpstream(t, "up", func(ctx context.Context, q []byte) []byte { return dnsTestReply(q, "192.0.2.71") })
			opts := CacheFileOptions{Enabled: true, StoreDNS: true, Path: filepath.Join(t.TempDir(), "cache.db"), FlushInterval: "10ms"}
			if threshold {
				opts.FlushInterval = ""
				opts.BufferSize = "1B"
			}
			r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{server}}, Experimental: ExperimentalOptions{CacheFile: opts}})
			q, _ := makeDNSQuery("flush.test", 1)
			if _, e := r.ExchangeDNS(context.Background(), q, ""); e != nil {
				t.Fatal(e)
			}
			deadline := time.Now().Add(time.Second)
			for {
				data, e := os.ReadFile(r.resolver.dnsStorePath())
				if e == nil && bytes.Count(data, []byte{'\n'}) >= 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("cache did not flush", e)
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}
func TestDNSStoreExpiryAndInvalidFiles(t *testing.T) {
	var hits atomic.Int32
	server := dnsTestUpstream(t, "up", func(ctx context.Context, q []byte) []byte { hits.Add(1); return dnsTestReply(q, "192.0.2.71") })
	cfg := Config{DNS: DNSConfig{Servers: []DNSServer{server}}, Experimental: ExperimentalOptions{CacheFile: CacheFileOptions{Enabled: true, StoreDNS: true, Path: filepath.Join(t.TempDir(), "cache.db")}}}
	first := newTestRuntime(t, cfg)
	q, _ := makeDNSQuery("expired.test", 1)
	if _, e := first.ExchangeDNS(context.Background(), q, ""); e != nil {
		t.Fatal(e)
	}
	first.resolver.mu.Lock()
	for _, v := range first.resolver.wireCache {
		v.Value.(*dnsWireEntry).until = time.Now().Add(-time.Second)
	}
	first.resolver.mu.Unlock()
	path := first.resolver.dnsStorePath()
	first.Close()
	second := newTestRuntime(t, cfg)
	if _, e := second.ExchangeDNS(context.Background(), q, ""); e != nil || hits.Load() != 2 {
		t.Fatal("expired entry reused", hits.Load(), e)
	}
	second.Close()
	// The loader rejects partial and malformed snapshots; startup recovers with an empty cache.
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, content := range [][]byte{[]byte("not json"), append(data, []byte("{bad")...)} {
		if e = os.WriteFile(path, content, 0600); e != nil {
			t.Fatal(e)
		}
		r := newTestRuntime(t, cfg)
		if len(r.resolver.wireCache) != 0 {
			t.Fatal("partial corrupt snapshot was published")
		}
		r.Close()
	}
}
func TestDNSStoreOptionsAndRemovedRDRC(t *testing.T) {
	for _, value := range []string{"1B", "1KB", "1KiB", "1.5MB", "16MiB", "1024"} {
		if _, e := (CacheFileOptions{BufferSize: value}).bufferSize(); e != nil {
			t.Fatal(value, e)
		}
	}
	for _, value := range []string{"0", "-1MB", "NaN", "Inf", "1TB", "65MiB"} {
		if _, e := (CacheFileOptions{BufferSize: value}).bufferSize(); e == nil {
			t.Fatal("invalid buffer size", value)
		}
	}
	for _, field := range []string{`"store_rdrc":false`, `"rdrc_timeout":"7d"`, `"buffer_size":"0"`, `"flush_interval":"-1s"`} {
		if _, e := Parse([]byte(`{"experimental":{"cache_file":{` + field + `}}}`)); e == nil {
			t.Fatal("invalid cache_file accepted", field)
		}
	}
}

func TestDNSStoreForcedHostsAndRecordTypes(t *testing.T) {
	cfg := Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"boot.test": {"192.0.2.8"}}}}}, Experimental: ExperimentalOptions{CacheFile: CacheFileOptions{Enabled: true, StoreDNS: true, Path: filepath.Join(t.TempDir(), "cache.db")}}}
	first := newTestRuntime(t, cfg)
	if ips, _, e := first.resolver.queryAnswer(context.Background(), "boot.test", 1, true, "hosts"); e != nil || len(ips) != 1 {
		t.Fatal(ips, e)
	}
	first.Close()
	restored := newTestRuntime(t, cfg)
	if len(restored.resolver.wireCache) != 1 {
		t.Fatal("bootstrap cache not restored")
	}
	restored.Close()
	var hits atomic.Int32
	server := dnsTestUpstream(t, "rr", func(ctx context.Context, q []byte) []byte {
		hits.Add(1)
		reply, e := predefinedDNS(q, DNSRule{Answer: []string{`records.test. 60 IN TXT "hello world"`}, NS: []string{`records.test. 30 IN NS ns.records.test.`}, Extra: []string{`ns.records.test. 30 IN A 192.0.2.8`}})
		if e != nil {
			t.Error(e)
		}
		return reply
	})
	cfg.DNS.Servers = []DNSServer{server}
	rr := newTestRuntime(t, cfg)
	query, _ := makeDNSQuery("records.test", 16)
	original, e := rr.ExchangeDNS(context.Background(), query, "")
	if e != nil {
		t.Fatal(e)
	}
	rr.Close()
	rr = newTestRuntime(t, cfg)
	reply, e := rr.ExchangeDNS(context.Background(), query, "")
	if e != nil || hits.Load() != 1 {
		t.Fatal("wire records not restored", hits.Load(), e)
	}
	a, e := dnsRecords(original)
	if e != nil {
		t.Fatal(e)
	}
	b, e := dnsRecords(reply)
	if e != nil {
		t.Fatal(e)
	}
	for i := range 3 {
		if len(a[i]) != len(b[i]) {
			t.Fatal("DNS section lost", i)
		}
		for j, record := range a[i] {
			if record.typ != b[i][j].typ || !bytes.Equal(record.data, b[i][j].data) {
				t.Fatal("DNS record changed", record, b[i][j])
			}
		}
	}
}
