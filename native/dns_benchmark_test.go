package native

import (
	"context"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

func BenchmarkDNSPolicyCached(b *testing.B) {
	for _, mode := range []string{"ordinary", "race", "speculative"} {
		b.Run(mode, func(b *testing.B) {
			cfg := Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"cache.test": {"192.0.2.1"}}}}}}
			if mode != "ordinary" {
				rule := DNSRule{Rule: Rule{Action: "respond", MatchResponse: "a"}, Race: true}
				cfg.DNS.Rules = []DNSRule{{Rule: Rule{Action: "evaluate"}, Server: "hosts", Tag: "a"}, rule}
				if mode == "speculative" {
					cfg.DNS.Rules[1].IPCIDR = []string{"10.0.0.0/8"}
					cfg.DNS.Rules = append(cfg.DNS.Rules, DNSRule{Rule: Rule{Action: "route"}, Server: "hosts", Speculative: true})
				}
			}
			data, _ := json.Marshal(cfg)
			r, e := New(context.Background(), data, zap.NewNop())
			if e != nil {
				b.Fatal(e)
			}
			b.Cleanup(func() { r.Close() })
			q, _ := makeDNSQuery("cache.test", 1)
			if _, e = r.ExchangeDNS(context.Background(), q, ""); e != nil {
				b.Fatal(e)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, e := r.ExchangeDNS(context.Background(), q, ""); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
