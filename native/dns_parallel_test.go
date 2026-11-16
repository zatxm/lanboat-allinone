package native

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func dnsTestUpstream(t *testing.T, tag string, answer func(context.Context, []byte) []byte) DNSServer {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		q, e := io.ReadAll(io.LimitReader(req.Body, 65536))
		if e != nil {
			return
		}
		reply := answer(req.Context(), q)
		if reply != nil {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(reply)
		}
	}))
	t.Cleanup(s.Close)
	host, port := splitTestAddress(t, s.Listener.Addr().String())
	return DNSServer{Type: "https", Tag: tag, Server: host, ServerPort: port, TLS: TLSOptions{Insecure: true}}
}
func dnsTestReply(q []byte, ip string) []byte {
	_, end, _, _ := dnsQuestion(q)
	return dnsResponse(q, end, []netip.Addr{netip.MustParseAddr(ip)}, 60, 0)
}
func dnsTestExchange(t *testing.T, r *Runtime) []netip.Addr {
	t.Helper()
	q, _ := makeDNSQuery("parallel.test", 1)
	reply, e := r.ExchangeDNS(context.Background(), q, "")
	if e != nil {
		t.Fatal(e)
	}
	ips, _, e := parseDNSReply(q, reply)
	if e != nil {
		t.Fatal(e)
	}
	return ips
}
func TestDNSParallelWinnerAndOrdering(t *testing.T) {
	for _, speculative := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordered", true: "speculative"}[speculative], func(t *testing.T) {
			aStarted, bStarted, aCanceled := make(chan struct{}, 1), make(chan struct{}, 1), make(chan struct{}, 1)
			release := make(chan struct{})
			a := dnsTestUpstream(t, "a", func(ctx context.Context, q []byte) []byte {
				close(aStarted)
				select {
				case <-release:
					return dnsTestReply(q, "192.0.2.1")
				case <-ctx.Done():
					aCanceled <- struct{}{}
					return nil
				}
			})
			b := dnsTestUpstream(t, "b", func(ctx context.Context, q []byte) []byte {
				bStarted <- struct{}{}
				select {
				case <-aStarted:
				case <-ctx.Done():
					return nil
				}
				return dnsTestReply(q, "192.0.2.2")
			})
			rules := []DNSRule{{Rule: Rule{Action: "evaluate"}, Server: "a", Tag: "a"}, {Rule: Rule{MatchResponse: "a", Action: "respond"}, Race: true}, {Rule: Rule{Action: "evaluate"}, Server: "b", Tag: "b", Speculative: speculative}, {Rule: Rule{MatchResponse: "b", Action: "respond"}, Race: true}}
			r := newTestRuntime(t, Config{DNS: DNSConfig{DisableCache: true, Servers: []DNSServer{a, b}, Rules: rules}})
			done := make(chan []byte, 1)
			errCh := make(chan error, 1)
			q, _ := makeDNSQuery("parallel.test", 1)
			go func() { reply, e := r.ExchangeDNS(context.Background(), q, ""); done <- reply; errCh <- e }()
			select {
			case <-aStarted:
			case <-time.After(time.Second):
				t.Fatal("first query not sent")
			}
			want := "192.0.2.1"
			if speculative {
				want = "192.0.2.2"
				select {
				case <-bStarted:
				case <-time.After(time.Second):
					close(release)
					t.Fatal("speculative evaluation serialized")
				}
			} else {
				select {
				case <-bStarted:
					close(release)
					t.Fatal("non-speculative query bypassed pending race")
				case <-time.After(15 * time.Millisecond):
				}
				close(release)
			}
			select {
			case reply := <-done:
				if e := <-errCh; e != nil {
					t.Fatal(e)
				}
				ips, _, e := parseDNSReply(q, reply)
				if e != nil || len(ips) != 1 || ips[0].String() != want {
					t.Fatal(ips, e)
				}
			case <-time.After(time.Second):
				t.Fatal("parallel query did not finish")
			}
			if speculative {
				select {
				case <-aCanceled:
				case <-time.After(time.Second):
					t.Fatal("losing query not canceled")
				}
			}
		})
	}
}
func TestDNSParallelFallbackAndFailures(t *testing.T) {
	for _, speculative := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			t.Run(map[bool]string{false: "ordered", true: "speculative"}[speculative]+map[bool]string{false: "-filtered", true: "-failed"}[failed], func(t *testing.T) {
				a := dnsTestUpstream(t, "a", func(ctx context.Context, q []byte) []byte {
					if failed {
						return nil
					}
					return dnsTestReply(q, "192.0.2.1")
				})
				b := dnsTestUpstream(t, "b", func(ctx context.Context, q []byte) []byte { return dnsTestReply(q, "192.0.2.2") })
				r := newTestRuntime(t, Config{DNS: DNSConfig{DisableCache: true, Servers: []DNSServer{a, b}, Rules: []DNSRule{{Rule: Rule{Action: "evaluate"}, Server: "a", Tag: "a"}, {Rule: Rule{MatchResponse: "a", IPCIDR: []string{"10.0.0.0/8"}, Action: "respond"}, Race: true}, {Rule: Rule{Action: "route"}, Server: "b", Speculative: speculative}}}})
				ips := dnsTestExchange(t, r)
				if len(ips) != 1 || ips[0].String() != "192.0.2.2" {
					t.Fatal(ips)
				}
			})
		}
	}
}
func TestDNSParallelOrdinaryPriorityAndLogical(t *testing.T) {
	var hits atomic.Int32
	a := dnsTestUpstream(t, "a", func(ctx context.Context, q []byte) []byte { hits.Add(1); return dnsTestReply(q, "192.0.2.1") })
	rules := []DNSRule{
		{Rule: Rule{Action: "evaluate"}, Server: "a", Tag: "a"},
		{Rule: Rule{Action: "evaluate"}, Server: "a"},
		{Rule: Rule{MatchResponse: "@last", IPCIDR: []string{"10.0.0.0/8"}, Action: "respond"}, Race: true},
		{Rule: Rule{Type: "logical", Mode: "or", Rules: []Rule{
			{MatchResponse: "@last", IPCIDR: []string{"192.0.2.0/24"}},
			{Domain: []string{"other.test"}},
		}, Action: "respond"}},
	}
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{a}, Rules: rules}})
	ips := dnsTestExchange(t, r)
	if len(ips) != 1 || ips[0].String() != "192.0.2.1" || hits.Load() != 1 {
		t.Fatal(ips, hits.Load())
	}
}
func TestDNSParallelCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	a := dnsTestUpstream(t, "a", func(ctx context.Context, q []byte) []byte { started <- struct{}{}; <-ctx.Done(); return nil })
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{a}, Rules: []DNSRule{{Rule: Rule{Action: "evaluate"}, Server: "a", Tag: "a"}, {Rule: Rule{MatchResponse: "a", Action: "respond"}, Race: true}}}})
	ctx, cancel := context.WithCancel(context.Background())
	q, _ := makeDNSQuery("parallel.test", 1)
	done := make(chan error, 1)
	go func() { _, e := r.ExchangeDNS(ctx, q, ""); done <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	cancel()
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
}
func TestDNSParallelValidation(t *testing.T) {
	for _, raw := range []string{
		`{"race":true,"server":"a"}`,
		`{"race":true,"speculative":true,"match_response":"a","action":"respond"}`,
		`{"race":true,"match_response":"a","action":"evaluate","server":"a"}`,
		`{"speculative":true,"action":"reject"}`,
	} {
		data := []byte(`{"dns":{"servers":[{"type":"local","tag":"a"}],"rules":[{"action":"evaluate","server":"a","tag":"a"},` + raw + `]}}`)
		if _, e := Parse(data); e == nil {
			t.Fatal("bad parallel DNS rule accepted", string(data))
		}
	}
}

func TestDNSCanceledOwnerDoesNotPoisonWaiter(t *testing.T) {
	var requests atomic.Int32
	started := make(chan struct{}, 1)
	server := dnsTestUpstream(t, "up", func(ctx context.Context, q []byte) []byte {
		if requests.Add(1) == 1 {
			started <- struct{}{}
			<-ctx.Done()
			return nil
		}
		return dnsTestReply(q, "192.0.2.3")
	})
	r := newTestRuntime(t, Config{DNS: DNSConfig{DisableCache: true, Servers: []DNSServer{server}}})
	q, _ := makeDNSQuery("same.test", 1)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { _, e := r.ExchangeDNS(ctx, q, ""); first <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("owner not started")
	}
	go func() {
		reply, e := r.ExchangeDNS(context.Background(), q, "")
		if e == nil {
			ips, _, err := parseDNSReply(q, reply)
			e = err
			if e == nil && (len(ips) != 1 || ips[0].String() != "192.0.2.3") {
				e = errors.New("wrong answer")
			}
		}
		second <- e
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if e := <-first; e == nil {
		t.Fatal("owner ignored cancellation")
	}
	select {
	case e := <-second:
		if e != nil {
			t.Fatal("waiter inherited owner cancellation", e)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter blocked")
	}
}

func TestDNSParallelTagValidation(t *testing.T) {
	for _, rules := range []string{
		`[{"action":"evaluate","server":"a","tag":"x"},{"action":"evaluate","server":"a","tag":"x"}]`,
		`[{"action":"evaluate","server":"a","tag":"x"},{"action":"respond"}]`,
	} {
		if _, e := Parse([]byte(`{"dns":{"servers":[{"type":"local","tag":"a"}],"rules":` + rules + `}}`)); e == nil {
			t.Fatal("invalid evaluate tags accepted", rules)
		}
	}
}

func FuzzDNSPolicyOptions(f *testing.F) {
	f.Add([]byte(`{"action":"route","server":"a","speculative":true}`))
	f.Add([]byte(`{"action":"respond","match_response":"a","race":true}`))
	f.Add([]byte(`{"buffer_size":"1MB","flush_interval":"30s"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var rule DNSRule
		if decodeOptions(data, &rule) == nil {
			_ = validateDNSAction(rule)
			_ = validateDNSResponses([]DNSRule{{Rule: Rule{Action: "evaluate"}, Server: "a", Tag: "a"}, rule})
		}
		var cache CacheFileOptions
		if decodeOptions(data, &cache) == nil {
			_, _ = cache.bufferSize()
			_, _ = optionDuration(cache.FlushInterval, 0)
		}
	})
}
