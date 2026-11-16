package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type networkTestCloser struct{ closed atomic.Bool }

func (c *networkTestCloser) Close() error { c.closed.Store(true); return nil }
func networkTestChoice(name, kind string, def bool) networkChoice {
	return networkChoice{Name: name, Kind: kind, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, Default4: def, Default6: def}
}

func TestNetworkStrategyConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"outbounds":{"type":"direct","network_strategy":"fallback","network_type":"wifi","fallback_network_type":"cellular","fallback_delay":"10ms"}}`,
		`{"http_clients":{"tag":"web","network_strategy":"hybrid","network_type":["wifi","ethernet"]}}`,
		`{"dns":{"servers":{"type":"udp","tag":"dns","server":"1.1.1.1","network_strategy":"default","network_type":"ethernet"}}}`,
		`{"route":{"rules":[{"action":"route-options","network_strategy":"hybrid","network_type":"cellular"}]}}`,
		`{"route":{"rules":[{"type":"logical","mode":"and","rules":[{"network_type":"wifi"}],"network_strategy":"fallback","network_type":"ethernet","fallback_network_type":"cellular","outbound":"direct"}]}}`,
	} {
		cfg, e := Parse([]byte(raw))
		if e != nil {
			t.Fatal(raw, e)
		}
		b, e := json.Marshal(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = Parse(b); e != nil {
			t.Fatal("round trip", e)
		}
	}
	for _, raw := range []string{
		`{"outbounds":{"type":"direct","network_strategy":"bad"}}`,
		`{"outbounds":{"type":"direct","network_type":"bluetooth"}}`,
		`{"outbounds":{"type":"direct","network_strategy":"hybrid","network_type":["wifi","wifi"]}}`,
		`{"outbounds":{"type":"direct","network_strategy":"hybrid","fallback_network_type":"cellular"}}`,
		`{"outbounds":{"type":"direct","network_strategy":"fallback","bind_interface":"lo"}}`,
		`{"outbounds":{"type":"direct","network_type":"wifi","inet4_bind_address":"127.0.0.1"}}`,
		`{"outbounds":{"type":"direct","fallback_delay":"0s"}}`,
		`{"outbounds":{"type":"direct","fallback_delay":"-1s"}}`,
		`{"route":{"rules":[{"action":"reject","network_strategy":"hybrid"}]}}`,
		`{"route":{"rules":[{"type":"logical","mode":"and","rules":[{"network_strategy":"hybrid"}],"outbound":"direct"}]}}`,
	} {
		if _, e := Parse([]byte(raw)); e == nil {
			t.Fatal("invalid configuration accepted", raw)
		}
	}
}
func TestNetworkStrategyOrderAndFilters(t *testing.T) {
	r := newTestRuntime(t, Config{})
	var reads atomic.Int32
	choices := []networkChoice{networkTestChoice("eth", "ethernet", true), networkTestChoice("wifi", "wifi", false), networkTestChoice("cell", "cellular", false)}
	r.network.read = func(context.Context, *Runtime) Metadata { reads.Add(1); return Metadata{networkChoices: choices} }
	for _, tc := range []struct {
		o                 NetworkOptions
		primary, fallback string
	}{
		{NetworkOptions{NetworkStrategy: "default"}, "eth", ""},
		{NetworkOptions{NetworkStrategy: "hybrid"}, "eth,wifi,cell", ""},
		{NetworkOptions{NetworkStrategy: "default", NetworkType: []string{"cellular", "wifi"}}, "cell,wifi", ""},
		{NetworkOptions{NetworkStrategy: "fallback", NetworkType: []string{"wifi"}}, "wifi", "eth,cell"},
		{NetworkOptions{NetworkStrategy: "fallback", NetworkType: []string{"wifi"}, FallbackNetworkType: []string{"wifi", "cellular"}}, "wifi", "cell"},
	} {
		p, f, e := r.networkCandidates(context.Background(), tc.o, netip.MustParseAddr("192.0.2.2"))
		if e != nil {
			t.Fatal(e)
		}
		names := func(cs []networkChoice) string {
			var s string
			for _, c := range cs {
				if s != "" {
					s += ","
				}
				s += c.Name
			}
			return s
		}
		if names(p) != tc.primary || names(f) != tc.fallback {
			t.Fatal(tc, names(p), names(f))
		}
	}
	if reads.Load() != 1 {
		t.Fatal("interface discovery repeated", reads.Load())
	}
	r.network.exclude("wifi", true)
	p, _, e := r.networkCandidates(context.Background(), NetworkOptions{NetworkStrategy: "hybrid", NetworkType: []string{"wifi"}}, netip.MustParseAddr("192.0.2.2"))
	if e == nil || len(p) != 0 {
		t.Fatal("internal TUN selected")
	}
	r.network.exclude("wifi", false)
	p, _, e = r.networkCandidates(context.Background(), NetworkOptions{NetworkStrategy: "default", NetworkType: []string{"wifi"}}, netip.MustParseAddr("2001:db8::2"))
	if e != nil || len(p) != 1 {
		t.Fatal(e, p)
	}
}
func TestNetworkStrategyRacing(t *testing.T) {
	first, second := networkTestChoice("first", "wifi", true), networkTestChoice("second", "cellular", false)
	t.Run("sequential", func(t *testing.T) {
		var calls []string
		c := &networkTestCloser{}
		got, e := raceNetworks(context.Background(), NetworkOptions{NetworkStrategy: "default"}, []networkChoice{first, second}, nil, false, func(ctx context.Context, n networkChoice) (*networkTestCloser, error) {
			calls = append(calls, n.Name)
			if n.Name == "first" {
				return nil, io.EOF
			}
			return c, nil
		}, func(bool) {})
		if e != nil || got != c || len(calls) != 2 || calls[0] != "first" {
			t.Fatal(got, e, calls)
		}
		got.Close()
	})
	for _, strategy := range []string{"hybrid", "fallback"} {
		t.Run(strategy, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			started := time.Now()
			var fallbackAt time.Duration
			loser := &networkTestCloser{}
			done := make(chan struct{})
			success := &networkTestCloser{}
			var mu sync.Mutex
			var states []bool
			primary, backup := []networkChoice{first}, []networkChoice{second}
			if strategy == "hybrid" {
				primary = append(primary, second)
				backup = nil
			}
			got, e := raceNetworks(ctx, NetworkOptions{NetworkStrategy: strategy, FallbackDelay: "30ms"}, primary, backup, false, func(ctx context.Context, n networkChoice) (*networkTestCloser, error) {
				if n.Name == "first" {
					<-ctx.Done()
					defer close(done)
					return loser, nil
				}
				fallbackAt = time.Since(started)
				return success, nil
			}, func(b bool) { mu.Lock(); states = append(states, b); mu.Unlock() })
			if e != nil || got != success {
				t.Fatal(e)
			}
			<-done
			for limit := time.Now().Add(time.Second); !loser.closed.Load() && time.Now().Before(limit); {
				time.Sleep(time.Millisecond)
			}
			if !loser.closed.Load() {
				t.Fatal("losing resource leaked")
			}
			got.Close()
			if strategy == "fallback" && (fallbackAt < 20*time.Millisecond || len(states) == 0 || !states[len(states)-1]) {
				t.Fatal("fallback timing/state", fallbackAt, states)
			}
		})
	}
	t.Run("early-failure", func(t *testing.T) {
		started := time.Now()
		got, e := raceNetworks(context.Background(), NetworkOptions{NetworkStrategy: "fallback", FallbackDelay: "10s"}, []networkChoice{first}, []networkChoice{second}, false, func(ctx context.Context, n networkChoice) (*networkTestCloser, error) {
			if n.Name == "first" {
				return nil, io.EOF
			}
			return &networkTestCloser{}, nil
		}, func(bool) {})
		if e != nil || time.Since(started) > time.Second {
			t.Fatal(e)
		}
		got.Close()
	})
	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		_, e := raceNetworks(ctx, NetworkOptions{NetworkStrategy: "hybrid"}, []networkChoice{first, second}, nil, false, func(ctx context.Context, n networkChoice) (*networkTestCloser, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}, func(bool) {})
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal(e)
		}
	})
	t.Run("no-fallback-interface", func(t *testing.T) {
		_, e := raceNetworks(context.Background(), NetworkOptions{NetworkStrategy: "fallback"}, []networkChoice{first}, nil, false, func(context.Context, networkChoice) (*networkTestCloser, error) { return nil, io.EOF }, func(bool) {})
		if !errors.Is(e, io.EOF) {
			t.Fatal(e)
		}
	})
}
func TestNetworkStrategyFastFallback(t *testing.T) {
	r := newTestRuntime(t, Config{})
	key := networkFallbackKey{preferred: 1, fallback: 2}
	r.network.recordFallback(key, true)
	if !r.network.fastFallback(key) {
		t.Fatal("fast fallback not entered")
	}
	r.network.fastMu.Lock()
	until := r.network.fallback[key]
	r.network.fastMu.Unlock()
	if d := time.Until(until); d < 14*time.Second || d > 15*time.Second {
		t.Fatal(d)
	}
	first, second := networkTestChoice("first", "wifi", true), networkTestChoice("second", "cellular", false)
	start := time.Now()
	got, e := raceNetworks(context.Background(), NetworkOptions{NetworkStrategy: "fallback", FallbackDelay: "10s"}, []networkChoice{first}, []networkChoice{second}, true, func(ctx context.Context, n networkChoice) (*networkTestCloser, error) {
		if n.Name == "second" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &networkTestCloser{}, nil
	}, func(b bool) { r.network.recordFallback(key, b) })
	if e != nil || time.Since(start) > time.Second || r.network.fastFallback(key) {
		t.Fatal("preferred recovery", e)
	}
	got.Close()
	r.network.recordFallback(key, true)
	r.network.fastMu.Lock()
	r.network.fallback[key] = time.Now().Add(-time.Second)
	r.network.fastMu.Unlock()
	if r.network.fastFallback(key) {
		t.Fatal("fast fallback did not expire")
	}
}
func TestNetworkStrategyRouteActions(t *testing.T) {
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "route-options", NetworkOptions: NetworkOptions{NetworkStrategy: "hybrid"}, NetworkType: []string{"ethernet"}}, {Action: "route-options", NetworkOptions: NetworkOptions{FallbackDelay: "12ms"}}, {Outbound: "direct"}}}})
	q, tag, e := r.routeTarget(context.Background(), request{network: "tcp", address: "192.0.2.2:80"})
	if e != nil || tag != "direct" || q.networkOptions == nil {
		t.Fatal(tag, e)
	}
	options := (DialOptions{}).routeNetwork(q.networkContext(context.Background()))
	if options.NetworkStrategy != "hybrid" || len(options.NetworkType) != 1 || options.FallbackDelay != "12ms" {
		t.Fatal(options)
	}
	bound := DialOptions{BindInterface: "lo"}
	got := bound.routeNetwork(q.networkContext(context.Background()))
	if got.NetworkStrategy != "" || got.BindInterface != "lo" {
		t.Fatal("rule overwrote explicit binding", got)
	}
	cfg := r.config
	cfg.Route.Rules = []Rule{{NetworkType: []string{"wifi"}, Outbound: "direct"}}
	rules, e := compileRoute(cfg.Route, r.outbounds)
	if e != nil || rules[0].networkOptions != nil || len(rules[0].rule.NetworkType) != 1 {
		t.Fatal("network_type match became action", e)
	}
}
func FuzzNetworkStrategyConfiguration(f *testing.F) {
	f.Add([]byte(`{"outbounds":{"type":"direct","network_strategy":"fallback","network_type":"wifi","fallback_delay":"5ms"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 16384 {
			_, _ = Parse(b)
		}
	})
}

func TestNetworkStrategyRefreshSelectionMetadata(t *testing.T) {
	r := newTestRuntime(t, Config{})
	reads := 0
	r.network.read = func(ctx context.Context, _ *Runtime) Metadata {
		reads++
		kind := "other"
		if selecting, _ := ctx.Value(networkSelectionKey{}).(bool); selecting {
			kind = "cellular"
		}
		return Metadata{networkChoices: []networkChoice{networkTestChoice("modem", kind, true)}}
	}
	r.network.snapshot(context.Background(), r)
	p, _, e := r.networkCandidates(context.Background(), NetworkOptions{NetworkStrategy: "default", NetworkType: []string{"cellular"}}, netip.MustParseAddr("192.0.2.9"))
	if e != nil || len(p) != 1 || reads != 2 {
		t.Fatal(p, reads, e)
	}
}

func TestNetworkStrategyDNSContextIsolation(t *testing.T) {
	target := tcpEcho(t)
	_, port, _ := net.SplitHostPort(target)
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "udp", Tag: "dns", Server: "127.0.0.1"}}}})
	var queries atomic.Int32
	r.resolver.tunnelDial = func(ctx context.Context, _ DNSServer, _ string) (net.Conn, error) {
		if p, _ := ctx.Value(networkRouteKey{}).(*NetworkOptions); p != nil {
			t.Error("business routing options reached DNS")
		}
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			q := make([]byte, 4096)
			n, e := b.Read(q)
			if e != nil {
				return
			}
			q = q[:n]
			answer := dnsAnswer(q)
			_, end, _ := dnsName(q, 12)
			if binary.BigEndian.Uint16(q[end:]) == 1 {
				copy(answer[len(answer)-4:], []byte{127, 0, 0, 1})
			} else {
				copy(answer[len(answer)-16:], netip.MustParseAddr("::1").AsSlice())
			}
			queries.Add(1)
			b.Write(answer)
		}()
		return a, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, networkRouteKey{}, &NetworkOptions{FallbackDelay: "1ms"})
	c, e := r.dialOutbound(ctx, "direct", "tcp", net.JoinHostPort("network-isolation.test", port))
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if queries.Load() == 0 {
		t.Fatal("DNS fixture was not used")
	}
}

func TestNetworkStrategyCanceledFallbackState(t *testing.T) {
	for range 32 {
		ctx, cancel := context.WithCancel(context.Background())
		started := make(chan struct{})
		var recorded atomic.Int32
		done := make(chan error, 1)
		go func() {
			_, e := raceNetworks(ctx, NetworkOptions{NetworkStrategy: "fallback", FallbackDelay: "10s"}, []networkChoice{networkTestChoice("primary", "wifi", true)}, []networkChoice{networkTestChoice("backup", "cellular", false)}, false, func(ctx context.Context, c networkChoice) (*networkTestCloser, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}, func(bool) { recorded.Add(1) })
			done <- e
		}()
		<-started
		cancel()
		if e := <-done; !errors.Is(e, context.Canceled) || recorded.Load() != 0 {
			t.Fatal("caller cancellation changed interface health", e, recorded.Load())
		}
	}
}
