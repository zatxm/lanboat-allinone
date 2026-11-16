package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestQUICBrutalDeliveryWindow(t *testing.T) {
	now := time.Unix(100, 0)
	b := &quicBrutal{started: now}
	check := func(at time.Time, target uint64, rtt time.Duration, disabled bool, wantRate uint64, wantWindow int) {
		t.Helper()
		rate, window := b.pacing(at, target, rtt, disabled)
		if rate != wantRate || window != wantWindow {
			t.Fatal("Brutal pacing/window", rate, window, "want", wantRate, wantWindow)
		}
	}
	check(now, 1000000, 100*time.Millisecond, false, 1000000, 200000)
	b.feedback(now, 9*quicMSS, quicMSS)
	check(now, 1000000, 100*time.Millisecond, false, 1000000, 200000) // Sparse sample.
	b.feedback(now, 81*quicMSS, 9*quicMSS)
	check(now, 1000000, 100*time.Millisecond, false, 1111111, 222222)
	check(now, 1000000, 100*time.Millisecond, true, 1000000, 200000)
	b.feedback(now.Add(time.Second), 0, 900*quicMSS)
	check(now.Add(time.Second), 1000000, 100*time.Millisecond, false, 1250000, 250000)
	check(now.Add(6*time.Second), 1000000, 100*time.Millisecond, false, 1000000, 200000)
	b.feedback(now.Add(6*time.Second), 99*quicMSS, quicMSS)
	check(now.Add(6*time.Second), 1000000, 100*time.Millisecond, false, 1010101, 202020)
	check(now.Add(12*time.Second), 1, time.Nanosecond, false, 1, 10*quicMSS)
	check(now.Add(12*time.Second), ^uint64(0), time.Hour, false, maxHYRate, 4<<20)
}

func TestQUICBrutalACKLossAccounting(t *testing.T) {
	now := time.Unix(100, 0)
	c := &quicConn{brutal: &quicBrutal{started: now}, cwnd: 100000, srtt: time.Millisecond}
	space := &c.spaces[2]
	p := quicSent{at: now, size: quicMSS, eliciting: true}
	space.sent = map[uint64]quicSent{0: p, 1: p, 2: p, 3: p}
	c.inFlight = 4 * quicMSS
	c.acknowledge(2, 3, 0, []quicPNRange{{3, 3}}, now.Add(time.Millisecond))
	if c.cwnd != 100000 || c.inFlight != 2*quicMSS || c.brutal.buckets[0].acked != quicMSS || c.brutal.buckets[0].lost != quicMSS {
		t.Fatal("loss halved fixed-rate window or feedback missed packets", c.cwnd, c.inFlight, c.brutal)
	}
	c.acknowledge(2, 3, 0, []quicPNRange{{3, 3}}, now.Add(time.Millisecond))
	if c.brutal.buckets[0].acked != quicMSS || c.brutal.buckets[0].lost != quicMSS {
		t.Fatal("duplicate ACK changed delivery ratio")
	}
	c.acknowledge(2, 2, 0, []quicPNRange{{1, 2}}, now.Add(time.Millisecond))
	if c.inFlight != 0 || c.brutal.buckets[0].acked != 3*quicMSS {
		t.Fatal("application-limited ACKs missing from delivery ratio", c.inFlight, c.brutal)
	}
}

func TestQUICBrutalPacingAndPTO(t *testing.T) {
	now := time.Unix(100, 0)
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	c := &quicConn{cubic: new(quicCubic), cwnd: 12000, srtt: 100 * time.Millisecond, wake: make(chan struct{}, 1), send: func([]byte) error { sent++; return nil }}
	c.setBrutalRate(125000)
	space := &c.spaces[2]
	space.write, space.sent = key, make(map[uint64]quicSent)
	for range 100 {
		c.enqueue(quicFrame{data: bytes.Repeat([]byte{0}, 1100), level: 2, reliable: true})
	}
	if err = c.flush(now); err != nil || c.brutal == nil || c.cwnd != 25000 || sent == 0 || sent > 4 || c.rateNext.IsZero() {
		t.Fatal("Brutal not activated or unbounded burst", c.cwnd, sent, err)
	}
	before := sent
	if err = c.flush(now); err != nil || sent != before {
		t.Fatal("pacing credit reused", sent, err)
	}
	if err = c.flush(now.Add(20 * time.Millisecond)); err != nil || sent <= before {
		t.Fatal("pacer failed to resume", sent, err)
	}
	c.rateAt, c.rateTokens = now, 0
	c.onPTO(now)
	before = sent
	if err = c.flush(now); err != nil || sent != before+1 || c.probes[2] != 0 {
		t.Fatal("PTO was blocked by Brutal pacing", sent, err)
	}
	space.received, space.ack = []quicPNRange{{0, 0}}, true
	before = sent
	if err = c.flush(now); err != nil || sent != before+1 {
		t.Fatal("ACK was blocked by Brutal pacing", sent, err)
	}
}

func TestHysteria2BandwidthNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name, peer, advertised string
		up, down               int
		ignore                 bool
		tx                     uint64
	}{
		{"unlimited", "12500000", "0", 0, 0, false, 12500000},
		{"server-limit", "25000000", "10000000", 100, 80, false, 12500000},
		{"client-limit", "1250000", "250000", 100, 2, false, 1250000},
		{"unknown-client", "0", "0", 0, 0, false, 0},
		{"unknown-limited", "0", "1000000", 8, 8, false, 0},
		{"ignore-client", "12500000", "auto", 0, 0, true, 0},
		{"peer-overflow-bound", "18446744073709551615", "0", 0, 0, false, maxHYRate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, rx, err := hy2ServerRates(Inbound{UpMbps: tc.up, DownMbps: tc.down, IgnoreClientBandwidth: tc.ignore}, tc.peer)
			if err != nil || tx != tc.tx || rx != tc.advertised {
				t.Fatal(tx, rx, err)
			}
		})
	}
	for _, tc := range []struct {
		up   int
		peer string
		want uint64
	}{
		{100, "0", 12500000}, {100, "1250000", 1250000}, {1, "12500000", 125000}, {100, "auto", 0}, {0, "12500000", 0}, {0, "", 0},
	} {
		if got, err := hy2ClientRate(tc.up, tc.peer); err != nil || got != tc.want {
			t.Fatal("client negotiation", tc, got, err)
		}
	}
	for _, value := range []string{"auto", "-1", "+1", "1.5", "100mbps", "18446744073709551616", " 100"} {
		if _, _, err := hy2ServerRates(Inbound{}, value); err == nil {
			t.Fatal("invalid client bandwidth accepted", value)
		}
		if value != "auto" {
			if _, err := hy2ClientRate(100, value); err == nil {
				t.Fatal("invalid server bandwidth accepted", value)
			}
		}
	}
}

func TestHysteriaBandwidthConfig(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2"} {
		for _, rate := range []int{-1, 0, 1, 1000000, 1000001} {
			for _, inbound := range []bool{false, true} {
				in := Inbound{Type: kind, Tag: "server", TLS: certificate(t), Users: []User{{Password: "private"}}, UpMbps: rate, DownMbps: rate}
				out := testOutbound(t, in, "127.0.0.1:12345")
				out.UpMbps, out.DownMbps = rate, rate
				cfg := Config{Outbounds: []Outbound{out}}
				if inbound {
					cfg = Config{Inbounds: []Inbound{in}}
				}
				raw, _ := json.Marshal(cfg)
				if _, err := Parse(raw); (err == nil) != (rate >= 0 && rate <= 1000000) {
					t.Fatal("bandwidth range", kind, rate, inbound, err)
				}
			}
		}
	}
	for _, tc := range []struct {
		kind             string
		up, down         int
		ignore, disabled bool
	}{
		{"tuic", 1, 0, false, false}, {"juicity", 0, 0, false, true}, {"hysteria", 0, 0, true, false}, {"hysteria2", 1, 0, true, false},
	} {
		if err := validateHYBandwidth(tc.kind, tc.up, tc.down, tc.ignore, tc.disabled); err == nil {
			t.Fatal("ignored/conflicting bandwidth option accepted", tc)
		}
	}
}

func TestHysteriaBrutalIndependent(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2"} {
		for _, mode := range []string{"limited", "unlimited-server", "no-client-hint", "ignore-client", "disable-compensation", "asymmetric"} {
			if kind == "hysteria" && (mode == "no-client-hint" || mode == "ignore-client") {
				continue
			}
			t.Run(kind+"/"+mode, func(t *testing.T) {
				in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}, UpMbps: 30, DownMbps: 40}
				if mode == "unlimited-server" || mode == "ignore-client" {
					in.UpMbps, in.DownMbps = 0, 0
				}
				in.IgnoreClientBandwidth = mode == "ignore-client"
				in.DisableLossCompensation = mode == "disable-compensation"
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.UpMbps, out.DownMbps = 60, 20
				if mode == "no-client-hint" {
					out.UpMbps, out.DownMbps = 0, 0
				}
				if mode == "asymmetric" {
					out.UpMbps = 0
				}
				out.DisableLossCompensation = in.DisableLossCompensation
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
				session, err := client.quicClients["proxy"].session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				wantClient, wantServer := uint64(40*125000), uint64(20*125000)
				switch mode {
				case "unlimited-server":
					wantClient = 60 * 125000
				case "no-client-hint", "ignore-client":
					wantClient, wantServer = 0, 0
				case "asymmetric":
					if kind == "hysteria" {
						wantClient = 40 * 125000
					} else {
						wantClient = 0
					}
				}
				if session.conn.brutalTarget.Load() != wantClient {
					t.Fatal("client target", session.conn.brutalTarget.Load(), wantClient)
				}
				endpoint := server.quicListeners["server"]
				endpoint.mu.Lock()
				defer endpoint.mu.Unlock()
				if len(endpoint.conns) != 1 {
					t.Fatal("unexpected session count", len(endpoint.conns))
				}
				for _, conn := range endpoint.conns {
					if conn.brutalTarget.Load() != wantServer {
						t.Fatal("server target", conn.brutalTarget.Load(), wantServer)
					}
				}
			})
		}
	}
}

func TestQUICBrutalLossRecovery(t *testing.T) {
	listener := testQUICListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := net.Dial("udp", listener.packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	loss := &quicLossConn{Conn: raw}
	client, err := dialQUIC(ctx, context.Background(), loss, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"lanboat-quic-test"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	client.setBrutalRate(4000000)
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server.setBrutalRate(4000000)
	go func() {
		s, err := server.AcceptStream(ctx)
		if err == nil {
			defer s.Close()
			io.Copy(s, s)
			s.CloseWrite()
		}
	}()
	s, err := client.OpenStream(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	s.SetDeadline(time.Now().Add(12 * time.Second))
	want := bytes.Repeat([]byte("Brutal-loss-recovery"), 100000)
	written := make(chan error, 1)
	go func() {
		err := writeAll(s, want)
		if err == nil {
			err = s.CloseWrite()
		}
		written <- err
	}()
	got, err := io.ReadAll(s)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("Brutal loss roundtrip", len(got), err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-client.done
	_, window := client.brutal.pacing(time.Now(), 4000000, client.srtt, false)
	var lost uint64
	for _, bucket := range client.brutal.buckets {
		lost += bucket.lost
	}
	if loss.writes.Load() < 170 || lost == 0 || window < 10*quicMSS {
		t.Fatal("did not exercise delivery loss", loss.writes.Load(), lost, window)
	}
}

func TestHysteriaBrutalReference(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2"} {
		for _, direction := range []string{"client", "server"} {
			for _, mode := range []string{"bandwidth", "auto", "ignore-client"} {
				if kind == "hysteria" && mode != "bandwidth" {
					continue
				}
				t.Run(kind+"/"+direction+"/"+mode, func(t *testing.T) {
					in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}, UpMbps: 40, DownMbps: 40}
					in.TLS.ALPN = quicALPN(kind)
					if mode != "bandwidth" {
						in.UpMbps, in.DownMbps = 0, 0
					}
					in.IgnoreClientBandwidth = mode == "ignore-client"
					outbound := func(address string) Outbound {
						out := testOutbound(t, in, address)
						out.Username, out.UUID, out.TLS.ALPN = "", "", quicALPN(kind)
						out.UpMbps, out.DownMbps = 80, 20
						if mode == "auto" {
							out.UpMbps, out.DownMbps = 0, 0
						}
						return out
					}
					var client *Runtime
					if direction == "client" {
						in.ListenPort = unusedPort(t)
						ready := Inbound{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{ready, in}})
						client = newTestRuntime(t, Config{Outbounds: []Outbound{outbound(portAddress(in.Listen, in.ListenPort))}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{outbound(server.Address("server"))}})
						client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: local.Listen, ServerPort: local.ListenPort}}})
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 511, 4096})
					if direction == "client" {
						s, err := client.quicClients["proxy"].session(context.Background())
						if err != nil {
							t.Fatal(err)
						}
						want := uint64(40 * 125000)
						if mode != "bandwidth" {
							want = 0
						}
						if got := s.conn.brutalTarget.Load(); got != want {
							t.Fatal("reference bandwidth negotiation", strconv.FormatUint(got, 10), want)
						}
					}
				})
			}
		}
	}
}

func FuzzQUICBrutal(f *testing.F) {
	f.Add([]byte{0, 99, 1, 1, 255, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		now := time.Unix(100, 0)
		b := &quicBrutal{started: now}
		for i := 0; i+3 < min(8192, len(data)); i += 4 {
			now = now.Add(time.Duration(data[i]) * 100 * time.Millisecond)
			b.feedback(now, int(data[i+1])*quicMSS, int(data[i+2])*quicMSS)
			target := (uint64(data[i+3]) + 1) * 1000000
			rate, window := b.pacing(now, target, time.Duration(int(data[i+1])+1)*time.Millisecond, data[i]&1 != 0)
			if rate < target || rate > target*5/4 || window < 10*quicMSS || window > 4<<20 {
				t.Fatal("unbounded Brutal state", rate, window)
			}
		}
	})
}

func BenchmarkQUICBrutalFeedback(b *testing.B) {
	now := time.Unix(100, 0)
	s := &quicBrutal{started: now}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.feedback(now, quicMSS, 0)
		s.pacing(now, 10000000, 50*time.Millisecond, false)
	}
}
