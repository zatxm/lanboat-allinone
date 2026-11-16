package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

func TestQUICCubicEquations(t *testing.T) {
	now := time.Unix(100, 0)
	s := new(quicCubic)
	w := s.lost(100 * quicMSS)
	if w != 70*quicMSS || s.maximum != 100 || s.prior != 100 {
		t.Fatal("multiplicative decrease", w, s)
	}
	w = s.ack(now, w, quicMSS, 100*time.Millisecond)
	// C=.4, K=cuberoot((100-70)/.4); Reno-friendly at t=0, then the cubic curve wins.
	if w != 84009 || math.Abs(s.k-4.217163326508746) > 1e-12 {
		t.Fatal("concave region", w, s.k)
	}
	w = s.ack(now.Add(100*time.Millisecond), w, quicMSS, 100*time.Millisecond)
	if w != 84078 {
		t.Fatal("concave curve after Reno-friendly start", w)
	}
	w = s.ack(now.Add(5*time.Second), w, quicMSS, 100*time.Millisecond)
	if w != 84596 {
		t.Fatal("convex region", w)
	}
	if w = s.lost(70 * quicMSS); w != 49*quicMSS || s.maximum != 59.5 || s.prior != 70 {
		t.Fatal("fast convergence", w, s)
	}
	if w = s.lost(2 * quicMSS); w != 2*quicMSS {
		t.Fatal("minimum congestion window", w)
	}
	t.Run("reno-friendly", func(t *testing.T) {
		for _, rtt := range []time.Duration{time.Microsecond, time.Second, time.Minute} {
			s := new(quicCubic)
			w := s.ack(now, 100*quicMSS, quicMSS, rtt)
			if w != 100*quicMSS+12 {
				t.Fatal("initial Reno-friendly estimate", rtt, w)
			}
		}
		s := &quicCubic{maximum: 100, prior: 100}
		w := s.ack(now, 70*quicMSS, quicMSS, time.Microsecond)
		if w != 70*quicMSS+9 {
			t.Fatal("reduced Reno-friendly alpha", w)
		}
	})
}

func TestQUICCubicIdleAndSmallACKs(t *testing.T) {
	now := time.Unix(100, 0)
	for _, idle := range []time.Duration{0, time.Second, time.Hour, 24 * time.Hour} {
		s := &quicCubic{maximum: 100, prior: 100}
		w := s.ack(now, 70*quicMSS, quicMSS, 100*time.Millisecond)
		s.pause(now)
		got := s.ack(now.Add(idle), w, quicMSS, 100*time.Millisecond)
		if got != 84018 || s.elapsed != 0 {
			t.Fatal("idle time inflated CUBIC", idle, got, s.elapsed)
		}
	}
	s := new(quicCubic)
	w := 4 << 20
	for range 10000 {
		w = s.ack(now, w, 1, time.Microsecond)
	}
	if w != 4<<20 {
		t.Fatal("maximum congestion window", w)
	}
	s = new(quicCubic)
	w = 100 * quicMSS
	for range 10000 {
		w = s.ack(now, w, 1, time.Microsecond)
	}
	if w <= 100*quicMSS || w > 100*quicMSS+110 {
		t.Fatal("tiny ACKs lost credit or artificially increased window", w)
	}
}

func TestQUICCongestionAccounting(t *testing.T) {
	for _, cubic := range []bool{false, true} {
		now := time.Unix(100, 0)
		c := &quicConn{cwnd: 12000, ssthresh: 4 << 20, srtt: time.Millisecond}
		if cubic {
			c.cubic = new(quicCubic)
		}
		space := &c.spaces[2]
		space.sent = map[uint64]quicSent{0: {at: now, size: 100, eliciting: true}}
		c.inFlight = 100
		c.acknowledge(2, 0, 0, []quicPNRange{{0, 0}}, now.Add(time.Millisecond))
		if c.cwnd != 12000 || c.inFlight != 0 {
			t.Fatal("application-limited traffic grew congestion window", cubic, c.cwnd)
		}
		c.limitedUntil = now
		c.inFlight = 12000
		space.sent[1] = quicSent{at: now, size: 12000, eliciting: true}
		c.acknowledge(2, 1, 0, []quicPNRange{{1, 1}}, now.Add(2*time.Millisecond))
		if c.cwnd != 24000 || c.inFlight != 0 {
			t.Fatal("window-limited slow start", cubic, c.cwnd)
		}
		c.acknowledge(2, 1, 0, []quicPNRange{{1, 1}}, now.Add(time.Second))
		if c.cwnd != 24000 || c.inFlight != 0 {
			t.Fatal("duplicate ACK grew window or changed flight accounting")
		}
		p := quicSent{at: now, size: 1200, eliciting: true}
		c.inFlight = 2400
		space.sent[2], space.sent[3] = p, p
		c.losePacket(2, 2, p, now.Add(time.Second))
		window := c.cwnd
		c.losePacket(2, 3, p, now.Add(2*time.Second))
		want := 12000
		if cubic {
			want = 16800
		}
		if c.cwnd != want || c.cwnd != window || c.ssthresh != window || c.inFlight != 0 {
			t.Fatal("multiple reductions in same recovery epoch", cubic, c.cwnd)
		}
		space.sent[4] = p
		c.inFlight = p.size
		c.acknowledge(2, 4, 0, []quicPNRange{{4, 4}}, now.Add(3*time.Second))
		if c.cwnd != window {
			t.Fatal("recovery ACK increased window")
		}
	}
}

func TestQUICRenoSmallACKs(t *testing.T) {
	c := &quicConn{cwnd: 100 * quicMSS, ssthresh: 10 * quicMSS}
	for range 10000 {
		c.congestionACK(time.Time{}, 1)
	}
	if c.cwnd != 120099 || c.renoCredit == 0 {
		t.Fatal("Reno tiny ACK credit inflated or discarded", c.cwnd, c.renoCredit)
	}
}

func TestQUICCubicPacing(t *testing.T) {
	now := time.Unix(100, 0)
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	c := &quicConn{cubic: new(quicCubic), cwnd: 120000, srtt: 100 * time.Millisecond, send: func([]byte) error { sent++; return nil }}
	space := &c.spaces[2]
	space.write, space.sent = key, make(map[uint64]quicSent)
	for range 100 {
		c.enqueue(quicFrame{data: bytes.Repeat([]byte{0}, 1100), level: 2, reliable: true})
	}
	if err = c.flush(now); err != nil || sent == 0 || sent > 11 || c.rateNext.IsZero() {
		t.Fatal("unbounded burst or missing pacing wakeup", sent, c.rateNext, err)
	}
	initial := sent
	if err = c.flush(now); err != nil || sent != initial {
		t.Fatal("pacing credit reused", sent, err)
	}
	space.received, space.ack = []quicPNRange{{0, 0}}, true
	if err = c.flush(now); err != nil || sent != initial+1 || c.inFlight == 0 {
		t.Fatal("ACK blocked by pacer", sent, err)
	}
	if err = c.flush(now.Add(10 * time.Millisecond)); err != nil || sent <= initial+1 {
		t.Fatal("pacer did not resume", sent, err)
	}
	c.rateAt, c.rateTokens, c.cwnd = now, 0, c.inFlight
	c.onPTO(now)
	before := sent
	if err = c.flush(now); err != nil || sent != before+1 || c.probes[2] != 0 {
		t.Fatal("PTO blocked by pacer or congestion window", sent, err)
	}
}

func TestQUICCongestionConfiguration(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2", "tuic", "juicity"} {
		for _, algorithm := range []string{"", "cubic", "new_reno", "reno", "bbr", "bbr3", "bbr2", "brutal", "none", "Cubic"} {
			t.Run(kind+"/"+algorithm, func(t *testing.T) {
				in := Inbound{Type: kind, Tag: "server", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "private"}}, CongestionControl: algorithm}
				out := testOutbound(t, in, "127.0.0.1:12345")
				out.CongestionControl = algorithm
				valid := algorithm == "" || algorithm == "cubic" || algorithm == "bbr" || algorithm == "bbr2" || algorithm == "bbr3" || algorithm == "new_reno" || algorithm == "reno"
				for _, cfg := range []Config{{Inbounds: []Inbound{in}}, {Outbounds: []Outbound{out}}} {
					raw, _ := json.Marshal(cfg)
					if _, err := Parse(raw); (err == nil) != valid {
						t.Fatal("congestion config validation", err)
					}
				}
				if valid && proxyQUICOptions(kind, algorithm).cubic != (algorithm == "cubic" || kind == "tuic" && algorithm == "") {
					t.Fatal("wrong default or selected controller")
				}
				if valid && proxyQUICOptions(kind, algorithm).bbr != (algorithm == "bbr" || algorithm == "bbr2" || algorithm == "bbr3" || algorithm == "" && (kind == "hysteria2" || kind == "juicity")) {
					t.Fatal("wrong BBR default or selected controller")
				}
			})
		}
	}
	for _, kind := range []string{"direct", "socks", "http", "vmess", "vless", "wireguard", "dns-quic", "masque"} {
		if validateQUICCongestion(kind, "cubic") == nil {
			t.Fatal("accepted ignored congestion_control", kind)
		}
	}
}

func TestQUICCubicProxyIndependent(t *testing.T) {
	for _, mode := range []string{"hysteria", "hysteria2", "tuic", "tuic4", "juicity"} {
		for _, algorithm := range []string{"cubic", "new_reno", "reno"} {
			t.Run(mode+"/"+algorithm, func(t *testing.T) {
				kind := mode
				if mode == "tuic4" {
					kind = "tuic"
				}
				in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "private"}}, CongestionControl: algorithm}
				if mode == "tuic4" {
					in.Version = "4"
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.CongestionControl, out.Version = algorithm, in.Version
				if mode == "tuic4" {
					out.UDPRelayMode = "quic"
				}
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
				q, err := client.quicClients["proxy"].session(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if (q.conn.cubic != nil) != (algorithm == "cubic") || server.quicListeners["server"].options.cubic != (algorithm == "cubic") {
					t.Fatal("controller not connected to runtime")
				}
			})
		}
	}
}

func TestQUICCubicLossRecovery(t *testing.T) {
	listener := testQUICListener(t, quicOptions{cubic: true})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, err := net.Dial("udp", listener.packet.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	loss := &quicLossConn{Conn: raw}
	client, err := dialQUIC(ctx, context.Background(), loss, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"lanboat-quic-test"}}, quicOptions{cubic: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
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
	want := bytes.Repeat([]byte("CUBIC-loss-recovery"), 100000)
	written := make(chan error, 1)
	go func() {
		err := writeAll(s, want)
		if err == nil {
			err = s.CloseWrite()
		}
		written <- err
	}()
	got, err := io.ReadAll(s)
	if err != nil || !bytes.Equal(want, got) {
		t.Fatal("CUBIC loss roundtrip", len(got), err)
	}
	if err = <-written; err != nil {
		t.Fatal(err)
	}
	s.Close()
	client.Close()
	if loss.writes.Load() < 170 || client.cubic.prior == 0 || client.cwnd < 2*quicMSS {
		t.Fatal("test did not exercise actual CUBIC recovery", loss.writes.Load(), client.cubic.prior, client.cwnd)
	}
}

func TestQUICCubicProxyReference(t *testing.T) {
	testQUICProxyControllerReference(t, "cubic")
}

func TestQUICBBRProxyReference(t *testing.T) {
	testQUICProxyControllerReference(t, "bbr")
}

func testQUICProxyControllerReference(t *testing.T, algorithm string, kinds ...string) {
	if len(kinds) == 0 {
		kinds = []string{"hysteria", "hysteria2", "tuic"}
	}
	for _, kind := range kinds {
		for _, direction := range []string{"client", "server"} {
			t.Run(kind+"/"+direction, func(t *testing.T) {
				in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "private"}}}
				in.TLS.ALPN = quicALPN(kind)
				if kind == "hysteria2" {
					in.Users[0].UUID = ""
				}
				outbound := func(address string) Outbound {
					out := testOutbound(t, in, address)
					out.Username, out.TLS.ALPN = "", quicALPN(kind)
					if kind == "hysteria2" {
						out.UUID = ""
					}
					return out
				}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					ready := Inbound{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{ready, in}})
					out := outbound(portAddress(in.Listen, in.ListenPort))
					out.CongestionControl = algorithm
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					in.CongestionControl = algorithm
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := outbound(server.Address("server"))
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}})
					client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: local.Listen, ServerPort: local.ListenPort}}})
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func FuzzQUICCubic(f *testing.F) {
	f.Add([]byte{0, 255, 0, 1, 0, 30, 2, 100, 0, 200})
	f.Fuzz(func(t *testing.T, data []byte) {
		s, now, window := new(quicCubic), time.Unix(1, 0), 10*quicMSS
		for i := 0; i+1 < min(len(data), 8192); i += 2 {
			now = now.Add(time.Duration(data[i+1]) * time.Millisecond)
			switch data[i] % 3 {
			case 0:
				before := window
				window = s.ack(now, window, 1+int(data[i+1])*quicMSS, time.Duration(int(data[i+1])+1)*time.Millisecond)
				if window < before {
					t.Fatal("ACK reduced window")
				}
			case 1:
				window = s.lost(window)
			case 2:
				s.pause(now)
			}
			if window < 2*quicMSS || window > 4<<20 || math.IsNaN(s.window) || math.IsInf(s.window, 0) {
				t.Fatal("invalid congestion state", window, s)
			}
		}
	})
}

func BenchmarkQUICCubicACK(b *testing.B) {
	s, now, w := new(quicCubic), time.Unix(1, 0), 100*quicMSS
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w = s.ack(now, w, quicMSS, 100*time.Millisecond)
	}
}
