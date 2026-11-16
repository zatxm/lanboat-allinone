package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"math"
	"net"
	"testing"
	"time"
	"unsafe"
)

func bbrTestACK(b *quicBBR, sent, now time.Time, acked, window, inflight int, app bool, rtt time.Duration) int {
	p := quicSent{at: sent, size: acked, eliciting: true, delivery: b.sent(sent, max(1, inflight), acked, app)}
	return b.ack(now, p, acked, window, inflight, inflight+acked, rtt)
}

func TestQUICBBRDeliverySampler(t *testing.T) {
	now := time.Unix(100, 0)
	b := newQUICBBR(now)
	p := quicSent{at: now, size: quicMSS, delivery: b.sent(now, 0, quicMSS, false)}
	second := quicSent{at: now.Add(10 * time.Millisecond), size: quicMSS, delivery: b.sent(now.Add(10*time.Millisecond), quicMSS, quicMSS, false)}
	b.ack(now.Add(100*time.Millisecond), p, quicMSS, 12000, quicMSS, 2400, 100*time.Millisecond)
	if b.bandwidth != 12000 {
		t.Fatal("initial delivery sample", b.bandwidth)
	}
	b.ack(now.Add(100*time.Millisecond+time.Microsecond), second, quicMSS, 12000, 0, 1200, 90*time.Millisecond)
	if b.bandwidth != 23999 {
		t.Fatal("compressed ACK inflated delivery rate", b.bandwidth)
	}
	// Delivery over one microsecond cannot hide the earlier 100ms send span.
	b.firstSent, b.deliveredAt = now, now.Add(100*time.Millisecond)
	p = quicSent{at: now.Add(200 * time.Millisecond), size: 12000, delivery: b.sent(now.Add(200*time.Millisecond), 1, 12000, false)}
	b.ack(now.Add(200*time.Millisecond+time.Microsecond), p, 12000, 12000, 0, 12000, time.Microsecond)
	if b.bandwidth != 60000 {
		t.Fatal("send interval ignored", b.bandwidth)
	}
	latestSend := b.firstSent
	b.ack(now.Add(time.Second), second, quicMSS, 12000, 0, quicMSS, 900*time.Millisecond)
	if !b.firstSent.Equal(latestSend) {
		t.Fatal("late ACK rewound send sampling clock")
	}
	if unsafe.Sizeof(quicDelivery{}) > 40 {
		t.Fatal("unexpected per-packet sample overhead", unsafe.Sizeof(quicDelivery{}))
	}
}

func TestQUICBBRAppLimitedAndIdle(t *testing.T) {
	now := time.Unix(100, 0)
	b := newQUICBBR(now)
	b.mode, b.full, b.bandwidth, b.minRTT, b.cycleAt = bbrProbeBW, true, 1000000, 100*time.Millisecond, now
	b.filter[0].rate = b.bandwidth
	for i := range 20 {
		sent := now.Add(time.Duration(i) * time.Second)
		bbrTestACK(b, sent, sent.Add(100*time.Millisecond), 1200, 12000, 0, true, 100*time.Millisecond)
		if b.bandwidth != 1000000 || b.plateauRounds != 0 {
			t.Fatal("sparse traffic lowered bandwidth or filled pipe", b.bandwidth, b.plateauRounds)
		}
	}
	sent := now.Add(time.Hour)
	b.cycle = 0
	p := quicSent{at: sent, size: 1200, delivery: b.sent(sent, 0, 1200, true)}
	if b.pacing(true) != 1000000 {
		t.Fatal("idle restart used probe burst")
	}
	b.ack(sent.Add(100*time.Millisecond), p, 1200, 12000, 0, 1200, 100*time.Millisecond)
	if b.mode == bbrProbeRTT || b.bandwidth != 1000000 {
		t.Fatal("idle time distorted model", b.mode, b.bandwidth)
	}
	// A real busy sample is allowed to expire the old ten-round maximum.
	for i := 1; i <= 2; i++ {
		bbrTestACK(b, sent.Add(time.Duration(i)*time.Second), sent.Add(time.Duration(i+1)*time.Second), 1200, 12000, 0, false, time.Second)
	}
	if b.bandwidth >= 1000000 {
		t.Fatal("stale busy bandwidth did not expire", b.bandwidth)
	}
}

func TestQUICBBRStartupDrainAndGainCycle(t *testing.T) {
	now := time.Unix(100, 0)
	b := newQUICBBR(now)
	w := 200000
	for i := range 4 {
		sent := now.Add(time.Duration(i) * 100 * time.Millisecond)
		// Each delivery snapshot starts a new packet-timed round.
		b.firstSent, b.deliveredAt = sent, sent
		w = bbrTestACK(b, sent, sent.Add(40*time.Millisecond), 12000, w, 200000, false, 40*time.Millisecond)
	}
	if !b.full || b.mode != bbrDrain || b.bandwidth != 300000 {
		t.Fatal("startup did not detect plateau", b.full, b.mode, b.bandwidth)
	}
	if got := b.pacing(false); got != 103972 {
		t.Fatal("drain pacing", got)
	}
	sent := now.Add(time.Second)
	b.firstSent, b.deliveredAt = sent, sent
	w = bbrTestACK(b, sent, sent.Add(40*time.Millisecond), 12000, w, 1000, false, 40*time.Millisecond)
	if b.mode != bbrProbeBW || b.inflight(2) < b.inflight(1) {
		t.Fatal("queue did not drain", b.mode)
	}
	b.cycle, b.cycleAt = 0, sent
	lowFlight := b.inflight(1) / 2
	bbrTestACK(b, sent.Add(50*time.Millisecond), sent.Add(100*time.Millisecond), 1200, w, lowFlight, true, 40*time.Millisecond)
	if b.cycle != 0 {
		t.Fatal("probe advanced before filling pipe", b.cycle)
	}
	bbrTestACK(b, sent.Add(110*time.Millisecond), sent.Add(160*time.Millisecond), 1200, w, b.inflight(1.25), false, 40*time.Millisecond)
	if b.cycle != 1 || b.pacing(false) != b.bandwidth*3/4 {
		t.Fatal("probe did not enter drain phase", b.cycle)
	}
	bbrTestACK(b, sent.Add(161*time.Millisecond), sent.Add(162*time.Millisecond), 1200, w, 0, true, 40*time.Millisecond)
	if b.cycle != 2 {
		t.Fatal("drain phase did not finish early", b.cycle)
	}
	for phase := 3; phase <= 8; phase++ {
		at := b.cycleAt.Add(100 * time.Millisecond)
		bbrTestACK(b, at.Add(-40*time.Millisecond), at, 1200, w, 1000, true, 40*time.Millisecond)
		if int(b.cycle) != phase%8 {
			t.Fatal("eight-phase gain cycle", b.cycle, phase)
		}
	}
}

func TestQUICBBRProbeRTTAndRecovery(t *testing.T) {
	now := time.Unix(100, 0)
	b := newQUICBBR(now)
	b.mode, b.full, b.bandwidth, b.minRTT, b.cycleAt = bbrProbeBW, true, 1000000, 40*time.Millisecond, now
	b.filter[0].rate = b.bandwidth
	sent := now.Add(11 * time.Second)
	w := bbrTestACK(b, sent, sent.Add(100*time.Millisecond), 1200, 32000, 12000, true, 100*time.Millisecond)
	if b.mode != bbrProbeRTT || w != bbrMinimumWindow || !b.probeDone.IsZero() {
		t.Fatal("ProbeRTT started timer before draining", b.mode, w, b.probeDone)
	}
	if got := b.lost(sent.Add(101*time.Millisecond), sent, 1200, w, 12000); got != bbrMinimumWindow {
		t.Fatal("loss expanded ProbeRTT window", got)
	}
	b.recoveryAt, b.conserve = time.Time{}, false
	w = bbrTestACK(b, sent.Add(110*time.Millisecond), sent.Add(150*time.Millisecond), 1200, w, 0, true, 40*time.Millisecond)
	deadline := b.probeDone
	w = bbrTestACK(b, sent.Add(160*time.Millisecond), sent.Add(200*time.Millisecond), 1200, w, 0, true, 40*time.Millisecond)
	if b.mode != bbrProbeRTT || w != bbrMinimumWindow {
		t.Fatal("ProbeRTT ended before 200ms", b.mode, w)
	}
	w = bbrTestACK(b, deadline.Add(-30*time.Millisecond), deadline.Add(time.Millisecond), 1200, w, 0, true, 40*time.Millisecond)
	if b.mode != bbrProbeBW || w <= bbrMinimumWindow || w > 4<<20 {
		t.Fatal("ProbeRTT did not restore window", b.mode, w)
	}

	b = newQUICBBR(now)
	b.nextRound = 1000000
	w = b.lost(now.Add(time.Second), now, 1200, 100000, 80000)
	if w != 81200 || b.priorWindow != 100000 || !b.conserve {
		t.Fatal("loss did not conserve packets", w, b.priorWindow, b.conserve)
	}
	w = b.lost(now.Add(time.Second), now, 1200, w, 78800)
	if w != 80000 {
		t.Fatal("loss reduction repeated incorrectly", w)
	}
	p := quicSent{at: now, delivery: quicDelivery{valid: true}}
	w = b.ack(now.Add(2*time.Second), p, 1200, 4000, 4000, 5200, time.Second)
	if w < 5200 || !b.conserve {
		t.Fatal("first recovery round not packet-conserving", w)
	}
	p.at = now.Add(2 * time.Second)
	p.delivery = b.sent(p.at, 1, 1200, false)
	w = b.ack(now.Add(3*time.Second), p, 1200, w, 0, 1200, time.Second)
	if !b.recoveryAt.IsZero() || b.conserve || w < 100000 {
		t.Fatal("recovery did not restore saved window", w, b.conserve)
	}
}

func TestQUICBBRPacingAndDuplicateACK(t *testing.T) { testQUICBBRPacing(t, "bbr") }

func testQUICBBRPacing(t *testing.T, algorithm string) {
	now := time.Unix(100, 0)
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	sent := 0
	c := &quicConn{bbr: newQUICBBR(now), cwnd: 12000, srtt: 100 * time.Millisecond, wake: make(chan struct{}, 1), send: func([]byte) error { sent++; return nil }}
	first := 1
	if algorithm == "bbr3" {
		c.bbr = newQUICBBR3(now)
		first = 2
	} else if algorithm == "bbr2" {
		c.bbr = newQUICBBR2(now)
	}
	space := &c.spaces[2]
	space.write, space.sent = key, make(map[uint64]quicSent)
	for range 100 {
		c.enqueue(quicFrame{data: bytes.Repeat([]byte{0}, 1100), level: 2, reliable: true})
	}
	if err = c.flush(now); err != nil || sent != first || c.rateNext.IsZero() {
		t.Fatal("BBR pacing burst/wakeup", sent, err)
	}
	c.acknowledge(2, 0, 0, []quicPNRange{{0, 0}}, now.Add(100*time.Millisecond))
	delivered, rounds, bw := c.bbr.delivered, c.bbr.round, c.bbr.bandwidth
	c.acknowledge(2, 0, 0, []quicPNRange{{0, 0}}, now.Add(time.Second))
	if c.bbr.delivered != delivered || c.bbr.round != rounds || c.bbr.bandwidth != bw {
		t.Fatal("duplicate ACK changed BBR")
	}
	if err = c.flush(now.Add(2 * time.Second)); err != nil || len(space.sent) == 0 {
		t.Fatal("pacing did not resume", err)
	}
	c.rateAt, c.rateTokens, c.cwnd = now.Add(2*time.Second), 0, c.inFlight
	c.onPTO(now)
	before := sent
	if err = c.flush(now.Add(2 * time.Second)); err != nil || sent != before+1 {
		t.Fatal("PTO blocked by BBR", sent, err)
	}
}

func TestQUICBBRACKBatchOrder(t *testing.T) {
	now := time.Unix(100, 0)
	for range 128 {
		c := &quicConn{bbr: newQUICBBR(now), cwnd: 12000, inFlight: 2400}
		c.spaces[2].sent = map[uint64]quicSent{
			0: {at: now, size: 1200, eliciting: true, delivery: quicDelivery{valid: true}},
			1: {at: now, size: 1200, eliciting: true, delivery: quicDelivery{valid: true, appLimited: true}},
		}
		c.acknowledge(2, 1, 0, []quicPNRange{{0, 1}}, now.Add(100*time.Millisecond))
		if c.bbr.plateauRate != 0 || c.bbr.delivered != 2400 {
			t.Fatal("ACK map order changed latest sample", c.bbr.plateauRate, c.bbr.delivered)
		}
	}
}

func TestQUICBBRProxyIndependent(t *testing.T) {
	for _, mode := range []string{"hysteria", "hysteria2", "tuic", "tuic4", "juicity"} {
		t.Run(mode, func(t *testing.T) {
			kind := mode
			if mode == "tuic4" {
				kind = "tuic"
			}
			in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "private"}}, CongestionControl: "bbr"}
			if mode == "tuic4" {
				in.Version = "4"
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.CongestionControl, out.Version = "bbr", in.Version
			if mode == "tuic4" {
				out.UDPRelayMode = "quic"
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
			session, err := client.quicClients["proxy"].session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			client.Close()
			<-session.conn.done
			if session.conn.bbr == nil || session.conn.bbr.bandwidth == 0 || !server.quicListeners["server"].options.bbr {
				t.Fatal("BBR not connected to packet engine")
			}
		})
	}
}

func TestQUICBBRLossRecovery(t *testing.T) {
	for _, profile := range []string{"", "conservative", "standard", "aggressive", "bbr3", "bbr2"} {
		t.Run(profile, func(t *testing.T) {
			options := quicOptions{bbr: true, bbrProfile: profile, bbr3: profile == "bbr3", bbr2: profile == "bbr2"}
			listener := testQUICListener(t, options)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			raw, err := net.Dial("udp", listener.packet.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			loss := &quicLossConn{Conn: raw}
			client, err := dialQUIC(ctx, context.Background(), loss, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"lanboat-quic-test"}}, options)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			go func() {
				s, e := server.AcceptStream(ctx)
				if e == nil {
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
			want := bytes.Repeat([]byte("BBR-delivery-rate-and-loss"), 80000)
			written := make(chan error, 1)
			go func() {
				e := writeAll(s, want)
				if e == nil {
					e = s.CloseWrite()
				}
				written <- e
			}()
			got, err := io.ReadAll(s)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("BBR loss roundtrip", len(got), err)
			}
			if err = <-written; err != nil {
				t.Fatal(err)
			}
			client.Close()
			<-client.done
			if loss.writes.Load() < 170 || client.bbr.bandwidth == 0 || client.cwnd < bbrMinimumWindow || client.cwnd > 4<<20 {
				t.Fatal("BBR recovery not exercised", loss.writes.Load(), client.bbr.bandwidth, client.cwnd)
			}
		})
	}
}

func FuzzQUICBBR(f *testing.F) {
	f.Add([]byte{0, 255, 1, 255, 2, 5, 0, 50})
	f.Add([]byte{1, 255, 1, 255, 2, 5, 0, 50})
	f.Add([]byte{2, 255, 1, 255, 2, 5, 0, 50})
	f.Add([]byte{3, 255, 1, 255, 2, 5, 0, 50})
	f.Add([]byte{4, 255, 1, 255, 2, 5, 0, 50})
	f.Add([]byte{5, 255, 1, 255, 2, 5, 0, 50})
	f.Fuzz(func(t *testing.T, data []byte) {
		now := time.Unix(100, 0)
		profile := ""
		if len(data) > 0 {
			profile = [...]string{"", "conservative", "standard", "aggressive", "bbr3", "bbr2"}[data[0]%6]
		}
		b, w := newQUICBBR(now, profile), 12000
		if profile == "bbr3" {
			b = newQUICBBR3(now)
		} else if profile == "bbr2" {
			b = newQUICBBR2(now)
		}
		for i := 0; i+3 < min(len(data), 8192); i += 4 {
			now = now.Add(time.Duration(data[i]) * 100 * time.Millisecond)
			size := 1 + int(data[i+1])*1200
			flight := int(data[i+2]) * 1200
			if data[i+3]%3 == 0 {
				p := quicSent{at: now, size: size, delivery: b.sent(now, flight, size, data[i+3]&1 != 0)}
				w = b.lostPacket(now, p, w, flight)
			} else {
				p := quicSent{at: now, delivery: b.sent(now, flight, size, data[i+3]&1 != 0)}
				now = now.Add(time.Duration(int(data[i+3])+1) * time.Millisecond)
				w = b.ack(now, p, size, w, flight, flight+size, time.Duration(int(data[i+3])+1)*time.Millisecond)
			}
			if w < bbrMinimumWindow || w > 4<<20 || b.pacing(false) == 0 || b.mode < bbrStartup || b.mode > bbrProbeRTT || math.IsInf(float64(b.bandwidth), 0) {
				t.Fatal("invalid BBR state", w, b)
			}
		}
	})
}

func BenchmarkQUICBBRFeedback(b *testing.B) {
	now := time.Unix(100, 0)
	s := newQUICBBR(now)
	w := 12000
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := quicSent{at: now, delivery: s.sent(now, 12000, 1200, false)}
		now = now.Add(time.Millisecond)
		w = s.ack(now, p, 1200, w, 12000, 13200, time.Millisecond)
	}
}
