package native

import (
	"context"
	"math"
	"os"
	"testing"
	"time"
	"unsafe"
)

func bbr3Model(now time.Time) *quicBBR {
	b := newQUICBBR3(now)
	b.bandwidth, b.minRTT = 1000000, 100*time.Millisecond
	b.model.maxBW[0] = b.bandwidth
	return b
}

func TestQUICBBR3GainsAndBudget(t *testing.T) {
	t.Logf("delivery=%d bytes, sent=%d bytes, v3=%d bytes", unsafe.Sizeof(quicDelivery{}), unsafe.Sizeof(quicSent{}), unsafe.Sizeof(bbrModel{}))
	b := bbr3Model(time.Unix(100, 0))
	for _, tc := range []struct {
		mode, phase int
		pace, gain  float64
	}{
		{bbrStartup, 0, 4 * math.Ln2, 2}, {bbrDrain, 0, .5, 2}, {bbrProbeRTT, 0, 1, .5},
		{bbrProbeBW, bbrDown, .9, 2}, {bbrProbeBW, bbrCruise, 1, 2},
		{bbrProbeBW, bbrRefill, 1, 2}, {bbrProbeBW, bbrUp, 1.25, 2.25},
	} {
		b.mode, b.model.phase = tc.mode, tc.phase
		pace, gain := b.gains()
		if pace != tc.pace || gain != tc.gain {
			t.Fatal(tc, pace, gain)
		}
	}
	if unsafe.Sizeof(quicDelivery{}) != 40 || unsafe.Sizeof(bbrModel{}) > 1400 {
		t.Fatal("unexpected fixed sample/model size", unsafe.Sizeof(quicDelivery{}), unsafe.Sizeof(bbrModel{}))
	}
	b.mode = bbrStartup
	b.pace = 1000000
	if b.budgetModel(b.bdpModel(2)) != 200000 || b.quantum() != 2*quicMSS {
		t.Fatal("QUIC budget adds TCP offload padding")
	}
	b.mode, b.model.phase = bbrProbeBW, bbrUp
	if b.budgetModel(b.bdpModel(2.25)) != 225000+2*quicMSS {
		t.Fatal("missing UP quantization budget")
	}
}

func TestQUICBBR3PlateauAndApplicationLimited(t *testing.T) {
	for _, app := range []bool{false, true} {
		now := time.Unix(100, 0)
		b := newQUICBBR3(now)
		w := 200000
		for i := 0; i < 4; i++ {
			sent := now.Add(time.Duration(i) * 100 * time.Millisecond)
			b.firstSent, b.deliveredAt = sent, sent
			w = bbrTestACK(b, sent, sent.Add(40*time.Millisecond), 12000, w, 200000, app, 40*time.Millisecond)
		}
		if b.full == app || (b.mode == bbrDrain) == app {
			t.Fatal("plateau/app-limited Startup", app, b.full, b.mode)
		}
	}
}

func TestQUICBBR3Cycle(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	b.full = true
	b.downModel(now)
	if b.model.wait < 2*time.Second || b.model.wait >= 3*time.Second || b.model.sinceProbe > 1 {
		t.Fatal("probe randomization bounds")
	}
	b.model.flightLong = 100000
	b.cycleModel(now.Add(time.Millisecond), false, 1000000, 0, 80000, 1200, 100000, 90000, 100000, false)
	if b.model.phase != bbrDown {
		t.Fatal("DOWN ignored headroom")
	}
	b.cycleModel(now.Add(2*time.Millisecond), true, 1000000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.phase != bbrCruise || b.model.cycle != 1 {
		t.Fatal("DOWN sampling/CRUISE", b.model)
	}
	b.model.bwShort, b.model.flightShort = 100000, 12000
	b.cycleModel(now.Add(3*time.Second), false, 1000000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.phase != bbrRefill || b.model.bwShort != bbrInfinity || b.model.flightShort != bbrInfinity {
		t.Fatal("REFILL did not clear short model")
	}
	b.cycleModel(now.Add(3100*time.Millisecond), false, 1000000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.phase != bbrRefill {
		t.Fatal("REFILL must last a round")
	}
	b.cycleModel(now.Add(3200*time.Millisecond), true, 1000000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.phase != bbrUp || !b.model.checkLoss {
		t.Fatal("missing UP")
	}
	b.model.fullNow = true
	b.cycleModel(now.Add(3300*time.Millisecond), false, 1000000, 0, 80000, 1200, 100000, 80000, 80000, false)
	if b.model.phase != bbrDown {
		t.Fatal("plateau did not end UP")
	}
}

func TestQUICBBR3RenoClockAndPrecaution(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	b.full = true
	b.downModel(now)
	b.model.sinceProbe = 63
	b.cycleModel(now, false, 1000000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.phase != bbrRefill {
		t.Fatal("Reno clock ignored")
	}
	b.model.phase, b.model.tooHigh, b.model.flightLong = bbrUp, true, 100000
	b.cycleModel(now, false, 1000000, 0, 100000, 1200, 100000, 100000, 100000, false)
	if b.model.phase != bbrDown || !b.model.precautionary {
		t.Fatal("precautionary deceleration")
	}
	b.cycleModel(now.Add(time.Millisecond), true, 1000000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.phase != bbrRefill {
		t.Fatal("safe precautionary probe should resume promptly")
	}
}

func TestQUICBBR3ShortTermLoss(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	b.full, b.mode, b.model.phase = true, bbrProbeBW, bbrCruise
	b.cycleAt, b.model.wait = now, 3*time.Second
	p := quicSent{at: now, size: 1200, delivery: b.sent(now, 100000, 1200, false)}
	b.lostPacket(now.Add(time.Millisecond), p, 100000, 98800)
	bbrTestACK(b, now.Add(100*time.Millisecond), now.Add(200*time.Millisecond), 1200, 100000, 50000, false, 100*time.Millisecond)
	if b.model.bwShort != 700000 || b.model.flightShort != 70000 || b.bandwidth != 700000 {
		t.Fatal("non-probing loss must bound both rate and volume once per loss round", b.model.bwShort, b.model.flightShort, b.bandwidth)
	}
	before := b.model.bwShort
	bbrTestACK(b, now.Add(200*time.Millisecond), now.Add(300*time.Millisecond), 1200, 70000, 50000, false, 100*time.Millisecond)
	if b.model.bwShort != before {
		t.Fatal("no new loss should not cut again")
	}
}

func TestQUICBBR3ProbeLossAndAppLimited(t *testing.T) {
	for _, app := range []bool{false, true} {
		now := time.Unix(100, 0)
		b := bbr3Model(now)
		b.full, b.mode, b.model.phase, b.model.checkLoss = true, bbrProbeBW, bbrUp, true
		p := quicSent{at: now, size: 1200, delivery: b.sent(now, 100000, 1200, app)}
		for i := 0; i < 3; i++ {
			b.lostPacket(now.Add(time.Millisecond), p, 100000, 100000-(i+1)*1200)
		}
		if b.model.phase != bbrDown || !b.model.tooHigh || b.model.checkLoss {
			t.Fatal("loss must stop UP once")
		}
		if (b.model.flightLong == bbrInfinity) != app {
			t.Fatal("app-limited loss must not tighten long model", app, b.model.flightLong)
		}
	}
}

func TestQUICBBR3StartupLoss(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	for i := 0; i < 6; i++ {
		p := quicSent{at: now, size: 1200, delivery: b.sent(now, 100000, 1200, false)}
		b.lostPacket(now.Add(time.Millisecond), p, 100000, 100000-(i+1)*1200)
	}
	bbrTestACK(b, now.Add(100*time.Millisecond), now.Add(200*time.Millisecond), 1200, 100000, 200000, false, 100*time.Millisecond)
	// This ACK's packet was sent after the losses and must not be used as a lossy sample.
	if b.full {
		t.Fatal("post-loss packet was misclassified as Startup loss")
	}
	b = bbr3Model(now)
	p := quicSent{at: now, size: 1200, delivery: b.sent(now, 100000, 1200, false)}
	for i := 0; i < 6; i++ {
		b.lostPacket(now.Add(time.Millisecond), p, 100000, 98800)
	}
	b.ack(now.Add(100*time.Millisecond), p, 1200, 100000, 200000, 201200, 100*time.Millisecond)
	if !b.full || b.mode != bbrDrain || b.model.flightLong == bbrInfinity {
		t.Fatal("sustained Startup loss did not exit", b.full, b.mode)
	}
}

func TestQUICBBR3DrainTimeout(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	b.full, b.mode = true, bbrDrain
	for i := 0; i < 4; i++ {
		sent := now.Add(time.Duration(i) * 100 * time.Millisecond)
		b.firstSent, b.deliveredAt = sent, sent
		bbrTestACK(b, sent, sent.Add(50*time.Millisecond), 1200, 100000, 400000, false, 50*time.Millisecond)
	}
	if b.mode != bbrProbeBW {
		t.Fatal("overestimated model stuck in Drain", b.mode)
	}
}

func TestQUICBBR3ProbeRTTAndIdle(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	b.full = true
	b.downModel(now)
	bbrTestACK(b, now.Add(10*time.Second), now.Add(10100*time.Millisecond), 1200, 200000, 40000, false, 100*time.Millisecond)
	if b.mode != bbrProbeRTT || b.probeDone.IsZero() || b.model.probeWindow != 50000 {
		t.Fatal("10s ProbeRTT/half-BDP", b.mode, b.model.probeWindow)
	}
	w := bbrTestACK(b, now.Add(10150*time.Millisecond), now.Add(10250*time.Millisecond), 1200, 50000, 40000, false, 100*time.Millisecond)
	if b.mode != bbrProbeRTT || w > 50000 {
		t.Fatal("ProbeRTT exited before 200ms")
	}
	bbrTestACK(b, now.Add(10300*time.Millisecond), now.Add(10400*time.Millisecond), 1200, 50000, 40000, false, 100*time.Millisecond)
	if b.mode != bbrProbeBW || b.model.phase != bbrCruise {
		t.Fatal("ProbeRTT did not restore CRUISE")
	}
	b.model.phase = bbrUp
	b.appUntil = b.delivered + 1
	b.sent(now.Add(time.Minute), 0, 1200, true)
	if b.pacing(true) != b.bandwidth*99/100 || b.aggregation.bytes != 0 {
		t.Fatal("idle must avoid probe burst")
	}
	bbrTestACK(b, now.Add(time.Minute), now.Add(time.Minute+100*time.Millisecond), 1200, 100000, 0, true, 100*time.Millisecond)
	if b.mode == bbrProbeRTT {
		t.Fatal("idle refresh needlessly forced ProbeRTT")
	}
	b.mode, b.probeRound, b.round, b.appUntil = bbrProbeRTT, 10, 10, b.delivered+1
	b.probeDone, b.priorWindow = now, 200000
	w = b.resumeModel(now.Add(time.Hour), 0, bbrMinimumWindow)
	if b.mode != bbrProbeBW || b.model.phase != bbrCruise || w != 200000 {
		t.Fatal("idle restart must restore expired ProbeRTT before transmitting", b.mode, w)
	}
}

func TestQUICBBR3SpuriousLoss(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	b.full, b.mode, b.model.phase, b.model.checkLoss = true, bbrProbeBW, bbrUp, true
	p := quicSent{at: now, size: 1200, delivery: b.sent(now, 12000, 1200, false)}
	b.lostPacket(now.Add(time.Millisecond), p, 12000, 10800)
	b.model.recordLoss(2, 1)
	b.model.recordLoss(1, 2)
	b.ackLostModel(2, []quicPNRange{{low: 1, high: 2}}, now, 10000)
	if b.model.flightLong == bbrInfinity {
		t.Fatal("partial ACK or wrong packet space incorrectly undid loss")
	}
	b.ackLostModel(1, []quicPNRange{{low: 2, high: 2}}, now, 10000)
	if b.model.flightLong != bbrInfinity || b.model.phase != bbrRefill || !b.recoveryAt.IsZero() {
		t.Fatal("proven spurious recovery not restored")
	}
	for i := 0; i < 65; i++ {
		b.model.recordLoss(2, uint64(i))
	}
	b.model.flightLong = 10000
	b.ackLostModel(2, []quicPNRange{{low: 0, high: 100}}, now, 10000)
	if b.model.flightLong != 10000 || !b.model.lossOverflow {
		t.Fatal("forgotten losses must prohibit undo")
	}
}

func TestQUICBBR3SamplerFilterAndSlope(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr3Model(now)
	p := quicSent{at: now, size: 1200, delivery: b.sent(now, 100000, 1200, false)}
	b.ack(now.Add(time.Millisecond), p, 1200, 100000, 90000, 91200, time.Millisecond)
	if b.model.maxBW[0] != 1000000 || b.plateauRounds != 0 {
		t.Fatal("sub-minRTT sample inflated bandwidth or caused plateau")
	}
	b.full, b.mode, b.model.phase = true, bbrProbeBW, bbrUp
	b.model.flightLong = 100000
	b.model.slope(100000)
	b.cycleModel(now, false, 1000000, 0, 100000, 100000, 100000, 90000, 100000, false)
	if b.model.flightLong != 100000+quicMSS {
		t.Fatal("ACK-clocked long-term growth", b.model.flightLong)
	}
	b.downModel(now)
	b.cycleModel(now, true, 500000, 0, 80000, 1200, 100000, 80000, 100000, true)
	if b.model.cycle != 0 {
		t.Fatal("application-limited cycle expired max-bandwidth sample")
	}
	b.downModel(now)
	b.cycleModel(now, true, 500000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.cycle != 1 || b.model.maxBW[0] != 1000000 {
		t.Fatal("filter did not retain previous cycle")
	}
	b.model.maxBW[1] = 500000
	b.downModel(now)
	b.cycleModel(now, true, 500000, 0, 80000, 1200, 100000, 80000, 100000, false)
	if b.model.cycle != 2 || max(b.model.maxBW[0], b.model.maxBW[1]) != 500000 {
		t.Fatal("stale bandwidth did not expire after two probe cycles")
	}
}

func TestQUICBBR3PacingAndDuplicateACK(t *testing.T) { testQUICBBRPacing(t, "bbr3") }

func TestQUICBBR3ProxyIndependent(t *testing.T) {
	testQUICBBRProxyIndependent(t, "bbr3")
}

func testQUICBBRProxyIndependent(t *testing.T, algorithm string) {
	for _, mode := range []string{"hysteria", "hysteria2", "tuic", "tuic4", "juicity"} {
		t.Run(mode, func(t *testing.T) {
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
			client.resetNetworkTransports()
			assertTCP(t, client)
			session, err := client.quicClients["proxy"].session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			client.Close()
			<-session.conn.done
			if session.conn.bbr == nil || session.conn.bbr.model == nil || session.conn.bbr.model.v2 != (algorithm == "bbr2") || session.conn.bbr.bandwidth == 0 || server.quicListeners["server"].options.bbr2 != (algorithm == "bbr2") || server.quicListeners["server"].options.bbr3 != (algorithm == "bbr3") {
				t.Fatal("BBR version not connected to packet engine", algorithm)
			}
		})
	}
}

func TestQUICBBR3ProxyReference(t *testing.T) {
	testQUICProxyControllerReference(t, "bbr3")
}

func TestQUICBBR3ModernReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", reference)
	testQUICProxyControllerReference(t, "bbr3", "hysteria2", "tuic")
}

func TestQUICBBR3TUIC4Reference(t *testing.T) { testTUIC4ControllerReference(t, "bbr3") }

func TestQUICBBR3JuicityReference(t *testing.T) {
	t.Run("client", func(t *testing.T) { testJuicityOfficialServer(t, "bbr3") })
	t.Run("server", func(t *testing.T) { testJuicityOfficialClient(t, "bbr3") })
}

func TestQUICBBR3BrutalPriority(t *testing.T) {
	testQUICBBRBrutalPriority(t, "bbr3")
}

func testQUICBBRBrutalPriority(t *testing.T, algorithm string) {
	in := Inbound{Type: "hysteria2", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}, CongestionControl: algorithm}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.CongestionControl = algorithm
	out.UpMbps, out.DownMbps = 20, 20
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, client)
	assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
	session, err := client.quicClients["proxy"].session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	<-session.conn.done
	if session.conn.bbr == nil || session.conn.bbr.model == nil || session.conn.bbr.model.v2 != (algorithm == "bbr2") || session.conn.brutal == nil {
		t.Fatal("HY2 negotiated Brutal must take priority over BBR", algorithm)
	}
}

func TestQUICBBR3LossBatchOrder(t *testing.T) {
	now := time.Unix(100, 0)
	var want int
	for attempt := 0; attempt < 50; attempt++ {
		b := bbr3Model(now)
		b.full, b.mode, b.model.phase, b.model.checkLoss = true, bbrProbeBW, bbrUp, true
		c := &quicConn{bbr: b, cwnd: 100000, inFlight: 3600, srtt: 100 * time.Millisecond, latestRTT: 100 * time.Millisecond}
		c.spaces[2].sent = map[uint64]quicSent{}
		for i := 0; i < 3; i++ {
			c.spaces[2].sent[uint64(i)] = quicSent{at: now, size: 1200, eliciting: true, delivery: b.sent(now, 10000+i*1200, 1200, false)}
		}
		c.acknowledge(2, 10, 0, []quicPNRange{{low: 10, high: 10}}, now.Add(time.Millisecond))
		if attempt == 0 {
			want = b.model.flightLong
		}
		if b.model.flightLong != want || b.model.lossCount != 3 || c.inFlight != 0 {
			t.Fatal("loss map order changed model", attempt, b.model.flightLong, want)
		}
	}
}

func BenchmarkQUICBBR3Feedback(b *testing.B) {
	now := time.Unix(100, 0)
	s, w := newQUICBBR3(now), 12000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := quicSent{at: now, size: 1200, delivery: s.sent(now, 12000, 1200, false)}
		now = now.Add(time.Millisecond)
		w = s.ack(now, p, 1200, w, 12000, 13200, time.Millisecond)
	}
}
