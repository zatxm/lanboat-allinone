package native

import (
	"os"
	"testing"
	"time"
)

func bbr2Model(now time.Time) *quicBBR {
	b := newQUICBBR2(now)
	b.bandwidth, b.minRTT, b.model.probeRTT = 1000000, 100*time.Millisecond, 100*time.Millisecond
	b.model.maxBW[0] = b.bandwidth
	return b
}

func TestQUICBBR2GainsAndBudget(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr2Model(now)
	b.mode, b.model.phase = bbrProbeBW, bbrUp
	if pace, gain := b.gains(); pace != 1.25 || gain != 2 {
		t.Fatal("v2 UP gains", pace, gain)
	}
	b.pace = 149999
	if b.quantum() != quicMSS {
		t.Fatal("low-rate v2 quantum")
	}
	b.pace = 150000
	if b.quantum() != 2*quicMSS || b.budgetModel(b.bdpModel(2)) != 200000+2*quicMSS {
		t.Fatal("v2 probe budget")
	}
	b.mode, b.model.flightLong = bbrDrain, 50000
	if b.boundModel(100000) != 50000 {
		t.Fatal("v2 Drain ignored long-term loss bound")
	}
}

func TestQUICBBR2QueueProbeExit(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr2Model(now)
	b.full = true
	b.refillModel()
	b.cycleModel(now.Add(time.Second), true, 1000000, 0, 100000, 1200, 200000, 100000, 101200, false)
	if b.model.phase != bbrUp || b.cycleAt != now.Add(time.Second) {
		t.Fatal("UP must restart its wall clock")
	}
	b.model.fullNow = true
	b.cycleModel(now.Add(1050*time.Millisecond), false, 1000000, 0, 200000, 1200, 200000, 200000, 201200, false)
	if b.model.phase != bbrUp {
		t.Fatal("v2 must not use v3's bandwidth-plateau exit or exit before one RTT")
	}
	b.cycleModel(now.Add(1100*time.Millisecond), true, 1000000, 0, 100000, 1200, 200000, 100000, 101200, false)
	if b.model.phase != bbrUp {
		t.Fatal("v2 must wait for the queue threshold")
	}
	b.cycleModel(now.Add(1200*time.Millisecond), true, 1000000, 0, 200000, 1200, 200000, 200000, 201200, false)
	if b.model.phase != bbrDown || !b.model.stopping {
		t.Fatal("v2 queue threshold did not end probing")
	}
}

func TestQUICBBR2RTTWindows(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr2Model(now)
	if b.minRTT2(now.Add(4*time.Second), 120*time.Millisecond) || b.minRTT != 100*time.Millisecond {
		t.Fatal("raised 10s minimum before expiration")
	}
	if !b.minRTT2(now.Add(6*time.Second), 120*time.Millisecond) || b.minRTT != 100*time.Millisecond || b.model.probeRTT != 120*time.Millisecond {
		t.Fatal("5s probe and 10s path estimates are not independent")
	}
	if b.minRTT2(now.Add(11*time.Second), 130*time.Millisecond) || b.minRTT != 120*time.Millisecond {
		t.Fatal("expired path minimum did not use the recent probe minimum")
	}
	b = bbr2Model(now)
	if b.minRTT2(now.Add(4*time.Second), 90*time.Millisecond) || b.minRTT2(now.Add(6*time.Second), 100*time.Millisecond) || b.minRTT != 90*time.Millisecond {
		t.Fatal("natural RTT improvement must postpone the probe")
	}
}

func TestQUICBBR2ProbeRTTAndIdle(t *testing.T) {
	for _, idle := range []bool{false, true} {
		t.Run(map[bool]string{false: "busy", true: "idle"}[idle], func(t *testing.T) {
			now := time.Unix(100, 0)
			b := bbr2Model(now)
			b.full, b.mode = true, bbrProbeBW
			b.model.phase, b.cycleAt, b.model.wait = bbrCruise, now, 3*time.Second
			flight := 40000
			if idle {
				flight, b.appUntil = 0, 1
				b.sent(now.Add(6*time.Second), 0, 1200, true)
			}
			w := bbrTestACK(b, now.Add(6*time.Second), now.Add(6100*time.Millisecond), 1200, 200000, flight, idle, 100*time.Millisecond)
			if idle {
				if b.mode == bbrProbeRTT {
					t.Fatal("natural idle period must not cause a redundant ProbeRTT")
				}
				return
			}
			if b.mode != bbrProbeRTT || b.probeDone.IsZero() || w > 50000 {
				t.Fatal("v2 did not enter half-BDP ProbeRTT at 5s", b.mode, w)
			}
			w = bbrTestACK(b, now.Add(6200*time.Millisecond), now.Add(6301*time.Millisecond), 1200, w, 0, true, 100*time.Millisecond)
			if b.mode != bbrProbeBW || w < 200000 || w > 201200 || b.model.probeAt != now.Add(6301*time.Millisecond) || b.rttAt != now {
				t.Fatal("ProbeRTT must restore cwnd and reset only its 5s scheduling clock", b.mode, w, b.model.probeAt, b.rttAt)
			}
		})
	}
}

func TestQUICBBR2DrainWaitsForPipe(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr2Model(now)
	b.full, b.mode = true, bbrDrain
	for i := 0; i < 4; i++ {
		sent := now.Add(time.Duration(i) * 100 * time.Millisecond)
		b.firstSent, b.deliveredAt = sent, sent
		bbrTestACK(b, sent, sent.Add(50*time.Millisecond), 1200, 100000, 400000, false, 50*time.Millisecond)
	}
	if b.mode != bbrDrain {
		t.Fatal("v2 must not use v3's three-round Drain timeout")
	}
	bbrTestACK(b, now.Add(500*time.Millisecond), now.Add(600*time.Millisecond), 1200, 100000, 0, false, 50*time.Millisecond)
	if b.mode != bbrProbeBW {
		t.Fatal("empty pipe did not finish Drain")
	}
}

func TestQUICBBR2StartupLossRanges(t *testing.T) {
	for _, gap := range []uint64{1, 2} {
		t.Run(map[uint64]string{1: "one-burst", 2: "three-ranges"}[gap], func(t *testing.T) {
			now := time.Unix(100, 0)
			b := bbr2Model(now)
			p := quicSent{at: now, size: 1200, delivery: b.sent(now, 100000, 1200, false)}
			for i := range 3 {
				b.lostPacket(now.Add(time.Millisecond), p, 100000, 100000-(i+1)*1200)
				b.model.recordLoss(2, uint64(i)*gap)
			}
			b.ack(now.Add(100*time.Millisecond), p, 1200, 100000, 200000, 201200, 100*time.Millisecond)
			if b.full != (gap == 2) {
				t.Fatal("Startup must require three disjoint ranges in a completed recovery round", gap, b.full)
			}
		})
	}
}

func TestQUICBBR2ShortLossAndUndo(t *testing.T) {
	now := time.Unix(100, 0)
	b := bbr2Model(now)
	b.full, b.mode, b.model.phase = true, bbrProbeBW, bbrCruise
	b.cycleAt, b.model.wait = now, 3*time.Second
	p := quicSent{at: now, size: 1200, delivery: b.sent(now, 100000, 1200, false)}
	b.lostPacket(now.Add(time.Millisecond), p, 100000, 98800)
	b.model.recordLoss(2, 42)
	w := bbrTestACK(b, now.Add(100*time.Millisecond), now.Add(200*time.Millisecond), 1200, 100000, 50000, false, 100*time.Millisecond)
	if b.model.bwShort != 700000 || b.model.flightShort != 70000 {
		t.Fatal("v2 short-term loss did not constrain rate and volume")
	}
	w = b.ackLostModel(2, []quicPNRange{{low: 42, high: 42}}, now.Add(300*time.Millisecond), w)
	if b.model.bwShort != bbrInfinity || b.model.flightShort != bbrInfinity || w != 100000 {
		t.Fatal("proven spurious loss did not restore model", w)
	}
}

func TestQUICBBR2PacingAndDuplicateACK(t *testing.T) { testQUICBBRPacing(t, "bbr2") }
func TestQUICBBR2ProxyIndependent(t *testing.T)      { testQUICBBRProxyIndependent(t, "bbr2") }
func TestQUICBBR2BrutalPriority(t *testing.T)        { testQUICBBRBrutalPriority(t, "bbr2") }
func TestQUICBBR2ProxyReference(t *testing.T)        { testQUICProxyControllerReference(t, "bbr2") }
func TestQUICBBR2TUIC4Reference(t *testing.T)        { testTUIC4ControllerReference(t, "bbr2") }

func TestQUICBBR2ModernReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if reference == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", reference)
	testQUICProxyControllerReference(t, "bbr2", "hysteria2", "tuic")
}

func TestQUICBBR2JuicityReference(t *testing.T) {
	t.Run("client", func(t *testing.T) { testJuicityOfficialServer(t, "bbr2") })
	t.Run("server", func(t *testing.T) { testJuicityOfficialClient(t, "bbr2") })
}

func BenchmarkQUICBBR2Feedback(b *testing.B) {
	now := time.Unix(100, 0)
	s, w := newQUICBBR2(now), 12000
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := quicSent{at: now, size: 1200, delivery: s.sent(now, 12000, 1200, false)}
		now = now.Add(time.Millisecond)
		w = s.ack(now, p, 1200, w, 12000, 13200, time.Millisecond)
	}
}
