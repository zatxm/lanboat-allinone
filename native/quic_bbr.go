package native

import (
	"math"
	"time"
)

const (
	bbrStartup = iota
	bbrDrain
	bbrProbeBW
	bbrProbeRTT
	bbrHighGain      = 2 / math.Ln2
	bbrMinimumWindow = 4 * quicMSS
)

// Relative timestamps plus loss and flight snapshots occupy 40 bytes on 64-bit hosts.
type quicDelivery struct {
	delivered              uint64
	firstSent, deliveredAt int64
	lost                   uint64
	inFlight               uint32
	appLimited, valid      bool
}

type quicBBR struct {
	model                                 *bbrModel
	tuning                                *bbrTuning
	aggregation                           *bbrACKAggregation
	startupLost                           int
	busySample, overshot                  bool
	origin, firstSent, deliveredAt        time.Time
	delivered, appUntil, round, nextRound uint64
	bandwidth                             uint64
	filter                                [10]struct{ round, rate uint64 }
	minRTT                                time.Duration
	rttAt                                 time.Time
	mode                                  int
	full                                  bool
	plateauRate                           uint64
	plateauRounds                         int
	cycle                                 uint8
	cycleAt                               time.Time
	pace                                  uint64
	probeDone                             time.Time
	probeRound                            uint64
	priorWindow                           int
	recoveryAt                            time.Time
	recoveryRound                         uint64
	conserve, idleRestart                 bool
}

func newQUICBBR(now time.Time, profile ...string) *quicBBR {
	tuning := &bbrTunings[0]
	if len(profile) != 0 {
		switch profile[0] {
		case "conservative":
			tuning = &bbrTunings[1]
		case "standard":
			tuning = &bbrTunings[2]
		case "aggressive":
			tuning = &bbrTunings[3]
		}
	}
	b := &quicBBR{tuning: tuning, origin: now, firstSent: now, deliveredAt: now, rttAt: now, pace: uint64(tuning.startup * float64(10*quicMSS) / (333 * time.Millisecond).Seconds())}
	if tuning != &bbrTunings[0] {
		b.aggregation = &bbrACKAggregation{}
	}
	return b
}

func (b *quicBBR) sent(now time.Time, inFlight, size int, applicationLimited bool) quicDelivery {
	if inFlight == 0 {
		b.firstSent, b.deliveredAt = now, now
		b.idleRestart = b.appUntil != 0
		if b.aggregation != nil {
			*b.aggregation = bbrACKAggregation{at: now}
		}
	}
	if applicationLimited || b.mode == bbrProbeRTT {
		b.appUntil = max(uint64(1), b.delivered+uint64(inFlight+size))
	}
	sample := quicDelivery{delivered: b.delivered, firstSent: b.firstSent.Sub(b.origin).Nanoseconds(), deliveredAt: b.deliveredAt.Sub(b.origin).Nanoseconds(), appLimited: b.appUntil != 0, valid: true}
	if b.model != nil {
		sample.lost, sample.inFlight = b.model.lost, uint32(inFlight+size)
	}
	return sample
}

func (b *quicBBR) gains() (pacing, window float64) {
	if b.model != nil {
		return b.model.gains(b.mode)
	}
	switch b.mode {
	case bbrStartup:
		return b.tuning.startup, b.tuning.startupWindow
	case bbrDrain:
		return 1 / b.tuning.startup, b.tuning.startupWindow
	case bbrProbeRTT:
		return 1, 1
	}
	pacing = 1
	if !b.idleRestart {
		if b.cycle == 0 {
			pacing = 1.25
		}
		if b.cycle == 1 {
			pacing = .75
		}
	}
	return pacing, b.tuning.window
}

func (b *quicBBR) quantum() int {
	rate := b.pacing(false)
	if b.model != nil {
		if b.model.v2 && rate < 150000 {
			return quicMSS
		}
		return int(min(uint64(65536), max(uint64(2*quicMSS), rate/1000)))
	}
	if rate < 150000 {
		return quicMSS
	}
	if rate < 3000000 {
		return 2 * quicMSS
	}
	return int(min(uint64(65536), rate/1000))
}

func (b *quicBBR) inflight(gain float64) int {
	if b.minRTT == 0 {
		return 10 * quicMSS
	}
	return int(min(float64(4<<20), max(float64(bbrMinimumWindow), gain*float64(b.bandwidth)*b.minRTT.Seconds()+float64(3*b.quantum()))))
}

func (b *quicBBR) probe(now time.Time) {
	b.mode, b.cycle, b.cycleAt = bbrProbeBW, 2+uint8(b.round%6), now
}

func (b *quicBBR) ack(now time.Time, packet quicSent, acknowledged, window, inFlight, priorFlight int, rtt time.Duration) int {
	if b.model != nil {
		return b.ackModel(now, packet, acknowledged, window, inFlight, priorFlight, rtt)
	}
	s := packet.delivery
	if !s.valid || acknowledged == 0 {
		return window
	}
	b.delivered += uint64(acknowledged)
	if b.appUntil != 0 && b.delivered > b.appUntil {
		b.appUntil = 0
	}
	newRound := s.delivered >= b.nextRound
	if newRound {
		b.round++
		b.nextRound = b.delivered
	}
	interval := max(packet.at.Sub(b.origin)-time.Duration(s.firstSent), now.Sub(b.origin)-time.Duration(s.deliveredAt))
	if interval > 0 {
		b.busySample = b.busySample || !s.appLimited
		rate := uint64(min(float64(1<<40), float64(b.delivered-s.delivered)/interval.Seconds()))
		if !s.appLimited || rate >= b.bandwidth {
			slot := &b.filter[b.round%uint64(len(b.filter))]
			if slot.round != b.round {
				slot.round, slot.rate = b.round, 0
			}
			slot.rate = max(slot.rate, rate)
			b.bandwidth = 0
			for _, item := range b.filter {
				if b.round-item.round < uint64(len(b.filter)) {
					b.bandwidth = max(b.bandwidth, item.rate)
				}
			}
		}
	}
	if packet.at.After(b.firstSent) {
		b.firstSent = packet.at
	}
	b.deliveredAt = now
	expired := now.Sub(b.rttAt) > 10*time.Second
	if rtt > 0 && (b.minRTT == 0 || rtt <= b.minRTT || expired) {
		b.minRTT, b.rttAt = rtt, now
	}
	if !b.full && newRound && !s.appLimited {
		if float64(b.bandwidth) >= 1.25*float64(b.plateauRate) {
			b.plateauRate, b.plateauRounds = b.bandwidth, 0
			if b.aggregation != nil && (b.tuning.conservative || b.tuning.startupBoost) {
				*b.aggregation = bbrACKAggregation{at: now}
			}
		} else {
			b.plateauRounds++
			b.full = b.plateauRounds >= b.tuning.rounds
		}
	}
	if b.mode == bbrStartup && b.full {
		b.mode = bbrDrain
	}
	if b.mode == bbrDrain && inFlight <= b.inflight(1) {
		b.probe(now)
	}
	if b.mode == bbrProbeBW {
		elapsed := now.Sub(b.cycleAt) >= b.minRTT
		advance := elapsed
		if b.cycle == 0 {
			advance = elapsed && priorFlight >= b.inflight(1.25)
		}
		if b.cycle == 1 {
			advance = elapsed || inFlight <= b.inflight(1)
			if b.tuning.conservative {
				advance = inFlight <= b.inflight(1)
				if !advance && now.Sub(b.cycleAt) >= 7*max(b.minRTT, time.Microsecond) {
					b.cycle, advance = 7, true
				}
			}
		}
		if advance {
			b.cycle, b.cycleAt = (b.cycle+1)%8, now
		}
	}
	if b.mode != bbrProbeRTT && expired && !b.idleRestart {
		b.mode, b.probeDone = bbrProbeRTT, time.Time{}
		if b.recoveryAt.IsZero() {
			b.priorWindow = window
		} else {
			b.priorWindow = max(b.priorWindow, window)
		}
	}
	if b.mode == bbrProbeRTT {
		b.appUntil = max(uint64(1), b.delivered+uint64(inFlight))
		if b.probeDone.IsZero() && inFlight <= bbrMinimumWindow {
			b.probeDone, b.probeRound = now.Add(200*time.Millisecond), b.round+1
			b.nextRound = b.delivered
		}
		if !b.probeDone.IsZero() && !now.Before(b.probeDone) && b.round >= b.probeRound {
			b.rttAt = now
			window = max(window, b.priorWindow)
			if b.full {
				b.probe(now)
			} else {
				b.mode = bbrStartup
			}
		}
	}
	if !b.recoveryAt.IsZero() {
		if packet.at.After(b.recoveryAt) {
			b.recoveryAt, b.conserve = time.Time{}, false
			window = max(window, b.priorWindow)
		} else if b.round >= b.recoveryRound {
			b.conserve = false
		}
	}
	b.idleRestart = false
	paceGain, windowGain := b.gains()
	if b.bandwidth > 0 {
		b.checkOvershoot()
		rate := uint64(float64(b.bandwidth) * paceGain)
		if b.full || rate > b.pace {
			b.pace = max(uint64(1), rate)
		}
	}
	target := b.inflight(windowGain)
	if b.aggregation != nil {
		extra := b.aggregation.update(now, b.round, b.bandwidth, acknowledged, window)
		if b.full || b.tuning.startupBoost {
			target = min(4<<20, target+extra)
		}
	}
	if b.conserve {
		window = max(window, inFlight+acknowledged)
	} else if b.full {
		window = min(window+acknowledged, target)
	} else if window < target || b.delivered < 10*quicMSS {
		window += acknowledged
	}
	window = min(4<<20, max(bbrMinimumWindow, window))
	if b.mode == bbrProbeRTT {
		window = bbrMinimumWindow
	}
	return window
}

func (b *quicBBR) lost(now, sent time.Time, size, window, inFlight int) int {
	if b.tuning.conservative && !b.full {
		b.startupLost = min(10*quicMSS+1, b.startupLost+size)
		b.checkOvershoot()
	}
	if b.recoveryAt.IsZero() {
		if b.mode != bbrProbeRTT {
			b.priorWindow = window
		} else {
			b.priorWindow = max(b.priorWindow, window)
		}
		b.recoveryRound, b.conserve = b.round+1, true
		window = inFlight + quicMSS
	} else {
		window -= size
	}
	if sent.After(b.recoveryAt) {
		b.recoveryAt = now
	}
	if b.mode == bbrProbeBW && b.cycle == 0 && now.Sub(b.cycleAt) >= b.minRTT {
		b.cycle, b.cycleAt = 1, now
	}
	if b.mode == bbrProbeRTT {
		return bbrMinimumWindow
	}
	return min(4<<20, max(bbrMinimumWindow, window, inFlight+quicMSS))
}

func (b *quicBBR) pacing(idle bool) uint64 {
	if b.model != nil {
		if (idle && b.appUntil != 0 || b.idleRestart) && b.mode == bbrProbeBW {
			return max(uint64(1), b.bandwidth*99/100)
		}
		return b.pace
	}
	if idle && b.appUntil != 0 && b.mode == bbrProbeBW {
		return max(uint64(1), b.bandwidth)
	}
	if b.full && b.bandwidth != 0 {
		gain, _ := b.gains()
		return max(uint64(1), uint64(float64(b.bandwidth)*gain))
	}
	return b.pace
}
