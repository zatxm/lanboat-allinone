package native

import (
	"math"
	"math/rand/v2"
	"time"
)

const (
	bbrDown = iota
	bbrCruise
	bbrRefill
	bbrUp
	bbrInfinity = 1 << 60
)

// BBRv2/v3 share delivery and loss bounds, but use different probe exit criteria.
type bbrModel struct {
	v2                                    bool
	probeRTT                              time.Duration
	probeAt                               time.Time
	phase                                 int
	cycle                                 uint64
	maxBW                                 [2]uint64
	bwShort, bwLatest, lossRound, lost    uint64
	flightLong, flightShort, flightLatest int
	lossEvents                            int
	lossRanges                            int
	lastLossPN                            uint64
	lastLossLevel                         int
	lossInRound, checkLoss, stopping      bool
	tooHigh, precautionary, fullNow       bool
	sinceProbe, drainRound                uint64
	wait                                  time.Duration
	upRounds                              uint8
	upAcked, upPerInc, probeWindow        int
	undoMode, undoPhase                   int
	undoBW                                uint64
	undoShort, undoLong                   int
	// QUIC can prove an entire recovery spurious only while every lost PN is retained.
	lossPN [64]struct {
		pn    uint64
		level uint8
		acked bool
	}
	lossCount    int
	lossOverflow bool
}

func newQUICBBR3(now time.Time) *quicBBR {
	return newQUICBBRModel(now, false)
}

func newQUICBBRModel(now time.Time, v2 bool) *quicBBR {
	b := newQUICBBR(now)
	b.model = &bbrModel{v2: v2, probeAt: now, bwShort: bbrInfinity, flightLong: bbrInfinity, flightShort: bbrInfinity, upPerInc: bbrInfinity, undoMode: -1}
	b.aggregation = &bbrACKAggregation{}
	b.pace = uint64(4 * math.Ln2 * float64(10*quicMSS) / (333 * time.Millisecond).Seconds())
	return b
}

func (v *bbrModel) gains(mode int) (float64, float64) {
	switch mode {
	case bbrStartup:
		return 4 * math.Ln2, 2
	case bbrDrain:
		return .5, 2
	case bbrProbeRTT:
		return 1, .5
	}
	switch v.phase {
	case bbrDown:
		return .9, 2
	case bbrUp:
		if v.v2 {
			return 1.25, 2
		}
		return 1.25, 2.25
	}
	return 1, 2
}

func (b *quicBBR) bdpModel(gain float64) int {
	if b.minRTT == 0 {
		return 10 * quicMSS
	}
	return int(min(float64(4<<20), gain*float64(b.bandwidth)*b.minRTT.Seconds()))
}

func (b *quicBBR) budgetModel(flight int) int {
	flight = max(flight, b.quantum(), bbrMinimumWindow)
	if b.mode == bbrProbeBW && b.model.phase == bbrUp {
		flight += 2 * quicMSS
	}
	return min(flight, 4<<20)
}

func (v *bbrModel) headroom() int {
	if v.flightLong == bbrInfinity {
		return bbrInfinity
	}
	return max(bbrMinimumWindow, v.flightLong-max(quicMSS, v.flightLong*15/100))
}

func (v *bbrModel) probing(mode int) bool {
	return mode == bbrStartup || mode == bbrProbeBW && (v.phase == bbrRefill || v.phase == bbrUp)
}

func (b *quicBBR) downModel(now time.Time) {
	v := b.model
	b.mode, b.cycleAt, b.nextRound = bbrProbeBW, now, b.delivered
	v.phase, v.stopping, v.upPerInc = bbrDown, true, bbrInfinity
	v.lossInRound, v.lossEvents, v.lossRanges, v.bwLatest, v.flightLatest = false, 0, 0, 0, 0
	v.sinceProbe = uint64(rand.IntN(2))
	v.wait = 2*time.Second + time.Duration(rand.Int64N(int64(time.Second)))
}

func (b *quicBBR) refillModel() {
	v := b.model
	b.mode, b.nextRound = bbrProbeBW, b.delivered
	v.phase, v.bwShort, v.flightShort = bbrRefill, bbrInfinity, bbrInfinity
	v.upRounds, v.upAcked, v.precautionary, v.stopping = 0, 0, false, false
}

func (b *quicBBR) resetPlateauModel() {
	b.plateauRate, b.plateauRounds, b.model.fullNow = 0, 0, false
}

func (v *bbrModel) slope(window int) {
	v.upPerInc = max(quicMSS, window/(1<<v.upRounds))
	v.upRounds = min(30, v.upRounds+1)
}

func (b *quicBBR) boundModel(window int) int {
	v := b.model
	limit := bbrInfinity
	if b.mode == bbrProbeBW || v.v2 && b.mode == bbrDrain {
		limit = v.flightLong
	}
	if b.mode == bbrProbeRTT || b.mode == bbrProbeBW && v.phase == bbrCruise {
		limit = v.headroom()
	}
	if b.mode == bbrProbeRTT {
		limit = min(limit, max(bbrMinimumWindow, min(v.probeWindow, b.bdpModel(.5))))
	}
	return min(4<<20, window, max(bbrMinimumWindow, min(limit, v.flightShort)))
}

func (b *quicBBR) highLossModel(now time.Time, flight int, appLimited bool, window int) {
	v := b.model
	v.tooHigh, v.checkLoss = true, false
	if !appLimited {
		v.flightLong = max(bbrMinimumWindow, flight, min(b.bdpModel(1), window)*7/10)
	}
	if b.mode == bbrProbeBW && v.phase == bbrUp {
		v.undoMode, v.undoPhase = bbrProbeBW, bbrUp
		b.downModel(now)
	}
}

func (b *quicBBR) cycleModel(now time.Time, round bool, rate, lost uint64, flight, acked, window, inFlight, priorFlight int, app bool) {
	v := b.model
	if !b.full {
		return
	}
	tooHigh := lost > uint64(flight)/50
	if v.checkLoss && tooHigh {
		wasUp := b.mode == bbrProbeBW && v.phase == bbrUp
		b.highLossModel(now, flight, app, window)
		if wasUp {
			return
		}
	}
	if v.stopping && round {
		v.checkLoss, v.stopping = false, false
		if b.mode == bbrProbeBW && !app {
			v.cycle++
			v.maxBW[v.cycle%2] = 0
		}
		if b.mode == bbrProbeBW && v.precautionary && !v.tooHigh {
			b.refillModel()
			return
		}
	}
	if !tooHigh && v.flightLong != bbrInfinity {
		v.flightLong = max(v.flightLong, flight)
		if b.mode == bbrProbeBW && v.phase == bbrUp && priorFlight >= window && window >= v.flightLong {
			v.upAcked += acked
			v.flightLong = min(4<<20, v.flightLong+(v.upAcked/v.upPerInc)*quicMSS)
			v.upAcked %= v.upPerInc
			if round {
				v.slope(window)
			}
		}
	}
	if b.mode != bbrProbeBW {
		return
	}
	switch v.phase {
	case bbrDown, bbrCruise:
		rounds := uint64(min(63, max(1, min(b.bdpModel(1), window)/quicMSS)))
		if now.Sub(b.cycleAt) >= v.wait || v.sinceProbe >= rounds {
			b.refillModel()
		} else if v.phase == bbrDown && inFlight <= v.headroom() && inFlight <= b.budgetModel(b.bdpModel(1)) {
			v.phase = bbrCruise
		}
	case bbrRefill:
		if round {
			v.phase, v.checkLoss, b.nextRound = bbrUp, true, b.delivered
			if v.v2 {
				b.cycleAt = now
			}
			b.resetPlateauModel()
			b.plateauRate = rate
			v.slope(window)
		}
	case bbrUp:
		if v.v2 {
			if now.Sub(b.cycleAt) >= b.minRTT && inFlight > b.budgetModel(b.bdpModel(1.25)) {
				b.downModel(now)
			}
			return
		}
		if v.tooHigh && inFlight >= v.flightLong {
			v.precautionary, v.tooHigh = true, false
			b.downModel(now)
		} else if priorFlight >= window && window >= v.flightLong {
			b.resetPlateauModel()
			b.plateauRate = rate
		} else if v.fullNow {
			v.tooHigh = false
			b.downModel(now)
		}
	}
}

func (b *quicBBR) ackModel(now time.Time, packet quicSent, acked, window, inFlight, priorFlight int, rtt time.Duration) int {
	s, v := packet.delivery, b.model
	if !s.valid || acked == 0 {
		return window
	}
	b.delivered += uint64(acked)
	if b.appUntil != 0 && b.delivered > b.appUntil {
		b.appUntil = 0
	}
	round := s.delivered >= b.nextRound
	if round {
		b.round++
		v.sinceProbe++
		b.nextRound = b.delivered
	}
	delivered := b.delivered - s.delivered
	interval := max(packet.at.Sub(b.origin)-time.Duration(s.firstSent), now.Sub(b.origin)-time.Duration(s.deliveredAt))
	rate := uint64(0)
	if interval > 0 && interval >= b.minRTT {
		rate = uint64(min(float64(1<<40), float64(delivered)/interval.Seconds()))
	}
	maxBW := max(v.maxBW[0], v.maxBW[1])
	if rate >= maxBW || !s.appLimited {
		v.maxBW[v.cycle%2] = max(v.maxBW[v.cycle%2], rate)
		maxBW = max(v.maxBW[0], v.maxBW[1])
	}
	v.bwLatest = max(v.bwLatest, rate)
	v.flightLatest = max(v.flightLatest, int(delivered))
	lossRound := s.delivered >= v.lossRound
	if lossRound {
		v.lossRound = b.delivered
		if !v.probing(b.mode) && v.lossInRound {
			if v.bwShort == bbrInfinity {
				v.bwShort = maxBW
			}
			if v.flightShort == bbrInfinity {
				v.flightShort = window
			}
			v.bwShort = max(v.bwLatest, v.bwShort*7/10)
			v.flightShort = max(v.flightLatest, v.flightShort*7/10)
		}
	}
	if packet.at.After(b.firstSent) {
		b.firstSent = packet.at
	}
	b.deliveredAt = now
	// A Startup ACK burst has only a one-round lifetime; steady state retains ten rounds.
	if !v.v2 && !b.full && round {
		clear(b.aggregation.peak[:])
	}
	extra := b.aggregation.update(now, b.round, b.bandwidth, acked, window)
	plateauRate := rate
	if v.v2 {
		plateauRate = maxBW
	}
	if round && plateauRate > 0 && !s.appLimited && !v.fullNow && (!v.v2 || !b.full) {
		if plateauRate >= b.plateauRate+b.plateauRate/4 {
			b.resetPlateauModel()
			b.plateauRate = plateauRate
		} else {
			b.plateauRounds++
			v.fullNow = b.plateauRounds >= 3
			b.full = b.full || v.fullNow
		}
	}
	sampleLost := v.lost - min(v.lost, s.lost)
	startupLoss := v.lossEvents >= 6
	if v.v2 {
		startupLoss = v.lossRanges >= 3 && b.round >= b.recoveryRound
	}
	if !b.full && lossRound && v.lossInRound && startupLoss && !b.recoveryAt.IsZero() && sampleLost > uint64(s.inFlight)/50 {
		v.undoMode, b.full = bbrStartup, true
		v.flightLong = max(bbrMinimumWindow, b.bdpModel(1), v.flightLatest)
	}
	if lossRound {
		v.lossInRound = false
	}
	if b.mode == bbrStartup && b.full {
		b.mode, v.drainRound = bbrDrain, b.round
	}
	if b.mode == bbrDrain && (inFlight <= b.budgetModel(b.bdpModel(1)) || !v.v2 && b.round > v.drainRound+3) {
		b.downModel(now)
		round = false // The sentinel was just restarted by this transition.
	}
	b.cycleModel(now, round, rate, sampleLost, int(s.inFlight), acked, window, inFlight, priorFlight, s.appLimited)
	expired := now.Sub(b.rttAt) > 10*time.Second
	if v.v2 {
		expired = b.minRTT2(now, rtt)
	}
	if expired && b.mode != bbrProbeRTT {
		v.probeWindow = b.bdpModel(.5)
	}
	if !v.v2 && rtt > 0 && (b.minRTT == 0 || rtt < b.minRTT || expired) {
		b.minRTT, b.rttAt = rtt, now
	}
	if expired && !b.idleRestart && b.mode != bbrProbeRTT {
		b.priorWindow = max(b.priorWindow, window)
		b.mode, b.probeDone, b.nextRound, v.stopping = bbrProbeRTT, time.Time{}, b.delivered, true
	}
	if b.mode == bbrProbeRTT {
		b.appUntil = max(uint64(1), b.delivered+uint64(inFlight))
		if b.probeDone.IsZero() && inFlight <= max(bbrMinimumWindow, min(v.probeWindow, b.bdpModel(.5))) {
			b.probeDone, b.probeRound, b.nextRound = now.Add(200*time.Millisecond), b.round+1, b.delivered
		}
		if !b.probeDone.IsZero() && !now.Before(b.probeDone) && b.round >= b.probeRound {
			window = b.exitProbeRTTModel(now, window)
		}
	}
	if !b.recoveryAt.IsZero() && packet.at.After(b.recoveryAt) {
		b.recoveryAt = time.Time{}
		window = max(window, b.priorWindow)
	}
	if lossRound {
		v.bwLatest, v.flightLatest, v.lossEvents, v.lossRanges = rate, int(delivered), 0, 0
	}
	b.bandwidth = min(max(v.maxBW[0], v.maxBW[1]), v.bwShort)
	b.idleRestart = false
	pace, gain := b.gains()
	if b.bandwidth != 0 {
		next := max(uint64(1), uint64(float64(b.bandwidth)*pace*.99))
		if b.full || next > b.pace {
			b.pace = next
		}
	}
	target := b.budgetModel(b.bdpModel(gain) + extra)
	if b.full {
		window = min(window+acked, target)
	} else if window < target || b.delivered < 10*quicMSS {
		window += acked
	}
	return b.boundModel(max(bbrMinimumWindow, window))
}

func (b *quicBBR) exitProbeRTTModel(now time.Time, window int) int {
	if b.model.v2 {
		b.model.probeAt = now
	} else {
		b.rttAt = now
	}
	b.model.bwShort, b.model.flightShort = bbrInfinity, bbrInfinity
	if b.full {
		b.downModel(now)
		b.model.phase = bbrCruise
	} else {
		b.mode = bbrStartup
	}
	b.bandwidth = max(b.model.maxBW[0], b.model.maxBW[1])
	return b.boundModel(max(window, b.priorWindow))
}

func (b *quicBBR) resumeModel(now time.Time, inFlight, window int) int {
	if inFlight == 0 && b.appUntil != 0 {
		b.idleRestart = true
		if b.mode == bbrProbeRTT && !b.probeDone.IsZero() && !now.Before(b.probeDone) && b.round >= b.probeRound {
			return b.exitProbeRTTModel(now, window)
		}
	}
	return window
}

func (b *quicBBR) lostPacket(now time.Time, packet quicSent, window, inFlight int) int {
	v := b.model
	if v == nil {
		return b.lost(now, packet.at, packet.size, window, inFlight)
	}
	v.lost += uint64(packet.size)
	if b.recoveryAt.IsZero() || packet.at.After(b.recoveryAt) {
		if b.mode == bbrProbeRTT {
			b.priorWindow = max(b.priorWindow, window)
		} else {
			b.priorWindow = window
		}
		b.recoveryAt = now
		b.recoveryRound = b.round + 1
		v.undoMode, v.undoPhase = -1, v.phase
		v.undoBW, v.undoShort, v.undoLong = v.bwShort, v.flightShort, v.flightLong
		v.lossCount, v.lossOverflow = 0, false
	}
	if !v.lossInRound {
		v.lossRound = b.delivered
	}
	v.lossInRound, v.lossEvents = true, v.lossEvents+1
	s := packet.delivery
	lost := v.lost - min(v.lost, s.lost)
	if s.valid && v.checkLoss && lost > uint64(s.inFlight)/50 {
		before := max(0, int(s.inFlight)-packet.size)
		prefix := (float64(before)/50 - float64(lost-uint64(packet.size))) / .98
		b.highLossModel(now, max(0, before+int(prefix)), s.appLimited, window)
	}
	return b.boundModel(max(bbrMinimumWindow, window-packet.size))
}

func (v *bbrModel) recordLoss(level int, pn uint64) {
	if v.v2 {
		if v.lossRanges == 0 || level != v.lastLossLevel || pn != v.lastLossPN+1 {
			v.lossRanges = min(3, v.lossRanges+1)
		}
		v.lastLossPN, v.lastLossLevel = pn, level
	}
	if v.lossCount == len(v.lossPN) {
		v.lossOverflow = true
		return
	}
	v.lossPN[v.lossCount] = struct {
		pn    uint64
		level uint8
		acked bool
	}{pn, uint8(level), false}
	v.lossCount++
}

func (b *quicBBR) ackLostModel(level int, ranges []quicPNRange, now time.Time, window int) int {
	v := b.model
	if v.lossCount == 0 || v.lossOverflow {
		return window
	}
	all := true
	for i := 0; i < v.lossCount; i++ {
		p := &v.lossPN[i]
		if int(p.level) == level {
			for _, r := range ranges {
				if p.pn >= r.low && p.pn <= r.high {
					p.acked = true
					break
				}
			}
		}
		all = all && p.acked
	}
	if !all {
		return window
	}
	v.lossCount, v.lossInRound, v.lossEvents, v.lossRanges = 0, false, 0, 0
	v.bwShort, v.flightShort, v.flightLong = max(v.bwShort, v.undoBW), max(v.flightShort, v.undoShort), max(v.flightLong, v.undoLong)
	b.resetPlateauModel()
	if v.undoMode == bbrStartup {
		b.full = false
		if b.mode != bbrProbeRTT {
			b.mode = bbrStartup
		}
	} else if v.undoMode == bbrProbeBW && v.undoPhase == bbrUp && b.mode != bbrProbeRTT {
		b.refillModel()
	}
	v.undoMode, b.recoveryAt = -1, time.Time{}
	b.bandwidth = min(max(v.maxBW[0], v.maxBW[1]), v.bwShort)
	if b.bandwidth != 0 {
		gain, _ := b.gains()
		b.pace = max(uint64(1), uint64(float64(b.bandwidth)*gain*.99))
	}
	return b.boundModel(max(window, b.priorWindow))
}
