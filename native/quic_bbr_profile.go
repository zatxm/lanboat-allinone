package native

import (
	"errors"
	"time"
)

func validateBBRProfile(kind, algorithm, profile string) error {
	if profile == "" {
		return nil
	}
	if kind != "hysteria2" {
		return errors.New("bbr_profile requires Hysteria2")
	}
	if algorithm != "" && algorithm != "bbr" {
		return errors.New("bbr_profile requires the BBR congestion controller")
	}
	if profile != "conservative" && profile != "standard" && profile != "aggressive" {
		return errors.New("bbr_profile must be conservative, standard or aggressive")
	}
	return nil
}

type bbrTuning struct {
	startup, startupWindow, window float64
	rounds                         int
	conservative, startupBoost     bool
}

var bbrTunings = [...]bbrTuning{
	{startup: bbrHighGain, startupWindow: bbrHighGain, window: 2, rounds: 3},
	{startup: 2.25, startupWindow: 1.75, window: 1.75, rounds: 2, conservative: true},
	{startup: 2.885, startupWindow: 2, window: 2, rounds: 3},
	{startup: 3, startupWindow: 2.25, window: 2.5, rounds: 4, startupBoost: true},
}

func (b *quicBBR) checkOvershoot() {
	if !b.tuning.conservative || b.full || b.overshot || b.startupLost == 0 || b.minRTT <= 0 || b.bandwidth == 0 {
		return
	}
	rate := uint64(b.tuning.startup * float64(b.bandwidth))
	if b.pace > rate && (b.busySample || b.startupLost > 10*quicMSS) {
		floor := uint64(float64(bbrMinimumWindow) / b.minRTT.Seconds())
		b.pace = min(b.pace, max(rate, floor))
		b.overshot = true
	}
}

type bbrACKAggregation struct {
	at    time.Time
	bytes uint64
	peak  [10]struct {
		round uint64
		bytes int
	}
}

func (a *bbrACKAggregation) update(now time.Time, round, bandwidth uint64, acknowledged, window int) int {
	expected := float64(bandwidth) * max(0, now.Sub(a.at).Seconds())
	if a.at.IsZero() || float64(a.bytes) <= expected {
		a.at, a.bytes, expected = now, 0, 0
	}
	a.bytes += uint64(acknowledged)
	extra := int(min(float64(window), max(0, float64(a.bytes)-expected)))
	slot := &a.peak[round%uint64(len(a.peak))]
	if slot.round != round {
		slot.round, slot.bytes = round, 0
	}
	slot.bytes = max(slot.bytes, extra)
	peak := 0
	for _, slot := range a.peak {
		if round-slot.round < uint64(len(a.peak)) {
			peak = max(peak, slot.bytes)
		}
	}
	return min(window, peak)
}
