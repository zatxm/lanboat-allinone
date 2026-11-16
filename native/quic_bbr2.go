package native

import "time"

func newQUICBBR2(now time.Time) *quicBBR {
	return newQUICBBRModel(now, true)
}

// v2 schedules RTT probes every 5s while retaining a separate 10s path minimum.
func (b *quicBBR) minRTT2(now time.Time, rtt time.Duration) bool {
	v := b.model
	expired := now.Sub(v.probeAt) > 5*time.Second
	if rtt > 0 && (v.probeRTT == 0 || rtt < v.probeRTT || expired) {
		v.probeRTT, v.probeAt = rtt, now
	}
	if v.probeRTT > 0 && (b.minRTT == 0 || v.probeRTT < b.minRTT || now.Sub(b.rttAt) > 10*time.Second) {
		b.minRTT, b.rttAt = v.probeRTT, v.probeAt
	}
	return expired
}
