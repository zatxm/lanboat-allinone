package native

import (
	"errors"
	"strconv"
	"time"
)

// A configured rate is a delivery target, not an estimate of available bandwidth.
// Keep a fixed-size five-second delivery history. Only the QUIC event loop owns it.
type quicBrutal struct {
	started time.Time
	buckets [5]struct {
		second      int64
		acked, lost uint64
	}
}

const maxHYRate = uint64(1000000 * 125000)

func (b *quicBrutal) feedback(now time.Time, acked, lost int) {
	second := int64(now.Sub(b.started) / time.Second)
	if second < 0 {
		return
	}
	slot := &b.buckets[second%int64(len(b.buckets))]
	if slot.second != second {
		slot.second, slot.acked, slot.lost = second, 0, 0
	}
	slot.acked += uint64(acked)
	slot.lost += uint64(lost)
}

func (b *quicBrutal) pacing(now time.Time, target uint64, rtt time.Duration, disableCompensation bool) (uint64, int) {
	ackRatio := 1.0
	if !disableCompensation {
		second := int64(now.Sub(b.started) / time.Second)
		var acked, lost uint64
		for _, slot := range b.buckets {
			if age := second - slot.second; age >= 0 && age < int64(len(b.buckets)) {
				acked += slot.acked
				lost += slot.lost
			}
		}
		// Sparse traffic does not provide a useful loss estimate. Bound the
		// compensation to 25%, including complete outages and reordered ACKs.
		if acked+lost >= 50*quicMSS {
			ackRatio = max(.8, float64(acked)/float64(acked+lost))
		}
	}
	rate := uint64(float64(min(target, maxHYRate)) / ackRatio)
	window := 2 * float64(rate) * max(rtt, time.Microsecond).Seconds()
	return rate, int(min(float64(4<<20), max(float64(10*quicMSS), window)))
}

// Authentication runs outside the QUIC event loop: publish only the target.
func (c *quicConn) setBrutalRate(rate uint64) {
	c.brutalTarget.Store(min(rate, maxHYRate))
	signalQUIC(c.wake)
}

func (c *quicConn) setHY1Rate(algorithm string, rate uint64) {
	if algorithm == "" {
		c.setBrutalRate(rate)
	} else {
		c.sendRate.Store(rate)
		signalQUIC(c.wake)
	}
}

func validateHYBandwidth(kind string, up, down int, ignore, disableCompensation bool) error {
	if kind != "hysteria" && kind != "hysteria2" {
		if up != 0 || down != 0 || ignore || disableCompensation {
			return errors.New("bandwidth settings require Hysteria or Hysteria2")
		}
		return nil
	}
	if up < 0 || down < 0 || up > 1000000 || down > 1000000 {
		return errors.New("Hysteria bandwidth must be 0-1000000 Mbps")
	}
	if ignore && kind != "hysteria2" {
		return errors.New("ignore_client_bandwidth requires Hysteria2")
	}
	if ignore && (up != 0 || down != 0) {
		return errors.New("ignore_client_bandwidth conflicts with up_mbps and down_mbps")
	}
	return nil
}

func hy2ReceiveRate(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}
	rate, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("invalid Hysteria-CC-RX bandwidth")
	}
	return rate, nil
}

func hy2ClientRate(up int, peer string) (uint64, error) {
	if peer == "auto" {
		return 0, nil
	}
	limit, err := hy2ReceiveRate(peer)
	if err != nil {
		return 0, err
	}
	rate := uint64(up) * 125000
	if limit > 0 && rate > limit {
		rate = limit
	}
	return rate, nil
}

func hy2ServerRates(in Inbound, peer string) (tx uint64, rx string, err error) {
	tx, err = hy2ReceiveRate(peer)
	if err != nil {
		return 0, "", err
	}
	if in.IgnoreClientBandwidth {
		return 0, "auto", nil
	}
	if limit := uint64(in.UpMbps) * 125000; limit > 0 && tx > limit {
		tx = limit
	}
	return min(tx, maxHYRate), strconv.FormatUint(uint64(in.DownMbps)*125000, 10), nil
}
