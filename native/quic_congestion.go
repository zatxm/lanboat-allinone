package native

import (
	"errors"
	"math"
	"time"
)

type quicOptions struct {
	datagramLimit                           int
	discoverMTU                             bool
	packetSize                              int
	idleTimeout                             time.Duration
	streamWindow, connectionWindow, streams uint64
	receiveMTU                              int
	keepAlive                               time.Duration
	initial                                 int
	cubic                                   bool
	bbr                                     bool
	bbrProfile                              string
	bbr2                                    bool
	bbr3                                    bool
	disableLossCompensation                 bool
}

func proxyQUICOptions(kind, algorithm string) quicOptions {
	o := quicOptions{cubic: algorithm == "cubic" || kind == "tuic" && algorithm == "", bbr2: algorithm == "bbr2", bbr3: algorithm == "bbr3", bbr: algorithm == "bbr2" || algorithm == "bbr3" || algorithm == "bbr" || algorithm == "" && (kind == "hysteria2" || kind == "juicity")}
	if kind == "hysteria2" && o.bbr && !o.bbr2 && !o.bbr3 {
		o.bbrProfile = "standard"
	}
	if kind == "hysteria" {
		// Legacy peers fragment against this limit before their path MTU converges.
		o.datagramLimit = 1200 - 64
	}
	return o
}

func validateQUICCongestion(kind, algorithm string) error {
	if algorithm == "" {
		return nil
	}
	if !isQUICProxy(kind) {
		return errors.New("congestion_control requires Hysteria, Hysteria2, TUIC or Juicity")
	}
	if algorithm != "cubic" && algorithm != "bbr" && algorithm != "bbr2" && algorithm != "bbr3" && algorithm != "new_reno" && algorithm != "reno" {
		return errors.New("independent QUIC congestion_control must be bbr, bbr2, bbr3, cubic or new_reno (reno alias)")
	}
	return nil
}

// Window values are segments; fractional ACK credit is retained, even for tiny packets.
type quicCubic struct {
	maximum, prior, origin, estimate, window, k float64
	elapsed                                     time.Duration
	updated                                     time.Time
	active, epoch                               bool
}

func (s *quicCubic) pause(now time.Time) {
	s.updated, s.active = now, false
}

func (s *quicCubic) lost(window int) int {
	w := float64(window) / quicMSS
	s.prior = w
	if w < s.maximum {
		s.maximum = w * .85
	} else {
		s.maximum = w
	}
	s.epoch, s.active = false, false
	return max(2*quicMSS, window*7/10)
}

func (s *quicCubic) ack(now time.Time, window, acknowledged int, rtt time.Duration) int {
	w := float64(window) / quicMSS
	if !s.epoch {
		s.epoch, s.active = true, false
		s.origin = max(s.maximum, w)
		s.k = math.Cbrt((s.origin - w) / .4)
		s.window, s.estimate, s.elapsed = w, w, 0
		if s.prior == 0 {
			s.prior = w
		}
	}
	if s.active {
		s.elapsed += now.Sub(s.updated)
	}
	s.updated, s.active = now, true
	t := s.elapsed.Seconds()
	cube := func(t float64) float64 { d := t - s.k; return .4*d*d*d + s.origin }
	alpha := 9.0 / 17
	if s.estimate >= s.prior {
		alpha = 1
	}
	n := float64(acknowledged) / quicMSS
	s.estimate += alpha * n / w
	target := min(1.5*w, max(w, cube(t+max(rtt, time.Microsecond).Seconds())))
	if cube(t) < s.estimate {
		s.window = max(s.window, s.estimate)
	} else {
		s.window = max(s.window, w) + (target-w)*n/w
	}
	s.window = min(s.window, float64(4<<20)/quicMSS)
	return max(window, int(s.window*quicMSS))
}

func (c *quicConn) congestionACK(now time.Time, acknowledged int) {
	if c.brutal != nil || c.bbr != nil {
		return
	}
	if acknowledged == 0 {
		if c.cubic != nil {
			c.cubic.pause(now)
		}
		return
	}
	if c.cwnd < c.ssthresh {
		c.cwnd += acknowledged
	} else if c.cubic != nil {
		c.cwnd = c.cubic.ack(now, c.cwnd, acknowledged, c.srtt)
	} else {
		c.renoCredit += quicMSS * acknowledged
		increase := c.renoCredit / c.cwnd
		c.renoCredit %= c.cwnd
		c.cwnd += increase
	}
	c.cwnd = min(c.cwnd, 4<<20)
	if c.cubic != nil && c.inFlight == 0 {
		c.cubic.pause(now)
	}
}
