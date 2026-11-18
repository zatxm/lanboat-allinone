package native

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"slices"
	"time"
)

func (s *quicSpace) record(pn uint64) bool {
	if s.largest >= 0 && pn+4096 < uint64(s.largest) {
		return false
	}
	for _, r := range s.received {
		if pn >= r.low && pn <= r.high {
			return false
		}
	}
	s.received = append(s.received, quicPNRange{pn, pn})
	for i := len(s.received) - 1; i > 0 && s.received[i].high > s.received[i-1].high; i-- {
		s.received[i], s.received[i-1] = s.received[i-1], s.received[i]
	}
	out := s.received[:0]
	for _, r := range s.received {
		if len(out) > 0 && r.high+1 >= out[len(out)-1].low {
			out[len(out)-1].low = min(out[len(out)-1].low, r.low)
		} else {
			out = append(out, r)
		}
	}
	if len(out) > 128 {
		out = out[:128]
	}
	s.received = out
	if int64(pn) > s.largest {
		s.largest = int64(pn)
	}
	return true
}
func (s *quicSpace) ackFrame() []byte { return s.appendACKFrame(nil) }
func (s *quicSpace) appendACKFrame(f []byte) []byte {
	if len(s.received) == 0 {
		return f
	}
	ranges := s.received
	f = quicVar(append(f, 2), ranges[0].high)
	f = quicVar(f, 0)
	f = quicVar(f, uint64(len(ranges)-1))
	f = quicVar(f, ranges[0].high-ranges[0].low)
	for i := 1; i < len(ranges); i++ {
		f = quicVar(f, ranges[i-1].low-ranges[i].high-2)
		f = quicVar(f, ranges[i].high-ranges[i].low)
	}
	return f
}
func (c *quicConn) handleFrames(level int, pn uint64, data []byte) error {
	r := quicReader(data)
	eliciting := false
	for len(r) > 0 {
		kind, err := r.v()
		if err != nil {
			return err
		}
		if kind != 0 && kind != 2 && kind != 3 && kind != 28 && kind != 29 {
			eliciting = true
		}
		if level != 2 && kind != 0 && kind != 1 && kind != 2 && kind != 3 && kind != 6 && kind != 28 {
			return errors.New("QUIC frame forbidden at encryption level")
		}
		switch {
		case kind == 0:
		case kind == 1:
		case kind == 2 || kind == 3:
			largest, err := r.v()
			if err != nil {
				return err
			}
			delay, err := r.v()
			if err != nil {
				return err
			}
			count, err := r.v()
			if err != nil {
				return err
			}
			first, err := r.v()
			if err != nil {
				return err
			}
			if count > 256 || first > largest || largest >= c.spaces[level].nextPN {
				return errors.New("invalid QUIC acknowledgment")
			}
			ranges := []quicPNRange{{largest - first, largest}}
			for range count {
				gap, err := r.v()
				if err != nil {
					return err
				}
				n, err := r.v()
				if err != nil {
					return err
				}
				low := ranges[len(ranges)-1].low
				if gap+2 > low {
					return errors.New("QUIC ACK range underflow")
				}
				high := low - gap - 2
				if n > high {
					return errors.New("QUIC ACK range underflow")
				}
				ranges = append(ranges, quicPNRange{high - n, high})
			}
			if kind == 3 {
				for range 3 {
					if _, err := r.v(); err != nil {
						return err
					}
				}
			}
			c.acknowledge(level, largest, delay, ranges, quicNow())
		case kind == 6:
			offset, err := r.v()
			if err != nil {
				return err
			}
			n, err := r.v()
			if err != nil {
				return err
			}
			body, err := r.take(n)
			if err != nil {
				return err
			}
			if offset+n > 1<<20 {
				return errors.New("QUIC CRYPTO buffer limit exceeded")
			}
			buffer := &c.spaces[level].crypto
			if err := buffer.put(offset, body); err != nil {
				return err
			}
			for len(buffer.parts) > 0 && buffer.parts[0].offset == buffer.position {
				part := buffer.parts[0]
				buffer.parts[0] = quicPiece{}
				buffer.parts = buffer.parts[1:]
				buffer.position += uint64(len(part.data))
				encryption := tls.QUICEncryptionLevelInitial
				if level == 1 {
					encryption = tls.QUICEncryptionLevelHandshake
				}
				if level == 2 {
					encryption = tls.QUICEncryptionLevelApplication
				}
				if err := c.tls.HandleData(encryption, part.data); err != nil {
					return err
				}
				if err := c.tlsEvents(); err != nil {
					return err
				}
			}
		case kind >= 8 && kind <= 15:
			id, err := r.v()
			if err != nil {
				return err
			}
			var offset uint64
			if kind&4 != 0 {
				offset, err = r.v()
				if err != nil {
					return err
				}
			}
			n := uint64(len(r))
			if kind&2 != 0 {
				n, err = r.v()
				if err != nil {
					return err
				}
			}
			body, err := r.take(n)
			if err != nil {
				return err
			}
			if err := c.receiveStream(id, offset, body, kind&1 != 0); err != nil {
				return err
			}
		case kind == 4:
			id, err := r.v()
			if err != nil {
				return err
			}
			code, err := r.v()
			if err != nil {
				return err
			}
			final, err := r.v()
			if err != nil {
				return err
			}
			s, err := c.streamFor(id)
			if err != nil {
				return err
			}
			if s == nil {
				continue
			}
			if final < s.highest || final > s.readLimit {
				return errors.New("invalid QUIC reset final size")
			}
			delta := final - s.highest
			if c.receiveHighest+delta > c.receiveMax {
				return errors.New("QUIC reset exceeded receive window")
			}
			c.receiveHighest += delta
			s.highest = final
			if id&2 != 0 && (id&1 == 0) != c.server {
				return errors.New("peer reset send-only QUIC stream")
			}
			s.mu.Lock()
			if s.finalKnown && s.final != final {
				s.mu.Unlock()
				return errors.New("inconsistent QUIC reset final size")
			}
			s.finalKnown = true
			s.final = final
			s.readErr = fmt.Errorf("QUIC peer reset stream: %d", code)
			s.peerCanceled.Store(true)
			if cancel := s.peerCancel.Load(); cancel != nil {
				(*cancel)()
			}
			s.buffer.parts = nil
			s.discardReceived()
			s.stopped = true
			s.mu.Unlock()
			signalQUIC(s.readWake)
			if err := c.deliverStream(s); err != nil {
				return err
			}
			c.retireStream(s)
		case kind == 5:
			id, err := r.v()
			if err != nil {
				return err
			}
			code, err := r.v()
			if err != nil {
				return err
			}
			s, err := c.streamFor(id)
			if err != nil {
				return err
			}
			if s == nil {
				continue
			}
			if id&2 != 0 && (id&1 == 0) == c.server {
				return errors.New("peer stopped receive-only QUIC stream")
			}
			s.writeErr = &quicStreamStopError{code: code}
			s.peerCanceled.Store(true)
			if cancel := s.peerCancel.Load(); cancel != nil {
				(*cancel)()
			}
			if !s.resetSent {
				s.resetSent = true
				f := quicVar([]byte{4}, id)
				f = quicVar(f, code)
				f = quicVar(f, s.sendOffset)
				c.enqueue(quicFrame{data: f, level: 2, reliable: true})
			}
		case kind == 16:
			n, err := r.v()
			if err != nil {
				return err
			}
			c.peer.maxData = max(c.peer.maxData, n)
		case kind == 17:
			id, err := r.v()
			if err != nil {
				return err
			}
			n, err := r.v()
			if err != nil {
				return err
			}
			s, err := c.streamFor(id)
			if err != nil {
				return err
			}
			if s != nil {
				s.sendLimit = max(s.sendLimit, n)
			}
		case kind == 18 || kind == 19:
			n, err := r.v()
			if err != nil {
				return err
			}
			if n > 1<<60 {
				return errors.New("invalid QUIC stream limit")
			}
			if kind == 18 {
				c.peer.maxBi = max(c.peer.maxBi, n)
			} else {
				c.peer.maxUni = max(c.peer.maxUni, n)
			}
		case kind == 20 || kind == 22 || kind == 23:
			if _, err := r.v(); err != nil {
				return err
			}
		case kind == 21:
			if _, err := r.v(); err != nil {
				return err
			}
			if _, err := r.v(); err != nil {
				return err
			}
		case kind == 24:
			seq, err := r.v()
			if err != nil {
				return err
			}
			retire, err := r.v()
			if err != nil {
				return err
			}
			n, err := r.take(1)
			if err != nil {
				return err
			}
			if n[0] == 0 || n[0] > 20 || retire > seq {
				return errors.New("invalid QUIC connection ID")
			}
			cid, err := r.take(uint64(n[0]))
			if err != nil {
				return err
			}
			token, err := r.take(16)
			if err != nil {
				return err
			}
			if existing, ok := c.peerCIDs[seq]; ok && (!bytes.Equal(existing.id, cid) || !bytes.Equal(existing.token[:], token)) {
				return errors.New("conflicting QUIC connection ID")
			}
			c.retirePrior = max(c.retirePrior, retire)
			for n := range c.peerCIDs {
				if n < c.retirePrior {
					delete(c.peerCIDs, n)
					c.enqueue(quicFrame{data: quicVar([]byte{25}, n), level: 2, reliable: true})
				}
			}
			if seq < c.retirePrior {
				c.enqueue(quicFrame{data: quicVar([]byte{25}, seq), level: 2, reliable: true})
				continue
			}
			var reset [16]byte
			copy(reset[:], token)
			c.peerCIDs[seq] = quicPeerCID{id: append([]byte{}, cid...), token: reset}
			if len(c.peerCIDs) > 2 {
				return errors.New("QUIC active connection ID limit exceeded")
			}
			if c.peerCIDSeq < c.retirePrior {
				c.peerCIDSeq = seq
				c.dcid = append([]byte{}, cid...)
			}

		case kind == 25:
			seq, err := r.v()
			if err != nil {
				return err
			}
			if seq == 0 {
				return errors.New("peer retired its active QUIC destination CID")
			}
		case kind == 26:
			body, err := r.take(8)
			if err != nil {
				return err
			}
			if c.sendTo != nil && c.packetRemote != nil {
				_ = c.sendPathFrame(c.packetRemote, append([]byte{27}, body...))
			} else {
				frame := quicFrame{data: append([]byte{27}, body...), level: 2}
				c.enqueue(frame)
				queue := c.spaces[2].queue
				copy(queue[1:], queue[:len(queue)-1])
				queue[0] = frame
			}
		case kind == 27:
			body, err := r.take(8)
			if err != nil {
				return err
			}
			c.pathResponse(body)
		case kind == 28 || kind == 29:
			code, err := r.v()
			if err != nil {
				return err
			}
			if kind == 28 {
				if _, err := r.v(); err != nil {
					return err
				}
			}
			reason, err := r.text(4096)
			if err != nil {
				return err
			}
			return fmt.Errorf("QUIC peer closed: code %d %s", code, reason)
		case kind == 30:
			if c.server {
				return errors.New("client sent QUIC HANDSHAKE_DONE")
			}
			if !c.established {
				return errors.New("premature QUIC HANDSHAKE_DONE")
			}
			c.confirmed = true
		case kind == 7:
			n, err := r.v()
			if err != nil {
				return err
			}
			if c.server {
				return errors.New("client sent QUIC NEW_TOKEN")
			}
			if _, err := r.take(n); err != nil {
				return err
			}
		case kind == 48 || kind == 49:
			n := uint64(len(r))
			if kind == 49 {
				n, err = r.v()
				if err != nil {
					return err
				}
			}
			body, err := r.take(n)
			if err != nil {
				return err
			}
			if len(body) > 1400 {
				return errors.New("QUIC datagram limit exceeded")
			}
			select {
			case c.datagrams <- append([]byte{}, body...):
			default:
			}
		default:
			return fmt.Errorf("unsupported QUIC frame %d", kind)
		}
	}
	if eliciting {
		c.spaces[level].ack = true
	}
	return nil
}
func (c *quicConn) acknowledge(level int, largest, delay uint64, ranges []quicPNRange, now time.Time) {
	space := &c.spaces[level]
	ackedBytes := 0
	bbrBytes, priorFlight := 0, c.inFlight
	var deliveryPacket quicSent
	var deliveryPN uint64
	var rttSample time.Duration
	newlyAcked := false
	latest := space.sent[largest]
	for pn, p := range space.sent {
		acked := false
		for _, r := range ranges {
			if pn >= r.low && pn <= r.high {
				acked = true
				break
			}
		}
		if !acked {
			continue
		}
		delete(space.sent, pn)
		if level == 2 && pn >= c.phaseFirstPN {
			c.writePhaseAcked = true
		}
		if p.mtuProbe {
			c.inFlight -= p.size
			c.ackPMTU(pn, p.size, now)
			continue
		}
		if c.pmtu != nil && p.size > 1200 {
			c.pmtu.largeLoss = 0
		}
		if p.eliciting {
			newlyAcked = true
			c.inFlight -= p.size
			c.probes[level] = 0
			if c.brutal != nil && !p.at.Before(c.brutal.started) {
				c.brutal.feedback(now, p.size, 0)
			}
			if c.bbr != nil && c.brutal == nil && p.delivery.valid {
				bbrBytes += p.size
				if !deliveryPacket.delivery.valid || p.delivery.delivered > deliveryPacket.delivery.delivered || p.delivery.delivered == deliveryPacket.delivery.delivered && (p.at.After(deliveryPacket.at) || p.at.Equal(deliveryPacket.at) && pn > deliveryPN) {
					deliveryPacket = p
					deliveryPN = pn
				}
			}
			if p.at.After(c.recovery) && !p.at.After(c.limitedUntil) {
				ackedBytes += p.size
			}
		}
		for _, f := range p.frames {
			c.retained -= len(f.data)
			if f.fin && f.stream != nil {
				f.stream.finAck = true
				c.retireStream(f.stream)
			}
		}
	}
	if !latest.at.IsZero() && !latest.mtuProbe {
		sample := now.Sub(latest.at)
		c.latestRTT = sample
		if c.minRTT == 0 || sample < c.minRTT {
			c.minRTT = sample
		}
		if level == 2 {
			d := time.Duration(min(delay, uint64(c.peer.maxAckDelay/time.Microsecond)>>c.peer.ackExponent)<<c.peer.ackExponent) * time.Microsecond
			if sample-c.minRTT > d {
				sample -= d
			}
		}
		if c.srtt == 333*time.Millisecond {
			c.srtt = sample
			c.rttvar = sample / 2
		} else {
			diff := c.srtt - sample
			if diff < 0 {
				diff = -diff
			}
			c.rttvar = (3*c.rttvar + diff) / 4
			c.srtt = (7*c.srtt + sample) / 8
		}
		c.ptoCount = 0
		rttSample = sample
	}
	if c.bbr != nil && c.bbr.model != nil && c.brutal == nil {
		c.cwnd = c.bbr.ackLostModel(level, ranges, now, c.cwnd)
	}
	if bbrBytes > 0 {
		c.cwnd = c.bbr.ack(now, deliveryPacket, bbrBytes, c.cwnd, c.inFlight, priorFlight, rttSample)
	} else if newlyAcked {
		c.congestionACK(now, ackedBytes)
	}
	threshold := max(time.Millisecond, max(c.srtt, c.latestRTT)*9/8)
	if c.bbr != nil && c.bbr.model != nil && c.brutal == nil {
		// A loss sample's cumulative byte count must not depend on Go map iteration order.
		var small [32]uint64
		lost := small[:0]
		for pn, p := range space.sent {
			if pn+3 <= largest || pn < largest && now.Sub(p.at) >= threshold {
				lost = append(lost, pn)
			}
		}
		slices.Sort(lost)
		for _, pn := range lost {
			c.losePacket(level, pn, space.sent[pn], now)
		}
		return
	}
	for pn, p := range space.sent {
		if pn+3 <= largest || pn < largest && now.Sub(p.at) >= threshold {
			c.losePacket(level, pn, p, now)
		}
	}
}
func (c *quicConn) losePacket(level int, pn uint64, p quicSent, now time.Time) {
	delete(c.spaces[level].sent, pn)
	if p.mtuProbe {
		c.inFlight -= p.size
		c.losePMTU(now)
		return
	}
	c.lostPMTUData(p.size, now)
	if p.eliciting {
		c.inFlight -= p.size
		if c.brutal != nil {
			if !p.at.Before(c.brutal.started) {
				c.brutal.feedback(now, 0, p.size)
			}
		} else if c.bbr != nil {
			c.cwnd = c.bbr.lostPacket(now, p, c.cwnd, c.inFlight)
			if c.bbr.model != nil {
				c.bbr.model.recordLoss(level, pn)
			}
		} else if p.at.After(c.recovery) {
			c.renoCredit = 0
			if c.cubic != nil {
				c.cwnd = c.cubic.lost(c.cwnd)
			} else {
				c.cwnd = max(2*quicMSS, c.cwnd/2)
			}
			c.ssthresh = c.cwnd
			c.recovery = now
		}
	}
	var retry []quicFrame
	for _, f := range p.frames {
		if f.reliable && (f.stream == nil || !f.stream.resetSent) {
			retry = append(retry, f)
		} else {
			c.retained -= len(f.data)
		}
	}
	// Recover missing stream headers before draining queued later payloads.
	c.spaces[level].prependRecovery(retry)
}

func isPathResponse(frame quicFrame) bool { return len(frame.data) == 9 && frame.data[0] == 27 }

func (s *quicSpace) prependRecovery(frames []quicFrame) {
	// A blocked path needs its response before retransmitted application data,
	// including when a PTO grants only one congestion-exempt packet.
	index := 0
	for index < len(s.queue) && isPathResponse(s.queue[index]) {
		index++
	}
	count := len(s.queue)
	s.queue = append(s.queue, make([]quicFrame, len(frames))...)
	copy(s.queue[index+len(frames):], s.queue[index:count])
	copy(s.queue[index:], frames)
}
func (c *quicConn) pto() time.Duration {
	return max(10*time.Millisecond, c.srtt+max(4*c.rttvar, time.Millisecond)+c.peer.maxAckDelay) * time.Duration(1<<min(c.ptoCount, uint(8)))
}
func (c *quicConn) lossDeadline() time.Time {
	_, deadline := c.probeSpace()
	return deadline
}
func (c *quicConn) probeSpace() (int, time.Time) {
	level := -1
	var deadline time.Time
	for i, s := range c.spaces {
		var latest time.Time
		for _, p := range s.sent {
			if p.eliciting && !p.mtuProbe && p.at.After(latest) {
				latest = p.at
			}
		}
		if latest.IsZero() {
			continue
		}
		at := latest.Add(c.pto())
		if deadline.IsZero() || at.Before(deadline) {
			level, deadline = i, at
		}
	}
	return level, deadline
}
func (c *quicConn) onPTO(now time.Time) {
	level, _ := c.probeSpace()
	if level < 0 {
		return
	}
	var oldest time.Time
	var selected quicSent
	for _, p := range c.spaces[level].sent {
		if p.eliciting && !p.mtuProbe && (oldest.IsZero() || p.at.Before(oldest)) {
			oldest = p.at
			selected = p
		}
	}
	// PTO probes are not loss declarations and must be allowed past cwnd.
	// Keep the original packet accounted until ACK/loss, and account copies too.
	var probe []quicFrame
	for _, f := range selected.frames {
		if f.reliable && (f.stream == nil || !f.stream.resetSent) {
			probe = append(probe, f)
			c.retained += len(f.data)
		}
	}
	if len(probe) == 0 {
		probe = []quicFrame{{data: []byte{1}, level: level, reliable: true}}
		c.retained++
	}
	c.spaces[level].prependRecovery(probe)
	c.probes[level] = 1
	c.ptoCount++
	if c.ptoCount >= 2 && c.sendMTU.Load() > 1200 {
		c.resetPMTU(now)
	}
}
func (c *quicConn) flush(now time.Time) error {
	err := c.flushPackets(now)
	if c.batch != nil {
		if e := c.batch.flush(); err == nil {
			err = e
		}
	}
	return err
}

// sendPacket sends one sealed packet, batching it when offload is enabled.
func (c *quicConn) sendPacket(packet []byte) error {
	if c.batch != nil {
		return c.batch.add(packet)
	}
	return c.send(packet)
}

func (c *quicConn) flushPackets(now time.Time) error {
	rate := c.sendRate.Load()
	if target := c.brutalTarget.Load(); target != 0 {
		if c.brutal == nil {
			c.brutal = &quicBrutal{started: now}
			c.rateAt, c.rateTokens = time.Time{}, 0
		}
		rate, c.cwnd = c.brutal.pacing(now, target, c.srtt, c.disableLossCompensation)
	} else if c.bbr != nil {
		if c.bbr.model != nil {
			c.cwnd = c.bbr.resumeModel(now, c.inFlight, c.cwnd)
		}
		pacing := c.bbr.pacing(c.inFlight == 0)
		if rate == 0 || pacing < rate {
			rate = pacing
		}
	} else if c.cubic != nil {
		pacing := uint64(1.25 * float64(c.cwnd) / max(c.srtt, time.Microsecond).Seconds())
		if rate == 0 || pacing < rate {
			rate = pacing
		}
	}
	c.rateNext = time.Time{}
	if rate > 0 {
		burst := max(float64(4096), float64(rate)/50)
		if c.cubic != nil || c.brutal != nil {
			burst = min(burst, 10*quicMSS)
		}
		if c.bbr != nil && c.brutal == nil {
			burst = min(burst, float64(c.bbr.quantum()))
		}
		if c.rateAt.IsZero() {
			c.rateTokens = burst
		} else {
			c.rateTokens = min(burst, c.rateTokens+now.Sub(c.rateAt).Seconds()*float64(rate))
		}
		c.rateAt = now
	}

	for packets := 0; packets < 64; packets++ {
		sent := false
		for level := 0; level < 3; level++ {
			space := &c.spaces[level]
			if space.write == nil {
				continue
			}
			// A path can shrink after a datagram was queued. Reliable stream
			// frames stay below the minimum path size; oversized UDP is dropped.
			for len(space.queue) > 0 && !space.queue[0].reliable && len(space.queue[0].data) > c.payloadLimit() {
				c.retained -= len(space.queue[0].data)
				space.queue[0] = quicFrame{}
				space.queue = space.queue[1:]
			}
			payload := c.payload[:0]
			var frames []quicFrame
			if space.ack {
				payload = space.appendACKFrame(payload)
				space.ack = false
			}
			// Keep application replies queued until the new port is validated;
			// sending unreliable UDP replies to the old NAT tuple loses them.
			if (level != 2 || c.path == nil) && (c.inFlight < c.cwnd || c.probes[level] != 0) && (level != 2 || rate == 0 || c.rateTokens >= 1200 || c.probes[level] != 0) {
				for len(space.queue) > 0 && len(payload)+len(space.queue[0].data) <= c.payloadLimit() {
					f := space.queue[0]
					space.queue[0] = quicFrame{}
					space.queue = space.queue[1:]
					if f.stream != nil && f.stream.resetSent {
						c.retained -= len(f.data)
						continue
					}
					payload = append(payload, f.data...)
					frames = append(frames, f)
				}
			}
			if len(payload) == 0 {
				if level == 2 && rate > 0 && len(space.queue) > 0 && c.rateTokens < 1200 {
					c.rateNext = now.Add(time.Duration((1200 - c.rateTokens) / float64(rate) * float64(time.Second)))
				}
				continue
			}
			if space.nextPN >= 1<<62 {
				return errors.New("QUIC packet number exhausted")
			}
			if level == 2 && c.confirmed && c.writePhaseAcked && space.nextPN-c.phaseFirstPN >= 1<<20 {
				next, e := space.write.next()
				if e != nil {
					return e
				}
				space.write = next
				c.phase = !c.phase
				c.phaseFirstPN = space.nextPN
				c.writePhaseAcked = false
			}
			for _, frame := range frames {
				if level == 2 && isPathResponse(frame) {
					if padding := 1200 - (1 + len(c.dcid) + 4 + 16) - len(payload); padding > 0 {
						payload = append(payload, make([]byte, padding)...)
					}
					break
				}
			}
			if cap(payload) <= quicScratchLimit {
				c.payload = payload[:0]
			}
			packet := c.scratch.sealPacket(payload, c.dcid, c.cid, c.token, level, space.nextPN, c.phase, space.write, c.minInitial)
			if err := c.sendPacket(packet); err != nil {
				if level == 2 && c.pmtu != nil && quicMessageTooLarge(err) && c.sendMTU.Load() > 1200 {
					// Never reuse a packet number after a failed OS send.
					space.nextPN++
					space.queue = append(frames, space.queue...)
					space.ack = true
					c.resetPMTU(now)
					sent = true
					continue
				}
				return err
			}
			if level == 2 && rate > 0 && len(frames) > 0 {
				c.rateTokens -= float64(len(packet))
			}
			c.lastSend = now
			reliable := frames[:0]
			for _, f := range frames {
				if f.reliable {
					reliable = append(reliable, f)
				} else {
					c.retained -= len(f.data)
				}
			}
			if len(frames) > 0 {
				if c.probes[level] != 0 {
					c.probes[level]--
				}
				p := quicSent{at: now, size: len(packet), frames: reliable, eliciting: true}
				if c.bbr != nil && c.brutal == nil {
					backlogged := false
					for _, s := range c.spaces {
						backlogged = backlogged || len(s.queue) > 0
					}
					p.delivery = c.bbr.sent(now, c.inFlight, p.size, !backlogged && c.inFlight+p.size < c.cwnd)
				}
				space.sent[space.nextPN] = p
				c.inFlight += len(packet)
				if c.inFlight+quicMSS >= c.cwnd || c.cubic != nil && c.retained >= c.cwnd {
					c.limitedUntil = now
				}
			}
			space.nextPN++
			sent = true
			if level == 1 && !c.server && c.spaces[0].write != nil {
				c.dropSpace(0)
			}
			break
		}
		if !sent {
			return nil
		}
	}
	signalQUIC(c.wake)
	return nil
}
