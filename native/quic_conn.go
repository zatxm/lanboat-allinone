package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type quicFailure struct{ err error }
type quicPeerCID struct {
	id    []byte
	token [16]byte
}
type quicPNRange struct{ low, high uint64 }
type quicFrame struct {
	data     []byte
	level    int
	reliable bool
	stream   *quicStream
	fin      bool
}
type quicSent struct {
	mtuProbe  bool
	at        time.Time
	frames    []quicFrame
	size      int
	eliciting bool
	delivery  quicDelivery
}
type quicSpace struct {
	read, write  *quicKey
	crypto       quicBuffer
	cryptoOffset uint64
	nextPN       uint64
	largest      int64
	received     []quicPNRange
	ack          bool
	sent         map[uint64]quicSent
	queue        []quicFrame
}
type quicConn struct {
	pmtu                                            *quicPMTU
	sendMTU                                         atomic.Int64
	idleTimeout                                     time.Duration
	streamWindow, connectionWindow                  uint64
	keepAlive                                       time.Duration
	minInitial                                      int
	sendRate                                        atomic.Uint64
	brutalTarget                                    atomic.Uint64
	brutal                                          *quicBrutal
	disableLossCompensation                         bool
	rateAt                                          time.Time
	rateTokens                                      float64
	rateNext                                        time.Time
	ctx                                             context.Context
	cancel                                          context.CancelFunc
	server                                          bool
	local, remote                                   net.Addr
	cid, dcid, originalCID, retryCID, token         []byte
	tls                                             *tls.QUICConn
	state                                           tls.ConnectionState
	peer                                            quicPeerParams
	spaces                                          [3]quicSpace
	ready, done                                     chan struct{}
	packets                                         chan quicDatagram
	packetMu                                        sync.Mutex
	packetBytes                                     int
	pathRemote, packetRemote                        net.Addr
	sendTo                                          func([]byte, net.Addr) error
	path                                            *quicPath
	ops                                             chan *quicOperation
	wake                                            chan struct{}
	accept                                          chan *quicStream
	datagrams                                       chan []byte
	failure                                         atomic.Pointer[quicFailure]
	consumed                                        atomic.Uint64
	streams                                         map[uint64]*quicStream
	pending                                         []*quicOperation
	nextLocal                                       [2]uint64
	nextPeer                                        [2]uint64
	peerLimits                                      [2]uint64
	receiveMax, receiveHighest, sendTotal           uint64
	retained                                        int
	send                                            func([]byte) error
	cleanup                                         func()
	onReady                                         func(*quicConn) bool
	start, lastReceive, lastSend, handshakeDeadline time.Time
	srtt, rttvar, minRTT, latestRTT                 time.Duration
	cwnd, ssthresh, inFlight                        int
	cubic                                           *quicCubic
	bbr                                             *quicBBR
	renoCredit                                      int
	limitedUntil                                    time.Time
	recovery                                        time.Time
	ptoCount                                        uint
	probes                                          [3]byte
	established, confirmed, paramsReceived          bool
	phase, readPhase                                bool
	previousRead                                    *quicKey
	phaseStart                                      uint64
	writePhaseAcked                                 bool
	phaseFirstPN                                    uint64
	initialHello                                    []byte
	peerCIDs                                        map[uint64]quicPeerCID
	peerCIDSeq, retirePrior                         uint64
}

func newQUICConn(ctx context.Context, cfg *tls.Config, local, remote net.Addr, cid, dcid, odcid, retry []byte, server bool, send func([]byte) error, cleanup func(), options ...quicOptions) (*quicConn, error) {
	child, cancel := context.WithCancel(ctx)
	opt := quicOptions{}
	if len(options) != 0 {
		opt = options[0]
	}
	opt = opt.defaults()
	now := time.Now()
	minimum := max(1200, opt.initial)
	c := &quicConn{keepAlive: 30 * time.Second, minInitial: minimum, ctx: child, cancel: cancel, local: local, remote: remote, pathRemote: remote, cid: append([]byte{}, cid...), dcid: append([]byte{}, dcid...), originalCID: append([]byte{}, odcid...), retryCID: append([]byte{}, retry...), server: server, send: send, cleanup: cleanup, ready: make(chan struct{}), done: make(chan struct{}), packets: make(chan quicDatagram, quicInboxPackets), ops: make(chan *quicOperation, 128), wake: make(chan struct{}, 1), accept: make(chan *quicStream, 128), datagrams: make(chan []byte, 128), streams: map[uint64]*quicStream{}, receiveMax: opt.connectionWindow, start: now, lastReceive: now, lastSend: now, handshakeDeadline: now.Add(15 * time.Second), srtt: 333 * time.Millisecond, rttvar: 166 * time.Millisecond, cwnd: 10 * quicMSS, ssthresh: 4 << 20}
	c.idleTimeout, c.streamWindow, c.connectionWindow = opt.idleTimeout, opt.streamWindow, opt.connectionWindow
	if opt.discoverMTU {
		c.pmtu = &quicPMTU{upper: 1472, next: now.Add(200 * time.Millisecond)}
	}
	if opt.discoverMTU || opt.packetSize != 0 {
		c.sendMTU.Store(int64(minimum))
	}
	if opt.bbr2 {
		c.bbr = newQUICBBR2(now)
	} else if opt.bbr3 {
		c.bbr = newQUICBBR3(now)
	} else if opt.bbr {
		c.bbr = newQUICBBR(now, opt.bbrProfile)
	} else if opt.cubic {
		c.cubic = new(quicCubic)
	}
	if opt.keepAlive != 0 {
		c.keepAlive = opt.keepAlive
	}
	c.disableLossCompensation = opt.disableLossCompensation
	base := uint64(0)
	if server {
		base = 1
	}
	c.peerCIDs = map[uint64]quicPeerCID{0: {id: append([]byte{}, dcid...)}}
	c.nextLocal = [2]uint64{base, base + 2}
	c.nextPeer = [2]uint64{base ^ 1, (base ^ 1) + 2}
	c.peerLimits = [2]uint64{opt.streams, 16}
	for i := range c.spaces {
		c.spaces[i].largest = -1
		c.spaces[i].sent = map[uint64]quicSent{}
	}
	var err error
	c.spaces[0].read, c.spaces[0].write, err = quicInitialKeys(odcid, server)
	if err != nil {
		cancel()
		return nil, err
	}
	if server && len(retry) > 0 {
		c.spaces[0].read, c.spaces[0].write, err = quicInitialKeys(cid, true)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	if cfg.MinVersion > tls.VersionTLS13 || cfg.MaxVersion != 0 && cfg.MaxVersion < tls.VersionTLS13 {
		cancel()
		return nil, errors.New("QUIC requires TLS1.3")
	}
	tlsOptions := cloneTLSConfig(cfg)
	tlsOptions.MinVersion = tls.VersionTLS13
	tlsOptions.MaxVersion = tls.VersionTLS13
	if server {
		c.tls = tls.QUICServer(&tls.QUICConfig{TLSConfig: tlsOptions})
	} else {
		c.tls = tls.QUICClient(&tls.QUICConfig{TLSConfig: tlsOptions})
	}
	c.tls.SetTransportParameters(quicConnectionParameters(cid, odcid, retry, server, opt))
	return c, nil
}
func (c *quicConn) err() error {
	if f := c.failure.Load(); f != nil {
		return f.err
	}
	return net.ErrClosed
}
func (c *quicConn) finish(op *quicOperation, result quicResult) {
	select {
	case op.reply <- result:
	default:
	}
}
func quicLevel(level tls.QUICEncryptionLevel) int {
	switch level {
	case tls.QUICEncryptionLevelInitial:
		return 0
	case tls.QUICEncryptionLevelHandshake:
		return 1
	case tls.QUICEncryptionLevelApplication:
		return 2
	}
	return -1
}
func (c *quicConn) tlsEvents() error {
	for {
		event := c.tls.NextEvent()
		if event.Kind == tls.QUICNoEvent {
			return nil
		}
		level := quicLevel(event.Level)
		switch event.Kind {
		case tls.QUICSetReadSecret, tls.QUICSetWriteSecret:
			if level < 0 {
				return errors.New("QUIC early data is disabled")
			}
			key, err := newQUICKey(event.Data, event.Suite)
			if err != nil {
				return err
			}
			if event.Kind == tls.QUICSetReadSecret {
				c.spaces[level].read = key
			} else {
				c.spaces[level].write = key
			}
		case tls.QUICWriteData:
			if level < 0 {
				return errors.New("invalid QUIC TLS level")
			}
			data := append([]byte{}, event.Data...)
			space := &c.spaces[level]
			if !c.server && level == 0 {
				c.initialHello = append(c.initialHello, data...)
			}
			for len(data) > 0 {
				n := min(1024, len(data))
				frame := quicVar([]byte{6}, space.cryptoOffset)
				frame = quicVar(frame, uint64(n))
				frame = append(frame, data[:n]...)
				space.cryptoOffset += uint64(n)
				c.enqueue(quicFrame{data: frame, level: level, reliable: true})
				data = data[n:]
			}
		case tls.QUICTransportParameters:
			peer, err := parseQUICParameters(event.Data, c.dcid, c.originalCID, c.retryCID, c.server)
			if err != nil {
				return err
			}
			if peer.maxUDPPayload < uint64(c.minInitial) {
				return errors.New("QUIC peer cannot support configured minimum packet size")
			}
			c.peer = peer
			c.paramsReceived = true
		case tls.QUICTransportParametersRequired:
			return errors.New("QUIC transport parameters were not configured")
		case tls.QUICHandshakeDone:
			if !c.paramsReceived {
				return errors.New("missing peer QUIC parameters")
			}
			c.established = true
			c.initialHello = nil
			c.state = c.tls.ConnectionState()
			close(c.ready)
			if c.onReady != nil && !c.onReady(c) {
				return errors.New("QUIC listener accept capacity reached")
			}
			if c.server {
				c.confirmed = true
				c.enqueue(quicFrame{data: []byte{30}, level: 2, reliable: true})
			}
		case tls.QUICStoreSession:
			if err := c.tls.StoreSession(event.SessionState); err != nil {
				return err
			}
		case tls.QUICRejectedEarlyData:
		case tls.QUICErrorEvent:
			return event.Err
		}
	}
}
func (c *quicConn) enqueue(frame quicFrame) {
	c.spaces[frame.level].queue = append(c.spaces[frame.level].queue, frame)
	c.retained += len(frame.data)
}
func (c *quicConn) dropSpace(level int) {
	s := &c.spaces[level]
	for _, p := range s.sent {
		if p.eliciting {
			c.inFlight -= p.size
		}
		for _, f := range p.frames {
			c.retained -= len(f.data)
		}
	}
	for _, f := range s.queue {
		c.retained -= len(f.data)
	}
	s.sent = map[uint64]quicSent{}
	s.queue = nil
	s.write = nil
	s.read = nil
	s.ack = false
	c.probes[level] = 0
}
func (c *quicConn) run() {
	var result error
	defer func() {
		if result == nil {
			result = net.ErrClosed
		}
		c.failure.Store(&quicFailure{result})
		for level := 2; level >= 0; level-- {
			s := &c.spaces[level]
			if s.write != nil {
				reason := result.Error()
				if len(reason) > 128 {
					reason = reason[:128]
				}
				frame := quicVar([]byte{28}, 0)
				frame = quicVar(frame, 0)
				frame = quicString(frame, reason)
				_ = c.send(sealQUICPacket(frame, c.dcid, c.cid, c.token, level, s.nextPN, c.phase, s.write))
				break
			}
		}
		c.cancel()
		_ = c.tls.Close()
		if c.cleanup != nil {
			c.cleanup()
		}
		c.discardPackets()
		close(c.done)
	}()
	if err := c.tls.Start(c.ctx); err != nil {
		result = err
		return
	}
	if err := c.tlsEvents(); err != nil {
		result = err
		return
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		if err := c.receiveBurst(); err != nil {
			result = err
			return
		}
		now := time.Now()
		c.servicePath(now)
		c.updateWindows()
		c.serviceOperations()
		if c.retained > 8<<20 {
			result = errors.New("QUIC send buffer limit exceeded")
			return
		}
		if err := c.flush(now); err != nil {
			result = err
			return
		}
		if err := c.servicePMTU(now); err != nil {
			result = err
			return
		}
		deadline := c.lastReceive.Add(c.idleDuration())
		if !c.established {
			deadline = c.handshakeDeadline
		}
		if at := c.lossDeadline(); !at.IsZero() && at.Before(deadline) {
			deadline = at
		}
		if at := c.pmtuDeadline(); !at.IsZero() && at.Before(deadline) {
			deadline = at
		}
		if c.established && c.keepAlive > 0 && c.lastSend.Add(c.keepAliveDuration()).Before(deadline) {
			deadline = c.lastSend.Add(c.keepAliveDuration())
		}
		if !c.rateNext.IsZero() && c.rateNext.Before(deadline) {
			deadline = c.rateNext
		}
		if c.path != nil {
			at := c.path.expires
			if c.path.attempts < 3 && c.path.received*3-c.path.sent >= 40 {
				if c.path.next.Before(at) {
					at = c.path.next
				}
			}
			if at.Before(deadline) {
				deadline = at
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(max(time.Millisecond, time.Until(deadline)))
		select {
		case <-c.ctx.Done():
			result = c.ctx.Err()
			return
		case packet := <-c.packets:
			if err := c.receivePacket(packet); err != nil {
				result = err
				return
			}
		case op := <-c.ops:
			if len(c.pending) >= 256 {
				c.finish(op, quicResult{err: errors.New("QUIC operation queue full")})
			} else {
				c.pending = append(c.pending, op)
			}
		case <-c.wake:
		case now := <-timer.C:
			if !c.established && !now.Before(c.handshakeDeadline) {
				result = errors.New("QUIC handshake timeout")
				return
			}
			idle := c.idleDuration()
			if c.established && !now.Before(c.lastReceive.Add(idle)) {
				result = errors.New("QUIC idle timeout")
				return
			}
			if c.established && c.keepAlive > 0 && !now.Before(c.lastSend.Add(c.keepAliveDuration())) {
				c.enqueue(quicFrame{data: []byte{1}, level: 2, reliable: true})
			}
			if at := c.lossDeadline(); !at.IsZero() && !now.Before(at) {
				c.onPTO(now)
			}
		}
	}
}
func (c *quicConn) serviceOperations() {
	original := c.pending
	pending := original[:0]
	for _, op := range c.pending {
		if op.canceled.Load() {
			c.finish(op, quicResult{err: context.Canceled})
			continue
		}
		s := op.stream
		switch op.kind {
		case 'o':
			if !c.established {
				pending = append(pending, op)
				continue
			}
			index := int(op.n)
			if index > 1 {
				c.finish(op, quicResult{err: errors.New("invalid QUIC stream type")})
				continue
			}
			limit := c.peer.maxBi
			if index == 1 {
				limit = c.peer.maxUni
			}
			id := c.nextLocal[index]
			if id/4 >= limit {
				pending = append(pending, op)
				continue
			}
			if len(c.streams) >= 256 {
				c.finish(op, quicResult{err: errors.New("QUIC stream capacity reached")})
				continue
			}
			s = newQUICStream(c, id)
			s.delivered = true
			c.streams[id] = s
			c.nextLocal[index] += 4
			c.finish(op, quicResult{stream: s})
		case 'd':
			if !c.established {
				pending = append(pending, op)
				continue
			}
			if c.peer.maxDatagram == 0 {
				c.finish(op, quicResult{err: errors.New("peer disabled QUIC datagrams")})
				continue
			}
			frame := append(quicVar([]byte{49}, uint64(len(op.data))), op.data...)
			if len(frame) > c.payloadLimit() || uint64(len(frame)) > c.peer.maxDatagram {
				c.finish(op, quicResult{err: errQUICDatagramSize})
				continue
			}
			if c.retained > 1<<20 {
				pending = append(pending, op)
				continue
			}
			c.enqueue(quicFrame{data: frame, level: 2})
			c.finish(op, quicResult{n: len(op.data)})
		case 'u':
			if !c.confirmed {
				pending = append(pending, op)
				continue
			}
			next, err := c.spaces[2].write.next()
			if err == nil {
				c.spaces[2].write = next
				c.phase = !c.phase
				c.writePhaseAcked = false
				c.phaseFirstPN = c.spaces[2].nextPN
			}
			c.finish(op, quicResult{err: err})
		case 'w', 'f':
			if s == nil || s.writeErr != nil || s.sendFin || s.appClosed {
				err := io.ErrClosedPipe
				if s != nil && s.writeErr != nil {
					err = s.writeErr
				}
				c.finish(op, quicResult{n: int(op.accepted.Load()), err: err})
				continue
			}
			if s.id&2 != 0 && (s.id&1 == 0) == c.server {
				c.finish(op, quicResult{err: errors.New("cannot write receive-only QUIC stream")})
				continue
			}
			if op.kind == 'f' {
				s.sendFin = true
				frame := quicVar([]byte{15}, s.id)
				frame = quicVar(frame, s.sendOffset)
				frame = quicVar(frame, 0)
				c.enqueue(quicFrame{data: frame, level: 2, reliable: true, stream: s, fin: true})
				c.finish(op, quicResult{})
				continue
			}
			pos := int(op.accepted.Load())
			for pos < len(op.data) && c.retained < 1<<20 && s.sendOffset < s.sendLimit && c.sendTotal < c.peer.maxData {
				n := min(1000, len(op.data)-pos, int(s.sendLimit-s.sendOffset), int(c.peer.maxData-c.sendTotal))
				frame := quicVar([]byte{14}, s.id)
				frame = quicVar(frame, s.sendOffset)
				frame = quicVar(frame, uint64(n))
				frame = append(frame, op.data[pos:pos+n]...)
				s.sendOffset += uint64(n)
				c.sendTotal += uint64(n)
				pos += n
				op.accepted.Store(int64(pos))
				c.enqueue(quicFrame{data: frame, level: 2, reliable: true, stream: s})
			}
			if pos == len(op.data) {
				c.finish(op, quicResult{n: pos})
			} else {
				pending = append(pending, op)
			}
		case 'c':
			if s != nil && !s.appClosed {
				s.appClosed = true
				s.writeErr = net.ErrClosed
				s.mu.Lock()
				s.readErr = net.ErrClosed
				s.buffer.parts = nil
				s.mu.Unlock()
				signalQUIC(s.readWake)
				if !s.sendFin && !(s.id&2 != 0 && (s.id&1 == 0) == c.server) {
					s.resetSent = true
					frame := quicVar([]byte{4}, s.id)
					frame = quicVar(frame, 0)
					frame = quicVar(frame, s.sendOffset)
					c.enqueue(quicFrame{data: frame, level: 2, reliable: true})
				}
				if !s.stopped && !(s.id&2 != 0 && (s.id&1 == 0) != c.server) {
					s.stopped = true
					frame := quicVar([]byte{5}, s.id)
					frame = quicVar(frame, 0)
					c.enqueue(quicFrame{data: frame, level: 2, reliable: true})
				}
				c.retireStream(s)
			}
			c.finish(op, quicResult{})
		default:
			c.finish(op, quicResult{err: errors.New("unknown QUIC operation")})
		}
	}
	clear(original[len(pending):])
	c.pending = pending
}
func (c *quicConn) updateWindows() {
	consumed := c.consumed.Load()
	connWindow, streamWindow := c.receiveWindows()
	if consumed+connWindow/2 >= c.receiveMax {
		c.receiveMax = consumed + connWindow
		c.enqueue(quicFrame{data: quicVar([]byte{16}, c.receiveMax), level: 2, reliable: true})
	}
	for _, s := range c.streams {
		read := s.consumed.Load()
		if !s.stopped && read+streamWindow/2 >= s.readLimit {
			s.readLimit = read + streamWindow
			f := quicVar([]byte{17}, s.id)
			f = quicVar(f, s.readLimit)
			c.enqueue(quicFrame{data: f, level: 2, reliable: true})
		}
	}
}
func (c *quicConn) retireStream(s *quicStream) {
	if !s.appClosed {
		return
	}
	s.mu.Lock()
	received := s.finalKnown && (s.stopped || s.buffer.position == s.final) || s.id&2 != 0 && (s.id&1 == 0) != c.server
	s.mu.Unlock()
	if !received || !s.resetSent && !s.finAck && !(s.id&2 != 0 && (s.id&1 == 0) == c.server) {
		return
	}
	if c.streams[s.id] != s {
		return
	}
	delete(c.streams, s.id)
	remote := (s.id&1 == 0) == c.server
	if remote {
		index := int((s.id >> 1) & 1)
		c.peerLimits[index]++
		f := quicVar([]byte{byte(18 + index)}, c.peerLimits[index])
		c.enqueue(quicFrame{data: f, level: 2, reliable: true})
	}
}
func (c *quicConn) streamFor(id uint64) (*quicStream, error) {
	if s := c.streams[id]; s != nil {
		return s, nil
	}
	remote := (id&1 == 0) == c.server
	index := int((id >> 1) & 1)
	if !remote {
		if id < c.nextLocal[index] {
			return nil, nil
		}
		return nil, errors.New("peer used an uncreated local QUIC stream")
	}
	if id < c.nextPeer[index] {
		return nil, nil
	}
	if id/4 >= c.peerLimits[index] || (id-c.nextPeer[index])/4+uint64(len(c.streams)) >= 256 {
		return nil, errors.New("peer exceeded QUIC stream capacity")
	}
	for next := c.nextPeer[index]; next <= id; next += 4 {
		c.streams[next] = newQUICStream(c, next)
	}
	c.nextPeer[index] = id + 4
	return c.streams[id], nil
}
func (c *quicConn) receiveStream(id, offset uint64, data []byte, fin bool) error {
	s, err := c.streamFor(id)
	if err != nil || s == nil {
		return err
	}
	if id&2 != 0 && (id&1 == 0) != c.server {
		return errors.New("peer wrote to send-only QUIC stream")
	}
	end := offset + uint64(len(data))
	if end < offset || end >= 1<<62 || end > s.readLimit {
		return errors.New("QUIC stream receive window exceeded")
	}
	if end > s.highest {
		delta := end - s.highest
		if c.receiveHighest+delta > c.receiveMax {
			return errors.New("QUIC connection receive window exceeded")
		}
		c.receiveHighest += delta
		s.highest = end
	}
	s.mu.Lock()
	if s.finalKnown && end > s.final || fin && s.finalKnown && end != s.final {
		s.mu.Unlock()
		return errors.New("inconsistent QUIC final size")
	}
	if fin {
		if end < s.highest {
			s.mu.Unlock()
			return errors.New("QUIC final size below received data")
		}
		s.finalKnown = true
		s.final = end
	}
	if !s.stopped {
		err = s.buffer.put(offset, data)
	} else {
		s.discardReceived()
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if err := c.deliverStream(s); err != nil {
		return err
	}
	signalQUIC(s.readWake)
	c.retireStream(s)
	return nil
}
func (c *quicConn) handleDatagram(packet []byte) error {
	if c.packetRemote != nil && !sameQUICAddress(c.packetRemote, c.pathRemote) && (!c.established || !sameQUICIP(c.packetRemote, c.pathRemote)) {
		return nil
	}
	for len(packet) > 0 {
		header, err := parseQUICHeader(packet)
		if err != nil {
			return nil
		}
		if header.retry {
			if c.server || c.established || len(c.retryCID) > 0 || c.spaces[0].largest >= 0 {
				return nil
			}
			if !bytes.Equal(header.dcid, c.cid) || len(header.scid) < 1 || len(header.scid) > 20 {
				return nil
			}
			tag := quicRetryTag(c.originalCID, packet[:len(packet)-16])
			if !bytes.Equal(tag, packet[len(packet)-16:]) {
				return nil
			}
			c.retryCID = append([]byte{}, header.scid...)
			c.dcid = append([]byte{}, header.scid...)
			c.peerCIDs[0] = quicPeerCID{id: append([]byte{}, header.scid...)}
			c.token = append([]byte{}, header.token...)
			nextPN := c.spaces[0].nextPN
			c.dropSpace(0)
			read, write, err := quicInitialKeys(c.dcid, false)
			if err != nil {
				return err
			}
			s := &c.spaces[0]
			s.read, s.write = read, write
			s.nextPN = nextPN
			s.largest = -1
			s.received = nil
			data := c.initialHello
			var offset uint64
			for len(data) > 0 {
				n := min(1024, len(data))
				f := quicVar([]byte{6}, offset)
				f = quicVar(f, uint64(n))
				f = append(f, data[:n]...)
				c.enqueue(quicFrame{data: f, level: 0, reliable: true})
				offset += uint64(n)
				data = data[n:]
			}
			return nil
		}
		part := packet[:header.end]
		packet = packet[header.end:]
		if !bytes.Equal(header.dcid, c.cid) {
			continue
		}
		space := &c.spaces[header.level]
		if space.read == nil {
			continue
		}
		plain, pn, first, err := openQUICPacket(part, header, space.read, space.largest)
		if header.level == 2 && err == nil && (first&4 != 0) != c.readPhase {
			next, e := space.read.next()
			if e != nil {
				return e
			}
			plain, pn, first, err = openQUICPacket(part, header, next, space.largest)
			if err == nil {
				c.previousRead = space.read
				space.read = next
				c.readPhase = !c.readPhase
				c.phaseStart = pn
			}
		} else if header.level == 2 && err != nil {
			next, e := space.read.next()
			if e == nil {
				var p []byte
				var n uint64
				var f byte
				p, n, f, e = openQUICPacket(part, header, next, space.largest)
				if e == nil && (f&4 != 0) != c.readPhase && int64(n) > space.largest {
					c.previousRead = space.read
					space.read = next
					c.readPhase = !c.readPhase
					c.phaseStart = n
					plain, pn, first, err = p, n, f, nil
				}
			}
			if err != nil && c.previousRead != nil {
				p, n, f, e := openQUICPacket(part, header, c.previousRead, space.largest)
				if e == nil && n < c.phaseStart {
					plain, pn, first, err = p, n, f, nil
				}
			}
		}
		if err != nil {
			continue
		}
		if header.level == 2 && c.phase != c.readPhase {
			next, e := space.write.next()
			if e != nil {
				return e
			}
			space.write = next
			c.phase = c.readPhase
			c.writePhaseAcked = false
			c.phaseFirstPN = space.nextPN
		}
		c.lastReceive = time.Now()
		if !c.server && header.level == 0 && len(c.retryCID) == 0 && len(header.scid) > 0 {
			c.dcid = append(c.dcid[:0], header.scid...)
			c.peerCIDs[0] = quicPeerCID{id: append([]byte{}, header.scid...)}
		}
		if !space.record(pn) {
			space.ack = true
			continue
		}
		if header.level == 2 && c.established && int64(pn) == space.largest {
			c.observePath(c.packetRemote, len(part), time.Now())
		}
		if err := c.handleFrames(header.level, pn, plain); err != nil {
			return fmt.Errorf("QUIC level %d: %w", header.level, err)
		}
		if header.level == 1 && c.server && c.spaces[0].write != nil {
			c.dropSpace(0)
		}
		if header.level == 2 && c.confirmed && c.spaces[1].write != nil {
			c.dropSpace(1)
		}
	}
	return nil
}

func (c *quicConn) deliverStream(s *quicStream) error {
	if s.delivered {
		return nil
	}
	select {
	case c.accept <- s:
		s.delivered = true
		return nil
	default:
		return errors.New("QUIC accept queue capacity reached")
	}
}

func (c *quicConn) payloadLimit() int {
	if size := c.sendMTU.Load(); size != 0 {
		return int(size) - 100
	}
	if c.minInitial > 1200 {
		return 1300
	}
	return 1100
}
func (c *quicConn) datagramLimit() int { return c.payloadLimit() - 3 }
