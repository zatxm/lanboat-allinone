package native

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const mieruWindow = 128
const mieruCarrierBytes = 4 << 20

type MieruOptions struct {
	UserHint          bool   `json:"user_hint,omitempty"`
	MieruMultiplexing string `json:"multiplexing,omitempty"`
	TrafficPattern    string `json:"traffic_pattern,omitempty"`
	LowEntropy        byte   `json:"low_entropy,omitempty"`
}

func (o MieruOptions) validate(kind, network string, tls TLSOptions, mtu int) error {
	if kind != "mieru" {
		if o.UserHint || o.MieruMultiplexing != "" || o.TrafficPattern != "" || o.LowEntropy != 0 {
			return errors.New("Mieru options require mieru type")
		}
		return nil
	}
	if network != "" && network != "tcp" && network != "udp" {
		return errors.New("Mieru network must be tcp or udp")
	}
	if tls.Enabled {
		return errors.New("Mieru uses its own authenticated encryption, not TLS")
	}
	if mtu != 0 && (mtu < 1280 || mtu > 1400) {
		return errors.New("Mieru MTU must be1280-1400")
	}
	switch o.MieruMultiplexing {
	case "", "off", "low", "middle", "high", "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH":
	default:
		return errors.New("invalid Mieru multiplexing level")
	}

	if o.LowEntropy > 4 {
		return errors.New("Mieru low_entropy must be0-4")
	}
	_, e := parseMieruPattern(o.TrafficPattern, o.LowEntropy)
	return e
}

type mieruClient struct {
	r        *Runtime
	o        Outbound
	user     *mieruUser
	mu       sync.Mutex
	carriers []*mieruCarrier
}

func (c *mieruClient) reset() {
	c.mu.Lock()
	carriers := c.carriers
	c.carriers = nil
	c.mu.Unlock()
	for _, m := range carriers {
		m.close()
	}
}
func (c *mieruClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("Mieru supports TCP and UDP")
	}
	c.mu.Lock()
	single := c.o.MieruMultiplexing == "off" || c.o.MieruMultiplexing == "MULTIPLEXING_OFF"
	limit := 128
	switch c.o.MieruMultiplexing {
	case "low", "MULTIPLEXING_LOW":
		limit = 4
	case "middle", "MULTIPLEXING_MIDDLE":
		limit = 16
	}
	var m *mieruCarrier
	alive := c.carriers[:0]
	for _, candidate := range c.carriers {
		if candidate.closed.Load() {
			continue
		}
		alive = append(alive, candidate)
		candidate.mu.Lock()
		available := len(candidate.flows) < limit
		candidate.mu.Unlock()
		if m == nil && available && !single {
			m = candidate
		}
	}
	c.carriers = alive
	if m == nil {
		if len(alive) >= 8 {
			c.mu.Unlock()
			return nil, errors.New("Mieru carrier pool capacity reached")
		}
		transport := c.o.Network
		if transport == "" {
			transport = "tcp"
		}
		raw, e := c.r.endpoint(ctx, c.o, transport)
		if e != nil {
			c.mu.Unlock()
			return nil, e
		}
		m = newMieruCarrier(c.r, raw, transport == "udp", true, nil, c.o.MieruOptions, c.o.MTU)
		m.user = c.user
		key := c.user.ciphers()[1]
		m.key = key
		m.recv.key, m.recv.user = key, c.user
		if !m.start() {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		c.carriers = append(c.carriers, m)
	}
	p, e := m.open(ctx)
	c.mu.Unlock()
	if e != nil {
		if single {
			m.close()
		}
		return nil, e
	}

	p.single = single
	stop := context.AfterFunc(ctx, func() {
		p.finish(true)
		m.remove(p)
		if single {
			m.close()
		}
	})
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		p.SetDeadline(d)
	}
	command := byte(1)
	if network == "udp" {
		command = 3
	}
	if _, e = socksRequest(p, command, address); e != nil {
		p.Close()
		return nil, e
	}
	p.SetDeadline(time.Time{})
	var conn net.Conn = p
	if network == "udp" {
		conn = &mieruPacketStream{Conn: p, address: address}
	}
	return c.r.own(conn)
}

type mieruCarrier struct {
	r              *Runtime
	raw            net.Conn
	packet, client bool
	in             *Inbound
	options        MieruOptions
	pattern        *mieruPattern
	mtu            int
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	once           sync.Once
	closed         atomic.Bool
	send, recv     mieruCodec
	key            cipher.AEAD
	user           *mieruUser
	users          []*mieruUser
	gate           chan struct{}
	mu             sync.Mutex
	flows          map[uint32]*mieruFlow
	budget         atomic.Int64
	notify         chan struct{}
	workers        sync.WaitGroup
	last           atomic.Int64
}

func newMieruCarrier(r *Runtime, raw net.Conn, packet, client bool, in *Inbound, options MieruOptions, mtu int) *mieruCarrier {
	if packet {
		socket := raw
		if owned, ok := raw.(*ownedConn); ok {
			socket = owned.Conn
		}
		if udp, ok := socket.(*net.UDPConn); ok {
			_ = udp.SetReadBuffer(1 << 20)
		}
	}
	ctx, cancel := context.WithCancel(r.ctx)
	if mtu == 0 {
		mtu = 1400
	}
	m := &mieruCarrier{r: r, raw: raw, packet: packet, client: client, in: in, options: options, mtu: mtu, ctx: ctx, cancel: cancel, done: make(chan struct{}), gate: make(chan struct{}, 1), flows: map[uint32]*mieruFlow{}, notify: make(chan struct{}, 1)}
	m.pattern, _ = parseMieruPattern(options.TrafficPattern, options.LowEntropy)
	m.send.pattern = m.pattern
	m.send.mtu = mtu
	m.last.Store(time.Now().UnixNano())
	if in != nil {
		m.users = r.mieruUsers[in.Tag]
	}
	return m
}
func (m *mieruCarrier) start() bool {
	m.r.mu.Lock()
	if m.r.closed {
		m.r.mu.Unlock()
		m.close()
		return false
	}
	m.r.workers.Add(1)
	m.r.mu.Unlock()
	go func() { defer m.r.workers.Done(); m.run() }()
	return true
}
func (m *mieruCarrier) reserve(n int) bool {
	if m.budget.Add(int64(n)) > mieruCarrierBytes {
		m.budget.Add(-int64(n))
		return false
	}
	if m.r.mieruBudget.Add(int64(n)) > 16<<20 {
		m.r.mieruBudget.Add(-int64(n))
		m.budget.Add(-int64(n))
		return false
	}
	return true
}
func (m *mieruCarrier) release(n int) {
	if n == 0 {
		return
	}
	m.budget.Add(-int64(n))
	m.r.mieruBudget.Add(-int64(n))
	signal(m.notify)
}
func (m *mieruCarrier) close() {
	m.once.Do(func() {
		m.closed.Store(true)
		m.cancel()
		close(m.done)
		m.raw.Close()
		m.mu.Lock()
		flows := make([]*mieruFlow, 0, len(m.flows))
		for _, p := range m.flows {
			flows = append(flows, p)
		}
		m.mu.Unlock()
		for _, p := range flows {
			p.finish(true)
		}
	})
}
func (m *mieruCarrier) run() {
	defer func() { m.close(); m.workers.Wait() }()
	if m.packet {
		m.workers.Add(1)
		go func() {
			defer m.workers.Done()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case now := <-ticker.C:
					m.tick(now)
				case <-m.done:
					return
				}
			}
		}()
	}
	b := make([]byte, 2048)
	for {
		var f mieruFrame
		var e error
		if m.packet {
			var n int
			n, e = m.raw.Read(b)
			if e != nil {
				return
			}
			f, e = m.decodePacket(b[:n])
			if e != nil {
				continue
			}
		} else {
			f, e = m.recv.read(m.raw, m.users, &m.r.replay)
			if e != nil {
				return
			}
			m.mu.Lock()
			if m.user == nil {
				m.user = m.recv.user
				m.key = m.recv.key
			}
			m.mu.Unlock()
			m.raw.SetReadDeadline(time.Time{})
		}
		m.last.Store(time.Now().UnixNano())
		if e = m.handle(f); e != nil {
			return
		}
	}
}
func mieruReplayKey(b []byte) string { return "mieru-udp:" + string(b[:24]) + string(b[24:40]) }
func (m *mieruCarrier) decodePacket(b []byte) (mieruFrame, error) {
	users := m.users
	if m.client {
		users = []*mieruUser{m.user}
	}
	epoch := time.Now().Round(2 * time.Minute).Unix()
	known := m.recv.key
	if m.recv.keyEpoch != epoch {
		known = nil
	}
	f, u, key, e := mieruDecodePacket(b, users, known)
	if e != nil {
		return f, e
	}
	if u != nil && m.user != nil && u.name != m.user.name {
		return f, errors.New("Mieru UDP identity changed")
	}
	if e = m.r.replay.claimFor(mieruReplayKey(b), 2*time.Minute); e != nil {
		return f, e
	}
	if u != nil && m.user == nil {
		m.user = u
	}
	m.recv.key = key
	m.recv.keyEpoch = epoch
	// Incoming packets are authenticated before updating the response key.
	m.mu.Lock()
	m.key = key
	m.mu.Unlock()
	return f, nil
}
func (m *mieruCarrier) wire(f mieruFrame, deadline time.Time) error {
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		timer = time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case m.gate <- struct{}{}:
	case <-m.done:
		return net.ErrClosed
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
	defer func() { <-m.gate }()
	if m.closed.Load() {
		return net.ErrClosed
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return os.ErrDeadlineExceeded
	}
	m.mu.Lock()
	key, user := m.key, m.user
	if m.packet && m.client && user != nil {
		key = user.ciphers()[1]
	}
	m.mu.Unlock()
	if key == nil {
		return errors.New("Mieru cipher is not ready")
	}
	m.send.key, m.send.user = key, user
	b, e := m.send.encode(f, m.packet, m.options.UserHint)
	if e != nil {
		return e
	}
	until := time.Now().Add(handshakeTimeout)
	if !deadline.IsZero() && deadline.Before(until) {
		until = deadline
	}
	m.raw.SetWriteDeadline(until)
	if !m.packet && m.pattern.fragment && f.kind <= 5 {
		for len(b) > 0 {
			n := min(len(b), 1+mieruRandom(64))
			if e = writeAll(m.raw, b[:n]); e != nil {
				break
			}
			b = b[n:]
			if len(b) > 0 && m.pattern.sleepMS > 0 {
				delay := time.Duration(mieruRandom(m.pattern.sleepMS+1)) * time.Millisecond
				if time.Now().Add(delay).After(until) {
					e = os.ErrDeadlineExceeded
					break
				}
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-m.done:
					e = net.ErrClosed
				}
				timer.Stop()
				if e != nil {
					break
				}
			}
		}
	} else {
		e = writeAll(m.raw, b)
	}
	m.raw.SetWriteDeadline(time.Time{})
	if e != nil {
		m.raw.Close()
	}
	return e
}
func (m *mieruCarrier) newFlow(id uint32) *mieruFlow {
	ctx, cancel := context.WithCancel(m.ctx)
	p := &mieruFlow{ctx: ctx, cancel: cancel, m: m, id: id, done: make(chan struct{}), incoming: make(chan []byte, mieruWindow), notify: make(chan struct{}, 1), pending: map[uint32]*mieruFrame{}, reorder: map[uint32]mieruFrame{}, remoteWindow: mieruWindow, rto: 300 * time.Millisecond, cwnd: 16}
	m.flows[id] = p
	return p
}
func (m *mieruCarrier) open(ctx context.Context) (*mieruFlow, error) {
	m.mu.Lock()
	if len(m.flows) >= 128 || m.closed.Load() {
		m.mu.Unlock()
		return nil, errors.New("Mieru session capacity reached")
	}
	var id uint32
	for id == 0 || m.flows[id] != nil {
		var b [4]byte
		rand.Read(b[:])
		id = binary.BigEndian.Uint32(b[:])
	}
	p := m.newFlow(id)
	m.mu.Unlock()
	// An empty OPEN avoids coupling the SOCKS request size to the control limit.
	if e := p.transmit(mieruFrame{kind: 2, id: id}, ctx); e != nil {
		p.Close()
		return nil, e
	}
	return p, nil
}
func (m *mieruCarrier) handle(f mieruFrame) error {
	if (m.client && (f.kind == 2 || f.kind == 6 || f.kind == 8 || f.kind == 10)) || (!m.client && (f.kind == 3 || f.kind == 7 || f.kind == 9 || f.kind == 11)) {
		return errors.New("Mieru frame has wrong direction")
	}
	m.mu.Lock()
	p := m.flows[f.id]
	if p == nil && f.kind == 2 && !m.client {
		if f.seq != 0 || len(m.flows) >= 128 || m.closed.Load() {
			m.mu.Unlock()
			return errors.New("invalid Mieru session open")
		}
		m.r.mu.Lock()
		if m.r.closed {
			m.r.mu.Unlock()
			m.mu.Unlock()
			return net.ErrClosed
		}
		m.r.workers.Add(1)
		m.r.mu.Unlock()
		p = m.newFlow(f.id)
		m.workers.Add(1)
		user := m.user.name
		go func() { defer m.workers.Done(); defer m.r.workers.Done(); m.r.serveMieruFlow(m.in, p, user) }()
	}
	m.mu.Unlock()
	if p == nil {
		if f.kind == 4 {
			return m.wire(mieruFrame{kind: 5, id: f.id}, time.Now().Add(time.Second))
		}
		return nil
	}
	if f.kind >= 6 {
		p.mu.Lock()
		if f.kind == 10 {
			p.lowEntropy = true
		}
		if f.ack > p.nextSend {
			p.mu.Unlock()
			return errors.New("Mieru ACK exceeds sent sequence")
		}
		p.remoteWindow = int(f.window)
		for seq, old := range p.pending {
			if seq < f.ack {
				delete(p.pending, seq)
				m.release(len(old.body))
				if old.tries == 1 {
					sample := time.Since(old.sent) * 2
					p.rto = max(100*time.Millisecond, min(3*time.Second, (3*p.rto+sample)/4))
				}
				if p.cwnd < 64 {
					p.cwnd++
				}
			}
		}
		signal(p.notify)
		p.mu.Unlock()
		if f.kind == 8 || f.kind == 9 {
			return nil
		}
	}
	if f.kind == 4 {
		p.mu.Lock()
		if f.seq > p.nextRecv && m.packet {
			p.remoteClose = &f
			p.mu.Unlock()
			return p.ack()
		}
		p.mu.Unlock()
		return p.acceptClose()
	}
	if f.kind == 5 {
		p.finish(false)
		m.remove(p)
		return nil
	}
	if m.packet {
		p.mu.Lock()
		if f.seq < p.nextRecv {
			p.mu.Unlock()
			return p.ack()
		}
		if f.seq-p.nextRecv >= mieruWindow {
			p.mu.Unlock()
			return p.ack()
		}
		if p.closed {
			p.mu.Unlock()
			return nil
		}
		if _, exists := p.reorder[f.seq]; !exists {
			if !m.reserve(len(f.body)) {
				p.mu.Unlock()
				return p.ack()
			}
			p.reorder[f.seq] = f
		}
		p.pump()
		p.mu.Unlock()
		if e := p.ack(); e != nil {
			return e
		}
		if p.closeReady() {
			return p.acceptClose()
		}
	} else {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil
		}
		if f.seq != p.nextRecv {
			p.mu.Unlock()
			return errors.New("Mieru TCP sequence mismatch")
		}
		p.nextRecv++
		p.mu.Unlock()
		if len(f.body) > 0 {
			for !m.reserve(len(f.body)) {
				select {
				case <-m.notify:
				case <-m.done:
					return net.ErrClosed
				case <-p.done:
					return nil
				}
			}
			select {
			case p.incoming <- f.body:
			case <-p.done:
				m.release(len(f.body))
			case <-m.done:
				m.release(len(f.body))
				return net.ErrClosed
			}
		}
	}
	if f.kind == 2 {
		return p.transmit(mieruFrame{kind: 3, id: p.id}, m.ctx)
	}
	return nil
}
func (m *mieruCarrier) remove(p *mieruFlow) {
	m.mu.Lock()
	if m.flows[p.id] == p {
		delete(m.flows, p.id)
	}
	m.mu.Unlock()
}
func (m *mieruCarrier) tick(now time.Time) {
	m.mu.Lock()
	flows := make([]*mieruFlow, 0, len(m.flows))
	for _, p := range m.flows {
		flows = append(flows, p)
	}
	m.mu.Unlock()
	for _, p := range flows {
		p.mu.Lock()
		var retry []mieruFrame
		if p.closed {
			if now.Sub(p.closedAt) > 3*time.Second {
				p.mu.Unlock()
				m.remove(p)
				continue
			}
			if p.closeFrame != nil && now.Sub(p.closeFrame.sent) > 300*time.Millisecond {
				p.closeFrame.sent = now
				retry = append(retry, *p.closeFrame)
			}
		} else {
			for _, f := range p.pending {
				if f.tries == 0 {
					continue
				}
				if now.Sub(f.sent) >= p.rto {
					if f.tries >= 12 {
						p.mu.Unlock()
						p.finish(true)
						m.remove(p)
						return
					}
					f.sent = now
					f.tries++
					p.cwnd = max(2, p.cwnd/2)
					retry = append(retry, *f)
				}
			}
		}
		p.mu.Unlock()
		for _, f := range retry {
			if e := m.wire(f, now.Add(time.Second)); e != nil {
				return
			}
		}
	}
	if now.Sub(time.Unix(0, m.last.Load())) > 90*time.Second {
		m.close()
	}
}

type mieruFlow struct {
	ctx                          context.Context
	cancel                       context.CancelFunc
	m                            *mieruCarrier
	id                           uint32
	mu, readMu, writeMu, closeMu sync.Mutex
	done, notify                 chan struct{}
	incoming                     chan []byte
	unread                       []byte
	closed, single               bool
	lowEntropy                   bool
	closedAt                     time.Time
	readDeadline, writeDeadline  time.Time
	nextSend, nextRecv           uint32
	pending                      map[uint32]*mieruFrame
	reorder                      map[uint32]mieruFrame
	remoteWindow, cwnd           int
	rto                          time.Duration
	closeFrame                   *mieruFrame
	remoteClose                  *mieruFrame
}

// pump moves only contiguous packets into the application queue; callers hold mu.
func (p *mieruFlow) pump() {
	for !p.closed && len(p.incoming) < cap(p.incoming) {
		f, ok := p.reorder[p.nextRecv]
		if !ok {
			break
		}
		delete(p.reorder, p.nextRecv)
		p.nextRecv++
		if len(f.body) > 0 {
			p.incoming <- f.body
		}
	}
}
func (p *mieruFlow) closeReady() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.remoteClose != nil && p.nextRecv >= p.remoteClose.seq
}
func (p *mieruFlow) acceptClose() error {
	e := p.m.wire(mieruFrame{kind: 5, id: p.id, seq: p.sendSequence()}, time.Now().Add(time.Second))
	p.finish(false)
	p.m.remove(p)
	return e
}
func (p *mieruFlow) consumed() {
	p.mu.Lock()
	p.pump()
	p.mu.Unlock()
	_ = p.ack()
	if p.closeReady() {
		_ = p.acceptClose()
	}
}
func (p *mieruFlow) sendSequence() uint32 { p.mu.Lock(); defer p.mu.Unlock(); return p.nextSend }
func (p *mieruFlow) ack() error {
	p.mu.Lock()
	window := max(0, mieruWindow-len(p.reorder)-len(p.incoming))
	if p.m.budget.Load() >= mieruCarrierBytes {
		window = 0
	}
	f := mieruFrame{kind: 8, id: p.id, seq: p.nextSend, ack: p.nextRecv, window: uint16(window)}
	if !p.m.client {
		f.kind = 9
	}
	p.mu.Unlock()
	return p.m.wire(f, time.Now().Add(time.Second))
}
func (p *mieruFlow) transmit(f mieruFrame, ctx context.Context) error {
	for {
		p.mu.Lock()
		closed := p.closed
		deadline := p.writeDeadline
		if closed {
			p.mu.Unlock()
			return net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			p.mu.Unlock()
			return os.ErrDeadlineExceeded
		}
		if p.nextSend == ^uint32(0) {
			p.mu.Unlock()
			return errors.New("Mieru sequence exhausted")
		}
		if !p.m.packet || len(p.pending) < min(p.cwnd, max(1, p.remoteWindow)) {
			f.seq = p.nextSend
			f.ack = p.nextRecv
			f.window = uint16(max(0, mieruWindow-len(p.reorder)-len(p.incoming)))
			f.sent = time.Now()
			f.tries = 0
			if p.m.packet && !p.m.reserve(len(f.body)) {
				p.mu.Unlock()
			} else {
				p.nextSend++
				if p.m.packet {
					copyFrame := f
					p.pending[f.seq] = &copyFrame
				}
				p.mu.Unlock()
				e := p.m.wire(f, deadline)
				if e == nil && p.m.packet {
					p.mu.Lock()
					if old := p.pending[f.seq]; old != nil {
						old.sent = time.Now()
						old.tries = 1
					}
					p.mu.Unlock()
				}
				if e != nil {
					p.mu.Lock()
					if p.nextSend == f.seq+1 {
						p.nextSend--
					}
					if old := p.pending[f.seq]; old != nil {
						delete(p.pending, f.seq)
						p.m.release(len(old.body))
					}
					p.mu.Unlock()
				}
				return e
			}
		} else {
			p.mu.Unlock()
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		stopTimer := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case <-p.notify:
		case <-p.m.notify:
		case <-p.done:
			stopTimer()
			return net.ErrClosed
		case <-p.m.done:
			stopTimer()
			return net.ErrClosed
		case <-ctx.Done():
			stopTimer()
			return ctx.Err()
		case <-timeout:
			return os.ErrDeadlineExceeded
		}
		stopTimer()
	}
}
func (p *mieruFlow) Write(b []byte) (int, error) {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	sent := 0
	mode := p.m.pattern.mode
	p.mu.Lock()
	if !p.m.client && !p.lowEntropy {
		mode = 0
	}
	p.mu.Unlock()
	size := 32768
	if p.m.packet {
		size = p.m.mtu - 160
		if mode > 0 {
			size = size * (int(mode) + 3) / 8
		}
	}
	if mode != 0 {
		size = min(size, (65535/8)*(int(mode)+3))
	}
	for len(b) > 0 {
		n := min(len(b), size)
		kind := byte(6)
		if !p.m.client {
			kind = 7
		}
		if mode > 0 {
			kind += 4
		}
		body := b[:n]
		if p.m.packet {
			body = bytes.Clone(body)
		}
		f := mieruFrame{kind: kind, id: p.id, mode: mode, rotation: p.m.pattern.rotation, body: body}
		if e := p.transmit(f, p.m.ctx); e != nil {
			return sent, e
		}
		sent += n
		b = b[n:]
	}
	return sent, nil
}
func (p *mieruFlow) Read(b []byte) (int, error) {
	p.readMu.Lock()
	defer p.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	for {
		if len(p.unread) > 0 {
			n := copy(b, p.unread)
			p.unread = p.unread[n:]
			p.m.release(n)
			if p.m.packet {
				p.consumed()
			}
			return n, nil
		}
		p.mu.Lock()
		deadline := p.readDeadline
		closed := p.closed
		p.mu.Unlock()
		// Capture closure before checking the queue. A final frame can arrive
		// between these steps; observing closed must not bypass already queued data.
		select {
		case p.unread = <-p.incoming:
			continue
		default:
		}
		if closed {
			return 0, io.EOF
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		stopTimer := func() {
			if timer != nil {
				timer.Stop()
			}
		}
		select {
		case p.unread = <-p.incoming:
		case <-p.notify:
		case <-p.done:
		case <-p.m.done:
			stopTimer()
			return 0, net.ErrClosed
		case <-timeout:
			return 0, os.ErrDeadlineExceeded
		}
		stopTimer()
	}
}
func (p *mieruFlow) finish(discard bool) {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		p.cancel()
		p.closedAt = time.Now()
		close(p.done)
	}
	for seq, f := range p.pending {
		p.m.release(len(f.body))
		delete(p.pending, seq)
	}
	for seq, f := range p.reorder {
		p.m.release(len(f.body))
		delete(p.reorder, seq)
	}
	p.mu.Unlock()
	if discard {
		p.readMu.Lock()
		p.m.release(len(p.unread))
		p.unread = nil
		for {
			select {
			case b := <-p.incoming:
				p.m.release(len(b))
			default:
				p.readMu.Unlock()
				return
			}
		}
	}
}
func (p *mieruFlow) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	// A control CLOSE must follow delivery of preceding reliable UDP data.
	if p.m.packet {
		timer := time.NewTimer(2 * time.Second)
		for {
			p.mu.Lock()
			empty := len(p.pending) == 0 || p.closed
			p.mu.Unlock()
			if empty {
				break
			}
			select {
			case <-p.notify:
			case <-p.m.done:
				timer.Stop()
				p.finish(true)
				return nil
			case <-timer.C:
				p.finish(true)
				p.m.remove(p)
				return nil
			}
		}
		timer.Stop()
	}

	p.mu.Lock()
	already := p.closed
	seq := p.nextSend
	p.mu.Unlock()
	if !already {
		f := mieruFrame{kind: 4, id: p.id, seq: seq, sent: time.Now()}
		if p.m.packet {
			p.mu.Lock()
			p.closeFrame = &f
			p.mu.Unlock()
		}
		_ = p.m.wire(f, time.Now().Add(time.Second))
	}
	p.finish(true)
	if !p.m.packet {
		p.m.remove(p)
	}
	if p.single {
		p.m.close()
	}
	return nil
}
func (p *mieruFlow) LocalAddr() net.Addr  { return p.m.raw.LocalAddr() }
func (p *mieruFlow) RemoteAddr() net.Addr { return p.m.raw.RemoteAddr() }
func (p *mieruFlow) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readDeadline = t
	p.mu.Unlock()
	signal(p.notify)
	return nil
}
func (p *mieruFlow) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeDeadline = t
	p.mu.Unlock()
	signal(p.notify)
	return nil
}
func (p *mieruFlow) SetDeadline(t time.Time) error {
	p.SetReadDeadline(t)
	return p.SetWriteDeadline(t)
}

func (r *Runtime) serveMieru(in Inbound, raw net.Conn) error {
	m := newMieruCarrier(r, raw, false, false, &in, in.MieruOptions, in.MTU)
	m.run()
	return nil
}
func (r *Runtime) serveMieruFlow(in *Inbound, p *mieruFlow, user string) {
	defer p.Close()
	p.SetDeadline(time.Now().Add(handshakeTimeout))
	var h [3]byte
	if _, e := io.ReadFull(p, h[:]); e != nil || h[0] != 5 || h[2] != 0 {
		return
	}
	address, e := readAddress(p)
	if e != nil {
		return
	}
	q := request{origin: r.socketOrigin(p.RemoteAddr(), p.LocalAddr()), network: "tcp", inbound: in.Tag, source: p.RemoteAddr().String(), address: address, metadata: Metadata{AuthUser: user}}
	reply := func(status byte) error { return writeAll(p, []byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if h[1] == 1 {
		remote, e := r.routeDial(p.ctx, q)
		if e != nil {
			_ = reply(5)
			return
		}
		defer remote.Close()
		stop := context.AfterFunc(p.ctx, func() { remote.Close() })
		defer stop()
		if reply(0) != nil {
			return
		}
		p.SetDeadline(time.Time{})
		r.relay(p, remote)
		return
	}
	if h[1] != 3 {
		_ = reply(7)
		return
	}
	if reply(0) != nil {
		return
	}
	p.SetDeadline(time.Time{})
	r.serveMieruPackets(p, q)
}

type mieruPacketStream struct {
	net.Conn
	address string
	writeMu sync.Mutex
}

func (c *mieruPacketStream) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	target, e := encodeAddress(c.address)
	if e != nil {
		return 0, e
	}
	packet := append([]byte{0, 0, 0}, target...)
	packet = append(packet, b...)
	if len(packet) > 65535 {
		return 0, errors.New("Mieru UDP payload exceeds65535 bytes")
	}
	frame := binary.BigEndian.AppendUint16([]byte{0}, uint16(len(packet)))
	frame = append(frame, packet...)
	frame = append(frame, 255)
	if e = writeAll(c.Conn, frame); e != nil {
		return 0, e
	}
	return len(b), nil
}
func (c *mieruPacketStream) Read(b []byte) (int, error) {
	packet, e := mieruReadDatagram(c.Conn)
	if e != nil {
		return 0, e
	}
	reader := bytes.NewReader(packet)
	if len(packet) < 3 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return 0, errors.New("invalid Mieru UDP header")
	}
	reader.Seek(3, io.SeekStart)
	if _, e = readAddress(reader); e != nil {
		return 0, e
	}
	payload := packet[len(packet)-reader.Len():]
	if len(payload) > len(b) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, payload), nil
}
func mieruReadDatagram(r io.Reader) ([]byte, error) {
	var header [3]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(header[1:]))
	if header[0] != 0 || n < 7 {
		return nil, errors.New("invalid Mieru datagram marker")
	}
	b := make([]byte, n+1)
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, e
	}
	if b[n] != 255 {
		return nil, errors.New("invalid Mieru datagram suffix")
	}
	return b[:n], nil
}
