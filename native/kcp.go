package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type kcpFrame struct {
	conv, stamp, seq, next uint32
	cmd, fragment          byte
	window                 uint16
	body                   []byte
}

func parseKCP(b []byte) ([]kcpFrame, error) {
	var frames []kcpFrame
	for len(b) > 0 {
		if len(b) < 24 {
			return nil, io.ErrUnexpectedEOF
		}
		n := int(binary.LittleEndian.Uint32(b[20:]))
		cmd := b[4]
		if cmd < 81 || cmd > 84 || n > len(b)-24 || cmd != 81 && n != 0 {
			return nil, errors.New("invalid KCP frame")
		}
		frames = append(frames, kcpFrame{conv: binary.LittleEndian.Uint32(b), cmd: cmd, fragment: b[5], window: binary.LittleEndian.Uint16(b[6:]), stamp: binary.LittleEndian.Uint32(b[8:]), seq: binary.LittleEndian.Uint32(b[12:]), next: binary.LittleEndian.Uint32(b[16:]), body: b[24 : 24+n]})
		b = b[24+n:]
	}
	return frames, nil
}
func appendKCP(b []byte, f kcpFrame) []byte {
	b = binary.LittleEndian.AppendUint32(b, f.conv)
	b = append(b, f.cmd, f.fragment)
	b = binary.LittleEndian.AppendUint16(b, f.window)
	b = binary.LittleEndian.AppendUint32(b, f.stamp)
	b = binary.LittleEndian.AppendUint32(b, f.seq)
	b = binary.LittleEndian.AppendUint32(b, f.next)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(f.body)))
	return append(b, f.body...)
}
func kcpBefore(a, b uint32) bool { return int32(a-b) < 0 }

type kcpSent struct {
	seq         uint32
	data        []byte
	at          time.Time
	stamp       uint32
	tries, fast int
	rto         time.Duration
}
type kcpConn struct {
	r                            *Runtime
	o                            *kcptunOptions
	conv                         uint32
	local, remote                net.Addr
	raw                          net.Conn
	listener                     *kcpListener
	send                         func([]byte) error
	mu, rmu, wmu                 sync.Mutex
	sendNext, recvNext, readNext uint32
	peerWindow                   int
	pending                      map[uint32]*kcpSent
	queue                        []*kcpSent
	receive                      map[uint32][]byte
	acks                         map[uint32]uint32
	fec                          *kcpFEC
	memory, offset, cwnd, credit int
	rto, srtt, variation         time.Duration
	lastSeen, lastProbe, closeAt time.Time
	readDeadline, writeDeadline  time.Time
	closing, wins                bool
	err                          error
	readWake, writeWake, wake    chan struct{}
	done                         chan struct{}
	once                         sync.Once
	workers                      sync.WaitGroup
}

func (r *Runtime) newKCP(o *kcptunOptions, conv uint32, local, remote net.Addr, raw net.Conn, send func([]byte) error, l *kcpListener) (*kcpConn, error) {
	c := &kcpConn{r: r, o: o, conv: conv, local: local, remote: remote, raw: raw, send: send, listener: l, peerWindow: 32, pending: map[uint32]*kcpSent{}, receive: map[uint32][]byte{}, acks: map[uint32]uint32{}, cwnd: 1, rto: 200 * time.Millisecond, lastSeen: time.Now(), readWake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1), wake: make(chan struct{}, 1), done: make(chan struct{})}
	c.fec = newKCPFEC(r, o.code)
	r.kcpMu.Lock()
	if r.ctx.Err() != nil || len(r.kcpConns) >= 256 {
		r.kcpMu.Unlock()
		return nil, errors.New("kcptun connection capacity reached or runtime closed")
	}
	c.workers.Add(1)
	if raw != nil {
		c.workers.Add(1)
	}
	r.kcpConns[c] = struct{}{}
	r.kcpMu.Unlock()
	go func() { defer c.workers.Done(); c.maintain() }()
	if raw != nil {
		go func() {
			defer c.workers.Done()
			buffer := make([]byte, 1501)
			for {
				n, e := raw.Read(buffer)
				if e != nil {
					c.abort(e)
					return
				}
				if n > 1500 {
					continue
				}
				if b, e := o.crypt.open(buffer[:n]); e == nil {
					c.input(b)
				}
			}
		}()
	}
	return c, nil
}
func (r *Runtime) dialKCP(ctx context.Context, o Outbound, options *kcptunOptions) (*kcpConn, error) {
	if options.server != "" {
		o.Server = options.server
	}
	if options.port != 0 {
		o.ServerPort = options.port
	}
	raw, e := r.endpoint(ctx, o, "udp")
	if e != nil {
		return nil, e
	}
	if e = kcpSetDSCP(raw, options.dscp); e != nil {
		raw.Close()
		return nil, e
	}
	var id [4]byte
	rand.Read(id[:])
	c, e := r.newKCP(options, binary.LittleEndian.Uint32(id[:]), raw.LocalAddr(), raw.RemoteAddr(), raw, func(b []byte) error { _, e := raw.Write(b); return e }, nil)
	if e != nil {
		raw.Close()
		return nil, e
	}
	return c, nil
}
func (c *kcpConn) reserve(n int, head bool) bool {
	n = max(n, 256)
	limit := int64(16<<20) - 256*1500
	if head {
		limit = 16 << 20
	}
	if c.r.kcpBudget.Add(int64(n)) > limit {
		c.r.kcpBudget.Add(-int64(n))
		return false
	}
	c.memory += n
	return true
}
func (c *kcpConn) release(n int) { n = max(n, 256); c.memory -= n; c.r.kcpBudget.Add(-int64(n)) }
func (c *kcpConn) sendBase() uint32 {
	for len(c.queue) > 0 && c.pending[c.queue[0].seq] == nil {
		c.queue[0] = nil
		c.queue = c.queue[1:]
	}
	if len(c.queue) > 2*len(c.pending)+64 {
		kept := c.queue[:0]
		for _, p := range c.queue {
			if c.pending[p.seq] != nil {
				kept = append(kept, p)
			}
		}
		clear(c.queue[len(kept):])
		c.queue = kept
	}
	if len(c.queue) > 0 {
		return c.queue[0].seq
	}
	return c.sendNext
}
func (c *kcpConn) acknowledge(seq uint32) {
	if p := c.pending[seq]; p != nil {
		delete(c.pending, seq)
		c.release(len(p.data))
		p.data = nil
		if c.o.congestion {
			c.credit++
			if c.credit >= c.cwnd {
				c.credit = 0
				c.cwnd = min(c.cwnd+1, c.o.sendWindow)
			}
		}
	}
}
func (c *kcpConn) input(b []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	now := time.Now()
	var highest uint32
	gotACK := false
	for _, packet := range c.fec.decode(b) {
		frames, e := parseKCP(packet)
		if e != nil {
			continue
		}
		for _, f := range frames {
			if f.conv != c.conv {
				continue
			}
			c.lastSeen = now
			c.peerWindow = int(f.window)
			acked := c.pending[f.seq]
			if !kcpBefore(c.sendNext, f.next) {
				for len(c.queue) > 0 && kcpBefore(c.queue[0].seq, f.next) {
					p := c.queue[0]
					c.queue[0] = nil
					c.queue = c.queue[1:]
					c.acknowledge(p.seq)
				}
			}
			switch f.cmd {
			case 81:
				if kcpBefore(f.seq, c.readNext) {
					if uint32(c.readNext-f.seq) <= 4096 {
						c.acks[f.seq] = f.stamp
					}
					continue
				}
				if uint32(f.seq-c.readNext) >= uint32(c.o.receiveWindow) || c.closing {
					continue
				}
				if _, exists := c.receive[f.seq]; !exists {
					if !c.reserve(len(f.body), f.seq == c.recvNext) {
						continue
					}
					c.receive[f.seq] = append([]byte{}, f.body...)
				}
				c.acks[f.seq] = f.stamp
				for {
					if _, ok := c.receive[c.recvNext]; !ok {
						break
					}
					c.recvNext++
				}
				signal(c.readWake)
			case 82:
				if p := acked; p != nil {
					if p.tries == 1 {
						sample := time.Duration(int32(uint32(now.UnixMilli())-f.stamp)) * time.Millisecond
						if sample > 0 && sample < 10*time.Second {
							if c.srtt == 0 {
								c.srtt, c.variation = sample, sample/2
							} else {
								delta := c.srtt - sample
								if delta < 0 {
									delta = -delta
								}
								c.variation = (3*c.variation + delta) / 4
								c.srtt = (7*c.srtt + sample) / 8
							}
							minimum := 100 * time.Millisecond
							if c.o.nodelay {
								minimum = 30 * time.Millisecond
							}
							c.rto = max(minimum, min(3*time.Second, c.srtt+4*c.variation))
						}
					}
					c.acknowledge(f.seq)
					if !gotACK || kcpBefore(highest, f.seq) {
						highest = f.seq
						gotACK = true
					}
				}
			case 83:
				c.wins = true
			}
		}
	}
	if gotACK {
		for _, p := range c.pending {
			if kcpBefore(p.seq, highest) {
				p.fast++
			}
		}
	}
	c.sendBase()
	signal(c.writeWake)
	signal(c.wake)
}
func (c *kcpConn) emit(b []byte) error {
	for _, frame := range c.fec.encode(b) {
		if e := c.send(c.o.crypt.seal(frame)); e != nil {
			return e
		}
	}
	return nil
}
func (c *kcpConn) flush(now time.Time) error {
	window := max(0, c.o.receiveWindow-int(c.recvNext-c.readNext))
	base := kcpFrame{conv: c.conv, window: uint16(window), next: c.recvNext}
	limit := c.o.mtu - c.o.crypt.overhead()
	if c.o.code != nil {
		limit -= 8
	}
	b := make([]byte, 0, limit)
	for seq, stamp := range c.acks {
		if len(b)+24 > limit {
			if e := c.emit(b); e != nil {
				return e
			}
			b = b[:0]
		}
		f := base
		f.cmd, f.seq, f.stamp = 82, seq, stamp
		b = appendKCP(b, f)
		delete(c.acks, seq)
	}
	if c.wins || c.peerWindow == 0 && now.Sub(c.lastProbe) >= time.Second {
		f := base
		f.cmd = 84
		if c.peerWindow == 0 {
			f.cmd = 83
			c.lastProbe = now
		}
		if len(b)+24 > limit {
			if e := c.emit(b); e != nil {
				return e
			}
			b = b[:0]
		}
		b = appendKCP(b, f)
		c.wins = false
	}
	allowed := min(c.o.sendWindow, c.peerWindow)
	if c.o.congestion {
		allowed = min(allowed, c.cwnd)
	}
	floor := c.sendBase()
	for _, p := range c.queue {
		if c.pending[p.seq] == nil {
			continue
		}
		if p.tries == 0 && uint32(p.seq-floor) >= uint32(allowed) {
			continue
		}
		timed := p.tries != 0 && now.Sub(p.at) >= p.rto
		fast := c.o.resend > 0 && p.fast >= c.o.resend
		if p.tries != 0 && !timed && !fast {
			continue
		}
		if p.tries >= 60 {
			return errors.New("KCP retransmission limit reached")
		}
		if len(b)+24+len(p.data) > limit {
			if e := c.emit(b); e != nil {
				return e
			}
			b = b[:0]
		}
		if p.tries == 0 {
			p.rto = c.rto
		} else if timed {
			p.rto = min(3*time.Second, p.rto+p.rto/2)
			if c.o.congestion {
				c.cwnd = max(1, c.cwnd/2)
				c.credit = 0
			}
		}
		p.tries++
		p.fast = 0
		p.at = now
		p.stamp = uint32(now.UnixMilli())
		f := base
		f.cmd, f.seq, f.stamp, f.body = 81, p.seq, p.stamp, p.data
		b = appendKCP(b, f)
	}
	if len(b) > 0 {
		return c.emit(b)
	}
	return nil
}
func (c *kcpConn) maintain() {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		c.mu.Lock()
		now := time.Now()
		e := c.err
		if e == nil && c.closing && (len(c.pending) == 0 || now.After(c.closeAt)) {
			e = net.ErrClosed
		}
		if e == nil && now.Sub(c.lastSeen) > 90*time.Second {
			e = errors.New("KCP peer idle timeout")
		}
		if e == nil {
			e = c.flush(now)
		}
		wait := time.Second
		if len(c.pending) > 0 {
			wait = c.o.interval
		}
		signal(c.writeWake)
		c.mu.Unlock()
		if e != nil {
			c.abort(e)
			return
		}
		timer.Reset(wait)
		select {
		case <-timer.C:
		case <-c.wake:
			timer.Stop()
		case <-c.r.ctx.Done():
			c.abort(net.ErrClosed)
			return
		case <-c.done:
			return
		}
	}
}
func (c *kcpConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	for {
		c.mu.Lock()
		if c.err != nil || c.closing {
			e := c.err
			if e == nil {
				e = net.ErrClosed
			}
			c.mu.Unlock()
			return 0, e
		}
		if data, ok := c.receive[c.readNext]; ok {
			n := copy(b, data[c.offset:])
			c.offset += n
			if c.offset == len(data) {
				delete(c.receive, c.readNext)
				c.readNext++
				c.offset = 0
				c.release(len(data))
				c.wins = true
				signal(c.wake)
			}
			c.mu.Unlock()
			if n == 0 {
				continue
			}
			return n, nil
		}
		d := c.readDeadline
		c.mu.Unlock()
		if e := waitAny(c.readWake, c.r.ctx, d); e != nil {
			return 0, e
		}
	}
}
func (c *kcpConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	written := 0
	mss := c.o.mtu - c.o.crypt.overhead() - 24
	if c.o.code != nil {
		mss -= 8
	}
	for len(b) > 0 {
		c.mu.Lock()
		if c.err != nil || c.closing {
			e := c.err
			if e == nil {
				e = net.ErrClosed
			}
			c.mu.Unlock()
			return written, e
		}
		if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		n := min(len(b), mss)
		if len(c.pending) < c.o.sendWindow && c.reserve(n, false) {
			p := &kcpSent{seq: c.sendNext, data: append([]byte(nil), b[:n]...)}
			c.sendNext++
			c.pending[p.seq] = p
			c.queue = append(c.queue, p)
			signal(c.wake)
			c.mu.Unlock()
			written += n
			b = b[n:]
			continue
		}
		d := c.writeDeadline
		c.mu.Unlock()
		if e := waitAny(c.writeWake, c.r.ctx, d); e != nil {
			return written, e
		}
	}
	return written, nil
}
func (c *kcpConn) abort(e error) {
	c.once.Do(func() {
		c.mu.Lock()
		c.err = e
		c.r.kcpBudget.Add(-int64(c.memory))
		c.memory = 0
		c.pending = nil
		c.queue = nil
		c.receive = nil
		c.acks = nil
		c.fec.close()
		close(c.done)
		signal(c.readWake)
		signal(c.writeWake)
		c.mu.Unlock()
		if c.raw != nil {
			c.raw.Close()
		}
		c.r.kcpMu.Lock()
		delete(c.r.kcpConns, c)
		c.r.kcpMu.Unlock()
		if c.listener != nil {
			c.listener.mu.Lock()
			if c.listener.peers[c.remote.String()] == c {
				delete(c.listener.peers, c.remote.String())
			}
			c.listener.mu.Unlock()
		}
	})
}
func (c *kcpConn) Close() error {
	if c.r.ctx.Err() != nil {
		c.abort(net.ErrClosed)
		return nil
	}
	c.mu.Lock()
	if !c.closing {
		c.closing = true
		c.closeAt = time.Now().Add(3 * time.Second)
	}
	signal(c.wake)
	signal(c.readWake)
	signal(c.writeWake)
	c.mu.Unlock()
	return nil
}
func (c *kcpConn) LocalAddr() net.Addr           { return c.local }
func (c *kcpConn) RemoteAddr() net.Addr          { return c.remote }
func (c *kcpConn) SetDeadline(t time.Time) error { c.SetReadDeadline(t); return c.SetWriteDeadline(t) }
func (c *kcpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	signal(c.readWake)
	c.mu.Unlock()
	return nil
}
func (c *kcpConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	signal(c.writeWake)
	c.mu.Unlock()
	return nil
}

type kcpListener struct {
	r        *Runtime
	o        *kcptunOptions
	packet   net.PacketConn
	mu       sync.Mutex
	peers    map[string]*kcpConn
	accepted chan net.Conn
	done     chan struct{}
	once     sync.Once
	worker   sync.WaitGroup
}

func (r *Runtime) listenKCP(in Inbound, host string) (*kcpListener, error) {
	o := in.plugin.kcp
	packet, e := in.ListenOptions.listenPacket(r.ctx, "udp", portAddress(host, in.ListenPort))
	if e != nil {
		return nil, e
	}
	if e = kcpSetPacketDSCP(packet, o.dscp); e != nil {
		packet.Close()
		return nil, e
	}
	l := &kcpListener{r: r, o: o, packet: packet, peers: map[string]*kcpConn{}, accepted: make(chan net.Conn, 128), done: make(chan struct{})}
	l.worker.Go(l.read)
	return l, nil
}
func (l *kcpListener) read() {
	buffer := make([]byte, 1501)
	for {
		n, from, e := l.packet.ReadFrom(buffer)
		if e != nil {
			return
		}
		if n > 1500 {
			continue
		}
		b, e := l.o.crypt.open(buffer[:n])
		if e != nil {
			continue
		}
		plain := b
		first := kcpFrame{}
		if l.o.code != nil {
			plain = nil
			if len(b) >= 32 && binary.LittleEndian.Uint16(b[4:]) == 0xf1 {
				size := int(binary.LittleEndian.Uint16(b[6:]))
				if size >= 26 && size <= len(b)-6 {
					plain = b[8 : 6+size]
				}
			}
		}
		if frames, e := parseKCP(plain); e == nil && len(frames) > 0 {
			first = frames[0]
		}
		l.mu.Lock()
		c := l.peers[from.String()]
		if c != nil && first.cmd == 81 && first.seq == 0 && first.conv != c.conv {
			l.mu.Unlock()
			c.abort(net.ErrClosed)
			l.mu.Lock()
			c = l.peers[from.String()]
		}
		fresh := c == nil
		if fresh {
			if first.cmd != 81 || first.seq != 0 || len(l.peers) >= 128 {
				l.mu.Unlock()
				continue
			}
			c, e = l.r.newKCP(l.o, first.conv, l.packet.LocalAddr(), from, nil, func(b []byte) error { _, e := l.packet.WriteTo(b, from); return e }, l)
			if e != nil {
				l.mu.Unlock()
				continue
			}
			l.peers[from.String()] = c
		}
		l.mu.Unlock()
		c.input(b)
		if fresh {
			select {
			case l.accepted <- c:
			case <-l.done:
				c.abort(net.ErrClosed)
				return
			default:
				c.abort(net.ErrClosed)
			}
		}
	}
}
func (l *kcpListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accepted:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.r.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *kcpListener) Addr() net.Addr { return l.packet.LocalAddr() }
func (l *kcpListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		l.packet.Close()
		l.worker.Wait()
		l.mu.Lock()
		var peers []*kcpConn
		for _, c := range l.peers {
			peers = append(peers, c)
		}
		l.mu.Unlock()
		for _, c := range peers {
			c.abort(net.ErrClosed)
		}
		for _, c := range peers {
			c.workers.Wait()
		}
	})
	return nil
}
