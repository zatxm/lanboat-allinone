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

const mkcpMemoryLimit = 16 << 20

type mkcpSent struct {
	seq   uint32
	data  []byte
	at    time.Time
	tries int
}

type mkcpConn struct {
	r                           *Runtime
	options                     MKCPOptions
	codec                       *mkcpCodec
	conv                        uint16
	local, remote               net.Addr
	raw                         net.Conn
	listener                    *mkcpListener
	key                         string
	send                        func([]byte) error
	mu, readMu, writeMu         sync.Mutex
	sendNext, recvNext          uint32
	peerWindow                  uint32
	pending                     map[uint32]*mkcpSent
	queue                       []*mkcpSent
	receive                     map[uint32][]byte
	acks                        map[uint32]uint32
	readOffset, memory, queued  int
	mss, receiveWindow          int
	window                      int
	rto, srtt, variation        time.Duration
	start, lastSeen, lastPing   time.Time
	tokenAt                     time.Time
	tokens                      float64
	readDeadline, writeDeadline time.Time
	appClosed, peerClosed       bool
	peerTerminated              bool
	localTerminated             bool
	ackWindow                   bool
	peerEnd                     uint32
	closeAt                     time.Time
	err                         error
	readWake, writeWake, wake   chan struct{}
	done                        chan struct{}
	once                        sync.Once
	workers                     sync.WaitGroup
}

func (r *Runtime) newMKCP(o MKCPOptions, codec *mkcpCodec, conv uint16, local, remote net.Addr, raw net.Conn, send func([]byte) error, listener *mkcpListener, key string) (*mkcpConn, error) {
	now := time.Now()
	mss := o.MTU - codec.overhead() - 18
	window := min(4096, max(8, o.rate(true)*o.TTI/1000/o.MTU))
	c := &mkcpConn{listener: listener, key: key, r: r, options: o, codec: codec, conv: conv, local: local, remote: remote, raw: raw, send: send, peerWindow: 32, pending: map[uint32]*mkcpSent{}, receive: map[uint32][]byte{}, acks: map[uint32]uint32{}, mss: mss, receiveWindow: min(4096, max(1, min(o.ReadBuffer/(1460-18), o.rate(false)*o.TTI/1000/o.MTU))), window: window, rto: 200 * time.Millisecond, start: now, lastSeen: now, tokenAt: now, tokens: float64(o.rate(true) * o.TTI / 1000), readWake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1), wake: make(chan struct{}, 1), done: make(chan struct{})}
	if o.Congestion {
		c.window = min(c.window, 8)
	}
	r.mkcpMu.Lock()
	defer r.mkcpMu.Unlock()
	if r.ctx.Err() != nil || len(r.mkcpConns) >= 256 {
		return nil, errors.New("mKCP connection capacity reached or runtime closed")
	}
	r.mkcpConns[c] = struct{}{}
	c.startWorkers()
	return c, nil
}

func (c *mkcpConn) startWorkers() {
	c.workers.Go(c.maintain)
	if c.raw != nil {
		c.workers.Go(func() {
			buffer := make([]byte, 2049)
			for {
				n, e := c.raw.Read(buffer)
				if e != nil {
					c.abort(e)
					return
				}
				c.inputPacket(buffer[:n])
			}
		})
	}
}

func (r *Runtime) dialMKCP(ctx context.Context, o Outbound) (net.Conn, error) {
	raw, e := r.endpoint(ctx, o, "udp")
	if e != nil {
		return nil, e
	}
	var id [2]byte
	rand.Read(id[:])
	options := o.Transport.mkcpOptions()
	c, e := r.newMKCP(options, newMKCPCodec(options), binary.BigEndian.Uint16(id[:]), raw.LocalAddr(), raw.RemoteAddr(), raw, func(b []byte) error { _, e := raw.Write(b); return e }, nil, "")
	if e != nil {
		raw.Close()
		return nil, e
	}
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	}
	return c, nil
}

func (c *mkcpConn) reserve(n int, next bool) bool {
	// Keep one maximum-size missing head per connection admissible under load.
	limit := int64(mkcpMemoryLimit - 256*(1460-18))
	if next {
		limit = mkcpMemoryLimit
	}
	if c.r.mkcpBudget.Add(int64(n)) > limit {
		c.r.mkcpBudget.Add(-int64(n))
		return false
	}
	c.memory += n
	return true
}
func (c *mkcpConn) release(n int) { c.memory -= n; c.r.mkcpBudget.Add(-int64(n)) }
func mkcpBefore(a, b uint32) bool { return int32(a-b) < 0 }
func (c *mkcpConn) sendBase() uint32 {
	for len(c.queue) > 0 && c.pending[c.queue[0].seq] == nil {
		c.queue[0] = nil
		c.queue = c.queue[1:]
	}
	if len(c.queue) > 0 {
		return c.queue[0].seq
	}
	return c.sendNext
}
func (c *mkcpConn) acknowledge(n uint32) {
	if p := c.pending[n]; p != nil {
		delete(c.pending, n)
		c.queued -= len(p.data)
		c.release(len(p.data))
		p.data = nil
	}
}
func (c *mkcpConn) advance(next uint32) {
	if mkcpBefore(c.sendNext, next) {
		return
	}
	for n := range c.pending {
		if mkcpBefore(n, next) {
			c.acknowledge(n)
		}
	}
	c.sendBase()
	signal(c.writeWake)
}
func (c *mkcpConn) inputPacket(packet []byte) {
	b, e := c.codec.open(packet)
	if e != nil {
		return
	}
	frames, e := parseMKCP(b)
	if e != nil || len(frames) == 0 {
		return
	}
	c.input(frames)
}
func (c *mkcpConn) input(frames []mkcpFrame) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	for _, f := range frames {
		if f.conv != c.conv {
			return
		}
		c.lastSeen = time.Now()
		switch f.cmd {
		case 0:
			if mkcpBefore(c.sendNext, f.next) {
				continue
			}
			if !mkcpBefore(f.window, c.peerWindow) {
				c.peerWindow = f.window
			}
			c.advance(f.next)
			acked := false
			for _, n := range f.acks {
				if c.pending[n] != nil {
					acked = true
					c.acknowledge(n)
				}
			}
			if acked {
				elapsed := uint32(time.Since(c.start)/time.Millisecond) - f.stamp
				if elapsed > 0 && elapsed < 10000 {
					sample := time.Duration(elapsed) * time.Millisecond
					if c.srtt == 0 {
						c.srtt = sample
						c.variation = sample / 2
					} else {
						delta := sample - c.srtt
						if delta < 0 {
							delta = -delta
						}
						c.variation = (3*c.variation + delta) / 4
						c.srtt = (7*c.srtt + sample) / 8
					}
					c.rto = min(3*time.Second, max(50*time.Millisecond, c.srtt+4*c.variation))
				}
				if c.options.Congestion {
					c.window = min(c.window+1, max(8, c.options.rate(true)*c.options.TTI/1000/c.options.MTU))
				}
			}
			c.sendBase()
			signal(c.writeWake)
		case 1:
			for n := range c.acks {
				if mkcpBefore(n, f.next) {
					delete(c.acks, n)
				}
			}
			if mkcpBefore(f.number, c.recvNext) {
				if c.recvNext-f.number <= uint32(c.receiveWindow) {
					c.acks[f.number] = f.stamp
				}
				continue
			}
			if f.number-c.recvNext >= uint32(c.receiveWindow) {
				continue
			}
			if _, ok := c.receive[f.number]; !ok && !c.appClosed {
				received := c.memory - c.queued
				if len(f.body) > 1460-18 || received+len(f.body) > c.options.ReadBuffer || !c.reserve(len(f.body), f.number == c.recvNext) {
					continue
				}
				c.receive[f.number] = append([]byte{}, f.body...)
			}
			c.acks[f.number] = f.stamp
			signal(c.readWake)
		case 2, 3:
			c.advance(f.next)
			for n := range c.acks {
				if mkcpBefore(n, f.number) {
					delete(c.acks, n)
				}
			}
			if f.cmd == 2 {
				c.peerClosed = true
				c.peerTerminated = true
				c.peerEnd = f.number
				if c.closeAt.IsZero() {
					c.closeAt = time.Now()
				}
				signal(c.readWake)
				signal(c.writeWake)
			}
		}
		if f.flags&1 != 0 {
			c.peerClosed = true
			signal(c.writeWake)
		}
	}
	signal(c.wake)
}

func (c *mkcpConn) control(cmd byte) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b, c.conv)
	b[2] = cmd
	binary.BigEndian.PutUint32(b[4:], c.sendBase())
	binary.BigEndian.PutUint32(b[8:], c.recvNext)
	binary.BigEndian.PutUint32(b[12:], uint32(c.rto/time.Millisecond))
	return b
}
func (c *mkcpConn) flush(now time.Time) bool {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return false
	}
	if now.Sub(c.lastSeen) > 30*time.Second || !c.closeAt.IsZero() && now.Sub(c.closeAt) > 5*time.Second {
		c.mu.Unlock()
		c.abort(io.EOF)
		return false
	}
	var packets [][]byte
	if len(c.acks) > 0 || c.ackWindow {
		c.ackWindow = false
		b := make([]byte, 17)
		binary.BigEndian.PutUint16(b, c.conv)
		binary.BigEndian.PutUint32(b[4:], c.recvNext+uint32(c.receiveWindow))
		binary.BigEndian.PutUint32(b[8:], c.recvNext)
		for n, stamp := range c.acks {
			if len(b)+4 > c.options.MTU-c.codec.overhead() || b[16] == 128 {
				packets = append(packets, b)
				b = append([]byte{}, b[:17]...)
				b[16] = 0
			}
			binary.BigEndian.PutUint32(b[12:], stamp)
			b = binary.BigEndian.AppendUint32(b, n)
			b[16]++
			delete(c.acks, n)
		}
		packets = append(packets, b)
	}
	capacity := float64(max(c.options.MTU, c.options.rate(true)*c.options.TTI/1000))
	c.tokens = min(capacity, c.tokens+now.Sub(c.tokenAt).Seconds()*float64(c.options.rate(true)))
	c.tokenAt = now
	limit := c.window
	if c.options.Congestion {
		limit = max(4, limit)
	}
	base := c.sendBase()
	lost := false
	for _, p := range c.queue {
		if c.pending[p.seq] == nil {
			continue
		}
		if mkcpBefore(p.seq, c.peerWindow) && p.seq-base < uint32(limit) {
			timeout := min(3*time.Second, c.rto*time.Duration(1+p.tries/2))
			if !p.at.IsZero() && now.Sub(p.at) < timeout {
				continue
			}
			if c.tokens < float64(len(p.data)+18) {
				break
			}
			if p.tries >= 20 {
				c.mu.Unlock()
				c.abort(errors.New("mKCP retransmission limit"))
				return false
			}
			lost = lost || p.tries > 0
			p.tries++
			p.at = now
			c.tokens -= float64(len(p.data) + 18)
			b := make([]byte, 18, len(p.data)+18)
			binary.BigEndian.PutUint16(b, c.conv)
			b[2] = 1
			binary.BigEndian.PutUint32(b[4:], uint32(now.Sub(c.start)/time.Millisecond))
			binary.BigEndian.PutUint32(b[8:], p.seq)
			binary.BigEndian.PutUint32(b[12:], base)
			binary.BigEndian.PutUint16(b[16:], uint16(len(p.data)))
			packets = append(packets, append(b, p.data...))
		}
	}
	if lost && c.options.Congestion {
		c.window = max(4, c.window*3/4)
	}
	closing := (c.appClosed || c.peerTerminated) && len(c.pending) == 0
	pingInterval := 3 * time.Second
	if closing {
		pingInterval = time.Second
	}
	if closing && !c.localTerminated || now.Sub(c.lastPing) >= pingInterval {
		cmd := byte(3)
		if closing {
			cmd = 2
			c.localTerminated = true
		}
		packets = append(packets, c.control(cmd))
		c.lastPing = now
	}
	complete := c.appClosed && c.peerTerminated && c.localTerminated && len(c.pending) == 0
	c.mu.Unlock()
	for _, b := range packets {
		if e := c.send(c.codec.seal(b)); e != nil {
			c.abort(e)
			return false
		}
	}
	if complete {
		c.abort(io.EOF)
		return false
	}
	return true
}
func (c *mkcpConn) maintain() {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-c.r.ctx.Done():
			c.abort(net.ErrClosed)
			return
		case <-c.wake:
		case <-timer.C:
		}
		if !c.flush(time.Now()) {
			return
		}
		c.mu.Lock()
		interval := 3 * time.Second
		if !c.closeAt.IsZero() {
			interval = time.Second
		}
		if len(c.pending) > 0 || len(c.acks) > 0 {
			interval = time.Duration(c.options.TTI) * time.Millisecond
		}
		c.mu.Unlock()
		timer.Reset(interval)
	}
}

func mkcpWait(wake, done <-chan struct{}, deadline time.Time) error {
	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		if !time.Now().Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-wake:
		return nil
	case <-done:
		return net.ErrClosed
	case <-timeout:
		return os.ErrDeadlineExceeded
	}
}
func (c *mkcpConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		d := c.readDeadline
		if !d.IsZero() && !time.Now().Before(d) {
			c.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if c.appClosed || c.err != nil {
			e := c.err
			if e == nil {
				e = net.ErrClosed
			}
			c.mu.Unlock()
			return 0, e
		}
		if data, ok := c.receive[c.recvNext]; ok {
			n := copy(b, data[c.readOffset:])
			c.readOffset += n
			if c.readOffset == len(data) {
				delete(c.receive, c.recvNext)
				c.release(len(data))
				c.readOffset = 0
				c.recvNext++
				c.ackWindow = true
				signal(c.wake)
			}
			c.mu.Unlock()
			if n > 0 {
				return n, nil
			}
			continue
		}
		if c.peerTerminated && c.recvNext == c.peerEnd {
			c.mu.Unlock()
			return 0, io.EOF
		}
		c.mu.Unlock()
		if e := mkcpWait(c.readWake, c.done, d); e != nil {
			return 0, e
		}
	}
}
func (c *mkcpConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	written := 0
	for len(b) > 0 {
		c.mu.Lock()
		d := c.writeDeadline
		if !d.IsZero() && !time.Now().Before(d) {
			c.mu.Unlock()
			return written, os.ErrDeadlineExceeded
		}
		if c.err != nil || c.appClosed || c.peerClosed {
			c.mu.Unlock()
			return written, net.ErrClosed
		}
		n := min(len(b), c.mss)
		if c.queued+n <= c.options.WriteBuffer && c.sendNext-c.sendBase() < 4096 && c.reserve(n, false) {
			p := &mkcpSent{seq: c.sendNext, data: append([]byte(nil), b[:n]...)}
			c.sendNext++
			c.pending[p.seq] = p
			c.queue = append(c.queue, p)
			c.queued += n
			written += n
			b = b[n:]
			signal(c.wake)
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		// The global budget may be released by another connection.
		waitUntil := time.Now().Add(100 * time.Millisecond)
		if !d.IsZero() && d.Before(waitUntil) {
			waitUntil = d
		}
		if e := mkcpWait(c.writeWake, c.done, waitUntil); e != nil && !errors.Is(e, os.ErrDeadlineExceeded) {
			return written, e
		}
	}
	return written, nil
}
func (c *mkcpConn) Close() error {
	c.mu.Lock()
	if !c.appClosed {
		c.appClosed = true
		if c.closeAt.IsZero() {
			c.closeAt = time.Now()
		}
	}
	c.mu.Unlock()
	signal(c.readWake)
	signal(c.writeWake)
	signal(c.wake)
	return nil
}
func (c *mkcpConn) abort(e error) {
	if c.raw != nil {
		c.raw.Close()
	}
	c.once.Do(func() {
		c.mu.Lock()
		c.err = e
		c.r.mkcpBudget.Add(-int64(c.memory))
		c.memory = 0
		c.pending = nil
		c.receive = nil
		c.acks = nil
		c.queue = nil
		close(c.done)
		c.mu.Unlock()
		c.r.mkcpMu.Lock()
		delete(c.r.mkcpConns, c)
		c.r.mkcpMu.Unlock()
		if c.listener != nil {
			c.listener.mu.Lock()
			if c.listener.peers[c.key] == c {
				delete(c.listener.peers, c.key)
			}
			c.listener.mu.Unlock()
		}
		signal(c.readWake)
		signal(c.writeWake)
	})
}
func (c *mkcpConn) CloseWrite() error {
	return errors.New("mKCP does not support independent write-side closure")
}
func (c *mkcpConn) LocalAddr() net.Addr  { return c.local }
func (c *mkcpConn) RemoteAddr() net.Addr { return c.remote }
func (c *mkcpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	signal(c.readWake)
	return nil
}
func (c *mkcpConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	signal(c.writeWake)
	return nil
}
func (c *mkcpConn) SetDeadline(t time.Time) error { c.SetReadDeadline(t); return c.SetWriteDeadline(t) }

func (r *Runtime) closeMKCP(clientsOnly bool) {
	r.mkcpMu.Lock()
	var list []*mkcpConn
	for c := range r.mkcpConns {
		if !clientsOnly || c.raw != nil {
			list = append(list, c)
		}
	}
	r.mkcpMu.Unlock()
	for _, c := range list {
		c.abort(net.ErrClosed)
	}
	for _, c := range list {
		c.workers.Wait()
	}
}
