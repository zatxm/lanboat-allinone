package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type wgIPStack struct {
	nat         *masqueNATScope
	peer        *ipEndpoint
	mu          sync.Mutex
	next        uint16
	udp         map[tunFlowKey]*wgUDPConn
	tcp         map[tunFlowKey]*wgTCPConn
	fragments   tunFragments
	flows       *udpFlows
	closed      bool
	udpJobs     chan wgUDPJob
	icmpJobs    chan tunPacket
	icmpPending map[uint16]*wgICMPRequest
	jobs        sync.WaitGroup
}

type wgUDPJob struct {
	query  request
	data   []byte
	reply  func([]byte, string) error
	reject func()
}

type ipEndpoint struct {
	nat            *masqueNAT
	runtime        *Runtime
	inbound        string
	local          []netip.Addr
	localAddresses func() []netip.Addr
	authUser       string
	mtu            int
	done           <-chan struct{}
	sendIP         func([]byte) error
	ensure         func(context.Context) error
	dnsHijack      func(netip.Addr, uint16) bool
	loopback       []string
	acceptPacket   func(tunPacket) bool
	udpIdleTimeout time.Duration
	tcpService     func(netip.AddrPort) (func(net.Conn), bool)
	rawInput       func(tunPacket) bool
	reservePort    func(string, netip.Addr) (io.Closer, uint16, error)
}

func (p *ipEndpoint) addresses() []netip.Addr {
	if p.localAddresses != nil {
		return p.localAddresses()
	}
	return p.local
}

func newWGIPStack(p *wgPeer, configure ...func(*ipEndpoint)) *wgIPStack {
	opts := &ipEndpoint{runtime: p.runtime, inbound: p.inbound, local: p.local, mtu: p.mtu, done: p.done, sendIP: p.sendIP, ensure: p.ensure}
	for _, fn := range configure {
		fn(opts)
	}
	return newIPStack(opts)
}
func newIPStack(p *ipEndpoint) *wgIPStack {
	s := &wgIPStack{peer: p, next: 20000, udp: map[tunFlowKey]*wgUDPConn{}, tcp: map[tunFlowKey]*wgTCPConn{}, fragments: tunFragments{}, flows: newUDPFlows(p.runtime)}
	if p.nat != nil {
		s.nat = p.nat.scope()
	}
	if p.inbound != "" {
		s.udpJobs = make(chan wgUDPJob, 64)
		s.icmpJobs = make(chan tunPacket, 64)
		for range 4 {
			s.jobs.Add(1)
			go func() {
				defer s.jobs.Done()
				for {
					select {
					case <-p.done:
						return
					case packet := <-s.icmpJobs:
						s.forwardICMP(packet)
					case job := <-s.udpJobs:
						h, port, _ := net.SplitHostPort(job.query.address)
						ip, _ := netip.ParseAddr(h)
						if p.dnsHijack != nil && port == "53" && p.dnsHijack(ip, 53) {
							p.runtime.enrichProcess(p.runtime.ctx, &job.query)
							p.runtime.enrichNeighbor(p.runtime.ctx, &job.query)
							if b, e := p.runtime.ExchangeDNS(WithMetadata(p.runtime.ctx, job.query.metadata), job.data, p.inbound); e == nil {
								job.reply(b, job.query.address)
							}
						} else {
							send := func() error {
								if s.nat != nil {
									return s.nat.send(job.query, job.data, job.reply)
								}
								return s.flows.send(job.query.source+"/"+job.query.address, job.query, job.data, job.reply)
							}
							if e := send(); errors.Is(e, ErrRejected) && job.reject != nil {
								job.reject()
							}
						}
					}
				}
			}()
		}
	}
	return s
}
func (s *wgIPStack) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	udp := make([]*wgUDPConn, 0, len(s.udp))
	tcp := make([]*wgTCPConn, 0, len(s.tcp))
	for _, c := range s.udp {
		udp = append(udp, c)
	}
	for _, c := range s.tcp {
		tcp = append(tcp, c)
	}
	s.mu.Unlock()
	for _, c := range udp {
		c.Close()
	}
	for _, c := range tcp {
		c.abort(net.ErrClosed)
	}
	if s.nat != nil {
		s.nat.close()
	}
	s.flows.Close()
	s.jobs.Wait()
}
func (s *wgIPStack) expire(now time.Time) {
	s.mu.Lock()
	var packets [][]byte
	var expiredUDP []*wgUDPConn
	if s.peer.udpIdleTimeout > 0 {
		for _, c := range s.udp {
			c.mu.Lock()
			expired := now.Sub(c.last) >= s.peer.udpIdleTimeout
			c.mu.Unlock()
			if expired {
				expiredUDP = append(expiredUDP, c)
			}
		}
	}
	for k, c := range s.tcp {
		c.mu.Lock()
		expired := now.Sub(c.last) > 5*time.Minute || c.closed && !c.closedAt.IsZero() && now.Sub(c.closedAt) > 30*time.Second
		if !expired && c.eof && c.sendUna != c.sendNext && c.finRetries < 5 && now.Sub(c.finAt) >= time.Second*time.Duration(1<<min(c.finRetries, 3)) {
			packets = append(packets, c.packetLocked(c.sendNext-1, 17, nil))
			c.finRetries++
			c.finAt = now
		}
		c.mu.Unlock()
		if expired {
			delete(s.tcp, k)
			c.abort(errors.New("WireGuard TCP idle timeout"))
		}
	}
	s.mu.Unlock()
	for _, c := range expiredUDP {
		c.Close()
	}
	for _, packet := range packets {
		s.peer.sendIP(packet)
	}
}
func (s *wgIPStack) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	pn, e := strconv.ParseUint(port, 10, 16)
	if e != nil || pn == 0 {
		return nil, errors.New("invalid WireGuard destination port")
	}
	ips, e := s.peer.runtime.resolver.lookupReal(ctx, host)
	if e != nil {
		return nil, e
	}
	var dest, local netip.Addr
	for _, ip := range ips {
		for _, a := range s.peer.addresses() {
			if ip.Is4() == a.Is4() {
				dest, local = ip, a
				break
			}
		}
		if dest.IsValid() {
			break
		}
	}
	if !dest.IsValid() {
		return nil, errors.New("WireGuard local_address has no matching address family")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	if len(s.tcp)+len(s.udp) >= 256 {
		s.mu.Unlock()
		return nil, errors.New("WireGuard flow capacity reached")
	}
	key := tunFlowKey{source: local, destination: dest, dport: uint16(pn)}
	var reserved io.Closer
	for range 65535 {
		if s.peer.reservePort != nil {
			reserved, key.sport, e = s.peer.reservePort(network, local)
			if e != nil {
				s.mu.Unlock()
				return nil, e
			}
		} else {
			s.next++
			if s.next < 1024 {
				s.next = 1024
			}
			key.sport = s.next
		}
		if s.udp[key] == nil && s.tcp[key] == nil {
			break
		}
		if reserved != nil {
			reserved.Close()
			reserved = nil
		}
	}
	if network == "udp" {
		c := &wgUDPConn{stack: s, key: key, incoming: make(chan []byte, 64), closed: make(chan struct{}), wake: make(chan struct{}, 1), last: time.Now(), reserved: reserved}
		s.udp[key] = c
		s.mu.Unlock()
		return c, nil
	}
	c := newWGTCP(s, key, false)
	c.reserved = reserved
	s.tcp[key] = c
	s.mu.Unlock()
	if e = c.connect(ctx); e != nil {
		c.abort(e)
		s.mu.Lock()
		delete(s.tcp, key)
		s.mu.Unlock()
		return nil, e
	}
	return c, nil
}
func (s *wgIPStack) input(p tunPacket) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	assembled, e := s.fragments.assemble(p)
	s.mu.Unlock()
	if e != nil || assembled == nil {
		return
	}
	p, e = parseTunPacket(assembled)
	if e != nil {
		return
	}
	if p.source.Is4() && checksum(p.data[:p.header], 0) != 0 {
		return
	}
	segment := p.data[p.header:]
	if s.peer.rawInput != nil && s.rawPacket(p) {
		return
	}
	if p.protocol == 1 || p.protocol == 58 {
		s.icmp(p)
		return
	}
	if p.protocol != 6 && p.protocol != 17 || len(segment) < 8 {
		return
	}
	if transportChecksum(p, segment) != 0 && !(p.protocol == 17 && p.source.Is4() && binary.BigEndian.Uint16(segment[6:]) == 0) {
		return
	}
	sport, dport := binary.BigEndian.Uint16(segment), binary.BigEndian.Uint16(segment[2:])
	key := tunFlowKey{source: p.destination, destination: p.source, sport: dport, dport: sport}
	if p.protocol == 17 {
		n := int(binary.BigEndian.Uint16(segment[4:]))
		if n < 8 || n > len(segment) {
			return
		}
		data := segment[8:n]
		s.mu.Lock()
		c := s.udp[key]
		s.mu.Unlock()
		if c != nil {
			c.mu.Lock()
			c.last = time.Now()
			c.mu.Unlock()
			select {
			case c.incoming <- append([]byte{}, data...):
			default:
			}
			return
		}
		if s.peer.inbound == "" {
			return
		}
		if s.peer.acceptPacket != nil && !s.peer.acceptPacket(p) {
			return
		}
		query := request{metadata: Metadata{AuthUser: s.peer.authUser}, network: "udp", inbound: s.peer.inbound, source: net.JoinHostPort(p.source.String(), strconv.Itoa(int(sport))), address: net.JoinHostPort(p.destination.String(), strconv.Itoa(int(dport)))}
		replySrc, replyDest := p.destination, p.source
		job := wgUDPJob{query: query, data: append([]byte{}, data...), reply: func(b []byte, from string) error {
			if s.nat != nil {
				address, err := netip.ParseAddrPort(from)
				if err != nil || address.Addr().Is4() != replyDest.Is4() {
					return errors.New("invalid NAT reply address")
				}
				return s.peer.sendIP(makeUDPPacket(address.Addr(), replyDest, address.Port(), sport, b))
			}
			return s.peer.sendIP(makeUDPPacket(replySrc, replyDest, dport, sport, b))
		}}
		quoted := p
		quoted.data = append([]byte{}, p.data[:min(len(p.data), 1232)]...)
		job.reject = func() { s.sendICMPError(quoted, true, false) }
		job.query.icmpError = func(cause *icmpFlowError) { s.relayICMPError(quoted, cause.response) }
		select {
		case s.udpJobs <- job:
		default:
		}
		return
	}
	if len(segment) < 20 {
		return
	}
	s.mu.Lock()
	c := s.tcp[key]
	if c == nil && s.peer.acceptPacket != nil {
		s.mu.Unlock()
		allowed := s.peer.acceptPacket(p)
		s.mu.Lock()
		c = s.tcp[key]
		if c == nil && !allowed {
			s.mu.Unlock()
			return
		}
	}
	if c == nil && !s.closed && s.peer.inbound != "" && segment[13]&0x17 == 2 && len(s.tcp)+len(s.udp) < 256 {
		c = newWGTCP(s, key, true)
		s.tcp[key] = c
		c.mu.Lock()
		c.receive = binary.BigEndian.Uint32(segment[4:]) + 1
		c.mu.Unlock()
		s.peer.runtime.mu.Lock()
		if s.peer.runtime.closed {
			s.peer.runtime.mu.Unlock()
			s.mu.Unlock()
			return
		}
		s.peer.runtime.workers.Add(1)
		s.peer.runtime.mu.Unlock()
		quoted := p
		quoted.data = append([]byte{}, p.data[:min(len(p.data), 1232)]...)
		go func() {
			defer s.peer.runtime.workers.Done()
			defer c.Close()
			ctx, cancel := context.WithTimeout(s.peer.runtime.ctx, handshakeTimeout)
			defer cancel()
			q := request{metadata: Metadata{AuthUser: s.peer.authUser}, icmpError: func(cause *icmpFlowError) { s.relayICMPError(quoted, cause.response) }, network: "tcp", inbound: s.peer.inbound, source: net.JoinHostPort(key.destination.String(), strconv.Itoa(int(key.dport))), address: net.JoinHostPort(key.source.String(), strconv.Itoa(int(key.sport)))}
			if s.peer.tcpService != nil {
				if serve, ok := s.peer.tcpService(netip.AddrPortFrom(key.source, key.sport)); ok {
					if c.accept(ctx) == nil {
						serve(c)
					}
					return
				}
			}
			for _, address := range s.peer.loopback {
				if address == key.source.String() {
					q.address = net.JoinHostPort(key.destination.String(), strconv.Itoa(int(key.sport)))
					break
				}
			}
			if s.peer.dnsHijack != nil && s.peer.dnsHijack(key.source, key.sport) {
				if e := c.accept(ctx); e != nil {
					return
				}
				s.peer.runtime.serveDNSStream(c, s.peer.inbound)
				return
			}
			remote, e := s.peer.runtime.routeDial(ctx, q)
			if e != nil {
				var cause *icmpFlowError
				if errors.Is(e, ErrDropped) || errors.As(e, &cause) {
					c.abort(e)
				} else {
					c.reset()
				}
				return
			}
			if e = c.accept(ctx); e != nil {
				remote.Close()
				return
			}
			s.peer.runtime.relay(c, remote)
		}()
	}
	s.mu.Unlock()
	if c != nil {
		c.input(segment)
	}
}
func (s *wgIPStack) icmp(p tunPacket) {
	local := false
	for _, a := range s.peer.addresses() {
		if a == p.destination {
			local = true
			break
		}
	}
	segment := p.data[p.header:]
	if len(segment) < 8 {
		return
	}

	if p.protocol == 1 && checksum(segment, 0) != 0 || p.protocol == 58 && transportChecksum(p, segment) != 0 {
		return
	}
	if s.receiveICMPResponse(p, segment) {
		return
	}
	if icmpError(segment[0], p.protocol == 58) {
		s.receiveICMPFlowError(p, segment)
		return
	}
	if p.protocol == 1 && segment[0] == 8 && segment[1] == 0 && checksum(segment, 0) == 0 || p.protocol == 58 && segment[0] == 128 && segment[1] == 0 && transportChecksum(p, segment) == 0 {
		if s.peer.acceptPacket != nil && !s.peer.acceptPacket(p) {
			return
		}
		if !local {
			if s.icmpJobs != nil {
				p.data = append([]byte{}, p.data...)
				select {
				case s.icmpJobs <- p:
				default:
				}
			}
			return
		}
		reply := append([]byte{}, segment...)
		reply[0] = 0
		if p.protocol == 58 {
			reply[0] = 129
		}
		clear(reply[2:4])
		packet := makeWGIP(p.destination, p.source, p.protocol, reply)
		rp, _ := parseTunPacket(packet)
		sum := checksum(reply, 0)
		if p.protocol == 58 {
			sum = transportChecksum(rp, reply)
		}
		binary.BigEndian.PutUint16(packet[rp.header+2:], sum)
		s.peer.sendIP(packet)
	}
}
func makeWGIP(source, dest netip.Addr, protocol byte, segment []byte) []byte {
	header := 20
	if source.Is6() {
		header = 40
	}
	b := make([]byte, header+len(segment))
	if source.Is4() {
		b[0] = 0x45
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		b[8], b[9] = 64, protocol
		copy(b[12:], source.AsSlice())
		copy(b[16:], dest.AsSlice())
		binary.BigEndian.PutUint16(b[10:], checksum(b[:20], 0))
	} else {
		b[0] = 0x60
		binary.BigEndian.PutUint16(b[4:], uint16(len(segment)))
		b[6], b[7] = protocol, 64
		copy(b[8:], source.AsSlice())
		copy(b[24:], dest.AsSlice())
	}
	copy(b[header:], segment)
	return b
}

type wgUDPConn struct {
	reserved                    io.Closer
	failure                     error
	stack                       *wgIPStack
	key                         tunFlowKey
	incoming                    chan []byte
	closed, wake                chan struct{}
	once                        sync.Once
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	last                        time.Time
}

func (c *wgUDPConn) Read(b []byte) (int, error) {
	for {
		c.mu.Lock()
		d := c.readDeadline
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !d.IsZero() {
			timer = time.NewTimer(max(0, time.Until(d)))
			timeout = timer.C
		}
		var data []byte
		var e error
		select {
		case data = <-c.incoming:
		case <-c.closed:
			e = net.ErrClosed
		case <-c.stack.peer.done:
			e = net.ErrClosed
		case <-timeout:
			e = context.DeadlineExceeded
		case <-c.wake:
		}
		if timer != nil {
			timer.Stop()
		}
		if e != nil {
			c.mu.Lock()
			if c.failure != nil {
				e = c.failure
			}
			c.mu.Unlock()
			return 0, e
		}
		if data != nil {
			if len(data) > len(b) {
				return 0, io.ErrShortBuffer
			}
			return copy(b, data), nil
		}
	}
}
func (c *wgUDPConn) Write(b []byte) (int, error) {
	if len(b) > 65507 {
		return 0, errors.New("UDP payload too large")
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	d := c.writeDeadline
	c.last = time.Now()
	c.mu.Unlock()
	if !d.IsZero() && time.Now().After(d) {
		return 0, context.DeadlineExceeded
	}
	ctx, cancel := context.WithTimeout(c.stack.peer.runtime.ctx, handshakeTimeout)
	defer cancel()
	if e := c.stack.peer.ensure(ctx); e != nil {
		return 0, e
	}
	k := c.key
	if e := c.stack.peer.sendIP(makeUDPPacket(k.source, k.destination, k.sport, k.dport, b)); e != nil {
		return 0, e
	}
	return len(b), nil
}
func (c *wgUDPConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
		c.stack.mu.Lock()
		delete(c.stack.udp, c.key)
		c.stack.mu.Unlock()
		if c.reserved != nil {
			c.reserved.Close()
		}
	})
	return nil
}
func (c *wgUDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(c.key.source.AsSlice()), Port: int(c.key.sport)}
}
func (c *wgUDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(c.key.destination.AsSlice()), Port: int(c.key.dport)}
}
func (c *wgUDPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	signalQUIC(c.wake)
	return nil
}
func (c *wgUDPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
func (c *wgUDPConn) SetDeadline(t time.Time) error {
	c.SetWriteDeadline(t)
	return c.SetReadDeadline(t)
}

type wgTCPSegment struct {
	seq  uint32
	data []byte
	fin  bool
}
type wgTCPConn struct {
	reserved                            io.Closer
	stack                               *wgIPStack
	key                                 tunFlowKey
	mu, writeMu                         sync.Mutex
	sendNext, sendUna, receive          uint32
	window                              uint32
	mss                                 int
	queue                               [][]byte
	queued                              int
	pending                             map[uint32]wgTCPSegment
	ready, server, closed, eof, readEOF bool
	err                                 error
	last, closedAt, finAt               time.Time
	finRetries                          int
	wakeRead, wakeWrite                 chan struct{}
	readDeadline, writeDeadline         time.Time
}

func newWGTCP(s *wgIPStack, key tunFlowKey, server bool) *wgTCPConn {
	var n [4]byte
	rand.Read(n[:])
	seq := binary.BigEndian.Uint32(n[:])
	return &wgTCPConn{stack: s, key: key, sendNext: seq, sendUna: seq, window: 65535, mss: min(1200, s.peer.mtu-60), server: server, pending: map[uint32]wgTCPSegment{}, last: time.Now(), wakeRead: make(chan struct{}, 1), wakeWrite: make(chan struct{}, 1)}
}
func tcpBefore(a, b uint32) bool { return int32(a-b) < 0 }
func (c *wgTCPConn) signal()     { signalQUIC(c.wakeRead); signalQUIC(c.wakeWrite) }
func (c *wgTCPConn) packetLocked(seq uint32, flags byte, data []byte) []byte {
	segment := make([]byte, 20+len(data))
	binary.BigEndian.PutUint16(segment, c.key.sport)
	binary.BigEndian.PutUint16(segment[2:], c.key.dport)
	binary.BigEndian.PutUint32(segment[4:], seq)
	binary.BigEndian.PutUint32(segment[8:], c.receive)
	segment[12], segment[13] = 5<<4, flags
	binary.BigEndian.PutUint16(segment[14:], uint16(max(0, 65535-c.queued)))
	copy(segment[20:], data)
	if flags&2 != 0 {
		segment = append(segment[:20], 0x02, 4, byte(c.mss>>8), byte(c.mss))
		segment[12] = 6 << 4
	}
	packet := makeWGIP(c.key.source, c.key.destination, 6, segment)
	p, _ := parseTunPacket(packet)
	binary.BigEndian.PutUint16(packet[p.header+16:], transportChecksum(p, segment))
	return packet
}
func (c *wgTCPConn) send(seq uint32, flags byte, data []byte) error {
	c.mu.Lock()
	b := c.packetLocked(seq, flags, data)
	c.last = time.Now()
	c.mu.Unlock()
	return c.stack.peer.sendIP(b)
}
func (c *wgTCPConn) connect(ctx context.Context) error {
	c.mu.Lock()
	seq := c.sendNext
	c.sendNext++
	c.mu.Unlock()
	for attempt := 0; attempt < 8; attempt++ {
		if e := c.send(seq, 2, nil); e != nil {
			return e
		}
		timer := time.NewTimer(time.Duration(min(200<<attempt, 2000)) * time.Millisecond)
		for {
			c.mu.Lock()
			ready, e := c.ready, c.err
			c.mu.Unlock()
			if ready {
				timer.Stop()
				return nil
			}
			if e != nil {
				timer.Stop()
				return e
			}
			select {
			case <-c.wakeWrite:
				continue
			case <-timer.C:
				goto retry
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-c.stack.peer.done:
				timer.Stop()
				return net.ErrClosed
			}
		}
	retry:
	}
	return errors.New("WireGuard TCP SYN timed out")
}
func (c *wgTCPConn) accept(ctx context.Context) error {
	c.mu.Lock()
	seq := c.sendNext
	c.sendNext++
	c.mu.Unlock()
	for attempt := 0; attempt < 8; attempt++ {
		if e := c.send(seq, 0x12, nil); e != nil {
			return e
		}
		timer := time.NewTimer(time.Duration(min(200<<attempt, 2000)) * time.Millisecond)
		for {
			c.mu.Lock()
			ready, e := c.ready, c.err
			c.mu.Unlock()
			if ready {
				timer.Stop()
				return nil
			}
			if e != nil {
				timer.Stop()
				return e
			}
			select {
			case <-c.wakeWrite:
				continue
			case <-timer.C:
				goto retry
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-c.stack.peer.done:
				timer.Stop()
				return net.ErrClosed
			}
		}
	retry:
	}
	return errors.New("WireGuard TCP accept timed out")
}
func (c *wgTCPConn) input(segment []byte) {
	header := int(segment[12]>>4) * 4
	if header < 20 || header > len(segment) {
		return
	}
	seq, ack := binary.BigEndian.Uint32(segment[4:]), binary.BigEndian.Uint32(segment[8:])
	flags := segment[13]
	data := segment[header:]
	c.mu.Lock()
	defer func() { c.mu.Unlock(); c.signal() }()
	if c.err != nil {
		return
	}
	c.last = time.Now()
	if flags&4 != 0 {
		if c.ready && seq == c.receive || !c.ready && flags&16 != 0 && ack == c.sendNext {
			c.err = errors.New("WireGuard TCP reset")
		}
		return
	}
	if !c.ready {
		if !c.server && flags&0x12 == 0x12 && ack == c.sendNext {
			c.receive = seq + 1
			c.sendUna = ack
			c.ready = true
			c.window = uint32(binary.BigEndian.Uint16(segment[14:]))
			c.parseOptions(segment[20:header])
			packet := c.packetLocked(c.sendNext, 16, nil)
			c.mu.Unlock()
			c.stack.peer.sendIP(packet)
			c.mu.Lock()
			return
		}
		if c.server && flags&16 != 0 && ack == c.sendNext && seq == c.receive {
			c.ready = true
			c.sendUna = ack
			c.window = uint32(binary.BigEndian.Uint16(segment[14:]))
		} else {
			return
		}
	}
	if flags&16 == 0 || tcpBefore(c.sendNext, ack) || tcpBefore(seq, c.receive-65535) || tcpBefore(c.receive+65535, seq) {
		return
	}
	if !tcpBefore(ack, c.sendUna) {
		c.sendUna = ack
		c.window = uint32(binary.BigEndian.Uint16(segment[14:]))
	}
	if flags&2 != 0 {
		return
	}
	if len(data) == 0 && flags&1 == 0 {
		return
	}
	if c.readEOF || c.closed {
		if flags&1 != 0 {
			if !c.readEOF && seq == c.receive && len(data) == 0 {
				c.receive++
				c.readEOF = true
			}
			packet := c.packetLocked(c.sendNext, 16, nil)
			c.mu.Unlock()
			c.stack.peer.sendIP(packet)
			c.mu.Lock()
		}
		return
	}
	if tcpBefore(seq, c.receive) {
		overlap := int(c.receive - seq)
		if overlap > len(data) {
			packet := c.packetLocked(c.sendNext, 16, nil)
			c.mu.Unlock()
			c.stack.peer.sendIP(packet)
			c.mu.Lock()
			return
		}
		data = data[overlap:]
		seq = c.receive
	}
	if len(data) > 65535-c.queued {
		return
	}
	entry := wgTCPSegment{seq: seq, data: append([]byte{}, data...), fin: flags&1 != 0}
	if seq == c.receive {
		c.deliverLocked(entry)
		for {
			next, ok := c.pending[c.receive]
			if !ok {
				break
			}
			delete(c.pending, c.receive)
			c.deliverLocked(next)
		}
	} else if len(c.pending) < 32 && len(data) <= 32768 {
		total := c.queued
		overlap := false
		for _, p := range c.pending {
			total += len(p.data)
			if tcpBefore(seq, p.seq+uint32(len(p.data))) && tcpBefore(p.seq, seq+uint32(len(data))) {
				overlap = true
			}
		}
		if !overlap && total+len(data) <= 65535 {
			c.pending[seq] = entry
		}
	}
	packet := c.packetLocked(c.sendNext, 16, nil)
	c.mu.Unlock()
	c.stack.peer.sendIP(packet)
	c.mu.Lock()
}
func (c *wgTCPConn) parseOptions(b []byte) {
	for len(b) > 0 {
		kind := b[0]
		if kind == 0 {
			return
		}
		if kind == 1 {
			b = b[1:]
			continue
		}
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return
		}
		if kind == 2 && b[1] == 4 {
			mss := int(binary.BigEndian.Uint16(b[2:]))
			if mss >= 64 {
				c.mss = min(c.mss, mss)
			}
		}
		b = b[b[1]:]
	}
}
func (c *wgTCPConn) deliverLocked(p wgTCPSegment) {
	if len(p.data) > 0 {
		c.queue = append(c.queue, p.data)
		c.queued += len(p.data)
		c.receive += uint32(len(p.data))
	}
	if p.fin {
		c.receive++
		c.readEOF = true
	}
}
func (c *wgTCPConn) wait(d time.Time, write bool) error {
	wake := c.wakeRead
	if write {
		wake = c.wakeWrite
	}
	var timeout <-chan time.Time
	var timer *time.Timer
	if !d.IsZero() {
		timer = time.NewTimer(max(0, time.Until(d)))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case <-wake:
		return nil
	case <-c.stack.peer.done:
		return net.ErrClosed
	case <-timeout:
		return context.DeadlineExceeded
	}
}
func (c *wgTCPConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.queue) > 0 {
			n := copy(b, c.queue[0])
			c.queue[0] = c.queue[0][n:]
			if len(c.queue[0]) == 0 {
				c.queue[0] = nil
				c.queue = c.queue[1:]
			}
			c.queued -= n
			packet := c.packetLocked(c.sendNext, 16, nil)
			c.mu.Unlock()
			c.stack.peer.sendIP(packet)
			return n, nil
		}
		err, eof, closed, d := c.err, c.readEOF, c.closed, c.readDeadline
		c.mu.Unlock()
		if err != nil {
			return 0, err
		}
		if eof {
			return 0, io.EOF
		}
		if closed {
			return 0, net.ErrClosed
		}
		if e := c.wait(d, false); e != nil {
			return 0, e
		}
	}
}
func (c *wgTCPConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	cwnd := 4 * c.mss
	for len(b) > 0 {
		c.mu.Lock()
		if c.err != nil {
			e := c.err
			c.mu.Unlock()
			return total, e
		}
		if c.closed || c.eof {
			c.mu.Unlock()
			return total, net.ErrClosed
		}
		deadline, window := c.writeDeadline, int(c.window)
		if !deadline.IsZero() && time.Now().After(deadline) {
			c.mu.Unlock()
			return total, context.DeadlineExceeded
		}
		seq := c.sendNext
		n := min(len(b), window, cwnd, 32768)
		if n == 0 {
			c.mu.Unlock()
			until := time.Now().Add(time.Second)
			if !deadline.IsZero() && deadline.Before(until) {
				until = deadline
			}
			if e := c.wait(until, true); e != nil {
				if !errors.Is(e, context.DeadlineExceeded) {
					return total, e
				}
				if !deadline.IsZero() && !time.Now().Before(deadline) {
					return total, e
				}
				if e = c.send(seq-1, 16, []byte{0}); e != nil {
					return total, e
				}
			}
			continue
		}
		c.sendNext += uint32(n)
		end := c.sendNext
		c.mu.Unlock()
		data := b[:n]
		acked := false
		for attempt := 0; attempt < 8 && !acked; attempt++ {
			if attempt > 0 {
				cwnd = max(c.mss, cwnd/2)
			}
			for offset := 0; offset < n; offset += c.mss {
				m := min(c.mss, n-offset)
				if e := c.send(seq+uint32(offset), 24, data[offset:offset+m]); e != nil {
					return total, e
				}
			}
			until := time.Now().Add(time.Duration(min(200<<attempt, 2000)) * time.Millisecond)
			if !deadline.IsZero() && deadline.Before(until) {
				until = deadline
			}
			for {
				c.mu.Lock()
				done := !tcpBefore(c.sendUna, end)
				e := c.err
				c.mu.Unlock()
				if e != nil {
					return total, e
				}
				if done {
					acked = true
					break
				}
				if e = c.wait(until, true); e != nil {
					if !deadline.IsZero() && !time.Now().Before(deadline) {
						return total, context.DeadlineExceeded
					}
					if !errors.Is(e, context.DeadlineExceeded) {
						return total, e
					}
					break
				}
			}
		}
		if !acked {
			e := errors.New("WireGuard TCP retransmission limit reached")
			c.abort(e)
			return total, e
		}
		total += n
		b = b[n:]
		cwnd = min(32768, cwnd+c.mss)
	}
	return total, nil
}
func (c *wgTCPConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.mu.Lock()
	if c.eof || c.closed {
		c.mu.Unlock()
		return nil
	}
	c.eof = true
	c.finAt = time.Now()
	seq := c.sendNext
	c.sendNext++
	c.mu.Unlock()
	return c.send(seq, 17, nil)
}
func (c *wgTCPConn) Close() error {
	c.CloseWrite()
	c.mu.Lock()
	c.closed = true
	c.closedAt = time.Now()
	c.last = time.Now()
	c.queue = nil
	c.queued = 0
	c.mu.Unlock()
	c.signal()
	return nil
}
func (c *wgTCPConn) abort(e error) {
	c.mu.Lock()
	c.err = e
	c.closed = true
	c.closedAt = time.Now()
	c.queue = nil
	clear(c.pending)
	reserved := c.reserved
	c.reserved = nil
	c.mu.Unlock()
	if reserved != nil {
		reserved.Close()
	}
	c.signal()
}
func (c *wgTCPConn) reset() {
	c.mu.Lock()
	seq := c.sendNext
	c.mu.Unlock()
	c.send(seq, 0x14, nil)
	c.abort(errors.New("WireGuard destination connection failed"))
}
func (c *wgTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP(c.key.source.AsSlice()), Port: int(c.key.sport)}
}
func (c *wgTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IP(c.key.destination.AsSlice()), Port: int(c.key.dport)}
}
func (c *wgTCPConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	signalQUIC(c.wakeRead)
	return nil
}
func (c *wgTCPConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	signalQUIC(c.wakeWrite)
	return nil
}
func (c *wgTCPConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (s *wgIPStack) rawPacket(p tunPacket) bool {
	segment := p.data[p.header:]
	original := p
	if (p.protocol == 1 || p.protocol == 58) && len(segment) >= 8 && icmpError(segment[0], p.protocol == 58) {
		quote, e := parseICMPQuote(segment[8:])
		if e == nil {
			p = quote
			segment = p.data[p.header:]
		}
	}
	s.mu.Lock()
	owned := false
	if (p.protocol == 6 || p.protocol == 17) && len(segment) >= 4 {
		key := tunFlowKey{source: p.destination, destination: p.source, sport: binary.BigEndian.Uint16(segment[2:]), dport: binary.BigEndian.Uint16(segment)}
		if original.protocol != p.protocol {
			key = tunFlowKey{source: p.source, destination: p.destination, sport: key.dport, dport: key.sport}
		}
		owned = s.tcp[key] != nil || s.udp[key] != nil
	} else if (p.protocol == 1 || p.protocol == 58) && len(segment) >= 8 {
		owned = s.icmpPending[binary.BigEndian.Uint16(segment[4:])] != nil
	}
	s.mu.Unlock()
	if owned {
		return false
	}
	p = original
	segment = p.data[p.header:]
	if p.protocol == 6 && len(segment) >= 4 && s.peer.tcpService != nil {
		if _, ok := s.peer.tcpService(netip.AddrPortFrom(p.destination, binary.BigEndian.Uint16(segment[2:]))); ok {
			return false
		}
	}
	return s.peer.rawInput(p)
}
