package native

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const fakeTCPMaxFlows = 512

type fakeTCPKey struct{ local, remote netip.AddrPort }
type fakeTCPFlow struct {
	conn          *net.TCPConn
	socket        *net.IPConn
	sequence, ack uint32
	sent, ready   bool
	window        uint16
	seen          time.Time
	oob           []byte
	remote        *net.IPAddr
	addr          *net.UDPAddr
}
type fakeTCPDatagram struct {
	data []byte
	addr *net.UDPAddr
}
type fakeTCPPacket struct {
	listener *net.TCPListener
	local    *net.TCPAddr
	sockets  []*net.IPConn
	mu       sync.Mutex
	writeMu  sync.Mutex
	flows    map[fakeTCPKey]*fakeTCPFlow
	peers    map[netip.AddrPort]fakeTCPKey
	changed  chan struct{}
	peer     netip.AddrPort
	queue    chan fakeTCPDatagram
	bytes    int
	readBy   time.Time
	writeBy  time.Time
	wake     chan struct{}
	done     chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
}

func fakeTCPPlatform() error { return nil }

// Only the established socket is filtered: raw IP reception is independent.
// The kernel completed the handshake, but never ACKs/reassembles QUIC payloads.
func muteFakeTCP(c *net.TCPConn) error {
	if err := c.SetKeepAlive(false); err != nil {
		return err
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	return filterFakeTCP(raw, []syscall.SockFilter{{Code: 6, K: 0}})
}

func filterFakeTCP(raw syscall.RawConn, filters []syscall.SockFilter) error {
	program := syscall.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	var optionErr error
	err := raw.Control(func(fd uintptr) {
		_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER, uintptr(unsafe.Pointer(&program)), unsafe.Sizeof(program), 0)
		if e != 0 {
			optionErr = e
		}
	})
	if err != nil {
		return err
	}
	return optionErr
}

func filterFakeTCPPort(socket *net.IPConn, ipv4 bool, port uint16) error {
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	filters := []syscall.SockFilter{{Code: 0x28, K: 2}} // LDH destination port.
	if ipv4 {
		filters = []syscall.SockFilter{{Code: 0xb1}, {Code: 0x48, K: 2}}
	} // Skip IPv4 options.
	filters = append(filters, syscall.SockFilter{Code: 0x15, K: uint32(port), Jf: 1}, syscall.SockFilter{Code: 6, K: 65535}, syscall.SockFilter{Code: 6})
	return filterFakeTCP(raw, filters)
}

func newFakeTCP() *fakeTCPPacket {
	return &fakeTCPPacket{flows: make(map[fakeTCPKey]*fakeTCPFlow), peers: make(map[netip.AddrPort]fakeTCPKey), changed: make(chan struct{}), queue: make(chan fakeTCPDatagram, 256), wake: make(chan struct{}, 1), done: make(chan struct{})}
}

func fakeTCPPktinfo(ip netip.Addr) []byte {
	n, kind := 12, syscall.IP_PKTINFO
	if ip.Is6() {
		n, kind = 20, syscall.IPV6_PKTINFO
	}
	b := make([]byte, syscall.CmsgSpace(n))
	h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level, h.Type = syscall.IPPROTO_IP, int32(kind)
	if ip.Is6() {
		h.Level = syscall.IPPROTO_IPV6
	}
	h.SetLen(syscall.CmsgLen(n))
	data := b[syscall.CmsgLen(0):]
	if ip.Is4() {
		copy(data[4:8], ip.AsSlice())
	} else {
		copy(data[:16], ip.AsSlice())
		if ip.Zone() != "" {
			index, _ := strconv.ParseUint(ip.Zone(), 10, 32)
			binary.NativeEndian.PutUint32(data[16:], uint32(index))
		}
	}
	return b
}

func fakeTCPDestination(oob []byte) (netip.Addr, uint32, bool) {
	messages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	for _, m := range messages {
		if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= 12 {
			return netip.AddrFrom4([4]byte(m.Data[8:12])), binary.NativeEndian.Uint32(m.Data), true
		}
		if m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == syscall.IPV6_PKTINFO && len(m.Data) >= 20 {
			return netip.AddrFrom16([16]byte(m.Data[:16])), binary.NativeEndian.Uint32(m.Data[16:]), true
		}
	}
	return netip.Addr{}, 0, false
}

func fakeTCPAddr(a *net.TCPAddr, fallback string) (netip.AddrPort, error) {
	ip, _ := netip.AddrFromSlice(a.IP)
	ip = ip.Unmap()
	if ip.Is6() && ip.IsLinkLocalUnicast() {
		zone := a.Zone
		if zone == "" {
			zone = fallback
		}
		index, err := strconv.ParseUint(zone, 10, 32)
		if err != nil {
			iface, e := net.InterfaceByName(zone)
			if e != nil {
				return netip.AddrPort{}, e
			}
			index = uint64(iface.Index)
		}
		ip = ip.WithZone(strconv.FormatUint(index, 10))
	}
	return netip.AddrPortFrom(ip, uint16(a.Port)), nil
}

func (p *fakeTCPPacket) open(ctx context.Context, address string, control func(string, string, syscall.RawConn) error, options DialOptions, listener bool) error {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return err
	}
	network, level, option := "ip4:tcp", syscall.IPPROTO_IP, syscall.IP_PKTINFO
	if ip.Is6() {
		network, level, option = "ip6:tcp", syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO
	}
	lc := net.ListenConfig{Control: func(network, address string, raw syscall.RawConn) error {
		if control != nil {
			if e := control(network, address, raw); e != nil {
				return e
			}
		}
		var e error
		if err := raw.Control(func(fd uintptr) { e = syscall.SetsockoptInt(int(fd), level, option, 1) }); err != nil {
			return err
		}
		return e
	}}
	var raw net.PacketConn
	if options.namespace != nil {
		raw, err = options.namespace.packet(ctx, options, options.listenOptions(), network, address, net.JoinHostPort(address, "0"), listener)
	} else {
		raw, err = lc.ListenPacket(ctx, network, address)
	}
	if err != nil {
		return err
	}
	socket := raw.(*net.IPConn)
	if options.namespace != nil {
		raw, e := socket.SyscallConn()
		if e == nil {
			e = raw.Control(func(fd uintptr) { err = syscall.SetsockoptInt(int(fd), level, option, 1) })
		}
		if e != nil || err != nil {
			socket.Close()
			return errors.Join(e, err)
		}
	}
	bufferSize := quicInboxBytes
	if p.listener != nil {
		bufferSize = 1 << 20
	}
	if err = socket.SetReadBuffer(bufferSize); err != nil {
		socket.Close()
		return err
	}
	if p.local != nil {
		if err = filterFakeTCPPort(socket, ip.Is4(), uint16(p.local.Port)); err != nil {
			socket.Close()
			return err
		}
	}
	p.sockets = append(p.sockets, socket)
	p.wg.Go(func() { p.capture(socket) })
	return nil
}

func listenFakeTCP(ctx context.Context, address string, options ...ListenOptions) (net.PacketConn, error) {
	var opts ListenOptions
	if len(options) != 0 {
		opts = options[0]
	}
	lc := opts.listenConfig()
	raw, err := opts.listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	p := newFakeTCP()
	p.listener, p.local = raw.(*net.TCPListener), raw.Addr().(*net.TCPAddr)
	host, _, _ := net.SplitHostPort(address)
	if wanted, e := netip.ParseAddr(host); e == nil && wanted.Zone() != "" && p.local.Zone == "" {
		local := *p.local
		local.Zone = wanted.Zone()
		p.local = &local
	}
	ip := p.local.AddrPort().Addr().Unmap()
	addresses := []string{ip.String()}
	if ip.IsUnspecified() && ip.Is6() {
		addresses = []string{"0.0.0.0", "::"}
	}
	for _, address := range addresses {
		if err = p.open(ctx, address, lc.Control, opts.dialOptions(), true); err != nil {
			p.Close()
			return nil, err
		}
	}
	p.wg.Go(p.accept)
	p.wg.Go(p.expire)
	return p, nil
}

func (r *Runtime) dialFakeTCP(ctx context.Context, o Outbound) (net.Conn, error) {
	ips, err := r.directIPs(ctx, o.Server)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		ip = ip.Unmap()
		if o.NetworkOptions.active() {
			primary, fallback, e := r.networkCandidates(ctx, o.NetworkOptions, ip, o.namespace)
			if e != nil {
				return nil, e
			}
			key := o.NetworkOptions.key(ip)
			key.namespace = o.namespace
			return raceNetworks(ctx, o.NetworkOptions, primary, fallback, r.network.fastFallback(key), func(ctx context.Context, c networkChoice) (net.Conn, error) {
				bound := o
				bound.Server = ip.String()
				bound.NetworkOptions = NetworkOptions{}
				bound.BindInterface = c.Name
				return r.dialFakeTCP(ctx, bound)
			}, func(failed bool) { r.network.recordFallback(key, failed) })
		}
		p := newFakeTCP()
		p.peer, err = fakeTCPAddr(net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, o.ServerPort)), ip.Zone())
		if err != nil {
			return nil, err
		}
		local := "0.0.0.0"
		if ip.Is6() {
			local = "::"
		}
		bind := o.Inet4BindAddress
		if ip.Is6() {
			bind = o.Inet6BindAddress
		}
		if bind != "" {
			local = bind
		}
		dialer, e := r.newDialer(o.DialOptions, "tcp", netip.AddrPortFrom(ip, o.ServerPort).String())
		if e != nil {
			return nil, e
		}
		if err = p.open(ctx, local, dialer.Control, o.DialOptions, false); err != nil {
			p.Close()
			return nil, err
		}
		var raw net.Conn
		raw, err = r.dialSocket(ctx, o.DialOptions, "tcp", netip.AddrPortFrom(ip, o.ServerPort).String())
		if err != nil {
			p.Close()
			continue
		}
		c := raw.(*net.TCPConn)
		p.mu.Lock()
		p.local = c.LocalAddr().(*net.TCPAddr)
		p.mu.Unlock()
		if err = filterFakeTCPPort(p.sockets[0], ip.Is4(), uint16(p.local.Port)); err != nil {
			c.Close()
			p.Close()
			return nil, err
		}
		if err = p.register(c); err != nil {
			c.Close()
			p.Close()
			return nil, err
		}
		return &fakeTCPConn{fakeTCPPacket: p, remote: net.UDPAddrFromAddrPort(p.peer)}, nil
	}
	if err == nil {
		err = errors.New("HY1 FakeTCP DNS returned no addresses")
	}
	return nil, err
}

func (p *fakeTCPPacket) register(c *net.TCPConn) error {
	if err := muteFakeTCP(c); err != nil {
		return err
	}
	zone := p.peer.Addr().Zone()
	if p.local.Zone != "" {
		zone = p.local.Zone
	}
	local, err := fakeTCPAddr(c.LocalAddr().(*net.TCPAddr), zone)
	if err != nil {
		return err
	}
	remote, err := fakeTCPAddr(c.RemoteAddr().(*net.TCPAddr), zone)
	if err != nil {
		return err
	}
	key := fakeTCPKey{local, remote}
	p.mu.Lock()
	defer p.mu.Unlock()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for p.flows[key] == nil || !p.flows[key].ready {
		changed := p.changed
		p.mu.Unlock()
		var err error
		select {
		case <-p.done:
			err = net.ErrClosed
		case <-timer.C:
			err = errors.New("HY1 FakeTCP handshake not captured")
		case <-changed:
		}
		p.mu.Lock()
		if err != nil {
			return err
		}
	}
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	flow := p.flows[key]
	flow.conn, flow.seen = c, time.Now()
	flow.window = uint16(geckoRandom(0x8000, 0xffff))
	flow.oob, flow.remote = fakeTCPPktinfo(key.local.Addr()), &net.IPAddr{IP: key.remote.Addr().AsSlice(), Zone: key.remote.Addr().Zone()}
	flow.addr = net.UDPAddrFromAddrPort(key.remote)
	p.peers[key.remote] = key
	return nil
}

func (p *fakeTCPPacket) accept() {
	for {
		c, err := p.listener.AcceptTCP()
		if err != nil {
			return
		}
		if err = p.register(c); err != nil {
			c.Close()
		}
	}
}

func (p *fakeTCPPacket) capture(raw *net.IPConn) {
	buffer, oob := make([]byte, 65535), make([]byte, 128)
	for {
		n, cn, flags, remote, err := raw.ReadMsgIP(buffer, oob)
		if err != nil {
			return
		}
		local, index, found := fakeTCPDestination(oob[:cn])
		segmentBytes := buffer[:n]
		if found && local.Is4() {
			ip, err := parseTunPacket(segmentBytes)
			if err != nil || ip.protocol != 6 {
				continue
			}
			segmentBytes = ip.data[ip.header:]
		}
		segment, ok := parseFakeTCP(segmentBytes)
		if !ok || !found || flags&syscall.MSG_TRUNC != 0 {
			continue
		}
		remoteIP, ok := netip.AddrFromSlice(remote.IP)
		if !ok {
			continue
		}
		if local.IsLinkLocalUnicast() {
			local = local.WithZone(strconv.FormatUint(uint64(index), 10))
		}
		if remoteIP.IsLinkLocalUnicast() {
			remoteIP = remoteIP.WithZone(strconv.FormatUint(uint64(index), 10))
		}
		p.mu.Lock()
		select {
		case <-p.done:
			p.mu.Unlock()
			return
		default:
		}
		port := uint16(0)
		if p.local != nil {
			port = uint16(p.local.Port)
		}
		if port != 0 && segment.destination != port {
			p.mu.Unlock()
			continue
		}
		key := fakeTCPKey{netip.AddrPortFrom(local.Unmap(), segment.destination), netip.AddrPortFrom(remoteIP.Unmap(), segment.source)}
		if p.peer.IsValid() && key.remote != p.peer {
			p.mu.Unlock()
			continue
		}
		flow := p.flows[key]
		if flow == nil && segment.flags&2 != 0 && len(p.flows) < fakeTCPMaxFlows {
			flow = &fakeTCPFlow{socket: raw}
			p.flows[key] = flow
		}
		if flow != nil {
			flow.seen = time.Now()
			if !flow.sent && segment.flags&0x10 != 0 {
				flow.sequence, flow.ready = segment.ack, true
				close(p.changed)
				p.changed = make(chan struct{})
			}
			if segment.flags&2 != 0 {
				flow.ack = segment.sequence + 1
			}
			if segment.flags&8 != 0 && segment.flags&0x10 != 0 && len(segment.payload) > 0 {
				if flow.ack == segment.sequence {
					flow.ack += uint32(len(segment.payload))
				}
				if flow.conn != nil && p.bytes+len(segment.payload) <= quicInboxBytes && len(p.queue) < cap(p.queue) {
					payload := append([]byte(nil), segment.payload...)
					p.queue <- fakeTCPDatagram{payload, flow.addr}
					p.bytes += len(payload)
				}
			}
		}
		p.mu.Unlock()
	}
}

func (p *fakeTCPPacket) expire() {
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-p.done:
			return
		case now := <-timer.C:
			p.mu.Lock()
			for key, flow := range p.flows {
				age := 10 * time.Second
				if flow.conn != nil {
					age = 2 * time.Minute
				}
				if now.Sub(flow.seen) > age {
					if flow.conn != nil {
						flow.conn.Close()
						delete(p.peers, key.remote)
					}
					delete(p.flows, key)
				}
			}
			p.mu.Unlock()
		}
	}
}

func (p *fakeTCPPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		p.mu.Lock()
		deadline := p.readBy
		p.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero() {
			if time.Until(deadline) <= 0 {
				return 0, nil, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			timeout = timer.C
		}
		select {
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return 0, nil, net.ErrClosed
		case <-timeout:
			return 0, nil, os.ErrDeadlineExceeded
		case <-p.wake:
			if timer != nil {
				timer.Stop()
			}
		case packet := <-p.queue:
			if timer != nil {
				timer.Stop()
			}
			p.mu.Lock()
			p.bytes -= len(packet.data)
			p.mu.Unlock()
			return copy(b, packet.data), packet.addr, nil
		}
	}
}

func (p *fakeTCPPacket) WriteTo(b []byte, remote net.Addr) (int, error) {
	addr, ok := remote.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("HY1 FakeTCP requires datagram peer address")
	}
	ip := addr.AddrPort()
	ip = netip.AddrPortFrom(ip.Addr().Unmap(), ip.Port())
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	p.mu.Lock()
	select {
	case <-p.done:
		p.mu.Unlock()
		return 0, net.ErrClosed
	default:
	}
	if !p.writeBy.IsZero() && !time.Now().Before(p.writeBy) {
		p.mu.Unlock()
		return 0, os.ErrDeadlineExceeded
	}
	key := p.peers[ip]
	flow := p.flows[key]
	if flow == nil {
		p.mu.Unlock()
		return 0, errors.New("HY1 FakeTCP peer is not connected")
	}
	sequence, ack, window := flow.sequence, flow.ack, flow.window
	flow.sent = true
	p.mu.Unlock()
	owner := packetBuffers.Get()
	defer packetBuffers.Put(owner)
	packet, err := encodeFakeTCP(owner.([]byte)[:0], key.local, key.remote, sequence, ack, window, b)
	if err != nil {
		return 0, err
	}
	n, _, err := flow.socket.WriteMsgIP(packet, flow.oob, flow.remote)
	if err != nil {
		return 0, err
	}
	if n != len(packet) {
		return 0, io.ErrShortWrite
	}
	p.mu.Lock()
	flow.window = 0x8000 | (flow.window+1)&0x7fff
	flow.sequence += uint32(len(b))
	flow.seen = time.Now()
	p.mu.Unlock()
	return len(b), nil
}

func (p *fakeTCPPacket) Close() error {
	p.once.Do(func() {
		close(p.done)
		if p.listener != nil {
			p.listener.Close()
		}
		for _, socket := range p.sockets {
			socket.Close()
		}
		p.mu.Lock()
		for _, flow := range p.flows {
			if flow.conn != nil {
				flow.conn.Close()
			}
		}
		clear(p.flows)
		clear(p.peers)
		p.mu.Unlock()
		p.wg.Wait()
	})
	return nil
}
func (p *fakeTCPPacket) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(p.local.AddrPort()) }
func (p *fakeTCPPacket) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.readBy = t
	p.mu.Unlock()
	signal(p.wake)
	return nil
}
func (p *fakeTCPPacket) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	p.writeBy = t
	p.mu.Unlock()
	for _, socket := range p.sockets {
		if err := socket.SetWriteDeadline(t); err != nil {
			return err
		}
	}
	return nil
}
func (p *fakeTCPPacket) SetDeadline(t time.Time) error {
	if err := p.SetWriteDeadline(t); err != nil {
		return err
	}
	return p.SetReadDeadline(t)
}

type fakeTCPConn struct {
	*fakeTCPPacket
	remote *net.UDPAddr
}

func (c *fakeTCPConn) RemoteAddr() net.Addr        { return c.remote }
func (c *fakeTCPConn) Read(b []byte) (int, error)  { n, _, err := c.ReadFrom(b); return n, err }
func (c *fakeTCPConn) Write(b []byte) (int, error) { return c.WriteTo(b, c.remote) }
