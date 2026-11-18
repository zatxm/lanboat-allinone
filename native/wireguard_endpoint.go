package native

import (
	"context"
	"crypto/ecdh"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type wgEndpointOptions struct {
	DialOptions
	masqueNATOptions
	Type           string            `json:"type"`
	Tag            string            `json:"tag"`
	System         bool              `json:"system,omitempty"`
	Name           string            `json:"name,omitempty"`
	MTU            int               `json:"mtu,omitempty"`
	Address        []string          `json:"address"`
	PrivateKey     keyLines          `json:"private_key"`
	ListenPort     uint16            `json:"listen_port,omitempty"`
	Peers          []WireGuardPeer   `json:"peers"`
	Workers        int               `json:"workers,omitempty"`
	OnDemand       bool              `json:"on_demand,omitempty"`
	Detour         string            `json:"detour,omitempty"`
	DomainResolver resolverReference `json:"domain_resolver,omitempty"`
}

func (o wgEndpointOptions) validate() error {
	if o.Workers < 0 || o.Workers > 256 {
		return errors.New("WireGuard workers must be0-256")
	}
	// Leave room for the authenticated header and 16-byte padding in one UDP datagram.
	if o.MTU != 0 && (o.MTU < 1280 || o.MTU > 65472) {
		return errors.New("WireGuard endpoint MTU must be1280-65472")
	}
	if len(o.Address) == 0 || len(o.Address) > 64 {
		return errors.New("WireGuard endpoint requires1-64 interface addresses")
	}
	for _, text := range o.Address {
		p, err := netip.ParsePrefix(text)
		if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" || !p.Addr().IsGlobalUnicast() {
			return errors.New("invalid WireGuard endpoint address")
		}
	}
	if !o.System && o.Name != "" {
		return errors.New("WireGuard name requires system")
	}
	if o.System {
		if err := validateTUNPlatform(Inbound{InterfaceName: o.Name}); err != nil {
			return err
		}
	}
	if _, err := o.masqueNATOptions.settings(); err != nil {
		return err
	}
	peers := make([]WireGuardPeer, len(o.Peers))
	for i, p := range o.Peers {
		if p.Address == "" && p.Port != 0 || p.Address != "" && (p.Port == 0 || strings.ContainsAny(p.Address, "/?#@\x00\r\n\t ")) {
			return errors.New("WireGuard peer requires both address and port, or neither for a passive peer")
		}
		if p.Address != "" {
			ip, err := netip.ParseAddr(p.Address)
			if err == nil && (ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6()) || err != nil && !masqueDomain(strings.TrimSuffix(p.Address, "."), false) {
				return errors.New("invalid WireGuard peer address")
			}
		}
		if p.PersistentKeepaliveInterval < 0 || p.PersistentKeepaliveInterval > 65535 || len(p.Reserved) != 0 && len(p.Reserved) != 3 {
			return errors.New("invalid WireGuard peer keepalive or reserved bytes")
		}
		for _, text := range p.AllowedIPs {
			prefix, err := netip.ParsePrefix(text)
			if err != nil || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
				return errors.New("invalid WireGuard allowed_ips")
			}
		}
		peers[i] = WireGuardPeer{PublicKey: p.PublicKey, PreSharedKey: p.PreSharedKey, AllowedIPs: p.AllowedIPs}
	}
	return (WireGuardOptions{Peers: peers}).validate(o.PrivateKey, true, o.MTU)
}

type wgEndpoint struct {
	r          *Runtime
	o          wgEndpointOptions
	mu         sync.Mutex
	transition sync.Mutex
	resetting  bool
	current    *wgEndpointSession
	closed     bool
}

type wgEndpointSession struct {
	endpoint *wgEndpoint
	ctx      context.Context
	cancel   context.CancelFunc
	listener *wgListener
	packets  [2]*net.UDPConn
	peers    []*wgEndpointPeer
	nat      *masqueNAT
	system   *tunTunnel
	jobs     chan wgEndpointPacket
	output   chan wgEndpointOutput
	workers  sync.WaitGroup
	once     sync.Once
}

type wgEndpointPeer struct {
	peer       *wgPeer
	options    WireGuardPeer
	netMu      sync.Mutex
	resolved   *net.UDPAddr
	conn       net.Conn
	connTarget string
}

type wgEndpointPacket struct {
	data   []byte
	remote net.Addr
}

var wgEndpointBuffers = sync.Pool{New: func() any { return make([]byte, 2048) }}

func releaseWGEndpointPacket(b []byte) {
	if cap(b) == 2048 {
		wgEndpointBuffers.Put(b[:2048])
	} else {
		packetBuffers.Put(b[:cap(b)])
	}
}

type wgEndpointOutput struct {
	peer *wgPeer
	data []byte
}

func (e *wgEndpoint) session(ctx context.Context) (*wgEndpointSession, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if e.closed || e.resetting || e.r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if s := e.current; s != nil {
		if s.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		return s, nil
	}
	s := &wgEndpointSession{endpoint: e}
	s.ctx, s.cancel = context.WithCancel(e.r.ctx)
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	workers := e.o.Workers
	if workers == 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	s.jobs = make(chan wgEndpointPacket, 64)
	nat, _ := e.o.masqueNATOptions.settings()
	s.nat = newMasqueNAT(e.r, nat)
	port := e.o.ListenPort
	for i, host := range []string{"0.0.0.0", "::"} {
		network := "udp4"
		if i == 1 {
			network = "udp6"
		}
		pc, err := e.r.listenPacketWithOptions(s.ctx, e.o.DialOptions, network, portAddress(host, port), portAddress(host, 0))
		if err != nil {
			if i == 1 && e.o.Inet6BindAddress == "" && !slices.ContainsFunc(e.o.Address, func(text string) bool { p, _ := netip.ParsePrefix(text); return p.Addr().Is6() }) && !slices.ContainsFunc(e.o.Peers, func(p WireGuardPeer) bool { ip, _ := netip.ParseAddr(p.Address); return ip.Is6() }) && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)) {
				continue
			}
			return nil, err
		}
		s.packets[i] = pc.(*net.UDPConn)
		if err := s.packets[i].SetReadBuffer(1 << 20); err != nil {
			return nil, err
		}
		if i == 0 && port == 0 {
			port = uint16(s.packets[0].LocalAddr().(*net.UDPAddr).Port)
		}
	}
	key, _ := wgKey(strings.Join(e.o.PrivateKey, ""))
	private, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	s.listener = &wgListener{runtime: e.r, private: private, packet: s.packets[0], reservedHeader: true, done: make(chan struct{}), writer: s.writeCookie}
	mtu := e.o.MTU
	if mtu == 0 {
		mtu = 1408
	}
	for _, cfg := range e.o.Peers {
		p, err := newWGPeer(e.r, e.o.PrivateKey, cfg.PublicKey, cfg.PreSharedKey, e.o.Address, cfg.AllowedIPs, e.o.Tag, mtu, cfg.PersistentKeepaliveInterval, func(o *ipEndpoint) { o.nat = s.nat; o.udpIdleTimeout = nat.timeout })
		if err != nil {
			return nil, err
		}
		copy(p.reserved[:], cfg.Reserved)
		state := &wgEndpointPeer{peer: p, options: cfg}
		p.sender = func(b []byte, a net.Addr) error { return s.sendPeer(state, b, a) }
		p.ownsSource = func(ip netip.Addr) bool { return s.peerFor(ip) == p }
		s.peers = append(s.peers, state)
		s.listener.peers = append(s.listener.peers, p)
	}
	if e.o.System {
		name := e.o.Name
		if name != "" {
			if _, err := net.InterfaceByName(name); err == nil {
				return nil, errors.New("WireGuard system interface already exists")
			}
		}
		if name == "" && runtime.GOOS == "linux" {
			name = "wg%d"
		}
		s.system, err = openTUN(e.r, Inbound{Type: "tun", Tag: e.o.Tag, InterfaceName: name, Address: e.o.Address, MTU: mtu, DNSMode: "disabled", exclusiveTUN: true})
		if err != nil {
			return nil, fmt.Errorf("WireGuard system interface: %w", err)
		}
		s.system.ctx, s.system.cancel = context.WithCancel(s.ctx)
		for _, state := range s.peers {
			state.peer.stack.peer.reservePort = reserveSystemPort
			state.peer.stack.peer.rawInput = func(p tunPacket) bool { _ = s.system.writePacket(p.data); return true }
		}
		s.output = make(chan wgEndpointOutput, 64)
		for range min(4, workers) {
			s.workers.Go(s.sendSystem)
		}
		s.workers.Go(s.readSystem)
	}
	for range workers {
		s.workers.Go(s.handlePackets)
	}
	for _, pc := range s.packets {
		if pc != nil {
			s.workers.Go(func() { s.readPackets(pc) })
		}
	}
	for _, state := range s.peers {
		s.workers.Go(state.peer.maintain)
	}
	e.current = s
	ok = true
	context.AfterFunc(s.ctx, func() {
		s.close()
		e.mu.Lock()
		if e.current == s {
			e.current = nil
		}
		e.mu.Unlock()
	})
	return s, nil
}

func (s *wgEndpointSession) peerFor(ip netip.Addr) *wgPeer {
	var result *wgPeer
	bits := -1
	for _, state := range s.peers {
		for _, prefix := range state.peer.allowed {
			if prefix.Contains(ip) && prefix.Bits() >= bits {
				result = state.peer
				bits = prefix.Bits()
			}
		}
	}
	return result
}

func (s *wgEndpointSession) writePacket(b []byte, a net.Addr) error {
	if s.ctx.Err() != nil {
		return net.ErrClosed
	}
	if a == nil {
		return errors.New("WireGuard passive peer has no learned endpoint")
	}
	remote, ok := a.(*net.UDPAddr)
	if !ok {
		ip, err := netip.ParseAddrPort(a.String())
		if err != nil {
			return err
		}
		remote = net.UDPAddrFromAddrPort(ip)
	}
	i := 0
	if remote.IP.To4() == nil {
		i = 1
	}
	pc := s.packets[i]
	if pc == nil {
		return errors.New("WireGuard peer address family is unavailable")
	}
	_, err := pc.WriteToUDP(b, remote)
	return err
}

func (s *wgEndpointSession) sendPeer(p *wgEndpointPeer, b []byte, a net.Addr) error {
	conn, remote, err := s.peerTransport(p, a)
	if err != nil {
		return err
	}
	if conn == nil {
		return s.writePacket(b, remote)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	_, err = conn.Write(b)
	return err
}

func (s *wgEndpointSession) writeCookie(b []byte, a net.Addr) error {
	if s.endpoint.o.Detour == "" {
		return s.writePacket(b, a)
	}
	for _, p := range s.peers {
		p.netMu.Lock()
		conn := p.conn
		if a == nil || p.connTarget != a.String() {
			conn = nil
		}
		p.netMu.Unlock()
		if conn != nil {
			if err := conn.SetWriteDeadline(time.Now().Add(handshakeTimeout)); err != nil {
				return err
			}
			_, err := conn.Write(b)
			return err
		}
	}
	return errors.New("WireGuard cookie has no established detour transport")
}

func (s *wgEndpointSession) peerTransport(p *wgEndpointPeer, a net.Addr) (net.Conn, net.Addr, error) {
	if s.ctx.Err() != nil {
		return nil, nil, net.ErrClosed
	}
	p.netMu.Lock()
	defer p.netMu.Unlock()
	if a == nil {
		if p.resolved == nil {
			if p.options.Address == "" {
				return nil, nil, errors.New("WireGuard passive peer has no learned endpoint")
			}
			ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
			defer cancel()
			ref := s.endpoint.o.DomainResolver
			if ref != "" {
				var release context.CancelFunc
				ctx, release = ref.apply(ctx)
				defer release()
				ctx = context.WithValue(ctx, dnsBootstrapKey{}, ref.tag())
			} else {
				ctx = context.WithValue(ctx, dnsBootstrapKey{}, "@local")
			}
			ips, err := s.endpoint.r.directIPs(ctx, p.options.Address)
			if err != nil {
				return nil, nil, err
			}
			for _, ip := range ips {
				if ip.Is4() && s.packets[0] != nil || ip.Is6() && s.packets[1] != nil {
					p.resolved = net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, p.options.Port))
					break
				}
			}
			if p.resolved == nil {
				return nil, nil, errors.New("WireGuard peer has no usable address")
			}
		}
		a = p.resolved
	}
	if s.endpoint.o.Detour == "" {
		return nil, a, nil
	}
	if p.conn == nil || p.connTarget != a.String() {
		if p.conn != nil {
			p.conn.Close()
			p.conn = nil
		}
		host, port, err := net.SplitHostPort(a.String())
		if err != nil {
			return nil, nil, err
		}
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, nil, err
		}
		out := Outbound{Server: host, ServerPort: uint16(number), Detour: s.endpoint.o.Detour, DialOptions: s.endpoint.o.DialOptions, DomainResolver: s.endpoint.o.DomainResolver}
		call, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
		defer cancel()
		conn, err := s.endpoint.r.endpoint(call, out, "udp")
		if err != nil {
			return nil, nil, err
		}
		if s.ctx.Err() != nil {
			conn.Close()
			return nil, nil, net.ErrClosed
		}
		p.conn, p.connTarget = conn, a.String()
		s.workers.Go(func() { s.readDetour(p, conn, a) })
	}
	return p.conn, a, nil
}
func (s *wgEndpointSession) queuePacket(b []byte, a net.Addr) {
	var buffer []byte
	if len(b) <= 2048 {
		buffer = wgEndpointBuffers.Get().([]byte)
	} else {
		buffer = packetBuffers.Get().([]byte)
	}
	copy(buffer, b)
	select {
	case s.jobs <- wgEndpointPacket{buffer[:len(b)], a}:
	case <-s.ctx.Done():
		releaseWGEndpointPacket(buffer)
	default:
		releaseWGEndpointPacket(buffer)
	}
}

func (s *wgEndpointSession) readPackets(pc *net.UDPConn) {
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		n, remote, err := pc.ReadFromUDP(buffer)
		if err != nil {
			s.cancel()
			return
		}
		s.queuePacket(buffer[:n], remote)
	}
}

func (s *wgEndpointSession) readDetour(p *wgEndpointPeer, conn net.Conn, remote net.Addr) {
	defer conn.Close()
	defer func() {
		p.netMu.Lock()
		if p.conn == conn {
			p.conn = nil
		}
		p.netMu.Unlock()
	}()
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		s.queuePacket(buffer[:n], remote)
	}
}

func (s *wgEndpointSession) handlePackets() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.jobs:
			s.listener.handleDatagram(job.data, job.remote)
			releaseWGEndpointPacket(job.data)
		}
	}
}

func (s *wgEndpointSession) readSystem() {
	buffer := make([]byte, 65575)
	for {
		n, err := s.system.device.Read(buffer)
		if err != nil {
			s.cancel()
			return
		}
		packet, err := parseTunPacket(buffer[:n])
		if err != nil {
			continue
		}
		p := s.peerFor(packet.destination)
		if p == nil {
			continue
		}
		if len(s.output) == cap(s.output) {
			continue
		}
		select {
		case s.output <- wgEndpointOutput{p, slices.Clone(packet.data)}:
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *wgEndpointSession) sendSystem() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case packet := <-s.output:
			ctx, cancel := context.WithTimeout(s.ctx, handshakeTimeout)
			if packet.peer.ensure(ctx) == nil {
				_ = packet.peer.sendIP(packet.data)
			}
			cancel()
		}
	}
}

func (s *wgEndpointSession) close() {
	s.once.Do(func() {
		s.cancel()
		for _, pc := range s.packets {
			if pc != nil {
				pc.Close()
			}
		}
		for _, state := range s.peers {
			state.netMu.Lock()
			if state.conn != nil {
				state.conn.Close()
			}
			state.netMu.Unlock()
		}
		if s.listener != nil {
			s.listener.close()
		}
		if s.system != nil {
			s.system.close()
		}
		s.workers.Wait()
		if s.jobs != nil {
			for len(s.jobs) > 0 {
				job := <-s.jobs
				releaseWGEndpointPacket(job.data)
			}
		}

	})
}

func (e *wgEndpoint) close() {
	e.transition.Lock()
	defer e.transition.Unlock()
	e.mu.Lock()
	e.closed = true
	s := e.current
	e.current = nil
	e.mu.Unlock()
	if s != nil {
		s.close()
	}
}
func (e *wgEndpoint) reset(restart bool) {
	e.transition.Lock()
	defer e.transition.Unlock()
	e.mu.Lock()
	e.resetting = true
	s := e.current
	e.current = nil
	e.mu.Unlock()
	if s != nil {
		s.close()
	}
	e.mu.Lock()
	e.resetting = false
	e.mu.Unlock()
	if restart && !e.o.OnDemand && e.r.ctx.Err() == nil {
		if _, err := e.session(e.r.ctx); err != nil {
			logWarn(e.r.logger, err, e.r.outboundLabel(e.o.Tag), ": restart")
		}
	}
}

func (e *wgEndpoint) peer(ctx context.Context, ip netip.Addr) (*wgPeer, error) {
	s, err := e.session(ctx)
	if err != nil {
		return nil, err
	}
	p := s.peerFor(ip)
	if p == nil {
		return nil, errors.New("WireGuard endpoint has no peer for destination")
	}
	return p, nil
}

func (e *wgEndpoint) dial(ctx context.Context, network, address string) (net.Conn, error) {
	s, err := e.session(ctx)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := e.r.directIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	last := errors.New("WireGuard endpoint has no peer for resolved destination")
	for _, ip := range ips {
		p := s.peerFor(ip)
		if p == nil {
			continue
		}
		if err := p.ensure(ctx); err != nil {
			last = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		conn, err := p.stack.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return e.r.own(conn)
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}

func (r *Runtime) wireGuardSession(ctx context.Context, tag string, ip netip.Addr) (*wgPeer, error) {
	if e := r.wgEndpoints[tag]; e != nil {
		return e.peer(ctx, ip)
	}
	return r.wgClients[tag].session(ctx)
}

// DisconnectWireGuard releases an on-demand endpoint; a later Dial recreates it.
func (r *Runtime) DisconnectWireGuard(tag string) error {
	e := r.wgEndpoints[tag]
	if r.ctx.Err() != nil || e == nil || !e.o.OnDemand {
		return errors.New("disconnect requires an on_demand WireGuard endpoint")
	}
	e.reset(false)
	return nil
}
