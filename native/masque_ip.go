package native

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type masqueAssignment struct {
	id     uint64
	prefix netip.Prefix
}
type masqueRoute struct {
	first, last netip.Addr
	protocol    byte
}

func masqueAddresses(b []byte, request bool) ([]masqueAssignment, error) {
	r := quicReader(b)
	var out []masqueAssignment
	seen := map[uint64]bool{}
	for len(r) > 0 {
		if len(out) >= 128 {
			return nil, errors.New("MASQUE address capacity exceeded")
		}
		id, e := r.v()
		if e != nil || request && (id == 0 || seen[id]) {
			return nil, errors.New("invalid MASQUE address request ID")
		}
		seen[id] = true
		version, e := r.take(1)
		if e != nil {
			return nil, e
		}
		size := 4
		if version[0] == 6 {
			size = 16
		} else if version[0] != 4 {
			return nil, errors.New("invalid MASQUE address family")
		}
		raw, e := r.take(uint64(size + 1))
		if e != nil {
			return nil, e
		}
		a, _ := netip.AddrFromSlice(raw[:size])
		bits := int(raw[size])
		if bits > a.BitLen() {
			return nil, errors.New("invalid MASQUE prefix length")
		}
		p := netip.PrefixFrom(a, bits)
		if p != p.Masked() {
			return nil, errors.New("noncanonical MASQUE assigned prefix")
		}
		out = append(out, masqueAssignment{id, p})
	}
	if request && len(out) == 0 {
		return nil, errors.New("empty MASQUE address request")
	}
	return out, nil
}
func masqueAddressBytes(entries []masqueAssignment) []byte {
	var b []byte
	for _, a := range entries {
		b = quicVar(b, a.id)
		v := byte(4)
		if a.prefix.Addr().Is6() {
			v = 6
		}
		b = append(b, v)
		b = append(b, a.prefix.Addr().AsSlice()...)
		b = append(b, byte(a.prefix.Bits()))
	}
	return b
}
func masqueRoutes(b []byte) ([]masqueRoute, error) {
	var routes []masqueRoute
	r := quicReader(b)
	for len(r) > 0 {
		if len(routes) >= 128 {
			return nil, errors.New("MASQUE route capacity exceeded")
		}
		version, e := r.take(1)
		if e != nil {
			return nil, e
		}
		size := 4
		if version[0] == 6 {
			size = 16
		} else if version[0] != 4 {
			return nil, errors.New("invalid MASQUE route family")
		}
		b, e := r.take(uint64(size*2 + 1))
		if e != nil {
			return nil, e
		}
		first, _ := netip.AddrFromSlice(b[:size])
		last, _ := netip.AddrFromSlice(b[size : size*2])
		v := masqueRoute{first, last, b[size*2]}
		if first.Compare(last) > 0 {
			return nil, errors.New("reversed MASQUE route")
		}
		if n := len(routes); n > 0 {
			p := routes[n-1]
			if p.first.BitLen() > first.BitLen() || p.first.BitLen() == first.BitLen() && (p.protocol > v.protocol || p.protocol == v.protocol && p.last.Compare(first) >= 0) {
				return nil, errors.New("unordered MASQUE routes")
			}
		}
		routes = append(routes, v)
	}
	return routes, nil
}

type masqueIP struct {
	system                     atomic.Pointer[masqueSystemInterface]
	systemMu                   sync.Mutex
	systemOutputMu             sync.Mutex
	systemQueue                chan []byte
	systemQueued               int
	systemOutputStarted        bool
	systemOutputClosed         bool
	client                     *masqueClient
	acceptDNS, acceptPREF64    bool
	networkServer              *masqueNetworkServer
	configuration              MasqueNetworkConfiguration
	configurationChanged       chan struct{}
	dnsResolvers               map[string]*masqueDNSResolver
	dnsCacheEpoch              string
	runtime                    *Runtime
	flow                       *masqueFlow
	stack                      *wgIPStack
	server                     bool
	mu                         sync.Mutex
	local                      []netip.Addr
	configured                 []netip.Prefix
	assigned                   []masqueAssignment
	requested                  map[uint64]bool
	routes                     []masqueRoute
	permitted                  []netip.Prefix
	advertised                 []netip.Prefix
	scope                      masqueScope
	haveRoutes, haveAssignment bool
	ready                      chan struct{}
	readyOnce                  sync.Once
	packetID                   atomic.Uint32
	pathGate                   chan struct{}
	pathProbe                  *masqueMTUProbe
}

func newMasqueIP(r *Runtime, f *masqueFlow, inbound string, server bool, mtu int, assigned, local []string, user string, advertised []netip.Prefix, nat ...*masqueNAT) *masqueIP {
	if mtu == 0 {
		mtu = 1280
	}
	p := &masqueIP{runtime: r, flow: f, server: server, advertised: advertised, ready: make(chan struct{}), requested: map[uint64]bool{}, scope: masqueScope{protocol: 256}, configurationChanged: make(chan struct{}), dnsCacheEpoch: newMasqueCacheEpoch()}
	if p.server {
		if len(assigned) == 0 {
			assigned = []string{"10.44.0.2/32", "fd44::2/128"}
		}
		for _, v := range assigned {
			a, _ := netip.ParsePrefix(v)
			p.assigned = append(p.assigned, masqueAssignment{prefix: a})
		}
		p.haveAssignment = true
	}
	for _, v := range local {
		a, _ := netip.ParsePrefix(v)
		p.configured = append(p.configured, a)
		p.local = append(p.local, a.Addr())
	}
	endpoint := &ipEndpoint{runtime: r, inbound: inbound, mtu: mtu, done: f.done, sendIP: p.writePacket, ensure: func(context.Context) error {
		if f.isClosed() {
			return net.ErrClosed
		}
		return nil
	}, localAddresses: p.addresses, authUser: user}
	// Existing replies are matched first; only new inbound flows reach this check.
	endpoint.acceptPacket = func(packet tunPacket) bool {
		if p.server {
			return p.permits(packet.destination) && p.scope.allowsProtocol(packet.protocol)
		}
		return p.advertises(packet.destination)
	}
	if len(nat) != 0 {
		endpoint.nat = nat[0]
	}
	p.stack = newIPStack(endpoint)
	f.ipConfiguration = p
	f.control = p.control
	return p
}
func (p *masqueIP) addresses() []netip.Addr { p.mu.Lock(); defer p.mu.Unlock(); return p.local }
func (p *masqueIP) start() {
	m := p.flow.session
	m.goWork(func() { _ = p.flow.readCapsules() })
	m.goWork(func() {
		defer p.closeSystem()
		defer p.stack.close()
		defer p.flow.Close()
		b := make([]byte, 65535)
		for {
			n, reliable, e := p.flow.readPacket(b)
			if e != nil {
				return
			}
			packet, e := parseTunPacket(b[:n])
			if e != nil {
				continue
			}
			if p.linkPacket(packet, reliable) {
				continue
			}
			if p.server && !p.allowed(packet.source) {
				continue
			}
			if s := p.system.Load(); p.server && s != nil && !s.server.systemSource(p, packet.source) {
				continue
			}
			if p.server && !p.permits(packet.destination) && !slices.Contains(p.addresses(), packet.destination) {
				continue
			}
			if !p.server && !slices.Contains(p.addresses(), packet.destination) && !p.advertises(packet.destination) {
				continue
			}
			p.stack.input(packet)
		}
	})
	m.goWork(func() {
		defer p.closeDNSResolvers()
		defer p.unregisterConfiguration()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case now := <-tick.C:
				p.stack.expire(now)
			case <-p.flow.done:
				return
			}
		}
	})
}
func (p *masqueIP) waitAddress(ctx context.Context) error {
	select {
	case <-p.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-p.flow.done:
		return net.ErrClosed
	}
}
func (p *masqueIP) requestAddresses() error {
	v := []masqueAssignment{{1, netip.MustParsePrefix("0.0.0.0/32")}, {2, netip.MustParsePrefix("::/128")}}
	return p.flow.capsule(2, masqueAddressBytes(v))
}
func (p *masqueIP) allowed(ip netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.haveAssignment {
		return true
	}
	for _, a := range p.assigned {
		if !a.prefix.Addr().IsUnspecified() && a.prefix.Contains(ip) {
			return true
		}
	}
	if p.server {
		for _, route := range p.routes {
			if masqueRouteContains(route, ip, 0) {
				return true
			}
		}
	} else if p.advertises(ip) {
		return true
	}
	return false
}
func (p *masqueIP) advertises(ip netip.Addr) bool {
	return slices.ContainsFunc(p.advertised, func(prefix netip.Prefix) bool { return prefix.Contains(ip) })
}

func masqueRouteContains(route masqueRoute, ip netip.Addr, protocol byte) bool {
	return ip.BitLen() == route.first.BitLen() && ip.Compare(route.first) >= 0 && ip.Compare(route.last) <= 0 && (protocol == 0 || route.protocol == 0 || route.protocol == protocol || protocol == 1 || protocol == 58)
}
func (p *masqueIP) permits(ip netip.Addr) bool {
	if len(p.permitted) == 0 {
		return true
	}
	for _, prefix := range p.permitted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func (p *masqueIP) writePacket(b []byte) error {
	packet, e := parseTunPacket(b)
	if e != nil {
		return e
	}
	if p.server {
		if !p.allowed(packet.destination) {
			return ErrRejected
		}
		if !p.scope.allowsProtocol(packet.protocol) {
			return ErrRejected
		}
	} else {
		// Addresses can arrive before route policy; do not forward in that gap.
		select {
		case <-p.ready:
		default:
			return ErrRejected
		}
		if !p.allowed(packet.source) {
			return ErrRejected
		}
		p.mu.Lock()
		routes, check := p.routes, p.haveRoutes
		p.mu.Unlock()
		if check && !p.advertises(packet.source) {
			match := false
			for _, route := range routes {
				if masqueRouteContains(route, packet.destination, packet.protocol) {
					match = true
					break
				}
			}
			if !match {
				return ErrRejected
			}
		}
	}
	// Keep fragments of one large packet on the same transport; mixing reliable
	// capsules with a short final QUIC datagram needlessly loses whole UDP packets.
	return writeIPFragments(b, p.stack.peer.mtu, p.packetID.Add(1), func(data []byte) error {
		_, e := p.flow.writeDatagram(data, len(b)+9 > p.flow.session.datagramLimit())
		return e
	})
}
func (p *masqueIP) advertise() error {
	p.mu.Lock()
	assigned := append([]masqueAssignment{}, p.assigned...)
	p.mu.Unlock()
	if e := p.flow.capsule(1, masqueAddressBytes(assigned)); e != nil {
		return e
	}
	prefixes := p.permitted
	if len(prefixes) == 0 {
		prefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	return p.advertiseRoutes(prefixes, p.scope.protocol)
}
func (p *masqueIP) advertiseClient() error {
	if len(p.advertised) == 0 {
		return nil
	}
	return p.advertiseRoutes(p.advertised, 256)
}
func (p *masqueIP) advertiseRoutes(prefixes []netip.Prefix, protocolNumber uint16) error {
	ranges := make([]masqueRoute, 0, len(prefixes))
	for _, prefix := range prefixes {
		ranges = append(ranges, masqueRoute{first: prefix.Masked().Addr(), last: prefixLast(prefix)})
	}
	slices.SortFunc(ranges, func(a, b masqueRoute) int {
		if a.first.BitLen() != b.first.BitLen() {
			return a.first.BitLen() - b.first.BitLen()
		}
		return a.first.Compare(b.first)
	})
	merged := ranges[:0]
	for _, item := range ranges {
		if n := len(merged); n > 0 && merged[n-1].first.BitLen() == item.first.BitLen() && item.first.Compare(merged[n-1].last) <= 0 {
			if item.last.Compare(merged[n-1].last) > 0 {
				merged[n-1].last = item.last
			}
		} else {
			merged = append(merged, item)
		}
	}
	var routes []byte
	for _, item := range merged {
		version := byte(4)
		if item.first.Is6() {
			version = 6
		}
		routes = append(routes, version)
		routes = append(routes, item.first.AsSlice()...)
		routes = append(routes, item.last.AsSlice()...)
		protocol := byte(0)
		if protocolNumber < 256 {
			protocol = byte(protocolNumber)
		}
		routes = append(routes, protocol)
	}
	if err := p.flow.capsule(3, routes); err != nil {
		return err
	}
	// Route advertisements must precede DNS configuration to prevent DNS leaks.
	if p.networkServer != nil {
		return p.registerConfiguration()
	}
	return nil
}
func (p *masqueIP) control(kind uint64, b []byte) error {
	switch kind {
	case masqueDNSAssign, masquePREF64:
		return p.configureNetwork(kind, b)
	case 1:
		entries, e := masqueAddresses(b, false)
		if e != nil {
			return e
		}
		if p.server {
			return nil
		}
		var local []netip.Addr
		for _, a := range entries {
			if a.prefix.Addr().IsUnspecified() {
				continue
			}
			if len(p.configured) == 0 {
				local = append(local, a.prefix.Addr())
			} else {
				for _, want := range p.configured {
					if a.prefix.Contains(want.Addr()) {
						local = append(local, want.Addr())
					}
				}
			}
		}
		p.mu.Lock()
		p.assigned, p.local, p.haveAssignment = entries, local, true
		ready := len(local) > 0 && p.haveRoutes
		p.mu.Unlock()
		// A changed assignment invalidates the old kernel address immediately.
		// Reconnect negotiates a fresh interface; no stale address remains usable.
		if s := p.system.Load(); s != nil && !slices.Equal(s.addresses, local) {
			p.flow.Close()
			return nil
		}
		if ready {
			p.readyOnce.Do(func() { close(p.ready) })
		}
		return nil
	case 2:
		requests, e := masqueAddresses(b, true)
		if e != nil {
			return e
		}
		if !p.server {
			return errors.New("MASQUE client cannot assign addresses")
		}
		p.mu.Lock()
		var assigned []masqueAssignment
		for _, q := range requests {
			if p.requested[q.id] || len(p.requested) >= 128 {
				p.mu.Unlock()
				return errors.New("MASQUE reused address request ID")
			}
			p.requested[q.id] = true
			var chosen netip.Prefix
			for _, a := range p.assigned {
				if a.prefix.Addr().BitLen() == q.prefix.Addr().BitLen() {
					chosen = a.prefix
					break
				}
			}
			if !chosen.IsValid() {
				chosen = netip.PrefixFrom(q.prefix.Addr().Unmap(), q.prefix.Addr().BitLen())
				if chosen.Addr().Is4() {
					chosen = netip.MustParsePrefix("0.0.0.0/32")
				} else {
					chosen = netip.MustParsePrefix("::/128")
				}
			}
			assigned = append(assigned, masqueAssignment{q.id, chosen})
		}
		for _, a := range p.assigned {
			present := false
			for _, v := range assigned {
				if v.prefix == a.prefix {
					present = true
					break
				}
			}
			if !present {
				assigned = append(assigned, a)
			}
		}
		p.mu.Unlock()
		return p.flow.capsule(1, masqueAddressBytes(assigned))
	case 3:
		routes, e := masqueRoutes(b)
		if e != nil {
			return e
		}
		p.mu.Lock()
		p.routes, p.haveRoutes = routes, true
		ready := !p.server && len(p.local) > 0
		p.mu.Unlock()
		if ready {
			p.readyOnce.Do(func() { close(p.ready) })
		}
		return nil
	}
	return nil
}
