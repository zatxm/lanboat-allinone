package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"time"
)

var errTSSystemInterface = errors.New("Tailscale system interface failed")

type tsSystemState struct {
	at        time.Time
	initiated bool
}

type tsSystemFlow struct {
	tunFlowKey
	protocol byte
}
type tsSystemInterface struct {
	c         *tailscaleClient
	tun       *tunTunnel
	addresses []netip.Prefix
	mu        sync.Mutex
	flows     map[tsSystemFlow]tsSystemState
	jobs      sync.WaitGroup
	queue     chan []byte
}

func (c *tailscaleClient) systemPlan() (addresses []netip.Prefix, routes []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.self.Expired || !c.self.KeyExpiry.IsZero() && time.Now().After(c.self.KeyExpiry) {
		return nil, nil
	}
	addresses = slices.Clone(c.self.Addresses)
	// Keep offline tailnet destinations off the physical default route.
	for _, a := range addresses {
		if a.Addr().Is4() {
			routes = append(routes, "100.64.0.0/10")
			if c.o.ExitNode != "" {
				routes = append(routes, "0.0.0.0/0")
			}
		} else {
			routes = append(routes, "fd7a:115c:a1e0::/48")
			if c.o.ExitNode != "" {
				routes = append(routes, "::/0")
			}
		}
	}
	for _, n := range c.nodes {
		if n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) {
			continue
		}
		for _, p := range n.AllowedIPs {
			if p.Bits() == 0 {
				if tsExitNodeMatches(n, c.o.ExitNode) {
					routes = append(routes, p.String())
				}
			} else if c.o.AcceptRoutes {
				routes = append(routes, p.Masked().String())
			}
		}
	}
	slices.Sort(routes)
	return addresses, slices.Compact(routes)
}
func (c *tailscaleClient) syncSystemInterface() error {
	c.systemMu.Lock()
	defer c.systemMu.Unlock()
	if c.ctx.Err() != nil {
		return nil
	}
	addresses, routes := c.systemPlan()
	s := c.system.Load()
	if s != nil && !slices.Equal(s.addresses, addresses) {
		c.system.Store(nil)
		s.close()
		s = nil
	}
	if len(addresses) == 0 {
		return nil
	}
	if s == nil {
		name := c.o.SystemInterfaceName
		if name == "" && runtime.GOOS != "darwin" {
			name = "tailscale"
		}
		mtu := c.o.SystemInterfaceMTU
		if mtu == 0 {
			mtu = 1280
		}
		in := Inbound{endpointSystem: true, Type: "tun", Tag: c.o.Tag, InterfaceName: name, MTU: mtu, AutoRoute: true, DNSMode: "disabled", RouteAddress: routes}
		for _, a := range addresses {
			in.Address = append(in.Address, a.String())
		}

		if c.o.ExitNodeAllowLANAccess {
			for _, p := range c.localRoutes {
				in.RouteExcludeAddress = append(in.RouteExcludeAddress, p.String())
			}
		}
		t, e := openTUN(c.r, in)
		if e != nil {
			return fmt.Errorf("%w: %w", errTSSystemInterface, e)
		}
		t.ctx, t.cancel = context.WithCancel(c.ctx)
		s = &tsSystemInterface{c: c, tun: t, addresses: addresses, flows: map[tsSystemFlow]tsSystemState{}, queue: make(chan []byte, 64)}
		c.system.Store(s)
		s.jobs.Add(5)
		go func() { defer s.jobs.Done(); s.read() }()
		for range 4 {
			go func() { defer s.jobs.Done(); s.send() }()
		}
		return nil
	}
	s.tun.platformMu.Lock()
	defer s.tun.platformMu.Unlock()
	in := s.tun.in
	in.RouteAddress = routes
	if s.tun.routes != nil {
		if e := s.tun.routes.replace(s.tun.routePlan(in)); e != nil {
			return e
		}
	}
	return nil
}
func (s *tsSystemInterface) close() { s.tun.close(); s.jobs.Wait() }
func (s *tsSystemInterface) read() {
	b := make([]byte, 65575)
	for {
		n, e := s.tun.device.Read(b)
		if e != nil {
			return
		}
		packet := append([]byte(nil), b[:n]...)
		select {
		case s.queue <- packet:
		case <-s.tun.ctx.Done():
			return
		default:
		}
	}
}
func tsSystemKey(p tunPacket, reverse bool) (tsSystemFlow, bool) {
	segment := p.data[p.header:]
	key := tsSystemFlow{tunFlowKey: tunFlowKey{source: p.source, destination: p.destination}, protocol: p.protocol}
	switch p.protocol {
	case 6, 17:
		if len(segment) < 8 {
			return key, false
		}
		key.sport = binary.BigEndian.Uint16(segment)
		key.dport = binary.BigEndian.Uint16(segment[2:])
	case 1, 58:
		if len(segment) < 8 {
			return key, false
		}
		if p.protocol == 1 && segment[0] != 8 && segment[0] != 0 || p.protocol == 58 && segment[0] != 128 && segment[0] != 129 {
			return key, false
		}
		key.sport = binary.BigEndian.Uint16(segment[4:])
		key.dport = key.sport
	default:
		return key, false
	}
	if reverse {
		key.source, key.destination = key.destination, key.source
		key.sport, key.dport = key.dport, key.sport
	}
	return key, true
}
func (s *tsSystemInterface) send() {
	for {
		select {
		case <-s.tun.ctx.Done():
			return
		case b := <-s.queue:
			p, e := parseTunPacket(b)
			if e != nil {
				continue
			}
			if !slices.ContainsFunc(s.addresses, func(a netip.Prefix) bool { return a.Addr() == p.source }) {
				continue
			}
			n, e := s.c.choose(p.destination)
			if e != nil {
				continue
			}
			peer, e := s.c.peer(n)
			if e != nil {
				continue
			}
			ctx, cancel := context.WithTimeout(s.tun.ctx, 10*time.Second)
			e = peer.ensure(ctx)
			cancel()
			if e != nil {
				continue
			}
			s.trackOutbound(p)

			_ = tsSendIP(peer.wg, p.data)
		}
	}
}
func (s *tsSystemInterface) receive(p tunPacket) bool {
	if !slices.ContainsFunc(s.addresses, func(a netip.Prefix) bool { return a.Addr() == p.destination }) {
		return false
	}
	allowed := false
	key, ok := tsSystemKey(p, true)
	segment := p.data[p.header:]
	if (p.protocol == 1 || p.protocol == 58) && len(segment) >= 8 && icmpError(segment[0], p.protocol == 58) {
		if quote, e := parseICMPQuote(segment[8:]); e == nil && quote.source == p.destination {
			key, ok = tsSystemKey(quote, false)
		}
	}
	if ok {
		s.mu.Lock()
		state, exists := s.flows[key]
		allowed = exists && state.initiated && time.Since(state.at) < s.flowTimeout(p.protocol)
		if allowed {
			state.at = time.Now()
			s.flows[key] = state
		}
		s.mu.Unlock()
	}
	if !allowed {
		s.c.mu.Lock()
		allowed = slices.ContainsFunc(s.c.filter, func(f tsFilter) bool { return f.allows(p) })
		s.c.mu.Unlock()
	}
	if allowed {
		if key, ok := tsSystemKey(p, true); ok {
			s.mu.Lock()
			if _, exists := s.flows[key]; !exists && len(s.flows) < 4096 {
				s.flows[key] = tsSystemState{at: time.Now()}
			}
			s.mu.Unlock()
		}
		_ = s.tun.writePacket(p.data)
	}
	return true
}

func (s *tsSystemInterface) flowTimeout(protocol byte) time.Duration {
	if protocol == 17 {
		d, _ := optionDuration(s.c.o.UDPTimeout, 5*time.Minute)
		return d
	}
	return 5 * time.Minute
}
func (s *tsSystemInterface) trackOutbound(p tunPacket) {
	key, ok := tsSystemKey(p, false)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	state, exists := s.flows[key]
	if exists && now.Sub(state.at) > s.flowTimeout(p.protocol) {
		delete(s.flows, key)
		exists = false
	}
	if !exists {
		segment := p.data[p.header:]
		if p.protocol == 6 && (len(segment) < 20 || segment[13]&0x12 != 2) {
			return
		}
		if p.protocol == 1 && segment[0] != 8 || p.protocol == 58 && segment[0] != 128 {
			return
		}
		state.initiated = true
	}
	if len(s.flows) >= 4096 {
		for k, v := range s.flows {
			if now.Sub(v.at) > s.flowTimeout(k.protocol) {
				delete(s.flows, k)
			}
		}
	}
	if exists || len(s.flows) < 4096 {
		state.at = now
		s.flows[key] = state
	}
}
