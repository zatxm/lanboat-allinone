package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

func (s *wgIPStack) forwardICMP(p tunPacket) {
	ctx, cancel := context.WithTimeout(s.peer.runtime.ctx, 3*time.Second)
	defer cancel()
	q := request{network: "icmp", inbound: s.peer.inbound, address: net.JoinHostPort(p.destination.String(), "0"), source: net.JoinHostPort(p.source.String(), "0"), payload: p.data[p.header:], metadata: Metadata{Protocol: "icmp", AuthUser: s.peer.authUser}}
	q, tag, e := s.peer.runtime.routeTarget(ctx, q)
	if errors.Is(e, ErrDropped) {
		return
	}
	if errors.Is(e, errICMPReply) {
		s.echoICMP(p, p.data[p.header:])
		return
	}
	if e != nil {
		s.sendICMPError(p, false, false)
		return
	}
	for range 32 {
		group := s.peer.runtime.groups[tag]
		if group == nil {
			break
		}
		tag = *group.selected.Load()
	}
	out := s.peer.runtime.outbounds[tag]
	if out.Type != "direct" && out.Type != "wireguard" && out.Type != "trusttunnel" && out.Type != "masque" && out.Type != "masque-server" && out.Type != "tailscale" && out.Type != "openconnect" {
		s.sendICMPError(p, false, false)
		return
	}
	host, _, _ := net.SplitHostPort(q.address)
	destination, e := netip.ParseAddr(host)
	if e != nil || destination.Is4() != p.source.Is4() {
		s.sendICMPError(p, false, false)
		return
	}
	if destination.IsMulticast() || destination.IsUnspecified() {
		return
	}
	ttl := p.data[8]
	if p.source.Is6() {
		ttl = p.data[7]
	}
	if ttl <= 1 {
		s.sendICMPError(p, false, true)
		return
	}

	var response icmpResponse
	if out.Type == "tailscale" {
		c := s.peer.runtime.tailscaleClient(tag)
		if e = c.wait(ctx); e == nil {
			var node tsNode
			node, e = c.choose(destination)
			if e == nil {
				var peer *tsPeer
				peer, e = c.peer(node)
				if e == nil {
					e = peer.ensure(ctx)
				}
				if e == nil {
					response, e = peer.wg.stack.exchangeICMP(ctx, destination, p.data[p.header:], ttl-1)
				}
			}
		}
	} else if out.Type == "wireguard" {
		var peer *wgPeer
		peer, e = s.peer.runtime.wireGuardSession(ctx, tag, destination)
		if e == nil {
			response, e = peer.stack.exchangeICMP(ctx, destination, p.data[p.header:], ttl-1)
		}
	} else if out.Type == "masque-server" {
		var peer *masqueIP
		protocol := byte(1)
		if destination.Is6() {
			protocol = 58
		}
		peer, e = s.peer.runtime.masqueServers[tag].peer(destination, protocol)
		if e == nil {
			response, e = peer.stack.exchangeICMP(ctx, destination, p.data[p.header:], ttl-1)
		}
	} else if out.Type == "masque" {
		if out.mode() != "ip" {
			s.sendICMPError(p, false, false)
			return
		}
		var peer *masqueIP
		peer, e = s.peer.runtime.masqueClients[tag].ipSession(ctx)
		if e == nil {
			response, e = peer.stack.exchangeICMP(ctx, destination, p.data[p.header:], ttl-1)
		}
	} else if out.Type == "openconnect" {
		var peer *ocTunnel
		peer, e = s.peer.runtime.ocClients[tag].session(ctx)
		if e == nil {
			response, e = peer.stack.exchangeICMP(ctx, destination, p.data[p.header:], ttl-1)
		}
	} else if out.Type == "trusttunnel" {
		response, e = s.peer.runtime.trustClients[tag].exchangeICMP(ctx, destination, p.data[p.header:], ttl-1)
		if e == nil && icmpError(response.data[0], p.source.Is6()) {
			response.data = append(response.data[:8], p.data[:min(len(p.data), p.header+8)]...)
		}
	} else {
		response, e = s.peer.runtime.directICMPExchange(ctx, destination, p.data[p.header:], int(ttl)-1, out.DialOptions.routeNetwork(q.networkContext(ctx)))
	}
	if e != nil {
		s.sendICMPError(p, false, false)
		return
	}
	if icmpError(response.data[0], p.source.Is6()) {
		s.relayICMPError(p, response)
	} else {
		s.echoICMP(p, response.data)
	}

}

func (r *Runtime) directICMPEcho(ctx context.Context, destination netip.Addr, request []byte, ttl int) ([]byte, error) {
	response, e := r.directICMPExchange(ctx, destination, request, ttl)
	return response.data, e
}
func (r *Runtime) directICMPExchange(ctx context.Context, destination netip.Addr, request []byte, ttl int, options ...DialOptions) (icmpResponse, error) {
	fail := func(e error) (icmpResponse, error) { return icmpResponse{}, e }
	var o DialOptions
	if len(options) != 0 {
		o = options[0]
	}
	// A protected UDP route lookup selects a source without emitting traffic.
	target := net.JoinHostPort(destination.String(), "9")
	probe, e := r.dialSocket(ctx, o, "udp", target)
	if e != nil {
		return fail(e)
	}
	local := probe.LocalAddr().(*net.UDPAddr).IP
	probe.Close()
	if o.NetworkOptions.active() {
		primary, fallback, err := r.networkCandidates(ctx, o.NetworkOptions, destination, o.namespace)
		if err != nil {
			return fail(err)
		}
		source, _ := netip.AddrFromSlice(local)
		source = source.Unmap()
		name := ""
		for _, list := range [][]networkChoice{primary, fallback} {
			for _, choice := range list {
				for _, ip := range choice.Addresses {
					if ip.Unmap() == source {
						name = choice.Name
						break
					}
				}
			}
		}
		if name == "" {
			return fail(errors.New("selected ICMP source interface disappeared"))
		}
		o.NetworkOptions = NetworkOptions{}
		o.BindInterface = name
	}
	network := "ip4:icmp"
	if destination.Is6() {
		network = "ip6:ipv6-icmp"
	}
	raw, e := r.listenPacketWithOptions(ctx, o, network, local.String(), target)
	if e != nil {
		return fail(e)
	}
	c := raw.(*net.IPConn)
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		deadline = d
	}
	c.SetDeadline(deadline)
	segment := append([]byte{}, request...)
	var id [2]byte
	if _, e = rand.Read(id[:]); e != nil {
		return fail(e)
	}
	copy(segment[4:6], id[:])
	clear(segment[2:4])
	sum := checksum(segment, 0)
	source, _ := netip.AddrFromSlice(local)
	source = source.Unmap()
	if destination.Is6() {
		packet := makeWGIP(source, destination, 58, segment)
		p, _ := parseTunPacket(packet)
		sum = transportChecksum(p, segment)
	}
	binary.BigEndian.PutUint16(segment[2:], sum)
	control, e := c.SyscallConn()
	if e != nil {
		return fail(e)
	}
	if e = setICMPTTL(control, destination.Is6(), ttl); e != nil {
		return fail(e)
	}
	if _, e = c.WriteToIP(segment, &net.IPAddr{IP: net.IP(destination.AsSlice())}); e != nil {
		return fail(e)
	}
	buffer := make([]byte, 65575)
	for {
		n, from, e := c.ReadFromIP(buffer)
		if e != nil {
			return fail(e)
		}
		b := buffer[:n]
		if len(b) >= 20 && b[0]>>4 == 4 {
			header := int(b[0]&15) * 4
			if header < 20 || header > len(b) {
				continue
			}
			b = b[header:]
		}
		origin, _ := netip.AddrFromSlice(from.IP)
		origin = origin.Unmap()
		if !matchICMPResponse(b, origin, destination, binary.BigEndian.Uint16(id[:]), binary.BigEndian.Uint16(request[6:])) {
			continue
		}
		if destination.Is4() && checksum(b, 0) != 0 {
			continue
		}
		if destination.Is6() {
			packet := makeWGIP(origin, source, 58, b)
			p, _ := parseTunPacket(packet)
			if transportChecksum(p, b) != 0 {
				continue
			}
		}
		if !icmpError(b[0], destination.Is6()) {
			copy(b[4:6], request[4:6])
		}
		return icmpResponse{source: origin, data: append([]byte{}, b...)}, nil
	}
}
func (s *wgIPStack) echoICMP(p tunPacket, segment []byte) {
	b := append([]byte{}, segment...)
	b[0] = 0
	if p.protocol == 58 {
		b[0] = 129
	}
	clear(b[2:4])
	packet := makeWGIP(p.destination, p.source, p.protocol, b)
	rp, _ := parseTunPacket(packet)
	sum := checksum(b, 0)
	if p.protocol == 58 {
		sum = transportChecksum(rp, b)
	}
	binary.BigEndian.PutUint16(packet[rp.header+2:], sum)
	s.peer.sendIP(packet)
}
func (s *wgIPStack) sendICMPError(p tunPacket, port, expired bool) {
	if p.source.IsMulticast() || p.source.IsUnspecified() || p.destination.IsMulticast() {
		return
	}
	protocol := byte(1)
	kind, code := byte(3), byte(1)
	limit := p.header + 8
	if port {
		code = 3
	}
	if expired {
		kind, code = 11, 0
	}
	if p.source.Is6() {
		protocol = 58
		kind, code = 1, 3
		limit = 1232
		if port {
			code = 4
		}
		if expired {
			kind, code = 3, 0
		}
	}
	segment := make([]byte, 8+min(limit, len(p.data)))
	segment[0], segment[1] = kind, code
	copy(segment[8:], p.data)
	packet := makeWGIP(p.destination, p.source, protocol, segment)
	rp, _ := parseTunPacket(packet)
	sum := checksum(segment, 0)
	if protocol == 58 {
		sum = transportChecksum(rp, segment)
	}
	binary.BigEndian.PutUint16(packet[rp.header+2:], sum)
	s.peer.sendIP(packet)
}
