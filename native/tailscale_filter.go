package native

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// These are control-channel wire fields; capability grants never authorize IP traffic.
type tsFilterRule struct {
	SrcIPs   []string
	SrcBits  []int
	IPProto  []int
	DstPorts []struct {
		IP    string
		Bits  *int
		Ports struct{ First, Last uint16 }
	}
	CapGrant []struct {
		Dsts   []netip.Prefix
		Caps   []string
		CapMap map[string][]json.RawMessage
	}
}

type tsIPMatch struct {
	all         bool
	prefix      netip.Prefix
	first, last netip.Addr
}

func tsMatchIP(raw string, bits *int) tsIPMatch {
	if raw == "*" {
		return tsIPMatch{all: true}
	}
	if p, e := netip.ParsePrefix(raw); e == nil {
		return tsIPMatch{prefix: p.Masked()}
	}
	if a, e := netip.ParseAddr(raw); e == nil {
		n := a.BitLen()
		if bits != nil {
			n = *bits
		}
		return tsIPMatch{prefix: netip.PrefixFrom(a.Unmap(), n).Masked()}
	}
	if a, b, ok := strings.Cut(raw, "-"); ok {
		first, e1 := netip.ParseAddr(a)
		last, e2 := netip.ParseAddr(b)
		if e1 == nil && e2 == nil && first.BitLen() == last.BitLen() && first.Compare(last) <= 0 {
			return tsIPMatch{first: first.Unmap(), last: last.Unmap()}
		}
	}
	return tsIPMatch{}
}

func (m tsIPMatch) contains(ip netip.Addr) bool {
	return m.all || m.prefix.IsValid() && m.prefix.Contains(ip) || m.first.IsValid() && m.first.BitLen() == ip.BitLen() && ip.Compare(m.first) >= 0 && ip.Compare(m.last) <= 0
}

type tsFilter struct {
	sources      []tsIPMatch
	protocols    []int
	destinations []struct {
		match       tsIPMatch
		first, last uint16
	}
}

func tsCompileFilters(rules []tsFilterRule) []tsFilter {
	var result []tsFilter
	for _, rule := range rules {
		f := tsFilter{protocols: rule.IPProto}
		for i, raw := range rule.SrcIPs {
			var bits *int
			if i < len(rule.SrcBits) {
				bits = &rule.SrcBits[i]
			}
			f.sources = append(f.sources, tsMatchIP(raw, bits))
		}
		for _, dst := range rule.DstPorts {
			f.destinations = append(f.destinations, struct {
				match       tsIPMatch
				first, last uint16
			}{tsMatchIP(dst.IP, dst.Bits), dst.Ports.First, dst.Ports.Last})
		}
		if len(f.sources) > 0 && len(f.destinations) > 0 {
			result = append(result, f)
		}
	}
	return result
}

func (f tsFilter) allows(p tunPacket) bool {
	if len(f.protocols) == 0 {
		if p.protocol != 6 && p.protocol != 17 && p.protocol != 1 && p.protocol != 58 {
			return false
		}
	} else if !slices.Contains(f.protocols, int(p.protocol)) {
		return false
	}
	if !slices.ContainsFunc(f.sources, func(m tsIPMatch) bool { return m.contains(p.source) }) {
		return false
	}
	for _, dst := range f.destinations {
		if !dst.match.contains(p.destination) {
			continue
		}
		if p.protocol != 6 && p.protocol != 17 {
			return true
		}
		if p.header+4 <= len(p.data) {
			port := binary.BigEndian.Uint16(p.data[p.header+2:])
			if port >= dst.first && port <= dst.last {
				return true
			}
		}
	}
	return false
}

func (c *tailscaleClient) acceptsPacket(p tunPacket) bool {
	if !p.destination.IsGlobalUnicast() || p.destination.IsLoopback() || p.destination.IsLinkLocalUnicast() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.self.Expired || c.self.lockInvalid || !c.self.KeyExpiry.IsZero() && time.Now().After(c.self.KeyExpiry) {
		return false
	}
	if slices.ContainsFunc(c.self.Addresses, func(a netip.Prefix) bool { return a.Addr() == p.destination }) {
		if c.ssh != nil && p.protocol == 6 && p.header+4 <= len(p.data) && binary.BigEndian.Uint16(p.data[p.header+2:]) == 22 {
			return slices.ContainsFunc(c.filter, func(f tsFilter) bool { return f.allows(p) })
		}
		if p.protocol == 1 || p.protocol == 58 {
			return slices.ContainsFunc(c.filter, func(f tsFilter) bool { return f.allows(p) })
		}
		return c.peerAPI != nil && p.protocol == 6 && p.header+4 <= len(p.data) && binary.BigEndian.Uint16(p.data[p.header+2:]) == c.peerAPI.port && (c.canReceiveFileLocked(p.source) || c.canServeDNSLocked(p))
	}
	// Only locally requested AND controller-approved routed destinations are exposed.
	requested := c.o.AdvertiseExitNode
	for _, raw := range c.o.AdvertiseRoutes {
		prefix, _ := netip.ParsePrefix(raw)
		requested = requested || prefix.Contains(p.destination)
	}
	approved := false
	for _, prefix := range c.self.AllowedIPs {
		if slices.ContainsFunc(c.self.Addresses, func(a netip.Prefix) bool { return a.Addr() == p.destination }) {
			return false
		}
		approved = approved || prefix.Contains(p.destination)
	}
	return requested && approved && slices.ContainsFunc(c.filter, func(f tsFilter) bool { return f.allows(p) })
}

func (c *tailscaleClient) ownUserLocked(ip netip.Addr) bool {
	if c.self.User == 0 || len(c.self.Tags) > 0 {
		return false
	}
	n, ok := c.nodes[c.addressOwners[ip]]
	return ok && n.User == c.self.User && len(n.Tags) == 0 && !n.restricted()
}

func (c *tailscaleClient) canReceiveFileLocked(ip netip.Addr) bool {
	n, ok := c.nodes[c.addressOwners[ip]]
	if !ok || n.restricted() || n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) || c.self.Expired || c.self.lockInvalid || !c.self.KeyExpiry.IsZero() && time.Now().After(c.self.KeyExpiry) {
		return false
	}
	if c.ownUserLocked(ip) {
		return true
	}
	return c.peerCapabilityLocked(ip, c.self.Addresses, "https://tailscale.com/cap/file-send")
}

func (c *tailscaleClient) peerCapabilityLocked(ip netip.Addr, destinations []netip.Prefix, capability string) bool {
	for _, rules := range c.filters {
		for _, rule := range rules {
			source := false
			for i, raw := range rule.SrcIPs {
				var bits *int
				if i < len(rule.SrcBits) {
					bits = &rule.SrcBits[i]
				}
				source = source || tsMatchIP(raw, bits).contains(ip)
			}
			if !source {
				continue
			}
			for _, grant := range rule.CapGrant {
				_, allowed := grant.CapMap[capability]
				if !allowed && !slices.Contains(grant.Caps, capability) {
					continue
				}
				for _, dst := range grant.Dsts {
					for _, local := range destinations {
						if dst.Contains(local.Addr()) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func (c *tailscaleClient) ownsSource(id int64, address netip.Addr) bool {
	if !address.IsGlobalUnicast() || address.IsLoopback() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, p := range c.self.Addresses {
		if p.Addr() == address {
			return false
		}
	}
	n, ok := c.nodes[id]
	now := time.Now()
	if !ok || n.restricted() || n.Expired || !n.KeyExpiry.IsZero() && now.After(n.KeyExpiry) || c.self.Expired || c.self.lockInvalid || !c.self.KeyExpiry.IsZero() && now.After(c.self.KeyExpiry) {
		return false
	}
	if owner, ok := c.addressOwners[address]; ok {
		return owner == id
	}
	bits := c.sourceBits4
	if address.Is6() {
		bits = c.sourceBits6
	}
	for _, n := range bits {
		for _, owner := range c.prefixOwners[netip.PrefixFrom(address, n).Masked()] {
			node := c.nodes[owner]
			if !node.Expired && (node.KeyExpiry.IsZero() || now.Before(node.KeyExpiry)) {
				return owner == id
			}
		}
	}
	return tsExitNodeMatches(n, c.o.ExitNode) && slices.ContainsFunc(n.AllowedIPs, func(p netip.Prefix) bool { return p.Bits() == 0 && p.Contains(address) })
}

func (c *tailscaleClient) updateOwnersLocked() {
	c.addressOwners = make(map[netip.Addr]int64, len(c.nodes)*2)
	c.prefixOwners = map[netip.Prefix][]int64{}
	bits4, bits6 := map[int]bool{}, map[int]bool{}
	for id, n := range c.nodes {
		for _, a := range n.Addresses {
			ip := a.Addr().Unmap()
			if old, ok := c.addressOwners[ip]; ok && old != id {
				c.addressOwners[ip] = 0
			} else {
				c.addressOwners[ip] = id
			}
		}
		for _, p := range n.AllowedIPs {
			p = p.Masked()
			if !p.IsValid() || p.Bits() == 0 || !c.o.AcceptRoutes {
				continue
			}
			c.prefixOwners[p] = append(c.prefixOwners[p], id)
			if p.Addr().Is4() {
				bits4[p.Bits()] = true
			} else {
				bits6[p.Bits()] = true
			}
		}
	}
	for prefix, owners := range c.prefixOwners {
		slices.Sort(owners)
		c.prefixOwners[prefix] = slices.Compact(owners)
	}
	c.sourceBits4 = c.sourceBits4[:0]
	c.sourceBits6 = c.sourceBits6[:0]
	for n := range bits4 {
		c.sourceBits4 = append(c.sourceBits4, n)
	}
	for n := range bits6 {
		c.sourceBits6 = append(c.sourceBits6, n)
	}
	slices.Sort(c.sourceBits4)
	slices.Reverse(c.sourceBits4)
	slices.Sort(c.sourceBits6)
	slices.Reverse(c.sourceBits6)
}
