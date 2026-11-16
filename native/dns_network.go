package native

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

type dnsNetworkState struct {
	addresses []netip.Addr
	servers   []string
	domains   []string
	key       string
}

// Only rules using network DNS metadata pay for discovery. No background poller.
type dnsNetworkCache struct {
	mu    sync.Mutex
	next  time.Time
	state dnsNetworkState
	read  func() dnsNetworkState
}

func (c *dnsNetworkCache) snapshot() dnsNetworkState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now := time.Now(); !now.Before(c.next) {
		read := c.read
		if read == nil {
			read = systemDNSNetwork
		}
		c.state = read()
		c.state.key = dnsNetworkKey(c.state)
		c.next = now.Add(5 * time.Second)
	}
	return c.state
}

func dnsNetworkKey(s dnsNetworkState) string {
	h := sha256.New()
	for _, ip := range s.addresses {
		h.Write([]byte(ip.String()))
		h.Write([]byte{0})
	}
	for _, server := range s.servers {
		h.Write([]byte(server))
		h.Write([]byte{0})
	}
	h.Write([]byte{0})
	for _, domain := range s.domains {
		h.Write([]byte(domain))
		h.Write([]byte{0})
	}
	return string(h.Sum(nil))
}

func (r *resolver) localDNSNamespace() string {
	key := r.localNetwork.snapshot().key
	r.mu.Lock()
	defer r.mu.Unlock()
	// TUN preserves physical DNS endpoints even after the OS points DNS at us.
	return key + ":" + strings.Join(r.systemServers, "\x00")
}

func (c *dnsNetworkCache) invalidate() {
	c.mu.Lock()
	c.next = time.Time{}
	c.mu.Unlock()
}

func dnsConditions(rules []DNSRule) []Rule {
	out := make([]Rule, len(rules))
	for i := range rules {
		out[i] = rules[i].Rule
	}
	return out
}

func dnsNetworkTags(rules []Rule) []string {
	seen := map[string]bool{}
	var walk func([]Rule)
	walk = func(rules []Rule) {
		for _, rule := range rules {
			for tag, values := range rule.DNSServerAddress {
				if len(values) > 0 {
					seen[tag] = true
				}
			}
			for tag, values := range rule.DNSSearchDomain {
				if len(values) > 0 {
					seen[tag] = true
				}
			}
			walk(rule.Rules)
		}
	}
	walk(rules)
	return slices.Sorted(maps.Keys(seen))
}

func validateDNSNetworkRules(c Config) error {
	servers := map[string]DNSServer{}
	for _, s := range c.DNS.Servers {
		servers[s.Tag] = s
	}
	for _, tag := range dnsPreferredTags(dnsConditions(c.DNS.Rules)) {
		s, ok := servers[tag]
		if !ok || (s.Type != "hosts" && s.Type != "openconnect" && s.Type != "tailscale" && s.Type != "resolved") {
			return fmt.Errorf("preferred_by requires a hosts,openconnect,tailscale or resolved DNS server: %q", tag)
		}
	}
	for _, tag := range dnsNetworkTags(append(append([]Rule{}, c.Route.Rules...), dnsConditions(c.DNS.Rules)...)) {
		s, exists := servers[tag]
		if !exists {
			return fmt.Errorf("DNS network condition references unknown server %q", tag)
		}
		if s.Type != "local" && s.Type != "dhcp" && s.Type != "masque" && s.Type != "openconnect" && s.Type != "tailscale" && s.Type != "resolved" {
			return fmt.Errorf("DNS server %q has no discovered network configuration", tag)
		}
	}
	return nil
}

func (r *resolver) enrichDNSNetworkMetadata(m *Metadata) {
	if r.runtime.controller != nil {
		m.ClashMode = r.runtime.controller.modeName()
	}
	if len(r.networkTags) == 0 {
		return
	}
	// A caller can supply a complete snapshot; never mutate its maps or slices.
	addresses, domains := m.DNSServerAddress, m.DNSSearchDomain
	clonedAddresses, clonedDomains := false, false
	for _, tag := range r.networkTags {
		_, hasAddresses := addresses[tag]
		_, hasDomains := domains[tag]
		if hasAddresses && hasDomains {
			continue
		}
		state := r.dnsNetwork(tag)
		if !hasAddresses {
			if !clonedAddresses {
				addresses = maps.Clone(addresses)
				if addresses == nil {
					addresses = map[string][]netip.Addr{}
				}
				clonedAddresses = true
			}
			addresses[tag] = state.addresses
		}
		if !hasDomains {
			if !clonedDomains {
				domains = maps.Clone(domains)
				if domains == nil {
					domains = map[string][]string{}
				}
				clonedDomains = true
			}
			domains[tag] = state.domains
		}
	}
	m.DNSServerAddress, m.DNSSearchDomain = addresses, domains
}

func (r *resolver) dnsNetwork(tag string) dnsNetworkState {
	if client := r.dhcp[tag]; client != nil {
		path, err := r.dhcpPath(r.ctx, r.servers[tag].Interfaces)
		if err != nil {
			return dnsNetworkState{}
		}
		client.mu.Lock()
		defer client.mu.Unlock()
		if client.closed || path.key != client.pathKey || time.Now().After(client.state.until) {
			return dnsNetworkState{}
		}
		return dnsNetworkState{addresses: client.state.servers, domains: client.state.domains, key: client.state.key}
	}
	s := r.servers[tag]
	if s.Type == "resolved" && r.runtime != nil {
		return r.runtime.resolved[s.Service].state.Load().network()
	}
	if s.Type == "tailscale" && r.runtime != nil {
		c := r.runtime.tailscaleClient(s.Endpoint)
		state := c.dns.Load()
		if state != nil && c.ctx.Err() == nil && state.valid() {
			return dnsNetworkState{addresses: state.addresses, domains: state.config.Domains}
		}
		return dnsNetworkState{}
	}
	if s.Type == "openconnect" && r.runtime != nil {
		t := r.runtime.ocClients[s.Endpoint].tunnel.Load()
		if t != nil && t.ctx.Err() == nil {
			return dnsNetworkState{addresses: t.dns.servers, domains: t.dns.search}
		}
		return dnsNetworkState{}
	}
	if s.Type == "local" {
		state := r.localNetwork.snapshot()
		r.mu.Lock()
		if len(r.systemServers) > 0 {
			state.addresses = nil
			for _, address := range r.systemServers {
				host, _, _ := net.SplitHostPort(address)
				if ip, err := netip.ParseAddr(host); err == nil {
					state.addresses = append(state.addresses, ip.WithZone("").Unmap())
				}
			}
		}
		r.mu.Unlock()
		return state
	}
	if s.Type == "masque" && r.runtime != nil {
		client := r.runtime.masqueClients[s.Endpoint]
		p := client.ip.Load()
		if p == nil || p.flow.isClosed() {
			return dnsNetworkState{}
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		var state dnsNetworkState
		for _, config := range p.configuration.DNS {
			for _, ns := range config.Nameservers {
				state.addresses = append(state.addresses, ns.IPv4Addresses...)
				state.addresses = append(state.addresses, ns.IPv6Addresses...)
			}
			state.domains = append(state.domains, config.SearchDomains...)
		}
		return state
	}
	return dnsNetworkState{}
}

func parseDNSNetwork(reader io.Reader, scutil bool) dnsNetworkState {
	var state dnsNetworkState
	addIP := func(value string) {
		if len(state.servers) == 128 {
			return
		}
		if ip, err := netip.ParseAddr(value); err == nil {
			ip = ip.Unmap()
			if !ip.IsUnspecified() && !ip.IsMulticast() {
				server := net.JoinHostPort(ip.String(), "53")
				if !slices.Contains(state.servers, server) {
					state.servers = append(state.servers, server)
				}
				if canonical := ip.WithZone(""); !slices.Contains(state.addresses, canonical) {
					state.addresses = append(state.addresses, canonical)
				}
			}
		}
	}
	addDomain := func(value string) {
		if len(state.domains) == 128 {
			return
		}
		value = canonicalDomain(value)
		if masqueDomain(value, false) && !slices.Contains(state.domains, value) {
			state.domains = append(state.domains, value)
		}
	}
	scan := bufio.NewScanner(io.LimitReader(reader, 1<<20))
	for scan.Scan() {
		line := scan.Text()
		if scutil {
			key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
			if ok && strings.HasPrefix(key, "nameserver[") {
				addIP(strings.TrimSpace(value))
			} else if ok && strings.HasPrefix(key, "search domain[") {
				addDomain(strings.TrimSpace(value))
			}
			continue
		}
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, ";")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			addIP(fields[1])
		case "search", "domain":
			state.domains = nil // resolv.conf uses the last search/domain directive.
			for _, value := range fields[1:] {
				addDomain(value)
			}
		}
	}
	return state
}
