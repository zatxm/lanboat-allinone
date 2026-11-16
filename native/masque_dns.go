package native

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

type masqueDNSResolver struct {
	resolver *resolver
	users    int
	retired  bool
}

func (r *Runtime) exchangeMasqueDNS(ctx context.Context, s DNSServer, query []byte) ([]byte, error) {
	c := r.masqueClients[s.Endpoint]
	p, err := c.ipSession(ctx)
	if err != nil {
		return nil, err
	}
	return p.exchangeDNS(ctx, s, query)
}

func (r *Runtime) masqueDNSVersion(ctx context.Context, s DNSServer) (string, error) {
	p, err := r.masqueClients[s.Endpoint].ipSession(ctx)
	if err != nil {
		return "", err
	}
	state, err := p.dnsConfiguration(ctx)
	return p.dnsCacheEpoch + ":" + strconv.FormatUint(state.Version, 10), err
}

func (p *masqueIP) dnsConfiguration(ctx context.Context) (MasqueNetworkConfiguration, error) {
	for {
		p.mu.Lock()
		state, changed := p.configuration, p.configurationChanged
		p.mu.Unlock()
		if state.DNSReceived {
			return state, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return state, ctx.Err()
		case <-p.flow.done:
			return state, net.ErrClosed
		}
	}
}

func (p *masqueIP) exchangeDNS(ctx context.Context, options DNSServer, query []byte) ([]byte, error) {
	host, end, typ, err := dnsQuestion(query)
	if err != nil {
		return nil, err
	}
	sections, err := dnsRecords(query)
	if err != nil {
		return nil, err
	}
	dnssec := false
	for _, rr := range sections[2] {
		dnssec = dnssec || rr.typ == 41 && rr.ttl&0x8000 != 0
	}
	state, err := p.dnsConfiguration(ctx)
	if err != nil {
		return nil, err
	}
	best, index := -1, -1
	for i, cfg := range state.DNS {
		for _, suffix := range cfg.InternalDomains {
			suffix = strings.ToLower(suffix)
			if (suffix == "" || host == suffix || strings.HasSuffix(host, "."+suffix)) && len(suffix) > best {
				best, index = len(suffix), i
			}
		}
	}
	if index < 0 {
		return nil, errors.New("MASQUE assigned DNS has no matching internal domain")
	}
	nameservers := slices.Clone(state.DNS[index].Nameservers)
	slices.SortStableFunc(nameservers, func(a, b MasqueNameserver) int { return int(a.Priority) - int(b.Priority) })
	var candidates []MasqueNameserver
	last := errors.New("MASQUE assigned DNS has no usable nameserver")
	for _, ns := range nameservers {
		for _, variant := range masqueDNSAlternatives(ns) {
			ips := append(slices.Clone(ns.IPv4Addresses), ns.IPv6Addresses...)
			if len(ips) == 0 {
				candidates = append(candidates, variant)
			} else {
				candidates = append(candidates, masqueDNSAddresses(variant, ips)...)
			}
		}
	}
	for i := 0; i < len(candidates); i++ {
		ns := candidates[i]
		s, err := masqueDNSService(ns, options)
		if err != nil {
			last = err
			continue
		}
		if len(ns.IPv4Addresses)+len(ns.IPv6Addresses) == 0 {
			ips, err := p.nameserverIPs(ctx, ns, s)
			if err != nil {
				last = err
				continue
			}
			candidates = slices.Insert(candidates, i+1, masqueDNSAddresses(ns, ips)...)
			continue
		}
		r, release, err := p.dnsResolver(ns, s, state.Version)
		if err != nil {
			return nil, err
		}
		call := ctx
		cancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			call, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(candidates)-i))
		}
		reply, err := r.exchangeOn(call, s, query)
		if err == nil {
			_, _, _, err = validateDNSQuestionResponse(query, reply)
		}
		if err == nil && typ == 28 && !dnssec && len(state.PREF64) > 0 {
			ips, _, e := parseDNSReply(query, reply)
			if e == nil && len(ips) == 0 {
				a := slices.Clone(query)
				binary.BigEndian.PutUint16(a[end-4:], 1)
				v4, e := r.exchangeOn(call, s, a)
				if e == nil {
					addresses, ttl, e := parseDNSReply(a, v4)
					if e == nil && len(addresses) > 0 {
						var synthesized []netip.Addr
						for _, ip := range addresses {
							if ip.Is4() {
								for _, prefix := range state.PREF64 {
									if mapped := masqueNAT64(prefix, ip); p.permits(mapped) {
										synthesized = append(synthesized, mapped)
										break
									}
								}
							}
						}
						if len(synthesized) > 0 {
							reply = dnsResponse(query, end, synthesized, ttl, 0)
						}
					}
				}
			}
		}
		release()
		cancel()
		if err == nil {
			return reply, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}

func masqueDNSAddresses(ns MasqueNameserver, ips []netip.Addr) []MasqueNameserver {
	out := make([]MasqueNameserver, 0, len(ips))
	for _, ip := range ips {
		v := ns
		v.IPv4Addresses, v.IPv6Addresses = nil, nil
		if ip.Is4() {
			v.IPv4Addresses = []netip.Addr{ip}
		} else {
			v.IPv6Addresses = []netip.Addr{ip}
		}
		out = append(out, v)
	}
	return out
}

func masqueDNSAlternatives(ns MasqueNameserver) []MasqueNameserver {
	var out []MasqueNameserver
	seen := map[string]bool{}
	for b := ns.Parameters[1]; len(b) > 0; {
		n := int(b[0])
		name := string(b[1 : n+1])
		b = b[n+1:]
		if seen[name] || !slices.Contains([]string{"dot", "doq", "h2", "h3", "http/1.1"}, name) {
			continue
		}
		seen[name] = true
		v := ns
		v.Parameters = maps.Clone(ns.Parameters)
		v.Parameters[1] = append([]byte{byte(n)}, name...)
		out = append(out, v)
	}
	if len(out) == 0 {
		return []MasqueNameserver{ns}
	}
	return out
}

func masqueDNSService(ns MasqueNameserver, base DNSServer) (DNSServer, error) {
	for b := ns.Parameters[0]; len(b) != 0; b = b[2:] {
		if key := binary.BigEndian.Uint16(b); key != 1 && key != 2 && key != 3 && key != 5 && key != 7 {
			return DNSServer{}, errors.New("MASQUE DNS requires an unknown mandatory SVCB parameter")
		}
	}
	s := DNSServer{Type: "udp", Tag: base.Tag, TLS: base.TLS, DomainResolver: base.DomainResolver, Server: ns.ServerName}
	_, encryptedOnly := ns.Parameters[2]
	selected := false
	for alpns := ns.Parameters[1]; len(alpns) > 0; {
		n := int(alpns[0])
		alpn := string(alpns[1 : n+1])
		alpns = alpns[n+1:]
		switch alpn {
		case "dot":
			s.Type = "tls"
		case "doq":
			s.Type = "quic"
		case "h3":
			s.Type = "h3"
		case "h2", "http/1.1":
			s.Type = "https"
		default:
			continue
		}
		s.TLS.ALPN, selected = []string{alpn}, true
		break
	}
	if !selected && encryptedOnly {
		return s, errors.New("MASQUE DNS has no supported ALPN")
	}
	if s.Type != "udp" {
		s.TLS.Enabled, s.TLS.ServerName = true, ns.ServerName
		if ech := ns.Parameters[5]; len(ech) > 0 {
			s.TLS.ECH = &ECHOptions{Enabled: true, Config: []string{base64.StdEncoding.EncodeToString(ech)}}
		}
	}
	if port := ns.Parameters[3]; len(port) > 0 {
		s.ServerPort = binary.BigEndian.Uint16(port)
		if s.ServerPort == 0 {
			return s, errors.New("MASQUE DNS port must not be zero")
		}
	}
	if s.Type == "https" || s.Type == "h3" {
		s.Path = string(ns.Parameters[7])
		for _, variable := range []string{"{?dns}", "{&dns}", "{/dns}", "{dns}"} {
			s.Path = strings.ReplaceAll(s.Path, variable, "")
		}
		if s.Path == "" || !strings.HasPrefix(s.Path, "/") || strings.ContainsAny(s.Path, "{}\r\n#") {
			return s, errors.New("MASQUE DoH requires a relative dohpath template with only dns variables")
		}
	}
	return s, nil
}

func (p *masqueIP) dnsResolver(ns MasqueNameserver, s DNSServer, version uint64) (*resolver, func(), error) {
	key, _ := json.Marshal(struct {
		NS  MasqueNameserver
		DNS DNSServer
	}{ns, s})
	hash := fmt.Sprintf("%x", sha256.Sum256(key))
	p.mu.Lock()
	var evicted *resolver
	defer func() {
		p.mu.Unlock()
		if evicted != nil {
			evicted.Close()
		}
	}()
	if p.flow.isClosed() {
		return nil, nil, net.ErrClosed
	}
	item := p.dnsResolvers[hash]
	if version != p.configuration.Version {
		item = nil
	}
	if item == nil {
		if len(p.dnsResolvers) == 256 {
			for key, old := range p.dnsResolvers {
				if old.users == 0 {
					old.retired = true
					evicted = old.resolver
					delete(p.dnsResolvers, key)
					break
				}
			}
			if evicted == nil {
				return nil, nil, errors.New("MASQUE DNS resolver capacity exceeded")
			}
		}
		r, err := newResolver(DNSConfig{Servers: []DNSServer{s}, DisableCache: true})
		if err != nil {
			return nil, nil, err
		}
		r.cancel()
		r.ctx, r.cancel = context.WithCancel(p.flow.session.ctx)
		if s.Type == "https" {
			protocols := new(http.Protocols)
			protocols.SetHTTP1(slices.Contains(s.TLS.ALPN, "http/1.1"))
			protocols.SetHTTP2(slices.Contains(s.TLS.ALPN, "h2"))
			r.clients[s.Tag].Transport.(*http.Transport).Protocols = protocols
		}
		r.tunnelDial = func(ctx context.Context, server DNSServer, network string) (net.Conn, error) {
			return p.dialDNS(ctx, ns, server, network)
		}
		item = &masqueDNSResolver{resolver: r, retired: version != p.configuration.Version}
		if !item.retired {
			if p.dnsResolvers == nil {
				p.dnsResolvers = map[string]*masqueDNSResolver{}
			}
			p.dnsResolvers[hash] = item
		}
	}
	item.users++
	release := func() {
		p.mu.Lock()
		item.users--
		closeNow := item.retired && item.users == 0
		p.mu.Unlock()
		if closeNow {
			item.resolver.Close()
		}
	}
	return item.resolver, release, nil
}

func (p *masqueIP) dialDNS(ctx context.Context, ns MasqueNameserver, s DNSServer, network string) (net.Conn, error) {
	ips, err := p.nameserverIPs(ctx, ns, s)
	if err != nil {
		return nil, err
	}
	port := s.ServerPort
	if port == 0 {
		port = 53
		if s.Type == "tls" || s.Type == "quic" {
			port = 853
		} else if s.Type == "https" || s.Type == "h3" {
			port = 443
		}
	}
	last := errors.New("MASQUE nameserver has no reachable address")
	for _, ip := range ips {
		if !p.permits(ip) {
			continue
		}
		c, err := p.stack.dial(ctx, network, portAddress(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

func (p *masqueIP) nameserverIPs(ctx context.Context, ns MasqueNameserver, s DNSServer) ([]netip.Addr, error) {
	ips := append(slices.Clone(ns.IPv4Addresses), ns.IPv6Addresses...)
	if len(ips) == 0 {
		bootstrap := s.DomainResolver.tag()
		if bootstrap == "" && strings.EqualFold(ns.ServerName, p.client.outbound.Server) {
			bootstrap = p.client.outbound.DomainResolver.tag()
			if bootstrap == "" {
				bootstrap = "@local"
			}
		}
		if bootstrap == "" {
			return nil, errors.New("MASQUE nameserver without IP addresses requires an explicit domain_resolver")
		}
		var err error
		ips, err = p.runtime.resolver.lookupMode(ctx, ns.ServerName, true, bootstrap)
		if err != nil {
			return nil, err
		}
	}
	return ips, nil
}

// RFC6052 puts the reserved u octet at byte8 for prefixes shorter than /96.
func masqueNAT64(prefix netip.Prefix, ip netip.Addr) netip.Addr {
	b, v4 := prefix.Addr().As16(), ip.As4()
	pos := prefix.Bits() / 8
	for _, value := range v4 {
		if pos == 8 {
			pos++
		}
		b[pos] = value
		pos++
	}
	return netip.AddrFrom16(b)
}
