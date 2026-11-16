package native

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Provisional capsule IDs from draft-ietf-masque-connect-ip-dns-07.
const masqueDNSAssign = 0x1ace79ec
const masquePREF64 = 0x274c0fbc

func newMasqueCacheEpoch() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type MasqueNameserver struct {
	Priority      uint16            `json:"priority"`
	IPv4Addresses []netip.Addr      `json:"ipv4_addresses,omitempty"`
	IPv6Addresses []netip.Addr      `json:"ipv6_addresses,omitempty"`
	ServerName    string            `json:"server_name,omitempty"`
	Parameters    map[uint16][]byte `json:"parameters,omitempty"`
}

type MasqueDNSConfiguration struct {
	Nameservers     []MasqueNameserver `json:"nameservers"`
	InternalDomains []string           `json:"internal_domains,omitempty"`
	SearchDomains   []string           `json:"search_domains,omitempty"`
}

type MasqueNetworkConfiguration struct {
	Version        uint64                   `json:"version"`
	DNSReceived    bool                     `json:"dns_received"`
	PREF64Received bool                     `json:"pref64_received"`
	DNS            []MasqueDNSConfiguration `json:"dns"`
	PREF64         []netip.Prefix           `json:"pref64"`
}

type masqueNetworkServer struct {
	gate                chan struct{}
	peers               map[*masqueIP]struct{}
	dns, pref64         []byte
	sendDNS, sendPREF64 bool
}

func newMasqueNetworkServer(options MasqueOptions) *masqueNetworkServer {
	dns, _ := masqueDNSBytes(options.DNS)
	pref64, _ := masquePREF64Bytes(options.PREF64)
	return &masqueNetworkServer{gate: make(chan struct{}, 1), peers: map[*masqueIP]struct{}{}, dns: dns, pref64: pref64, sendDNS: options.DNS != nil, sendPREF64: options.PREF64 != nil}
}

func (s *masqueNetworkServer) send(p *masqueIP) error {
	p.flow.SetWriteDeadline(time.Now().Add(15 * time.Second))
	defer p.flow.SetWriteDeadline(time.Time{})
	if s.sendDNS {
		if err := p.flow.capsule(masqueDNSAssign, s.dns); err != nil {
			return err
		}
	}
	if s.sendPREF64 {
		return p.flow.capsule(masquePREF64, s.pref64)
	}
	return nil
}

func (p *masqueIP) registerConfiguration() error {
	s := p.networkServer
	select {
	case s.gate <- struct{}{}:
	case <-p.flow.done:
		return net.ErrClosed
	}
	defer func() { <-s.gate }()
	if p.flow.isClosed() {
		return net.ErrClosed
	}
	s.peers[p] = struct{}{}
	return s.send(p)
}

func (p *masqueIP) unregisterConfiguration() {
	if s := p.networkServer; s != nil {
		s.gate <- struct{}{}
		delete(s.peers, p)
		<-s.gate
	}
}

// PublishMasqueConfiguration replaces the server's configuration for existing
// and future tunnels. Empty lists withdraw previously advertised configuration.
func (r *Runtime) PublishMasqueConfiguration(ctx context.Context, tag string, dns []MasqueDNSConfiguration, pref64 []netip.Prefix) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	s := r.masqueNetworkServers[tag]
	if s == nil {
		return errors.New("MASQUE configuration publication requires a server endpoint")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := masqueDNSBytes(dns)
	if err != nil {
		return err
	}
	p, err := masquePREF64Bytes(pref64)
	if err != nil {
		return err
	}
	select {
	case s.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.gate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.ctx.Err() != nil {
		return net.ErrClosed
	}
	s.dns, s.pref64, s.sendDNS, s.sendPREF64 = d, p, true, true
	var failures []error
	for peer := range s.peers {
		if err := ctx.Err(); err != nil {
			return err
		}
		stop := context.AfterFunc(ctx, func() { peer.flow.Close() })
		err := s.send(peer)
		stop()
		if err != nil {
			closed := peer.flow.isClosed()
			delete(s.peers, peer)
			peer.flow.Close()
			if !closed {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func masqueDomain(name string, empty bool) bool {
	if name == "" {
		return empty
	}
	if len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if c != '-' && c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
				return false
			}
		}
	}
	return true
}

func (n MasqueNameserver) validate() error {
	if n.Priority == 0 || !masqueDomain(n.ServerName, true) || len(n.IPv4Addresses)+len(n.IPv6Addresses) > 128 {
		return errors.New("invalid MASQUE nameserver priority, name or address count")
	}
	for _, v := range []struct {
		ips []netip.Addr
		v4  bool
	}{{n.IPv4Addresses, true}, {n.IPv6Addresses, false}} {
		for _, a := range v.ips {
			if !a.IsValid() || a.Is4() != v.v4 || a.Is4In6() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
				return errors.New("invalid MASQUE nameserver IP address")
			}
		}
	}
	if err := validateSVCBParams(n.Parameters); err != nil {
		return err
	}
	if _, ok := n.Parameters[4]; ok {
		return errors.New("MASQUE nameserver forbids ipv4hint")
	}
	if _, ok := n.Parameters[6]; ok {
		return errors.New("MASQUE nameserver forbids ipv6hint")
	}
	_, alpn := n.Parameters[1]
	_, encryptedOnly := n.Parameters[2]
	if n.ServerName == "" && (alpn || encryptedOnly) || !encryptedOnly && len(n.IPv4Addresses)+len(n.IPv6Addresses) == 0 {
		return errors.New("MASQUE nameserver requires addresses for plain DNS and a name for encrypted DNS")
	}
	return nil
}

func masqueDNSBytes(configs []MasqueDNSConfiguration) ([]byte, error) {
	if len(configs) > 16 {
		return nil, errors.New("MASQUE DNS configuration count exceeds16")
	}
	var b []byte
	for _, cfg := range configs {
		if len(cfg.Nameservers) == 0 || len(cfg.Nameservers) > 16 || len(cfg.InternalDomains) > 128 || len(cfg.SearchDomains) > 128 {
			return nil, errors.New("MASQUE DNS configuration capacity exceeded")
		}
		b = quicVar(b, uint64(len(cfg.Nameservers)))
		for _, ns := range cfg.Nameservers {
			if err := ns.validate(); err != nil {
				return nil, err
			}
			b = binary.BigEndian.AppendUint16(b, ns.Priority)
			for _, ips := range [][]netip.Addr{ns.IPv4Addresses, ns.IPv6Addresses} {
				b = quicVar(b, uint64(len(ips)))
				for _, ip := range ips {
					b = append(b, ip.AsSlice()...)
				}
			}
			b = append(quicVar(b, uint64(len(ns.ServerName))), ns.ServerName...)
			var params []byte
			for _, key := range slices.Sorted(maps.Keys(ns.Parameters)) {
				v := ns.Parameters[key]
				if len(v) > 4096 {
					return nil, errors.New("MASQUE SVCB parameter exceeds4096bytes")
				}
				params = binary.BigEndian.AppendUint16(params, key)
				params = binary.BigEndian.AppendUint16(params, uint16(len(v)))
				params = append(params, v...)
			}
			if len(params) > 4096 {
				return nil, errors.New("MASQUE nameserver parameters exceed4096bytes")
			}
			b = append(quicVar(b, uint64(len(params))), params...)
		}
		for i, domains := range [][]string{cfg.InternalDomains, cfg.SearchDomains} {
			b = quicVar(b, uint64(len(domains)))
			for _, name := range domains {
				if !masqueDomain(name, i == 0) {
					return nil, errors.New("invalid MASQUE DNS domain;use A-labels without a trailing dot")
				}
				b = append(quicVar(b, uint64(len(name))), name...)
			}
		}
		if len(b) > 65536 {
			return nil, errors.New("MASQUE DNS capsule exceeds65536bytes")
		}
	}
	return b, nil
}

func masqueDNSConfigurations(data []byte) ([]MasqueDNSConfiguration, error) {
	if len(data) > 65536 {
		return nil, errors.New("MASQUE DNS capsule exceeds65536bytes")
	}
	r := quicReader(data)
	count := func(limit uint64) (int, error) {
		n, err := r.v()
		if err != nil || n > limit {
			return 0, errors.New("MASQUE DNS field exceeds capacity")
		}
		return int(n), nil
	}
	var out []MasqueDNSConfiguration
	for len(r) > 0 {
		if len(out) == 16 {
			return nil, errors.New("MASQUE DNS configuration count exceeds16")
		}
		n, err := count(16)
		if err != nil || n == 0 {
			return nil, errors.New("invalid MASQUE nameserver count")
		}
		cfg := MasqueDNSConfiguration{Nameservers: make([]MasqueNameserver, n)}
		for i := range cfg.Nameservers {
			ns := &cfg.Nameservers[i]
			priority, err := r.take(2)
			if err != nil {
				return nil, err
			}
			ns.Priority = binary.BigEndian.Uint16(priority)
			for family := range 2 {
				n, err := count(128)
				if err != nil {
					return nil, err
				}
				size := 4 + family*12
				v, err := r.take(uint64(n * size))
				if err != nil {
					return nil, err
				}
				for len(v) > 0 {
					a, _ := netip.AddrFromSlice(v[:size])
					if family == 0 {
						ns.IPv4Addresses = append(ns.IPv4Addresses, a)
					} else {
						ns.IPv6Addresses = append(ns.IPv6Addresses, a)
					}
					v = v[size:]
				}
			}
			n, err := count(253)
			if err != nil {
				return nil, err
			}
			name, err := r.take(uint64(n))
			if err != nil {
				return nil, err
			}
			ns.ServerName = string(name)
			n, err = count(4096)
			if err != nil {
				return nil, err
			}
			params, err := r.take(uint64(n))
			if err != nil {
				return nil, err
			}
			svcb, err := parseSVCB(append([]byte{0, 1, 0}, params...))
			if err != nil {
				return nil, err
			}
			ns.Parameters = svcb.params
			if err = ns.validate(); err != nil {
				return nil, err
			}
		}
		for i := range 2 {
			n, err := count(128)
			if err != nil {
				return nil, err
			}
			for range n {
				size, err := count(253)
				if err != nil {
					return nil, err
				}
				v, err := r.take(uint64(size))
				if err != nil || !masqueDomain(string(v), i == 0) {
					return nil, errors.New("invalid MASQUE DNS domain")
				}
				if i == 0 {
					cfg.InternalDomains = append(cfg.InternalDomains, string(v))
				} else {
					cfg.SearchDomains = append(cfg.SearchDomains, string(v))
				}
			}
		}
		out = append(out, cfg)
	}
	return out, nil
}

func masquePrefixValid(p netip.Prefix) bool {
	return p.IsValid() && p.Addr().Is6() && !p.Addr().Is4In6() && p == p.Masked() && slices.Contains([]int{32, 40, 48, 56, 64, 96}, p.Bits())
}

func masquePREF64Bytes(prefixes []netip.Prefix) ([]byte, error) {
	if len(prefixes) > 128 {
		return nil, errors.New("MASQUE NAT64 prefix count exceeds128")
	}
	b := make([]byte, 0, len(prefixes)*13)
	for _, prefix := range prefixes {
		if !masquePrefixValid(prefix) {
			return nil, errors.New("MASQUE PREF64 requires canonical IPv6 /32,/40,/48,/56,/64 or /96")
		}
		a := prefix.Addr().As16()
		b = append(b, byte(prefix.Bits()))
		b = append(b, a[:12]...)
	}
	return b, nil
}

func masquePREF64Prefixes(b []byte) ([]netip.Prefix, error) {
	if len(b)%13 != 0 || len(b) > 128*13 {
		return nil, errors.New("invalid MASQUE PREF64 capsule size")
	}
	var out []netip.Prefix
	for len(b) > 0 {
		var a [16]byte
		copy(a[:12], b[1:13])
		p := netip.PrefixFrom(netip.AddrFrom16(a), int(b[0]))
		if !masquePrefixValid(p) {
			return nil, errors.New("invalid MASQUE NAT64 prefix")
		}
		out = append(out, p)
		b = b[13:]
	}
	return out, nil
}

func cloneMasqueConfiguration(c MasqueNetworkConfiguration) MasqueNetworkConfiguration {
	c.PREF64 = slices.Clone(c.PREF64)
	c.DNS = slices.Clone(c.DNS)
	for i := range c.DNS {
		cfg := &c.DNS[i]
		cfg.InternalDomains = slices.Clone(cfg.InternalDomains)
		cfg.SearchDomains = slices.Clone(cfg.SearchDomains)
		cfg.Nameservers = slices.Clone(cfg.Nameservers)
		for j := range cfg.Nameservers {
			n := &cfg.Nameservers[j]
			n.IPv4Addresses, n.IPv6Addresses = slices.Clone(n.IPv4Addresses), slices.Clone(n.IPv6Addresses)
			n.Parameters = maps.Clone(n.Parameters)
			for key, v := range n.Parameters {
				n.Parameters[key] = bytes.Clone(v)
			}
		}
	}
	return c
}

func (p *masqueIP) configureNetwork(kind uint64, b []byte) error {
	if p.server || kind == masqueDNSAssign && !p.acceptDNS || kind == masquePREF64 && !p.acceptPREF64 {
		return nil
	}
	var dns []MasqueDNSConfiguration
	var pref64 []netip.Prefix
	var err error
	if kind == masqueDNSAssign {
		dns, err = masqueDNSConfigurations(b)
	} else {
		pref64, err = masquePREF64Prefixes(b)
	}
	if err != nil {
		return err
	}
	p.mu.Lock()
	if kind == masqueDNSAssign && !p.haveRoutes {
		p.mu.Unlock()
		return errors.New("MASQUE DNS configuration preceded route advertisement")
	}
	if kind == masqueDNSAssign {
		p.configuration.DNS, p.configuration.DNSReceived = dns, true
	} else {
		p.configuration.PREF64, p.configuration.PREF64Received = pref64, true
	}
	p.configuration.Version = p.runtime.masqueConfigVersion.Add(1)
	close(p.configurationChanged)
	p.configurationChanged = make(chan struct{})
	var old []*resolver
	if kind == masqueDNSAssign {
		old = p.retireDNSResolvers()
	}
	p.mu.Unlock()
	for _, r := range old {
		r.Close()
	}
	return nil
}

func (p *masqueIP) closeDNSResolvers() {
	p.mu.Lock()
	old := p.retireDNSResolvers()
	p.mu.Unlock()
	for _, r := range old {
		r.Close()
	}
}

// Called with p.mu held. Active queries retain their transport until release.
func (p *masqueIP) retireDNSResolvers() []*resolver {
	var closeNow []*resolver
	for _, item := range p.dnsResolvers {
		item.retired = true
		if item.users == 0 {
			closeNow = append(closeNow, item.resolver)
		}
	}
	p.dnsResolvers = nil
	return closeNow
}

// MasqueConfiguration opens the endpoint if necessary and returns its current snapshot.
func (r *Runtime) MasqueConfiguration(ctx context.Context, tag string) (MasqueNetworkConfiguration, error) {
	return r.masqueConfiguration(ctx, tag, 0, false)
}

// WaitMasqueConfiguration waits for a newer DNS/PREF64 update. Version0 waits for the first update.
func (r *Runtime) WaitMasqueConfiguration(ctx context.Context, tag string, after uint64) (MasqueNetworkConfiguration, error) {
	return r.masqueConfiguration(ctx, tag, after, true)
}

func (r *Runtime) masqueConfiguration(ctx context.Context, tag string, after uint64, wait bool) (MasqueNetworkConfiguration, error) {
	c := r.masqueClients[tag]
	if c == nil || c.outbound.mode() != "ip" {
		return MasqueNetworkConfiguration{}, errors.New("MASQUE configuration requires an IP client endpoint")
	}
	p, err := c.ipSession(ctx)
	if err != nil {
		return MasqueNetworkConfiguration{}, err
	}
	for {
		p.mu.Lock()
		state, changed := p.configuration, p.configurationChanged
		if !wait || state.Version > after {
			state = cloneMasqueConfiguration(state)
			p.mu.Unlock()
			return state, nil
		}
		p.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return MasqueNetworkConfiguration{}, ctx.Err()
		case <-p.flow.done:
			return MasqueNetworkConfiguration{}, net.ErrClosed
		}
	}
}
