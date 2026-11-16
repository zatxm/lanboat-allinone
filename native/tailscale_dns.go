package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Control-plane wire fields, independently decoded; no upstream runtime types.
type tsDNSResolver struct {
	Addr                string
	BootstrapResolution []netip.Addr
	UseWithExitNode     bool
}
type tsDNSRecord struct{ Name, Type, Value string }
type tsDNSConfig struct {
	Resolvers, FallbackResolvers []*tsDNSResolver
	Routes                       map[string][]*tsDNSResolver
	Domains                      []string
	CertDomains                  []string
	Proxied                      bool
	ExtraRecords                 []tsDNSRecord
	ExitNodeFilteredSet          []string
}
type tsDNSUpstream struct {
	options tsDNSResolver
	server  DNSServer
	wire    *resolver
}
type tsDNSSnapshot struct {
	c                    *tailscaleClient
	ctx                  context.Context
	cancel               context.CancelFunc
	key                  string
	config               tsDNSConfig
	hosts                map[string][]dnsRecord
	root                 string
	addresses            []netip.Addr
	expires, selfExpires time.Time
	ready                bool
	mu                   sync.Mutex
	upstreams            map[string]*tsDNSUpstream
}
type tsDNSKey struct{}

func (o tsDNSConfig) validate() error {
	if len(o.Routes) > 4096 || len(o.Domains) > 128 || len(o.CertDomains) > 128 || len(o.ExtraRecords) > 16384 || len(o.ExitNodeFilteredSet) > 4096 {
		return errors.New("Tailscale DNS configuration capacity exceeded")
	}
	for _, name := range o.CertDomains {
		name = canonicalDomain(name)
		if !strings.Contains(name, ".") || !echDomain(name) {
			return errors.New("invalid Tailscale certificate domain")
		}
	}
	for _, d := range o.Domains {
		if !masqueDomain(canonicalDomain(d), false) {
			return errors.New("invalid Tailscale DNS search domain")
		}
	}
	groups := [][]*tsDNSResolver{o.Resolvers, o.FallbackResolvers}
	seen := map[string]bool{}
	for suffix, rs := range o.Routes {
		if !masqueDomain(canonicalDomain(suffix), true) {
			return errors.New("invalid Tailscale split DNS domain")
		}
		if seen[canonicalDomain(suffix)] {
			return errors.New("duplicate Tailscale DNS route suffix")
		}
		seen[canonicalDomain(suffix)] = true
		groups = append(groups, rs)
	}
	count := 0
	for _, rs := range groups {
		if len(rs) > 128 {
			return errors.New("Tailscale DNS resolver list exceeds128 entries")
		}
		for _, r := range rs {
			count++
			if count > 8192 || r == nil || len(r.BootstrapResolution) > 128 {
				return errors.New("invalid Tailscale DNS resolver")
			}
			if _, err := tsDNSService(*r); err != nil {
				return err
			}
			for _, ip := range r.BootstrapResolution {
				if !tsDNSAddress(ip) {
					return errors.New("invalid Tailscale DNS bootstrap address")
				}
			}
		}
	}
	for _, rr := range o.ExtraRecords {
		if !masqueDomain(canonicalDomain(rr.Name), false) {
			return errors.New("invalid Tailscale DNS record name")
		}
		if rr.Type == "" || rr.Type == "A" || rr.Type == "AAAA" {
			ip, err := netip.ParseAddr(rr.Value)
			if err != nil || !tsDNSAddress(ip) || rr.Type == "A" && !ip.Is4() || rr.Type == "AAAA" && !ip.Is6() {
				return errors.New("invalid Tailscale address record")
			}
		}
	}
	for _, v := range o.ExitNodeFilteredSet {
		if !masqueDomain(strings.TrimPrefix(v, "."), false) {
			return errors.New("invalid Tailscale exit DNS filter")
		}
	}
	return nil
}
func tsDNSAddress(ip netip.Addr) bool {
	return ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.Is4In6() && ip.Zone() == ""
}

func tsDNSService(o tsDNSResolver) (DNSServer, error) {
	s := DNSServer{Type: "udp", Tag: "upstream"}
	if ip, err := netip.ParseAddr(o.Addr); err == nil && tsDNSAddress(ip) {
		s.Server = ip.String()
		s.ServerPort = 53
		return s, nil
	}
	if a, err := netip.ParseAddrPort(o.Addr); err == nil && tsDNSAddress(a.Addr()) && a.Port() != 0 {
		s.Server = a.Addr().String()
		s.ServerPort = a.Port()
		return s, nil
	}
	u, err := url.Parse(o.Addr)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(o.Addr, "\x00\r\n") {
		return s, errors.New("invalid Tailscale DNS resolver address")
	}
	s.Type = u.Scheme
	s.Server = u.Hostname()
	if ip, e := netip.ParseAddr(s.Server); e == nil {
		if !tsDNSAddress(ip) {
			return s, errors.New("invalid Tailscale DNS resolver IP")
		}
	} else if !masqueDomain(canonicalDomain(s.Server), false) {
		return s, errors.New("invalid Tailscale DNS resolver host")
	}
	s.ServerPort = 443
	if u.Scheme == "http" {
		s.ServerPort = 80
	}
	if u.Port() != "" {
		p, e := strconv.ParseUint(u.Port(), 10, 16)
		if e != nil || p == 0 {
			return s, errors.New("invalid Tailscale DNS resolver port")
		}
		s.ServerPort = uint16(p)
	}
	s.Path = u.RequestURI()
	if s.Path == "/" {
		s.Path = "/dns-query"
	}
	return s, nil
}

// Called under the map lock. A published snapshot never aliases a later map update.
func (c *tailscaleClient) publishDNSLocked() *tsDNSSnapshot {
	type node struct {
		ID                int64
		Name, Key         string
		Addresses, Routes []netip.Prefix
		Expiry            time.Time
		Invalid           bool
		Services          []tsService
	}
	nodes := make([]node, 0, len(c.nodes)+1)
	add := func(n tsNode) {
		v := node{ID: n.ID, Name: n.Name, Key: n.Key, Addresses: n.Addresses, Routes: n.AllowedIPs, Expiry: n.KeyExpiry, Invalid: n.Expired || n.restricted() || !n.KeyExpiry.IsZero() && !time.Now().Before(n.KeyExpiry)}
		if n.Hostinfo != nil {
			v.Services = n.Hostinfo.Services
		}
		nodes = append(nodes, v)
	}
	add(c.self)
	for _, n := range c.nodes {
		add(n)
	}
	slices.SortFunc(nodes, func(a, b node) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	config := c.dnsConfig
	// HTTPS authorization changes do not change DNS answers or upstreams.
	config.CertDomains = nil
	b, _ := json.Marshal(struct {
		Config tsDNSConfig
		Nodes  []node
	}{config, nodes})
	sum := sha256.Sum256(b)
	old := c.dns.Load()
	if old != nil && old.ctx.Err() == nil && strings.HasSuffix(old.key, hex.EncodeToString(sum[:])) {
		return nil
	}
	ctx, cancel := context.WithCancel(c.ctx)
	s := &tsDNSSnapshot{c: c, ctx: ctx, cancel: cancel, config: c.dnsConfig, hosts: map[string][]dnsRecord{}, ready: len(c.self.Addresses) > 0 && !c.self.Expired && !c.self.restricted(), selfExpires: c.self.KeyExpiry, upstreams: map[string]*tsDNSUpstream{}}
	epoch := newMasqueCacheEpoch()
	s.key = epoch + ":" + hex.EncodeToString(sum[:])
	if s.config.Proxied {
		_, s.root, _ = strings.Cut(canonicalDomain(c.self.Name), ".")
	}
	for _, n := range nodes {
		if n.Invalid {
			continue
		}
		if !n.Expiry.IsZero() && (s.expires.IsZero() || n.Expiry.Before(s.expires)) {
			s.expires = n.Expiry
		}
		name := canonicalDomain(n.Name)
		if !s.config.Proxied || !masqueDomain(name, false) {
			continue
		}
		for _, p := range n.Addresses {
			s.addHost(name, p.Addr())
		}
	}
	for _, rr := range s.config.ExtraRecords {
		if rr.Type == "" || rr.Type == "A" || rr.Type == "AAAA" {
			ip, _ := netip.ParseAddr(rr.Value)
			s.addHost(canonicalDomain(rr.Name), ip)
		}
	}
	groups := [][]*tsDNSResolver{s.config.Resolvers, s.config.FallbackResolvers}
	for _, rs := range s.config.Routes {
		groups = append(groups, rs)
	}
	for _, rs := range groups {
		for _, r := range rs {
			u, _ := tsDNSService(*r)
			if ip, err := netip.ParseAddr(u.Server); err == nil && !slices.Contains(s.addresses, ip) {
				s.addresses = append(s.addresses, ip)
			}
			for _, ip := range r.BootstrapResolution {
				if !slices.Contains(s.addresses, ip) {
					s.addresses = append(s.addresses, ip)
				}
			}
		}
	}
	c.dns.Store(s)
	return old
}

func (s *tsDNSSnapshot) addHost(name string, ip netip.Addr) {
	if !tsDNSAddress(ip) {
		return
	}
	typ := uint16(28)
	if ip.Is4() {
		typ = 1
	}
	s.hosts[name] = append(s.hosts[name], dnsRecord{name: name, typ: typ, class: 1, ttl: 600, data: ip.AsSlice()})
	ptr := tsDNSReverse(ip)
	target, _ := dnsAppendName(nil, name)
	if len(s.hosts[ptr]) == 0 {
		s.hosts[ptr] = []dnsRecord{{name: ptr, typ: 12, class: 1, ttl: 600, data: target}}
	}
}
func tsDNSReverse(ip netip.Addr) string {
	if ip.Is4() {
		v := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", v[3], v[2], v[1], v[0])
	}
	v := ip.As16()
	h := hex.EncodeToString(v[:])
	var b strings.Builder
	for i := len(h) - 1; i >= 0; i-- {
		b.WriteByte(h[i])
		b.WriteByte('.')
	}
	b.WriteString("ip6.arpa")
	return b.String()
}
func (s *tsDNSSnapshot) valid() bool {
	return s.ready && s.ctx.Err() == nil && (s.selfExpires.IsZero() || time.Now().Before(s.selfExpires))
}
func (s *tsDNSSnapshot) close() {
	s.cancel()
	s.mu.Lock()
	items := slices.Collect(maps.Values(s.upstreams))
	s.upstreams = nil
	s.mu.Unlock()
	for _, u := range items {
		u.wire.Close()
	}
}

func (c *tailscaleClient) dnsSnapshot(ctx context.Context) (*tsDNSSnapshot, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	s := c.dns.Load()
	if s != nil && !s.expires.IsZero() && !time.Now().Before(s.expires) {
		c.mu.Lock()
		old := c.publishDNSLocked()
		s = c.dns.Load()
		c.mu.Unlock()
		if old != nil {
			old.close()
		}
	}
	if s == nil || !s.valid() {
		return nil, errors.New("Tailscale DNS configuration is unavailable")
	}
	return s, nil
}

func (s *tsDNSSnapshot) route(host string) ([]*tsDNSResolver, bool) {
	best := -1
	var selected []*tsDNSResolver
	for suffix, rs := range s.config.Routes {
		suffix = canonicalDomain(suffix)
		if suffix == "" {
			continue
		}
		if (host == suffix || strings.HasSuffix(host, "."+suffix)) && len(suffix) > best {
			best = len(suffix)
			selected = rs
		}
	}
	return selected, best >= 0
}
func (s *tsDNSSnapshot) preferred(host string, search bool) bool {
	if _, ok := s.hosts[host]; ok {
		return true
	}
	if s.root != "" && (host == s.root || strings.HasSuffix(host, "."+s.root) || tsDNSPrivateReverse(host)) {
		return true
	}
	_, ok := s.route(host)
	return ok || search && !strings.Contains(host, ".") && len(s.config.Domains) > 0
}
func (s *tsDNSSnapshot) exchange(ctx context.Context, o DNSServer, q []byte) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	host, end, _, err := dnsQuestion(q)
	if err != nil {
		return nil, err
	}
	if o.AcceptSearchDomain && !strings.Contains(host, ".") {
		sections, err := dnsRecords(q)
		if err != nil {
			return nil, err
		}
		if !slices.ContainsFunc(sections[2], func(r dnsRecord) bool { return r.typ == 250 || r.typ == 24 }) {
			for _, domain := range s.config.Domains {
				name := host + "." + canonicalDomain(domain)
				wire, err := dnsAppendName(slices.Clone(q[:12]), name)
				if err != nil {
					continue
				}
				wire = append(wire, q[end-4:]...)
				b, err := s.exchangeName(ctx, o, wire)
				if err != nil {
					return nil, err
				}
				if b[3]&15 != 3 {
					return ocSearchReply(q, b, name)
				}
			}
		}
	}
	return s.exchangeName(ctx, o, q)
}
func (s *tsDNSSnapshot) exchangeName(ctx context.Context, o DNSServer, q []byte) ([]byte, error) {
	host, end, typ, err := dnsQuestion(q)
	if err != nil {
		return nil, err
	}
	if records, ok := s.hosts[host]; ok {
		out := dnsResponse(q, end, nil, 0, 0)
		ttl := uint32(600)
		if !s.expires.IsZero() {
			ttl = min(ttl, uint32(max(0, time.Until(s.expires)/time.Second)))
		}
		count := uint16(0)
		for _, rr := range records {
			if rr.typ != typ && typ != 255 {
				continue
			}
			if len(out)+len(host)+2+10+len(rr.data) > 65535 {
				out[2] |= 2
				break
			}
			out, _ = dnsAppendName(out, host)
			out = binary.BigEndian.AppendUint16(out, rr.typ)
			out = binary.BigEndian.AppendUint16(out, 1)
			out = binary.BigEndian.AppendUint32(out, ttl)
			out = binary.BigEndian.AppendUint16(out, uint16(len(rr.data)))
			out = append(out, rr.data...)
			count++
		}
		binary.BigEndian.PutUint16(out[6:], count)
		return out, nil
	}
	rs, matched := s.route(host)
	if matched && len(rs) == 0 || s.root != "" && (host == s.root || strings.HasSuffix(host, "."+s.root) || tsDNSPrivateReverse(host)) {
		return dnsResponse(q, end, nil, 0, 3), nil
	}
	if !matched {
		if !o.AcceptDefaultResolvers {
			return dnsResponse(q, end, nil, 0, 3), nil
		}
		rs = s.config.Resolvers
		for suffix, root := range s.config.Routes {
			if canonicalDomain(suffix) == "" {
				if len(root) == 0 {
					return dnsResponse(q, end, nil, 0, 3), nil
				}
				rs = root
			}
		}
		if len(rs) == 0 {
			rs = s.config.FallbackResolvers
		}
	}
	if s.c.o.ExitNode != "" {
		kept := slices.DeleteFunc(slices.Clone(rs), func(r *tsDNSResolver) bool { return !r.UseWithExitNode })
		if len(kept) == 0 {
			r, err := s.c.exitDNS()
			if err != nil {
				return nil, err
			}
			rs = []*tsDNSResolver{&r}
		} else {
			rs = kept
		}
	}
	if len(rs) == 0 {
		return s.c.r.resolver.localDNSMessage(ctx, q)
	}
	last := errors.New("Tailscale DNS has no usable resolver")
	for i, r := range rs {
		u, err := s.upstream(*r)
		if err != nil {
			return nil, err
		}
		call, cancel := ctx, func() {}
		if d, ok := ctx.Deadline(); ok {
			call, cancel = context.WithTimeout(ctx, time.Until(d)/time.Duration(len(rs)-i))
		}
		b, err := u.wire.exchangeOn(call, u.server, q)
		cancel()
		if err == nil {
			_, _, _, err = validateDNSQuestionResponse(q, b)
		}
		if err == nil {
			return b, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, last
}

func (s *tsDNSSnapshot) upstream(o tsDNSResolver) (*tsDNSUpstream, error) {
	b, _ := json.Marshal(o)
	key := string(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if u := s.upstreams[key]; u != nil {
		return u, nil
	}
	if len(s.upstreams) >= 256 {
		return nil, errors.New("Tailscale DNS connection pool capacity exceeded")
	}
	d, err := tsDNSService(o)
	if err != nil {
		return nil, err
	}
	r, err := newResolver(DNSConfig{Servers: []DNSServer{d}, DisableCache: true})
	if err != nil {
		return nil, err
	}
	r.cancel()
	r.ctx, r.cancel = context.WithCancel(s.ctx)
	u := &tsDNSUpstream{options: o, server: d, wire: r}
	r.tunnelDial = func(ctx context.Context, d DNSServer, network string) (net.Conn, error) {
		return s.dial(ctx, o, d, network)
	}
	s.upstreams[key] = u
	return u, nil
}
func (s *tsDNSSnapshot) dial(ctx context.Context, o tsDNSResolver, d DNSServer, network string) (net.Conn, error) {
	ips := o.BootstrapResolution
	if ip, err := netip.ParseAddr(d.Server); err == nil {
		ips = []netip.Addr{ip}
	} else if len(ips) == 0 {
		var err error
		ips, err = s.c.r.resolver.lookupMode(ctx, d.Server, true, "@local")
		if err != nil {
			return nil, err
		}
	}
	last := errors.New("Tailscale DNS bootstrap returned no address")
	for i, ip := range ips {
		call, cancel := ctx, func() {}
		if d, ok := ctx.Deadline(); ok {
			call, cancel = context.WithTimeout(ctx, time.Until(d)/time.Duration(len(ips)-i))
		}
		n, err := s.c.chooseRoute(ip, !o.UseWithExitNode)
		address := portAddress(ip.String(), d.ServerPort)
		if err == nil {
			p, e := s.c.peer(n)
			if e == nil {
				e = p.ensure(call)
			}
			if e == nil {
				var conn net.Conn
				conn, e = p.wg.stack.dial(call, network, address)
				cancel()
				if e == nil {
					return conn, nil
				}
			} else {
				cancel()
			}
			last = e
			continue
		}
		if d.Type == "http" || tsDNSPrivateIP(ip) || s.c.o.ExitNode != "" && !o.UseWithExitNode {
			cancel()
			last = err
			continue
		}
		conn, e := s.c.r.direct(call, network, address)
		cancel()
		if e == nil {
			return conn, nil
		}
		last = e
	}
	return nil, last
}

func tsDNSPrivateIP(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip) || netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(ip)
}

func tsDNSPrivateReverse(host string) bool {
	const v6 = "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"
	if host == v6 || strings.HasSuffix(host, "."+v6) {
		return true
	}
	v, ok := strings.CutSuffix(host, ".100.in-addr.arpa")
	if !ok {
		return false
	}
	i := strings.LastIndexByte(v, '.')
	if i >= 0 {
		v = v[i+1:]
	}
	n, err := strconv.Atoi(v)
	return err == nil && n >= 64 && n <= 127
}
func (c *tailscaleClient) exitDNS() (tsDNSResolver, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.nodes {
		if !tsExitNodeMatches(n, c.o.ExitNode) || n.Expired || n.restricted() || !n.KeyExpiry.IsZero() && !time.Now().Before(n.KeyExpiry) {
			continue
		}
		if !slices.ContainsFunc(n.AllowedIPs, func(p netip.Prefix) bool { return p.Bits() == 0 }) {
			return tsDNSResolver{}, errors.New("Tailscale DNS exit has no approved default route")
		}
		if n.Hostinfo != nil {
			for _, service := range n.Hostinfo.Services {
				if service.Port == 0 || service.Proto != "peerapi4" && service.Proto != "peerapi6" {
					continue
				}
				for _, p := range n.Addresses {
					if p.Addr().Is4() == (service.Proto == "peerapi4") {
						return tsDNSResolver{Addr: "http://" + portAddress(p.Addr().String(), service.Port) + "/dns-query"}, nil
					}
				}
			}
		}
	}
	return tsDNSResolver{}, errors.New("Tailscale DNS exit peer API is unavailable")
}
