package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ServiceOptions struct {
	Type       string `json:"type"`
	Tag        string `json:"tag,omitempty"`
	Listen     string `json:"listen,omitempty"`
	ListenPort uint16 `json:"listen_port,omitempty"`
}

func (c *Config) prepareResolved() error {
	seen := map[string]bool{}
	for _, in := range c.Inbounds {
		seen[in.Tag] = true
	}
	for i := range c.Services {
		s := &c.Services[i]
		if s.Type != "resolved" {
			return fmt.Errorf("unsupported service %q", s.Type)
		}
		if runtime.GOOS != "linux" {
			return errors.New("resolved service requires Linux")
		}
		if i != 0 {
			return errors.New("only one resolved service can own the system D-Bus name")
		}
		if s.Tag == "" {
			s.Tag = "resolved"
		}
		if seen[s.Tag] {
			return errors.New("resolved service tag conflicts with an inbound")
		}
		seen[s.Tag] = true
		if s.Listen == "" {
			s.Listen = "127.0.0.53"
		}
		if s.ListenPort == 0 {
			s.ListenPort = 53
		}
		if ip, e := netip.ParseAddr(s.Listen); e != nil || ip.IsUnspecified() || ip.IsMulticast() {
			return errors.New("resolved listen must be a unicast IP address")
		}
	}
	for _, s := range c.DNS.Servers {
		if s.Type == "resolved" {
			found := false
			for _, service := range c.Services {
				found = found || service.Tag == s.Service
			}
			if !found {
				return fmt.Errorf("resolved DNS references unknown service %q", s.Service)
			}
		}
	}
	return nil
}

type resolvedDomain struct {
	name      string
	routeOnly bool
}
type resolvedServer struct {
	ip   netip.Addr
	port uint16
	name string
}
type resolvedLink struct {
	index        int32
	servers      []resolvedServer
	domains      []resolvedDomain
	defaultRoute bool
	tls          string
}
type resolvedSnapshot struct {
	links []resolvedLink
	key   string
}
type resolvedDNSKey struct{ service string }
type resolvedIfIndexKey struct{}
type resolvedLinkIndexKey struct{}
type resolvedService struct {
	owner   *Runtime
	options ServiceOptions
	bus     *resolvedBus
	mu      sync.Mutex
	links   map[int32]resolvedLink
	version uint64
	epoch   string
	state   atomic.Pointer[resolvedSnapshot]
}

func newResolvedService(owner *Runtime, s ServiceOptions) *resolvedService {
	r := &resolvedService{owner: owner, options: s, links: map[int32]resolvedLink{}, epoch: strconv.FormatInt(time.Now().UnixNano(), 36)}
	r.publish()
	return r
}
func (s *resolvedService) publish() {
	s.version++
	state := &resolvedSnapshot{links: slices.Collect(maps.Values(s.links)), key: s.epoch + ":" + strconv.FormatUint(s.version, 36)}
	slices.SortFunc(state.links, func(a, b resolvedLink) int { return int(a.index) - int(b.index) })
	s.state.Store(state)
}
func (s *resolvedService) change(index int32, update func(*resolvedLink) error) error {
	if index <= 0 {
		return errors.New("link index must be positive")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	link, exists := s.links[index]
	if !exists && len(s.links) >= 256 {
		return errors.New("resolved link limit reached")
	}
	link.index = index
	if e := update(&link); e != nil {
		return e
	}
	s.links[index] = link
	s.publish()
	return nil
}
func (s *resolvedService) start() error {
	b, e := connectResolvedBus(s.owner.ctx)
	if e != nil {
		return e
	}
	s.bus = b
	b.workers.Go(func() {
		defer func() {
			s.mu.Lock()
			clear(s.links)
			s.publish()
			s.mu.Unlock()
			if s.owner.ctx.Err() == nil {
				s.owner.logger.Warn("resolved D-Bus disconnected")
			}
		}()
		active := make(chan struct{}, 16)
		for {
			select {
			case <-b.ctx.Done():
				return
			case request := <-b.requests:
				select {
				case active <- struct{}{}:
					b.workers.Go(func() { defer func() { <-active }(); s.handle(request) })
				default:
					b.respond(request, "", "", nil, "org.freedesktop.DBus.Error.LimitsExceeded", "too many active resolved requests")
				}
			}
		}
	})
	return nil
}
func (s *resolvedService) close() {
	if s.bus != nil {
		s.bus.close()
	}
	s.mu.Lock()
	clear(s.links)
	s.publish()
	s.mu.Unlock()
}
func (s *resolvedSnapshot) candidates(host string, index int32, acceptDefault bool) ([]resolvedLink, bool) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	best := -1
	var out []resolvedLink
	for _, link := range s.links {
		if index != 0 && index != link.index {
			continue
		}
		score := -1
		for _, d := range link.domains {
			if d.name != "." && (host == d.name || strings.HasSuffix(host, "."+d.name)) {
				score = max(score, len(d.name))
			}
		}
		if score < 0 && acceptDefault {
			for _, d := range link.domains {
				if d.name == "." {
					score = 0
				}
			}
			if link.defaultRoute {
				score = max(score, 0)
			}
		}
		if score < 0 {
			continue
		}
		if score > best {
			out = nil
			best = score
		}
		if score == best {
			out = append(out, link)
		}
	}
	return out, best > 0
}
func (s *resolvedSnapshot) network() dnsNetworkState {
	state := dnsNetworkState{key: s.key}
	for _, link := range s.links {
		for _, server := range link.servers {
			state.addresses = append(state.addresses, server.ip.WithZone(""))
		}
		for _, d := range link.domains {
			state.domains = append(state.domains, d.name)
		}
	}
	return state
}
func (r *resolver) exchangeResolvedDNS(ctx context.Context, options DNSServer, query []byte) ([]byte, error) {
	s := r.runtime.resolved[options.Service]
	state, _ := ctx.Value(resolvedDNSKey{options.Service}).(*resolvedSnapshot)
	if state == nil {
		state = s.state.Load()
	}
	host, end, _, err := dnsQuestion(query)
	if err != nil {
		return nil, err
	}
	index, _ := ctx.Value(resolvedIfIndexKey{}).(int32)
	links, _ := state.candidates(host, index, options.AcceptDefaultResolvers)
	if len(links) == 0 {
		return dnsResponse(query, end, nil, 0, 3), nil
	}
	last := errors.New("resolved DNS query failed")
	for i, link := range links {
		for j, server := range link.servers {
			call, cancel := ctx, func() {}
			if deadline, ok := ctx.Deadline(); ok {
				remaining := len(link.servers) - j
				for _, rest := range links[i+1:] {
					remaining += len(rest.servers)
				}
				call, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(remaining))
			}
			upstream := DNSServer{Type: "udp", Server: server.ip.String(), ServerPort: server.port}
			call = context.WithValue(call, resolvedLinkIndexKey{}, link.index)
			if link.tls == "yes" || link.tls == "opportunistic" {
				upstream.Type = "tls"
				upstream.TLS = TLSOptions{Enabled: true, ServerName: server.name}
			}
			reply, e := r.exchangeOn(call, upstream, query)
			if e != nil && link.tls == "opportunistic" {
				upstream.Type = "udp"
				reply, e = r.exchangeOn(call, upstream, query)
			}
			cancel()
			if e == nil {
				_, _, _, e = validateDNSQuestionResponse(query, reply)
			}
			if e == nil {
				return reply, nil
			}
			last = e
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
	}
	return nil, last
}

func (s *resolvedService) handle(m busMessage) {
	b := s.bus
	fail := func(name, detail string) { b.respond(m, "", "", nil, name, detail) }
	if m.sender == "" || m.path != resolvedPath {
		fail("org.freedesktop.DBus.Error.UnknownObject", "unknown resolved object")
		return
	}
	if m.iface == "org.freedesktop.DBus.Peer" && m.member == "Ping" && m.signature == "" {
		b.respond(m, "", "", nil, "", "")
		return
	}
	if m.iface != "" && m.iface != resolvedInterface {
		fail("org.freedesktop.DBus.Error.UnknownInterface", "unknown resolved interface")
		return
	}
	ctx, cancel := context.WithTimeout(b.ctx, 15*time.Second)
	defer cancel()
	var sig string
	var values []any
	var err error
	switch m.member {
	case "ResolveHostname", "ResolveAddress", "ResolveRecord", "ResolveService":
		sig, values, err = s.resolve(ctx, m)
	default:
		// The bus authenticates sender names. Only root or this process's UID may mutate DNS.
		cred, e := b.call(ctx, "GetConnectionUnixUser", "s", []any{m.sender})
		if e != nil || cred.signature != "u" || len(cred.values) != 1 {
			fail("org.freedesktop.DBus.Error.AccessDenied", "cannot authenticate D-Bus caller")
			return
		}
		uid := cred.values[0].(uint32)
		if !resolvedCallerAllowed(uid) {
			fail("org.freedesktop.DBus.Error.AccessDenied", "resolved configuration requires root or service owner")
			return
		}
		err = s.configure(m)
	}
	if err != nil {
		name := "org.freedesktop.DBus.Error.InvalidArgs"
		var method *resolvedMethodError
		if errors.As(err, &method) {
			name = method.name
		}
		fail(name, err.Error())
		return
	}
	b.respond(m, "", sig, values, "", "")
}

type resolvedMethodError struct{ name, detail string }

func resolvedCallerAllowed(uid uint32) bool  { return uid == 0 || uid == uint32(os.Getuid()) }
func (e *resolvedMethodError) Error() string { return e.detail }
func resolvedUnsupported(detail string) error {
	return &resolvedMethodError{"org.freedesktop.DBus.Error.NotSupported", detail}
}

func (s *resolvedService) configure(m busMessage) error {
	if m.member == "FlushCaches" && m.signature == "" {
		r := s.owner.resolver
		r.mu.Lock()
		clear(r.wireCache)
		r.cacheEpoch.Add(1)
		if r.wireLRU != nil {
			r.wireLRU.Init()
		}
		r.dirtyDNS(1)
		r.mu.Unlock()
		s.mu.Lock()
		s.publish()
		s.mu.Unlock()
		return nil
	}
	expected := map[string]string{"SetLinkDNS": "ia(iay)", "SetLinkDNSEx": "ia(iayqs)", "SetLinkDomains": "ia(sb)", "SetLinkDefaultRoute": "ib", "SetLinkDNSOverTLS": "is", "SetLinkLLMNR": "is", "SetLinkMulticastDNS": "is", "SetLinkDNSSEC": "is", "SetLinkDNSSECNegativeTrustAnchors": "ias", "RevertLink": "i"}
	sig, ok := expected[m.member]
	if !ok {
		return &resolvedMethodError{"org.freedesktop.DBus.Error.UnknownMethod", "unknown resolved method"}
	}
	if m.signature != sig {
		return errors.New("incorrect resolved method signature")
	}
	index := m.values[0].(int32)
	if m.member == "RevertLink" {
		if index <= 0 {
			return errors.New("invalid link index")
		}
		s.mu.Lock()
		delete(s.links, index)
		s.publish()
		s.mu.Unlock()
		return nil
	}
	return s.change(index, func(link *resolvedLink) error {
		switch m.member {
		case "SetLinkDNS", "SetLinkDNSEx":
			items := m.values[1].([]any)
			if len(items) > 128 {
				return errors.New("too many DNS servers")
			}
			servers := make([]resolvedServer, 0, len(items))
			for _, item := range items {
				v := item.([]any)
				family, raw := v[0].(int32), v[1].([]byte)
				ip, valid := netip.AddrFromSlice(raw)
				if !valid || family != 2 && family != 10 || family == 2 && len(raw) != 4 || family == 10 && len(raw) != 16 || ip.IsUnspecified() || ip.IsMulticast() {
					return errors.New("invalid resolved DNS address")
				}
				if ip.Is6() && ip.IsLinkLocalUnicast() {
					ip = ip.WithZone(strconv.Itoa(int(index)))
				}
				ns := resolvedServer{ip: ip}
				if len(v) == 4 {
					ns.port, ns.name = v[2].(uint16), v[3].(string)
					if ns.name != "" {
						if _, e := makeDNSQuery(ns.name, 1); e != nil {
							return e
						}
					}
				}
				port := ns.port
				if port == 0 {
					port = 53
				}
				listen, _ := netip.ParseAddr(s.options.Listen)
				if ip.Unmap() == listen.Unmap() && port == s.options.ListenPort {
					return errors.New("resolved upstream cannot be its own DNS stub")
				}
				servers = append(servers, ns)
			}
			link.servers = servers
		case "SetLinkDomains":
			items := m.values[1].([]any)
			if len(items) > 128 {
				return errors.New("too many resolved domains")
			}
			domains := make([]resolvedDomain, 0, len(items))
			for _, item := range items {
				v := item.([]any)
				name := strings.ToLower(strings.TrimSuffix(v[0].(string), "."))
				if name == "" {
					name = "."
				}
				if _, e := makeDNSQuery(name, 1); e != nil {
					return e
				}
				domains = append(domains, resolvedDomain{name, v[1].(bool)})
			}
			link.domains = domains
		case "SetLinkDefaultRoute":
			link.defaultRoute = m.values[1].(bool)
		case "SetLinkDNSOverTLS":
			mode := m.values[1].(string)
			if mode != "" && mode != "no" && mode != "yes" && mode != "opportunistic" {
				return errors.New("invalid DNS-over-TLS mode")
			}
			link.tls = mode
		case "SetLinkLLMNR", "SetLinkMulticastDNS", "SetLinkDNSSEC":
			if mode := m.values[1].(string); mode != "" && mode != "no" {
				return resolvedUnsupported(m.member + " enabled mode is not provided by the unicast DNS service")
			}
		case "SetLinkDNSSECNegativeTrustAnchors":
			if len(m.values[1].([]any)) != 0 {
				return resolvedUnsupported("DNSSEC negative trust anchors require a validating resolver")
			}
		}
		return nil
	})
}

func (s *resolvedService) query(ctx context.Context, index int32, name string, typ, class uint16, flags uint64) ([]dnsRecord, error) {
	if index < 0 || typ == 0 || class == 0 {
		return nil, errors.New("invalid interface index")
	}
	// DNS only; do not claim LLMNR, mDNS or DNSSEC validation for ordinary replies.
	const supported = uint64(1 | 32 | 64 | 128 | 256 | 1024 | 4096 | 8192 | 16384)
	if flags & ^supported != 0 {
		return nil, resolvedUnsupported("unsupported resolved query flags")
	}
	query, e := makeDNSQuery(name, typ)
	if e != nil {
		return nil, e
	}
	binary.BigEndian.PutUint16(query[len(query)-2:], class)
	ctx = context.WithValue(ctx, resolvedIfIndexKey{}, index)
	if flags&4096 != 0 {
		ctx = context.WithValue(ctx, dnsNoCacheKey{}, true)
	}
	reply, e := s.owner.ExchangeDNS(ctx, query, s.options.Tag)
	if e != nil {
		return nil, &resolvedMethodError{resolvedName + ".DNSError.SERVFAIL", e.Error()}
	}
	if code := reply[3] & 15; code != 0 {
		name := "SERVFAIL"
		if code == 3 {
			name = "NXDOMAIN"
		}
		return nil, &resolvedMethodError{resolvedName + ".DNSError." + name, "DNS returned " + name}
	}
	records, e := dnsRecords(reply)
	if flags&32 != 0 {
		for _, rr := range records[0] {
			if rr.typ == 5 || rr.typ == 39 {
				return nil, &resolvedMethodError{resolvedName + ".CNameLoop", "CNAME/DNAME lookup disabled"}
			}
		}
	}
	return records[0], e
}
func (s *resolvedService) resolve(ctx context.Context, m busMessage) (string, []any, error) {
	bad := func() (string, []any, error) { return "", nil, errors.New("incorrect resolved query signature") }
	switch m.member {
	case "ResolveHostname":
		if m.signature != "isit" {
			return bad()
		}
		index, name, family, flags := m.values[0].(int32), m.values[1].(string), m.values[2].(int32), m.values[3].(uint64)
		if family != 0 && family != 2 && family != 10 {
			return bad()
		}
		var out []any
		var canonical string
		var e error
		names := []string{name}
		if !strings.Contains(name, ".") && flags&256 == 0 {
			names = nil
			for _, link := range s.state.Load().links {
				if index != 0 && link.index != index {
					continue
				}
				for _, d := range link.domains {
					if !d.routeOnly && d.name != "." {
						names = append(names, name+"."+d.name)
					}
				}
			}
			names = append(names, name)
		}
		for _, candidate := range names {
			out, canonical, e = s.resolveHost(ctx, index, candidate, family, flags)
			if e == nil {
				break
			}
			if ctx.Err() != nil {
				return "", nil, ctx.Err()
			}
		}
		if e != nil {
			return "", nil, e
		}
		return "a(iiay)st", []any{out, canonical, uint64(1)}, nil
	case "ResolveAddress":
		if m.signature != "iiayt" {
			return bad()
		}
		index, family, raw, flags := m.values[0].(int32), m.values[1].(int32), m.values[2].([]byte), m.values[3].(uint64)
		ip, valid := netip.AddrFromSlice(raw)
		if !valid || family == 2 && len(raw) != 4 || family == 10 && len(raw) != 16 || family != 2 && family != 10 {
			return bad()
		}
		name := resolvedReverseName(ip)
		records, e := s.query(ctx, index, name, 12, 1, flags)
		if e != nil {
			return "", nil, e
		}
		var out []any
		for _, rr := range records {
			if rr.typ == 12 && strings.EqualFold(rr.name, strings.TrimSuffix(name, ".")) {
				name, _, e := dnsName(rr.data, 0)
				if e != nil {
					return "", nil, e
				}
				out = append(out, []any{index, name})
			}
		}
		if len(out) == 0 {
			return "", nil, &resolvedMethodError{resolvedName + ".NoSuchResourceRecord", "no reverse address records"}
		}
		return "a(is)t", []any{out, uint64(1)}, nil
	case "ResolveRecord":
		if m.signature != "isqqt" {
			return bad()
		}
		index, name, class, typ, flags := m.values[0].(int32), m.values[1].(string), m.values[2].(uint16), m.values[3].(uint16), m.values[4].(uint64)
		records, e := s.query(ctx, index, name, typ, class, flags)
		if e != nil {
			return "", nil, e
		}
		var out []any
		for _, rr := range records {
			if rr.typ != typ && typ != 255 || rr.class != class && class != 255 {
				continue
			}
			wire, e := dnsAppendName(nil, rr.name)
			if e != nil {
				return "", nil, e
			}
			wire = binary.BigEndian.AppendUint16(wire, rr.typ)
			wire = binary.BigEndian.AppendUint16(wire, rr.class)
			wire = binary.BigEndian.AppendUint32(wire, rr.ttl)
			wire = binary.BigEndian.AppendUint16(wire, uint16(len(rr.data)))
			wire = append(wire, rr.data...)
			out = append(out, []any{index, rr.class, rr.typ, wire})
		}
		if len(out) == 0 {
			return "", nil, &resolvedMethodError{resolvedName + ".NoSuchResourceRecord", "no matching records"}
		}
		return "a(iqqay)t", []any{out, uint64(1)}, nil
	case "ResolveService":
		if m.signature != "isssit" {
			return bad()
		}
		return s.resolveService(ctx, m.values)
	default:
		return bad()
	}
}

func (s *resolvedService) resolveHost(ctx context.Context, index int32, name string, family int32, flags uint64) ([]any, string, error) {
	var out []any
	canonical := strings.TrimSuffix(name, ".") + "."
	var last error
	for _, q := range []struct {
		family int32
		typ    uint16
		size   int
	}{{2, 1, 4}, {10, 28, 16}} {
		if family != 0 && family != q.family {
			continue
		}
		current := name
		for hop := 0; hop < 16; hop++ {
			records, e := s.query(ctx, index, current, q.typ, 1, flags)
			if e != nil {
				last = e
				break
			}
			next := ""
			before := len(out)
			for _, rr := range records {
				if rr.typ == 5 && strings.EqualFold(rr.name, strings.TrimSuffix(current, ".")) {
					next, _, e = dnsName(rr.data, 0)
					if e != nil {
						return nil, "", e
					}
				}
			}
			target := current
			if next != "" {
				target = next
			}
			for _, rr := range records {
				if rr.typ == q.typ && len(rr.data) == q.size && strings.EqualFold(rr.name, strings.TrimSuffix(target, ".")) {
					out = append(out, []any{index, q.family, rr.data})
				}
			}
			if next != "" {
				canonical = strings.TrimSuffix(next, ".") + "."
			}
			if len(out) > before || next == "" {
				break
			}
			if hop == 15 || strings.EqualFold(next, current) {
				return nil, "", &resolvedMethodError{resolvedName + ".CNameLoop", "CNAME chain limit"}
			}
			current = next
		}
	}
	if len(out) > 0 {
		return out, canonical, nil
	}
	if last == nil {
		last = &resolvedMethodError{resolvedName + ".NoSuchResourceRecord", "no address records"}
	}
	return nil, "", last
}
func (s *resolvedService) resolveService(ctx context.Context, values []any) (string, []any, error) {
	index, name, service, domain, family, flags := values[0].(int32), values[1].(string), values[2].(string), values[3].(string), values[4].(int32), values[5].(uint64)
	if family != 0 && family != 2 && family != 10 {
		return "", nil, errors.New("invalid address family")
	}
	if !strings.HasPrefix(service, "_") || !strings.HasSuffix(service, "._tcp") && !strings.HasSuffix(service, "._udp") {
		return "", nil, errors.New("invalid DNS service type")
	}
	queryName := service + "." + strings.TrimSuffix(domain, ".")
	if name != "" {
		if strings.ContainsAny(name, ".\\\x00") {
			return "", nil, errors.New("invalid DNS service instance")
		}
		queryName = name + "." + queryName
	}
	records, e := s.query(ctx, index, queryName, 33, 1, flags)
	if e != nil {
		return "", nil, e
	}
	var out, txt []any
	for _, rr := range records {
		if rr.typ != 33 || len(rr.data) < 7 || !strings.EqualFold(rr.name, queryName) {
			continue
		}
		host, _, e := dnsName(rr.data, 6)
		if e != nil {
			return "", nil, e
		}
		if host == "" || host == "." {
			continue
		}
		var addresses []any
		canonical := strings.TrimSuffix(host, ".") + "."
		if flags&128 == 0 {
			addresses, canonical, e = s.resolveHost(ctx, index, host, family, flags|256)
			if e != nil {
				continue
			}
		}
		out = append(out, []any{binary.BigEndian.Uint16(rr.data), binary.BigEndian.Uint16(rr.data[2:]), binary.BigEndian.Uint16(rr.data[4:]), host, addresses, canonical})
		if len(out) >= 128 {
			return "", nil, &resolvedMethodError{"org.freedesktop.DBus.Error.LimitsExceeded", "too many DNS service records"}
		}
	}
	if len(out) == 0 {
		return "", nil, &resolvedMethodError{resolvedName + ".NoSuchResourceRecord", "no service records"}
	}
	if flags&64 == 0 {
		records, e = s.query(ctx, index, queryName, 16, 1, flags)
		if e != nil {
			return "", nil, e
		}
		for _, rr := range records {
			if rr.typ != 16 {
				continue
			}
			for pos := 0; pos < len(rr.data); {
				n := int(rr.data[pos])
				pos++
				if n > len(rr.data)-pos {
					return "", nil, errors.New("invalid DNS TXT")
				}
				txt = append(txt, slices.Clone(rr.data[pos:pos+n]))
				pos += n
			}
		}
	}
	return "a(qqqsa(iiay)s)aayssst", []any{out, txt, name, service, strings.TrimSuffix(domain, ".") + ".", uint64(1)}, nil
}

func resolvedReverseName(ip netip.Addr) string {
	if ip.Is4() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", b[3], b[2], b[1], b[0])
	}
	b := ip.As16()
	var out strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&out, "%x.%x.", b[i]&15, b[i]>>4)
	}
	return out.String() + "ip6.arpa"
}
