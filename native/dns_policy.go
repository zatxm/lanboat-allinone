package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type DNSRule struct {
	Race               bool     `json:"race,omitempty"`
	Speculative        bool     `json:"speculative,omitempty"`
	Tag                string   `json:"tag,omitempty"`
	RCode              string   `json:"rcode,omitempty"`
	Answer             []string `json:"answer,omitempty"`
	NS                 []string `json:"ns,omitempty"`
	Extra              []string `json:"extra,omitempty"`
	RemoveClientSubnet bool     `json:"remove_client_subnet,omitempty"`
	Rule
	Server     string  `json:"server,omitempty"`
	RewriteTTL *uint32 `json:"rewrite_ttl,omitempty"`
}
type dnsPolicy struct {
	rule    routeRule
	options DNSRule
}
type dnsBootstrapKey struct{}
type dnsInboundKey struct{}

func compileDNSRules(config DNSConfig, route Route, sets map[string]*ruleCollection) ([]dnsPolicy, error) {
	var policies []dnsPolicy
	for _, rule := range config.Rules {
		if rule.Outbound != "" {
			return nil, errors.New("DNS rules select server, not outbound")
		}
		condition := rule.Rule
		condition.Action = ""
		condition.Outbound = "_"
		cfg := Route{dnsRules: true, Final: "_", Rules: []Rule{condition}, RuleSet: route.RuleSet}
		var rules []routeRule
		var err error
		if sets == nil {
			rules, err = compileRoute(cfg, map[string]Outbound{"_": {Type: "direct", Tag: "_"}})
		} else {
			rules, err = compileRoute(cfg, map[string]Outbound{"_": {Type: "direct", Tag: "_"}}, sets)
		}
		if err != nil {
			return nil, err
		}
		policies = append(policies, dnsPolicy{rule: rules[0], options: rule})
	}
	return policies, nil
}
func (r *resolver) dialDNS(ctx context.Context, server DNSServer, network string) (net.Conn, error) {
	if r.tunnelDial != nil {
		return r.tunnelDial(ctx, server, network)
	}
	ctx, cancel := server.DomainResolver.apply(ctx)
	defer cancel()
	port := server.ServerPort
	if port == 0 {
		port = 53
		if server.Type == "tls" || server.Type == "quic" {
			port = 853
		}
		if server.Type == "https" || server.Type == "h3" {
			port = 443
		}
	}
	host := server.Server
	if _, err := netip.ParseAddr(host); err != nil {
		forced := server.DomainResolver.tag()
		if forced == "" {
			forced = "@local"
		}
		ips, err := r.lookupMode(ctx, host, true, forced)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, errors.New("DNS bootstrap returned no addresses")
		}
		host = ips[0].String()
	}
	address := portAddress(host, port)
	if server.Detour != "" {
		if r.runtime == nil {
			return nil, errors.New("DNS detour requires runtime")
		}
		bootstrap := server.DomainResolver.tag()
		if bootstrap == "" {
			bootstrap = "@local"
		}
		return r.runtime.dialOutbound(context.WithValue(ctx, dnsBootstrapKey{}, bootstrap), server.Detour, network, address)
	}
	if server.namespace != nil || server.NetworkOptions.active() {
		return r.runtime.dialSocket(ctx, server.DialOptions, network, address)
	}
	dialer, err := r.runtime.newDialer(server.DialOptions, network, address)
	if err != nil {
		return nil, err
	}
	if index, ok := ctx.Value(resolvedLinkIndexKey{}).(int32); ok {
		control := dialer.Control
		dialer.Control = func(network, address string, raw syscall.RawConn) error {
			if control != nil {
				if e := control(network, address, raw); e != nil {
					return e
				}
			}
			return resolvedBindLink(raw, index)
		}
	}
	return dialer.DialContext(ctx, network, address)
}

type fakeEntry struct {
	host  string
	until time.Time
}
type fakePool struct {
	mu           sync.Mutex
	v4, v6       netip.Prefix
	next4, next6 netip.Addr
	byHost       map[string]netip.Addr
	byIP         map[netip.Addr]fakeEntry
	capacity     int
}

func newFakePool(server DNSServer, capacity int) (*fakePool, error) {
	if server.Inet4Range == "" {
		server.Inet4Range = "198.18.0.0/15"
	}
	if server.Inet6Range == "" {
		server.Inet6Range = "fc00::/18"
	}
	v4, err := netip.ParsePrefix(server.Inet4Range)
	if err != nil || !v4.Addr().Is4() || v4.Bits() > 30 {
		return nil, errors.New("invalid FakeIP IPv4 range")
	}
	v6, err := netip.ParsePrefix(server.Inet6Range)
	if err != nil || !v6.Addr().Is6() || v6.Bits() > 126 {
		return nil, errors.New("invalid FakeIP IPv6 range")
	}
	if capacity == 0 {
		capacity = 16384
	}
	return &fakePool{v4: v4.Masked(), v6: v6.Masked(), next4: v4.Masked().Addr().Next(), next6: v6.Masked().Addr().Next(), byHost: map[string]netip.Addr{}, byIP: map[netip.Addr]fakeEntry{}, capacity: capacity}, nil
}
func (p *fakePool) allocate(host string, typ uint16, ttl ...uint32) (netip.Addr, error) {
	if typ != 1 && typ != 28 {
		return netip.Addr{}, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	hold := 10 * time.Minute
	if len(ttl) > 0 {
		hold = max(hold, time.Duration(ttl[0])*time.Second+time.Minute)
	}
	key := host + ":" + strconv.Itoa(int(typ))
	if ip, ok := p.byHost[key]; ok {
		entry := p.byIP[ip]
		entry.until = maxTime(entry.until, now.Add(hold))
		p.byIP[ip] = entry
		return ip, nil
	}
	if len(p.byIP) >= p.capacity {
		for ip, entry := range p.byIP {
			if now.After(entry.until) {
				delete(p.byIP, ip)
				typ := 1
				if ip.Is6() {
					typ = 28
				}
				delete(p.byHost, entry.host+":"+strconv.Itoa(typ))
			}
		}
	}
	if len(p.byIP) >= p.capacity {
		return netip.Addr{}, errors.New("FakeIP pool is full; active mappings are retained")
	}
	next, prefix := &p.next4, p.v4
	if typ == 28 {
		next, prefix = &p.next6, p.v6
	}
	for range p.capacity + 1 {
		ip := *next
		*next = next.Next()
		if !prefix.Contains(*next) {
			*next = prefix.Addr().Next()
		}
		if _, used := p.byIP[ip]; used {
			continue
		}
		p.byIP[ip] = fakeEntry{host: host, until: now.Add(hold)}
		p.byHost[key] = ip
		return ip, nil
	}
	return netip.Addr{}, errors.New("FakeIP address range exhausted")
}
func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}
func (r *resolver) reverseFake(ip netip.Addr) (string, bool) {
	for _, pool := range r.pools {
		pool.mu.Lock()
		entry, ok := pool.byIP[ip]
		if ok && time.Now().Before(entry.until) {
			pool.mu.Unlock()
			return entry.host, true
		}
		pool.mu.Unlock()
	}
	return "", false
}
func (r *resolver) isFake(ip netip.Addr) bool {
	for _, pool := range r.pools {
		if pool.v4.Contains(ip) || pool.v6.Contains(ip) {
			return true
		}
	}
	return false
}

// ExchangeDNS applies policy to a DNS message; used by DNS listeners and tunnel adapters.
func (r *Runtime) ExchangeDNS(ctx context.Context, query []byte, inbound string) ([]byte, error) {
	ctx = context.WithValue(ctx, dnsInboundKey{}, inbound)
	return r.resolver.exchangePolicy(ctx, query, false)
}

func dnsQuestion(query []byte) (string, int, uint16, error) {
	if len(query) < 12 || len(query) > 65535 || query[2]&0xf8 != 0 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return "", 0, 0, errors.New("invalid DNS query")
	}
	name, end, err := dnsName(query, 12)
	if err != nil || end+4 > len(query) {
		return "", 0, 0, errors.New("invalid DNS question")
	}
	if binary.BigEndian.Uint16(query[end+2:]) != 1 {
		return "", 0, 0, errors.New("unsupported DNS class")
	}
	return name, end + 4, binary.BigEndian.Uint16(query[end:]), nil
}
func dnsResponse(query []byte, end int, ips []netip.Addr, ttl uint32, rcode byte) []byte {
	reply := append([]byte(nil), query[:end]...)
	reply[2] = 0x80 | (query[2] & 1)
	reply[3] = 0x80 | rcode
	binary.BigEndian.PutUint16(reply[6:8], uint16(len(ips)))
	clear(reply[8:12])
	typ := binary.BigEndian.Uint16(query[end-4:])
	for _, ip := range ips {
		if typ == 1 {
			ip = ip.Unmap()
		}
		reply = append(reply, 0xc0, 12)
		reply = binary.BigEndian.AppendUint16(reply, typ)
		reply = binary.BigEndian.AppendUint16(reply, 1)
		reply = binary.BigEndian.AppendUint32(reply, ttl)
		data := ip.AsSlice()
		reply = binary.BigEndian.AppendUint16(reply, uint16(len(data)))
		reply = append(reply, data...)
	}
	return reply
}
func validateDNSQuestionResponse(query, reply []byte) (string, int, uint16, error) {
	name, end, typ, err := dnsQuestion(query)
	if err != nil {
		return "", 0, 0, err
	}
	if len(reply) < 12 || reply[0] != query[0] || reply[1] != query[1] || reply[2]&0x80 == 0 || binary.BigEndian.Uint16(reply[4:6]) != 1 {
		return "", 0, 0, errors.New("DNS response identity mismatch")
	}
	got, off, err := dnsName(reply, 12)
	if err != nil || off+4 > len(reply) || name != got || !slices.Equal(query[end-4:end], reply[off:off+4]) {
		return "", 0, 0, errors.New("DNS response question mismatch")
	}
	return name, off + 4, typ, nil
}

type queryTypes []uint16

func (q *queryTypes) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		raw = []json.RawMessage{data}
	}
	for _, value := range raw {
		var number uint16
		if json.Unmarshal(value, &number) == nil {
			*q = append(*q, number)
			continue
		}
		var name string
		if err := json.Unmarshal(value, &name); err != nil {
			return err
		}
		if strings.EqualFold(name, "ANY") {
			number = 255
		} else {
			var err error
			number, err = dnsTextType(name)
			if err != nil {
				return fmt.Errorf("unknown DNS query type %q", name)
			}
		}
		*q = append(*q, number)
	}
	return nil
}
