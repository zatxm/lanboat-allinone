package native

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Metadata supplies information known by an embedding application or tunnel adapter.
// Empty platform metadata never matches a condition that requires that metadata.
type Metadata struct {
	networkChoices                           []networkChoice
	SourceMACAddress                         string  `json:",omitempty"`
	SourceHostname                           string  `json:",omitempty"`
	UserID                                   *uint32 `json:",omitempty"`
	User                                     string  `json:",omitempty"`
	ClashMode                                string  `json:",omitempty"`
	DNSPreferredBy                           []string
	Domain, Protocol, Client, AuthUser       string
	ProcessName, ProcessPath, PackageName    string
	NetworkType, WiFiSSID, WiFiBSSID         string
	NetworkIsExpensive, NetworkIsConstrained bool
	NetworkInterfaceAddress                  map[string][]netip.Addr
	DefaultInterfaceAddress                  []netip.Addr
	DNSServerAddress                         map[string][]netip.Addr
	DNSSearchDomain                          map[string][]string
}
type metadataKey struct{}

func WithMetadata(ctx context.Context, m Metadata) context.Context {
	return context.WithValue(ctx, metadataKey{}, m)
}
func (r *routeRule) compileMetadata() error {
	o := r.rule
	if err := validateNeighborRule(o); err != nil {
		return err
	}
	if o.ClashMode != "" && o.ClashMode != "rule" && o.ClashMode != "global" && o.ClashMode != "direct" {
		return errors.New("clash_mode must be rule,global or direct")
	}
	if o.Strategy != "" && !slices.Contains([]string{"prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}, o.Strategy) {
		return errors.New("invalid resolver strategy")
	}
	if o.IPVersion != 0 && o.IPVersion != 4 && o.IPVersion != 6 {
		return errors.New("ip_version must be4 or6")
	}
	for _, name := range o.User {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return errors.New("invalid rule user name")
		}
	}
	for _, v := range o.ProcessPathRegex {
		re, e := regexp.Compile(v)
		if e != nil {
			return e
		}
		r.processRegex = append(r.processRegex, re)
	}
	for _, v := range o.PackageNameRegex {
		re, e := regexp.Compile(v)
		if e != nil {
			return e
		}
		r.packageRegex = append(r.packageRegex, re)
	}
	r.interfacePrefixes = map[string][]netip.Prefix{}
	parse := func(values []string) (out []netip.Prefix, e error) {
		for _, v := range values {
			p, err := netip.ParsePrefix(v)
			if err != nil {
				ip, err := netip.ParseAddr(v)
				if err != nil {
					return nil, err
				}
				p = netip.PrefixFrom(ip, ip.BitLen())
			}
			out = append(out, p.Masked())
		}
		return
	}
	var e error
	for k, v := range o.NetworkInterfaceAddress {
		r.interfacePrefixes[k], e = parse(v)
		if e != nil {
			return e
		}
	}
	r.defaultPrefixes, e = parse(o.DefaultInterfaceAddress)
	if e != nil {
		return e
	}
	if len(o.DNSServerAddress) > 0 {
		r.dnsServerPrefixes = make(map[string][]netip.Prefix, len(o.DNSServerAddress))
	}
	for tag, values := range o.DNSServerAddress {
		if len(values) == 0 {
			continue
		}
		if tag == "" {
			return errors.New("dns_server_address requires a DNS server tag and addresses")
		}
		r.dnsServerPrefixes[tag], e = parse(values)
		if e != nil {
			return e
		}
	}
	if len(o.DNSSearchDomain) > 0 {
		r.dnsSearchDomains = make(map[string]map[string]bool, len(o.DNSSearchDomain))
	}
	for tag, values := range o.DNSSearchDomain {
		if len(values) == 0 {
			continue
		}
		if tag == "" {
			return errors.New("dns_search_domain requires a DNS server tag and domains")
		}
		r.dnsSearchDomains[tag] = map[string]bool{}
		for _, value := range values {
			value = canonicalDomain(value)
			r.dnsSearchDomains[tag][value] = true
		}
	}
	if o.Timeout != "" {
		if _, e := optionDuration(o.Timeout, 300*time.Millisecond); e != nil {
			return e
		}
	}
	for _, v := range o.Sniffer {
		if !slices.Contains([]string{"http", "tls", "quic", "stun", "dns", "bittorrent", "dtls", "ssh", "rdp", "ntp"}, v) {
			return errors.New("unknown sniffer: " + v)
		}
	}
	if o.OverrideAddress != "" {
		if _, e := encodeAddress(net.JoinHostPort(o.OverrideAddress, "1")); e != nil {
			return e
		}
	}
	if o.Method == "drop" && o.NoDrop {
		return errors.New("no_drop conflicts with drop method")
	}
	if o.Method != "" && o.Method != "default" && o.Method != "drop" && o.Method != "reply" {
		return errors.New("unknown rejection method")
	}
	return nil
}
func (r *routeRule) matchMetadata(q request) bool {
	o, m := &r.rule, &q.metadata
	mode := m.ClashMode
	if mode == "" {
		mode = "rule"
	}
	if o.ClashMode != "" && o.ClashMode != mode {
		return false
	}
	if len(o.PreferredBy) > 0 && !slices.ContainsFunc(o.PreferredBy, func(tag string) bool { return slices.Contains(m.DNSPreferredBy, tag) }) {
		return false
	}
	for _, v := range []struct {
		want []string
		got  string
	}{{o.User, m.User}, {o.Protocol, m.Protocol}, {o.Client, m.Client}, {o.AuthUser, m.AuthUser}, {o.ProcessName, m.ProcessName}, {o.ProcessPath, m.ProcessPath}, {o.PackageName, m.PackageName}, {o.NetworkType, m.NetworkType}, {o.WiFiSSID, m.WiFiSSID}} {
		if len(v.want) > 0 && (v.got == "" || !slices.Contains(v.want, v.got)) {
			return false
		}
	}
	if !matchNeighborRule(*o, *m) {
		return false
	}
	if len(o.UserID) > 0 && (m.UserID == nil || !slices.Contains(o.UserID, *m.UserID)) {
		return false
	}
	if len(o.WiFiBSSID) > 0 && (m.WiFiBSSID == "" || !slices.ContainsFunc(o.WiFiBSSID, func(want string) bool { return strings.EqualFold(want, m.WiFiBSSID) })) {
		return false
	}
	matchRegex := func(res []*regexp.Regexp, v string) bool {
		if len(res) == 0 {
			return true
		}
		if v == "" {
			return false
		}
		for _, re := range res {
			if re.MatchString(v) {
				return true
			}
		}
		return false
	}
	if !matchRegex(r.processRegex, m.ProcessPath) || !matchRegex(r.packageRegex, m.PackageName) {
		return false
	}
	if o.NetworkIsExpensive && !m.NetworkIsExpensive || o.NetworkIsConstrained && !m.NetworkIsConstrained {
		return false
	}
	matchPrefixes := func(ps []netip.Prefix, ips []netip.Addr) bool {
		for _, p := range ps {
			for _, ip := range ips {
				if p.Contains(ip) {
					return true
				}
			}
		}
		return false
	}
	if len(r.defaultPrefixes) > 0 && !matchPrefixes(r.defaultPrefixes, m.DefaultInterfaceAddress) {
		return false
	}
	if len(r.interfacePrefixes) > 0 {
		matched := false
		for k, ps := range r.interfacePrefixes {
			matched = matched || matchPrefixes(ps, m.NetworkInterfaceAddress[k])
		}
		if !matched {
			return false
		}
	}
	for tag, prefixes := range r.dnsServerPrefixes {
		if !matchPrefixes(prefixes, m.DNSServerAddress[tag]) {
			return false
		}
	}
	for tag, domains := range r.dnsSearchDomains {
		matched := false
		for _, domain := range m.DNSSearchDomain[tag] {
			matched = matched || domains[canonicalDomain(domain)]
		}
		if !matched {
			return false
		}
	}
	if o.IPVersion != 0 && q.dns {
		return o.IPVersion == 4 && q.queryType == 1 || o.IPVersion == 6 && q.queryType == 28
	}
	if o.IPVersion != 0 {
		h, _, _ := net.SplitHostPort(q.address)
		ip, e := netip.ParseAddr(h)
		if e != nil || o.IPVersion == 4 != ip.Is4() {
			return false
		}
	}
	return true
}
func (r *Runtime) resolveRoute(ctx context.Context, q request, o Rule) (request, error) {
	host, port, _ := net.SplitHostPort(q.address)
	if _, e := netip.ParseAddr(host); e == nil {
		return q, nil
	}
	if o.Timeout != "" {
		d, _ := optionDuration(o.Timeout, 10*time.Second)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	ctx = context.WithValue(ctx, dnsQueryOptionsKey{}, resolverOptions{Server: o.Server, Strategy: o.Strategy, DisableCache: o.DisableCache, DisableOptimisticCache: o.DisableOptimisticCache, RewriteTTL: o.RewriteTTL, Timeout: o.Timeout, ClientSubnet: o.ClientSubnet})
	if o.DisableCache {
		ctx = context.WithValue(ctx, dnsNoCacheKey{}, true)
	}
	ips, e := r.resolver.lookupMode(ctx, host, true, o.Server)
	if e != nil {
		return q, e
	}
	for _, ip := range ips {
		if o.Strategy == "ipv4_only" && ip.Is6() || o.Strategy == "ipv6_only" && ip.Is4() {
			continue
		}
		q.metadata.Domain = host
		q.ips = ips
		q.address = net.JoinHostPort(ip.String(), port)
		return q, nil
	}
	return q, errors.New("resolve returned no matching addresses")
}

func canonicalDomain(s string) string { return strings.TrimSuffix(strings.ToLower(s), ".") }

func (r Rule) hasMetadataConditions() bool {
	if r.ClashMode != "" {
		return true
	}
	return r.IPVersion != 0 || len(r.SourceMACAddress)+len(r.SourceHostname)+len(r.User)+len(r.UserID)+len(r.PreferredBy)+len(r.Protocol)+len(r.Client)+len(r.AuthUser)+len(r.ProcessName)+len(r.ProcessPath)+len(r.ProcessPathRegex)+len(r.PackageName)+len(r.PackageNameRegex)+len(r.NetworkType)+len(r.WiFiSSID)+len(r.WiFiBSSID)+len(r.NetworkInterfaceAddress)+len(r.DefaultInterfaceAddress)+len(r.DNSServerAddress)+len(r.DNSSearchDomain) > 0 || r.NetworkIsExpensive || r.NetworkIsConstrained || r.MatchResponse != "" || r.ResponseRCode != "" || len(r.ResponseAnswer)+len(r.ResponseNS)+len(r.ResponseExtra) > 0 || r.IPAcceptAny
}
