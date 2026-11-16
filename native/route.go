package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Route struct {
	FindNeighbor          bool     `json:"find_neighbor,omitempty"`
	DHCPLeaseFiles        []string `json:"dhcp_lease_files,omitempty"`
	dnsRules              bool
	DefaultDomainResolver resolverReference `json:"default_domain_resolver,omitempty"`
	AutoDetectInterface   bool              `json:"auto_detect_interface,omitempty"`
	FindProcess           bool              `json:"find_process,omitempty"`
	DefaultInterface      string            `json:"default_interface,omitempty"`
	DefaultMark           FirewallMark      `json:"default_mark,omitempty"`
	DefaultHTTPClient     string            `json:"default_http_client,omitempty"`
	Rules                 []Rule            `json:"rules,omitempty"`
	Final                 string            `json:"final,omitempty"`
	RuleSet               []RuleSet         `json:"rule_set,omitempty"`
}

type Rule struct {
	NetworkOptions
	SourceMACAddress         []string            `json:"source_mac_address,omitempty"`
	SourceHostname           []string            `json:"source_hostname,omitempty"`
	ClashMode                string              `json:"clash_mode,omitempty"`
	PreferredBy              []string            `json:"preferred_by,omitempty"`
	MatchResponse            responseReference   `json:"match_response,omitempty"`
	ResponseRCode            string              `json:"response_rcode,omitempty"`
	ResponseAnswer           []string            `json:"response_answer,omitempty"`
	ResponseNS               []string            `json:"response_ns,omitempty"`
	ResponseExtra            []string            `json:"response_extra,omitempty"`
	IPAcceptAny              bool                `json:"ip_accept_any,omitempty"`
	IPVersion                int                 `json:"ip_version,omitempty"`
	Protocol                 []string            `json:"protocol,omitempty"`
	Client                   []string            `json:"client,omitempty"`
	User                     []string            `json:"user,omitempty"`
	UserID                   []uint32            `json:"user_id,omitempty"`
	AuthUser                 []string            `json:"auth_user,omitempty"`
	ProcessName              []string            `json:"process_name,omitempty"`
	ProcessPath              []string            `json:"process_path,omitempty"`
	ProcessPathRegex         []string            `json:"process_path_regex,omitempty"`
	PackageName              []string            `json:"package_name,omitempty"`
	PackageNameRegex         []string            `json:"package_name_regex,omitempty"`
	NetworkType              []string            `json:"network_type,omitempty"`
	NetworkIsExpensive       bool                `json:"network_is_expensive,omitempty"`
	NetworkIsConstrained     bool                `json:"network_is_constrained,omitempty"`
	WiFiSSID                 []string            `json:"wifi_ssid,omitempty"`
	WiFiBSSID                []string            `json:"wifi_bssid,omitempty"`
	NetworkInterfaceAddress  map[string][]string `json:"network_interface_address,omitempty"`
	DefaultInterfaceAddress  []string            `json:"default_interface_address,omitempty"`
	DNSServerAddress         map[string][]string `json:"dns_server_address,omitempty"`
	DNSSearchDomain          map[string][]string `json:"dns_search_domain,omitempty"`
	OverrideAddress          string              `json:"override_address,omitempty"`
	OverridePort             uint16              `json:"override_port,omitempty"`
	Sniffer                  []string            `json:"sniffer,omitempty"`
	Timeout                  string              `json:"timeout,omitempty"`
	Server                   string              `json:"server,omitempty"`
	Strategy                 string              `json:"strategy,omitempty"`
	DisableCache             bool                `json:"disable_cache,omitempty"`
	DisableOptimisticCache   bool                `json:"disable_optimistic_cache,omitempty"`
	RewriteTTL               *uint32             `json:"rewrite_ttl,omitempty"`
	ClientSubnet             string              `json:"client_subnet,omitempty"`
	Method                   string              `json:"method,omitempty"`
	NoDrop                   bool                `json:"no_drop,omitempty"`
	Type                     string              `json:"type,omitempty"`
	Mode                     string              `json:"mode,omitempty"`
	Rules                    []Rule              `json:"rules,omitempty"`
	Domain                   []string            `json:"domain,omitempty"`
	DomainSuffix             []string            `json:"domain_suffix,omitempty"`
	DomainKeyword            []string            `json:"domain_keyword,omitempty"`
	DomainRegex              []string            `json:"domain_regex,omitempty"`
	IPCIDR                   []string            `json:"ip_cidr,omitempty"`
	SourceIPCIDR             []string            `json:"source_ip_cidr,omitempty"`
	Port                     []uint16            `json:"port,omitempty"`
	SourcePort               []uint16            `json:"source_port,omitempty"`
	Inbound                  []string            `json:"inbound,omitempty"`
	Network                  []string            `json:"network,omitempty"`
	Invert                   bool                `json:"invert,omitempty"`
	Action                   string              `json:"action,omitempty"`
	Outbound                 string              `json:"outbound,omitempty"`
	RuleSet                  []string            `json:"rule_set,omitempty"`
	RuleSetIPCIDRMatchSource bool                `json:"rule_set_ip_cidr_match_source,omitempty"`
	PortRange                []string            `json:"port_range,omitempty"`
	SourcePortRange          []string            `json:"source_port_range,omitempty"`
	IPIsPrivate              bool                `json:"ip_is_private,omitempty"`
	SourceIPIsPrivate        bool                `json:"source_ip_is_private,omitempty"`
	QueryType                queryTypes          `json:"query_type,omitempty"`
	domains                  *domainTree
	ipRanges, sourceRanges   []ipRange
}

type request struct {
	networkOptions                    *NetworkOptions
	origin                            *socketOrigin
	logID                             uint64
	controllerTrace                   *controllerTrace
	network, address, inbound, source string
	ips                               []netip.Addr
	queryType                         uint16
	ipMatchSource                     bool
	dns                               bool
	metadata                          Metadata
	payload                           []byte
	icmpError                         func(*icmpFlowError)
	preMatch                          bool
}

type routeRule struct {
	networkOptions             *NetworkOptions
	responseRecords            *[3][]dnsRecord
	preMatchFields             uint32
	reject                     *rejectWindow
	rule                       Rule
	regex                      []*regexp.Regexp
	processRegex, packageRegex []*regexp.Regexp
	interfacePrefixes          map[string][]netip.Prefix
	defaultPrefixes            []netip.Prefix
	dnsServerPrefixes          map[string][]netip.Prefix
	dnsSearchDomains           map[string]map[string]bool
	ip, source                 []netip.Prefix
	children                   []routeRule
	sets                       []*ruleCollection
	ports, sourcePorts         [][2]uint16
}

func compileRoute(cfg Route, outbounds map[string]Outbound, loaded ...map[string]*ruleCollection) ([]routeRule, error) {
	if _, ok := outbounds[cfg.Final]; !ok {
		return nil, fmt.Errorf("unknown route final %q", cfg.Final)
	}
	sets := map[string]*ruleCollection{}
	for _, s := range cfg.RuleSet {
		if err := s.validate(); err != nil {
			return nil, err
		}
		if sets[s.Tag] != nil {
			return nil, fmt.Errorf("duplicate rule_set %q", s.Tag)
		}
		sets[s.Tag] = &ruleCollection{}
	}
	if len(loaded) > 0 {
		sets = loaded[0]
	}
	var compile func(Rule, int) (routeRule, error)
	compile = func(rule Rule, depth int) (routeRule, error) {
		if depth > 64 {
			return routeRule{}, errors.New("route nesting exceeds 64 levels")
		}
		if !cfg.dnsRules && (len(rule.PreferredBy) > 0 || rule.MatchResponse != "" || rule.ResponseRCode != "" || len(rule.ResponseAnswer)+len(rule.ResponseNS)+len(rule.ResponseExtra) > 0 || rule.IPAcceptAny) {
			return routeRule{}, errors.New("DNS response conditions are only valid in DNS rules")
		}
		networkOptions, err := networkRuleOptions(&rule)
		if err != nil {
			return routeRule{}, err
		}
		if networkOptions != nil && (depth > 0 || cfg.dnsRules) {
			return routeRule{}, errors.New("network action options are not rule conditions")
		}
		nested := depth > 0
		if rule.domains == nil && len(rule.Domain)+len(rule.DomainSuffix) > 16 {
			rule.domains = buildDomainTree(rule.Domain, rule.DomainSuffix)
			rule.Domain = nil
			rule.DomainSuffix = nil
		}
		r := routeRule{networkOptions: networkOptions, rule: rule, reject: &rejectWindow{}, preMatchFields: preMatchFields(rule)}
		if len(rule.ResponseAnswer)+len(rule.ResponseNS)+len(rule.ResponseExtra) > 0 {
			r.responseRecords = new([3][]dnsRecord)
			for i, values := range [][]string{rule.ResponseAnswer, rule.ResponseNS, rule.ResponseExtra} {
				for _, text := range values {
					rr, err := parseTextRecord(text)
					if err != nil {
						return r, err
					}
					r.responseRecords[i] = append(r.responseRecords[i], rr)
				}
			}
		}
		for _, tag := range rule.RuleSet {
			set := sets[tag]
			if set == nil {
				return r, fmt.Errorf("unknown rule_set %q", tag)
			}
			r.sets = append(r.sets, set)
		}
		var rangeErr error
		r.ports, rangeErr = compilePortRanges(rule.PortRange)
		if rangeErr != nil {
			return r, rangeErr
		}
		r.sourcePorts, rangeErr = compilePortRanges(rule.SourcePortRange)
		if rangeErr != nil {
			return r, rangeErr
		}
		if !slices.Contains([]string{"", "route", "bypass", "reject", "route-options", "sniff", "resolve", "hijack-dns"}, rule.Action) {
			return r, fmt.Errorf("unknown route action %q", rule.Action)
		}
		if !nested && (rule.Action == "" || rule.Action == "route" || rule.Action == "bypass" && rule.Outbound != "") {
			if _, ok := outbounds[rule.Outbound]; !ok {
				return r, fmt.Errorf("unknown rule outbound %q", rule.Outbound)
			}
		}
		if nested && (rule.Outbound != "" || rule.Action != "") {
			return r, errors.New("logical child rules cannot contain actions")
		}
		if rule.Type == "logical" {
			if rule.hasMetadataConditions() {
				return r, errors.New("logical rule conditions must be in child rules")
			}
			if rule.Mode != "and" && rule.Mode != "or" {
				return r, errors.New("logical mode must be and or or")
			}
			if len(rule.Rules) == 0 {
				return r, errors.New("logical rule cannot be empty")
			}
			if len(rule.Domain)+len(rule.DomainSuffix)+len(rule.DomainKeyword)+len(rule.DomainRegex)+len(rule.IPCIDR)+len(rule.SourceIPCIDR)+len(rule.Port)+len(rule.SourcePort)+len(rule.Inbound)+len(rule.Network)+len(rule.RuleSet)+len(rule.QueryType)+len(rule.PortRange)+len(rule.SourcePortRange)+len(rule.ipRanges)+len(rule.sourceRanges) != 0 || rule.IPIsPrivate || rule.SourceIPIsPrivate || rule.domains != nil {
				return r, errors.New("logical rule conditions must be in child rules")
			}
			for _, child := range rule.Rules {
				c, err := compile(child, depth+1)
				if err != nil {
					return r, err
				}
				r.children = append(r.children, c)
				r.preMatchFields |= c.preMatchFields
			}
		} else if rule.Type != "" && rule.Type != "default" || len(rule.Rules) != 0 {
			return r, errors.New("invalid route rule type")
		}
		if err := r.compileMetadata(); err != nil {
			return r, err
		}
		for _, value := range rule.DomainRegex {
			re, err := regexp.Compile(value)
			if err != nil {
				return r, err
			}
			r.regex = append(r.regex, re)
		}
		for _, value := range rule.IPCIDR {
			p, err := netip.ParsePrefix(value)
			if err != nil {
				return r, err
			}
			r.ip = append(r.ip, p.Masked())
		}
		for _, value := range rule.SourceIPCIDR {
			p, err := netip.ParsePrefix(value)
			if err != nil {
				return r, err
			}
			r.source = append(r.source, p.Masked())
		}
		for _, n := range rule.Network {
			if n != "tcp" && n != "udp" && n != "icmp" {
				return r, fmt.Errorf("invalid network %q", n)
			}
		}
		return r, nil
	}
	rules := make([]routeRule, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		r, err := compile(rule, 0)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

type routeMatch uint8

const (
	matchNo routeMatch = iota
	matchYes
	matchUnknown
)

func (r *routeRule) matches(q request) bool { return r.evaluate(q) == matchYes }
func (r *routeRule) evaluate(q request) routeMatch {
	result := r.evaluateBase(q)
	if r.rule.Invert && result != matchUnknown {
		if result == matchYes {
			return matchNo
		}
		return matchYes
	}
	return result
}
func matchAnd(a, b routeMatch) routeMatch {
	if a == matchNo || b == matchNo {
		return matchNo
	}
	if a == matchUnknown || b == matchUnknown {
		return matchUnknown
	}
	return matchYes
}
func matchOr(a, b routeMatch) routeMatch {
	if a == matchYes || b == matchYes {
		return matchYes
	}
	if a == matchUnknown || b == matchUnknown {
		return matchUnknown
	}
	return matchNo
}

const matchUnset routeMatch = 3

type routeGroups struct {
	address, port, source, sourcePort routeMatch
	ipFilter                          routeMatch
	other                             routeMatch
}

func (g routeGroups) result() routeMatch {
	m := g.other
	for _, v := range [5]routeMatch{g.address, g.port, g.source, g.sourcePort, g.ipFilter} {
		if v != matchUnset {
			m = matchAnd(m, v)
		}
	}
	return m
}
func mergeGroup(a, b routeMatch) routeMatch {
	if a == matchUnset {
		return b
	}
	if b == matchUnset {
		return a
	}
	return matchOr(a, b)
}
func (g routeGroups) merge(b routeGroups) routeGroups {
	return routeGroups{mergeGroup(g.address, b.address), mergeGroup(g.port, b.port), mergeGroup(g.source, b.source), mergeGroup(g.sourcePort, b.sourcePort), mergeGroup(g.ipFilter, b.ipFilter), matchAnd(g.other, b.other)}
}
func boolMatch(b bool) routeMatch {
	if b {
		return matchYes
	}
	return matchNo
}
func (r *routeRule) evaluateBase(q request) routeMatch {
	if len(r.children) > 0 {
		result := matchNo
		if r.rule.Mode == "and" {
			result = matchYes
		}
		for i := range r.children {
			child := &r.children[i]
			if r.rule.Mode == "or" {
				result = matchOr(result, child.evaluate(q))
				if result == matchYes {
					return result
				}
			} else {
				result = matchAnd(result, child.evaluate(q))
				if result == matchNo {
					return result
				}
			}
		}
		return result
	}
	fields := r.groups(q)
	if fields.other == matchNo {
		return matchNo
	}
	if len(r.sets) == 0 {
		return fields.result()
	}
	result := matchNo
	for _, set := range r.sets {
		target := q
		if r.rule.RuleSetIPCIDRMatchSource {
			target.ipMatchSource = true
		}
		snapshot := set.current.Load()
		if snapshot == nil {
			continue
		}
		var m routeMatch
		if len(snapshot.rules) == 1 && len(snapshot.rules[0].children) == 0 && !snapshot.rules[0].rule.Invert {
			m = fields.merge(snapshot.rules[0].groups(target)).result()
		} else {
			m = matchAnd(fields.result(), set.evaluate(target))
		}
		result = matchOr(result, m)
		if result == matchYes {
			return result
		}
	}
	return result
}
func (r *routeRule) groups(q request) routeGroups {
	g := routeGroups{matchUnset, matchUnset, matchUnset, matchUnset, matchUnset, matchYes}
	rule := &r.rule
	if q.preMatch && r.preMatchFields&preMatchMissing(q.metadata) != 0 {
		g.other = matchUnknown
		return g
	}
	if !r.matchMetadata(q) {
		g.other = matchNo
		return g
	}
	host, port, _ := net.SplitHostPort(q.address)
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	addressHost := host
	if q.metadata.Domain != "" {
		host = canonicalDomain(q.metadata.Domain)
	}
	source, sourcePort, _ := net.SplitHostPort(q.source)
	if len(rule.Inbound) > 0 && !slices.Contains(rule.Inbound, q.inbound) || len(rule.Network) > 0 && !slices.Contains(rule.Network, q.network) || len(rule.QueryType) > 0 && !slices.Contains(rule.QueryType, q.queryType) {
		g.other = matchNo
		return g
	}
	if len(rule.Port) > 0 || len(r.ports) > 0 {
		p, _ := strconv.Atoi(port)
		g.port = boolMatch(slices.Contains(rule.Port, uint16(p)) || inPortRanges(r.ports, port))
	}
	if len(rule.SourcePort) > 0 || len(r.sourcePorts) > 0 {
		p, _ := strconv.Atoi(sourcePort)
		g.sourcePort = boolMatch(slices.Contains(rule.SourcePort, uint16(p)) || inPortRanges(r.sourcePorts, sourcePort))
	}
	if len(rule.Domain)+len(rule.DomainSuffix)+len(rule.DomainKeyword)+len(r.regex) > 0 || rule.domains != nil {
		matched := rule.domains != nil && rule.domains.match(host)
		for _, v := range rule.Domain {
			matched = matched || host == strings.TrimSuffix(strings.ToLower(v), ".")
		}
		for _, v := range rule.DomainSuffix {
			if strings.HasPrefix(v, ".") {
				matched = matched || strings.HasSuffix(host, strings.ToLower(v))
				continue
			}
			v = strings.Trim(strings.ToLower(v), ".")
			matched = matched || host == v || strings.HasSuffix(host, "."+v)
		}
		for _, v := range rule.DomainKeyword {
			matched = matched || strings.Contains(host, strings.ToLower(v))
		}
		for _, re := range r.regex {
			matched = matched || re.MatchString(host)
		}
		g.address = boolMatch(matched)
	}
	if len(r.ip) > 0 || len(rule.ipRanges) > 0 || rule.IPIsPrivate {
		ipHost, ips := addressHost, q.ips
		if q.ipMatchSource {
			ipHost, ips = source, []netip.Addr{}
		}
		_, literalErr := netip.ParseAddr(ipHost)
		m := matchUnknown
		if literalErr == nil || ips != nil {
			m = boolMatch(containsResolvedIP(r.ip, ipHost, ips) || matchIPRanges(rule.ipRanges, ipHost, ips) || rule.IPIsPrivate && privateIP(ipHost, ips))
		}
		if q.dns && !q.ipMatchSource {
			g.ipFilter = m
		} else {
			g.address = mergeGroup(g.address, m)
		}
	}
	if len(r.source) > 0 || len(rule.sourceRanges) > 0 || rule.SourceIPIsPrivate {
		g.source = boolMatch(containsIP(r.source, source) || matchIPRanges(rule.sourceRanges, source, nil) || rule.SourceIPIsPrivate && privateIP(source, nil))
	}
	if rule.IPAcceptAny && q.dns {
		if q.ips == nil {
			g.ipFilter = mergeGroup(g.ipFilter, matchUnknown)
		} else {
			g.ipFilter = mergeGroup(g.ipFilter, boolMatch(len(q.ips) > 0))
		}
	}
	return g
}

func compilePortRanges(values []string) ([][2]uint16, error) {
	var out [][2]uint16
	for _, value := range values {
		left, right, ok := strings.Cut(value, ":")
		if !ok {
			return nil, errors.New("port range must be start:end")
		}
		if left == "" {
			left = "0"
		}
		if right == "" {
			right = "65535"
		}
		a, err := strconv.ParseUint(left, 10, 16)
		if err != nil {
			return nil, err
		}
		b, err := strconv.ParseUint(right, 10, 16)
		if err != nil || b < a {
			return nil, errors.New("invalid port range")
		}
		out = append(out, [2]uint16{uint16(a), uint16(b)})
	}
	return out, nil
}
func inPortRanges(ranges [][2]uint16, value string) bool {
	p, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return false
	}
	for _, r := range ranges {
		if p >= uint64(r[0]) && p <= uint64(r[1]) {
			return true
		}
	}
	return false
}
func containsResolvedIP(prefixes []netip.Prefix, host string, ips []netip.Addr) bool {
	if containsIP(prefixes, host) {
		return true
	}
	for _, ip := range ips {
		for _, prefix := range prefixes {
			if prefix.Contains(ip.Unmap()) {
				return true
			}
		}
	}
	return false
}
func privateIP(host string, ips []netip.Addr) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = append([]netip.Addr{ip}, ips...)
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}
	return false
}
func (r *routeRule) needsIP() bool {
	if len(r.ip) > 0 || len(r.rule.ipRanges) > 0 || r.rule.IPIsPrivate {
		return true
	}
	for i := range r.children {
		child := &r.children[i]
		if child.needsIP() {
			return true
		}
	}
	for _, set := range r.sets {
		if set.needsIP() {
			return true
		}
	}
	return false
}

func containsIP(prefixes []netip.Prefix, value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

var ErrRejected = errors.New("connection rejected by routing policy")

func (r *Runtime) routeDial(ctx context.Context, q request) (net.Conn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if q.network == "tcp" && q.address == genericMuxAddress {
		for _, in := range r.config.Inbounds {
			if in.Tag == q.inbound && in.Multiplex.Enabled {
				return &genericMuxTarget{request: q, options: in.Multiplex}, nil
			}
		}
		return nil, errors.New("multiplex is disabled on this inbound")
	}
	if m, ok := ctx.Value(metadataKey{}).(Metadata); ok {
		q.metadata = m
	}
	ctx = context.WithValue(ctx, inboundRouteKey{}, true)
	r.logInbound(&q)
	for i := range r.rules {
		rule := &r.rules[i]
		if rule.rule.Action == "sniff" {
			return newRouteConn(r, ctx, q), nil
		}
	}
	return r.routeResolved(ctx, q)
}

var errDNSRoute = errors.New("DNS route action")
var errICMPReply = errors.New("ICMP echo reply action")

func (r *Runtime) routeResolved(ctx context.Context, q request) (conn net.Conn, resultErr error) {
	var tag string
	defer func() { r.logConnection(q, tag, conn, resultErr) }()
	decision, err := r.brookInboundDecision(ctx, &q)
	if err != nil {
		return nil, err
	}
	q.address = decision.address
	if decision.bypass {
		tag = "direct"
		return r.direct(ctx, q.network, q.address)
	}
	if decision.detour != "" {
		tag = decision.detour
		return r.dialOutbound(ctx, tag, q.network, q.address)
	}
	q, tag, e := r.routeTarget(ctx, q)
	if errors.Is(e, errDNSRoute) {
		tag = "DNS"
		return r.dnsRouteConn(ctx, q)
	}
	if e != nil {
		return nil, e
	}
	if q.metadata.ProcessName != "" || q.metadata.ProcessPath != "" || q.metadata.UserID != nil || q.metadata.User != "" || q.metadata.SourceMACAddress != "" || q.metadata.SourceHostname != "" {
		ctx = WithMetadata(ctx, q.metadata)
	}
	c, e := r.dialOutbound(q.networkContext(ctx), tag, q.network, q.address)
	if q.icmpError != nil {
		if e != nil {
			var cause *icmpFlowError
			if errors.As(e, &cause) {
				q.icmpError(cause)
			}
		} else {
			c = &icmpErrorConn{Conn: c, notify: q.icmpError}
		}
	}
	if e == nil && r.controller != nil && !r.controller.readOnly {
		return r.controller.track(c, q, tag)
	}
	return c, e
}
func (r *Runtime) routeTarget(ctx context.Context, q request) (request, string, error) {
	r.enrichNetworkMetadata(ctx, &q.metadata)
	r.enrichProcess(ctx, &q)
	r.enrichNeighbor(ctx, &q)
	if q.metadata.ProcessName != "" || q.metadata.ProcessPath != "" || q.metadata.UserID != nil || q.metadata.User != "" || q.metadata.SourceMACAddress != "" || q.metadata.SourceHostname != "" {
		ctx = WithMetadata(ctx, q.metadata)
	}
	r.resolver.enrichDNSNetworkMetadata(&q.metadata)
	if q.network == "icmp" {
		host, port, e := net.SplitHostPort(q.address)
		if _, ipErr := netip.ParseAddr(host); e != nil || ipErr != nil || port != "0" {
			return q, "", errors.New("invalid ICMP destination")
		}
	} else if _, err := encodeAddress(q.address); err != nil {
		return q, "", err
	}
	host, port, _ := net.SplitHostPort(q.address)
	if r.config.DNS.ReverseMapping {
		if ip, e := netip.ParseAddr(host); e == nil {
			r.resolver.mu.Lock()
			entry, ok := r.resolver.reverse[ip]
			r.resolver.mu.Unlock()
			if ok && time.Now().Before(entry.until) {
				q.metadata.Domain = entry.host
			}
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil && r.resolver.isFake(ip) {
		original, ok := r.resolver.reverseFake(ip)
		if !ok {
			return q, "", errors.New("FakeIP mapping is absent or expired")
		}
		q.address = net.JoinHostPort(original, port)
	}
	tag := r.config.Route.Final
	mode := uint32(0)
	if r.controller != nil {
		mode = r.controller.mode.Load()
		q.metadata.ClashMode = [...]string{"rule", "global", "direct"}[mode]
		if !r.controller.readOnly {
			q.controllerTrace = &controllerTrace{}
		}
	}
	matched := false
	for i := range r.rules {
		rule := &r.rules[i]
		if mode != 0 && (rule.rule.Action == "" || rule.rule.Action == "route" || rule.rule.Action == "bypass" || rule.rule.Action == "route-options") {
			continue
		}
		m := rule.evaluate(q)
		if m == matchUnknown {
			host, _, _ := net.SplitHostPort(q.address)
			if _, err := netip.ParseAddr(host); err != nil {
				var err error
				q.ips, err = r.resolver.lookupReal(ctx, host)
				if err != nil {
					return q, "", err
				}
			}
			m = rule.evaluate(q)
		}
		if m != matchYes {
			continue
		}
		o := rule.rule
		r.logRule(q, i, o)
		switch o.Action {
		case "bypass":
			if o.Outbound == "" {
				continue
			}
		case "reject":
			if rule.reject.drop(o.Method, o.NoDrop) {
				return q, "", ErrDropped
			}
			if o.Method == "reply" && q.network == "icmp" {
				return q, "", errICMPReply
			}
			return q, "", ErrRejected
		case "sniff":
			if q.network == "icmp" {
				continue
			}
			protocol, domain, client := sniffPacketInfo(q.network, q.payload, o.Sniffer)
			q.metadata.Protocol = protocol
			if client != "" {
				q.metadata.Client = client
			}
			if domain != "" {
				q.metadata.Domain = domain
			}
			continue
		case "resolve":
			resolved, err := r.resolveRoute(ctx, q, o)
			if err != nil {
				return q, "", err
			}
			q = resolved
			continue
		case "hijack-dns":
			return q, "", errDNSRoute
		}
		if rule.networkOptions != nil {
			q.networkOptions = mergeNetworkOptions(q.networkOptions, rule.networkOptions)
		}
		if o.OverrideAddress != "" || o.OverridePort != 0 {
			h, p, _ := net.SplitHostPort(q.address)
			if o.OverrideAddress != "" {
				h = o.OverrideAddress
			}
			if o.OverridePort != 0 {
				p = strconv.Itoa(int(o.OverridePort))
			}
			q.address = net.JoinHostPort(h, p)
			q.ips = nil
		}
		if o.Action == "route-options" {
			continue
		}
		tag = o.Outbound
		if r.controller != nil && !r.controller.readOnly {
			description := ruleDescription(o)
			q.controllerTrace.rule, q.controllerTrace.payload = description.Type, description.Payload
		}
		matched = true
		break
	}
	if c := r.controller; c != nil && !c.readOnly {
		switch {
		case mode == 2:
			tag = c.directTag
			q.controllerTrace.chain = []string{"DIRECT"}
		case mode == 1:
			tag, q.controllerTrace.chain = c.resolvePath("GLOBAL")
		case !matched && c.virtualProxy:
			tag, q.controllerTrace.chain = c.resolvePath("PROXY")
		}
	}
	return q, tag, nil
}
