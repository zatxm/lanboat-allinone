package native

import (
	"bytes"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type DNSConfig struct {
	Optimistic       optimisticOptions `json:"optimistic,omitempty"`
	ClientSubnet     string            `json:"client_subnet,omitempty"`
	IndependentCache bool              `json:"independent_cache,omitempty"`
	DisableExpire    bool              `json:"disable_expire,omitempty"`
	Timeout          string            `json:"timeout,omitempty"`
	ReverseMapping   bool              `json:"reverse_mapping,omitempty"`
	Servers          []DNSServer       `json:"servers,omitempty"`
	Final            string            `json:"final,omitempty"`
	DisableCache     bool              `json:"disable_cache,omitempty"`
	CacheCapacity    int               `json:"cache_capacity,omitempty"`
	Rules            []DNSRule         `json:"rules,omitempty"`
	Strategy         string            `json:"strategy,omitempty"`
}

type DNSServer struct {
	NeighborDomain []string `json:"neighbor_domain,omitempty"`
	DialOptions
	Service                string              `json:"service,omitempty"`
	Interfaces             []string            `json:"interface,omitempty"`
	AcceptDefaultResolvers bool                `json:"accept_default_resolvers,omitempty"`
	AcceptSearchDomain     bool                `json:"accept_search_domain,omitempty"`
	Endpoint               string              `json:"endpoint,omitempty"`
	HostsPaths             []string            `json:"-"`
	Type                   string              `json:"type"`
	Tag                    string              `json:"tag"`
	Server                 string              `json:"server,omitempty"`
	ServerPort             uint16              `json:"server_port,omitempty"`
	Path                   string              `json:"path,omitempty"`
	TLS                    TLSOptions          `json:"tls,omitempty"`
	DomainResolver         resolverReference   `json:"domain_resolver,omitempty"`
	Detour                 string              `json:"detour,omitempty"`
	Inet4Range             string              `json:"inet4_range,omitempty"`
	Inet6Range             string              `json:"inet6_range,omitempty"`
	Predefined             map[string][]string `json:"predefined,omitempty"`
}

func (c DNSConfig) validate() error {
	if e := validateDNSResponses(c.Rules); e != nil {
		return e
	}
	if _, e := optionDuration(c.Timeout, 10*time.Second); e != nil {
		return e
	}
	if _, e := optionDuration(c.Optimistic.Timeout, 72*time.Hour); e != nil {
		return e
	}
	if c.Optimistic.Enabled && (c.DisableCache || c.DisableExpire) {
		return errors.New("optimistic conflicts with disable_cache/disable_expire")
	}
	if c.ClientSubnet != "" {
		if _, e := dnsClientSubnet([]byte{0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, c.ClientSubnet, false); e != nil {
			return e
		}
	}
	if c.CacheCapacity < 0 || c.CacheCapacity > 1_000_000 {
		return errors.New("DNS cache_capacity must be 0-1000000")
	}
	seen := map[string]bool{}
	for _, s := range c.Servers {
		if err := validateNeighborDNS(s); err != nil {
			return err
		}
		if err := s.DialOptions.validate(); err != nil {
			return err
		}
		if !reflect.DeepEqual(s.DialOptions, DialOptions{}) && s.Type != "udp" && s.Type != "tcp" && s.Type != "tls" && s.Type != "https" && s.Type != "quic" && s.Type != "h3" {
			return errors.New("DNS dial fields require udp,tcp,tls,https,quic or h3 transport")
		}
		if s.Type != "resolved" && s.Service != "" {
			return errors.New("DNS service requires resolved transport")
		}
		if s.Type != "mdns" && s.Type != "dhcp" && len(s.Interfaces) != 0 {
			return errors.New("DNS interface requires mdns or dhcp transport")
		}
		if s.Type != "masque" && s.Type != "openconnect" && s.Type != "tailscale" && s.Endpoint != "" {
			return errors.New("DNS endpoint requires masque,openconnect or tailscale transport")
		}
		if s.Type != "openconnect" && s.Type != "tailscale" && s.Type != "resolved" && (s.AcceptDefaultResolvers || s.AcceptSearchDomain) {
			return errors.New("accept_default_resolvers/accept_search_domain require openconnect or tailscale DNS")
		}
		if s.TLS.realityEnabled() {
			return errors.New("DNS Reality is configured through a proxy detour,not a DNS TLS identity")
		}
		if s.Tag == "" || seen[s.Tag] {
			return errors.New("DNS server tags must be nonempty and unique")
		}
		seen[s.Tag] = true
		for host, addresses := range s.Predefined {
			if _, err := makeDNSQuery(strings.TrimSuffix(strings.ToLower(host), "."), 1); err != nil {
				return fmt.Errorf("hosts %q: %w", host, err)
			}
			for _, value := range addresses {
				if _, err := netip.ParseAddr(value); err != nil {
					return fmt.Errorf("hosts %q: %w", host, err)
				}
			}
		}
		switch s.Type {
		case "resolved":
			if s.Service == "" || !reflect.DeepEqual(s, DNSServer{Type: s.Type, Tag: s.Tag, Service: s.Service, AcceptDefaultResolvers: s.AcceptDefaultResolvers}) {
				return errors.New("resolved DNS requires service and uses its discovered nameservers")
			}
		case "dhcp":
			if err := validateDHCPDNS(s); err != nil {
				return err
			}
		case "mdns":
			if !reflect.DeepEqual(s, DNSServer{Type: s.Type, Tag: s.Tag, Interfaces: s.Interfaces}) {
				return errors.New("mDNS uses local multicast interfaces,not an upstream server or proxy detour")
			}
			if len(s.Interfaces) > 64 {
				return errors.New("mDNS supports at most64 interfaces")
			}
			names := map[string]bool{}
			for _, name := range s.Interfaces {
				if name == "" || len(name) > 128 || strings.ContainsAny(name, "/\\\x00\r\n") || names[name] {
					return errors.New("invalid or duplicate mDNS interface")
				}
				names[name] = true
			}
		case "openconnect", "tailscale":
			if s.Endpoint == "" || !reflect.DeepEqual(s, DNSServer{Type: s.Type, Tag: s.Tag, Endpoint: s.Endpoint, AcceptDefaultResolvers: s.AcceptDefaultResolvers, AcceptSearchDomain: s.AcceptSearchDomain}) {
				return errors.New("endpoint DNS requires endpoint and uses its discovered nameservers")
			}
		case "masque":
			if s.Endpoint == "" || s.Server != "" || s.ServerPort != 0 || s.Detour != "" || s.Path != "" {
				return errors.New("MASQUE DNS requires endpoint and uses its assigned nameservers")
			}
		case "local", "hosts":
		case "fakeip":
			if _, err := newFakePool(s, c.CacheCapacity); err != nil {
				return err
			}
		case "udp", "tcp", "tls", "https", "quic", "h3":
			if s.Server == "" || strings.ContainsAny(s.Server, "/?#@\x00\r\n\t ") {
				return errors.New("DNS server must be an IP or hostname")
			}
		default:
			return fmt.Errorf("independent DNS has no %q transport", s.Type)
		}
		if (s.TLS.RecordFragment || s.TLS.Fragment || s.TLS.FragmentFallbackDelay != "") && s.Type != "tls" && s.Type != "https" {
			return errors.New("DNS fragmentation requires TLS or HTTPS")
		}
		if s.Type == "tls" || s.Type == "https" || s.Type == "quic" || s.Type == "h3" {
			o := s.TLS
			o.Enabled = true
			if _, err := o.config(false, s.Server); err != nil {
				return err
			}
			if s.Type == "quic" || s.Type == "h3" {
				if err := o.validateQUICVersion(); err != nil {
					return err
				}
			}
		}
		if s.Path != "" && (!strings.HasPrefix(s.Path, "/") || strings.ContainsAny(s.Path, "\r\n")) {
			return errors.New("invalid DoH path")
		}
	}
	if c.Final != "" && !seen[c.Final] {
		return fmt.Errorf("unknown DNS final %q", c.Final)
	}
	for _, s := range c.Servers {
		if s.DomainResolver != "" && !seen[s.DomainResolver.tag()] {
			return fmt.Errorf("unknown domain_resolver %q", s.DomainResolver)
		}
		for _, target := range c.Servers {
			if s.Type == "masque" && target.Tag == s.DomainResolver.tag() && target.Type == "masque" {
				return errors.New("MASQUE DNS bootstrap must use an independent resolver")
			}
			if target.Tag == s.DomainResolver.tag() && target.Type == "fakeip" {
				return errors.New("DNS bootstrap cannot use FakeIP")
			}
		}
	}
	for _, rule := range c.Rules {
		if err := validateDNSAction(rule); err != nil {
			return err
		}
		if rule.Server != "" && !seen[rule.Server] {
			return fmt.Errorf("unknown DNS rule server %q", rule.Server)
		}
		if !slices.Contains([]string{"", "route", "reject", "route-options", "evaluate", "respond", "predefined"}, rule.Action) {
			return fmt.Errorf("unsupported DNS rule action %q", rule.Action)
		}
		if (rule.Action == "" || rule.Action == "route" || rule.Action == "evaluate") && rule.Server == "" {
			return errors.New("DNS route rule requires server")
		}
	}
	if !slices.Contains([]string{"", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only"}, c.Strategy) {
		return errors.New("invalid DNS strategy")
	}
	for _, s := range c.Servers {
		seenPath := map[string]bool{}
		tag := s.Tag
		for tag != "" {
			if seenPath[tag] {
				return errors.New("DNS domain_resolver cycle")
			}
			seenPath[tag] = true
			next := ""
			for _, server := range c.Servers {
				if server.Tag == tag {
					next = server.DomainResolver.tag()
					break
				}
			}
			tag = next
		}
	}
	return nil
}

type resolver struct {
	dhcp           map[string]*dhcpDNSClient
	preferredTags  []string
	networkTags    []string
	localNetwork   dnsNetworkCache
	tunnelDial     func(context.Context, DNSServer, string) (net.Conn, error)
	systemServers  []string
	system         *net.Resolver
	ctx            context.Context
	cancel         context.CancelFunc
	config         DNSConfig
	server         DNSServer
	mu             sync.Mutex
	wireCache      map[string]*list.Element
	wireInflight   map[string]*dnsWireLookup
	wireLRU        *list.List
	cacheEpoch     atomic.Uint64
	reverse        map[netip.Addr]fakeEntry
	cacheReady     bool
	reject         rejectWindow
	http           *http.Client
	clients        map[string]*http.Client
	quicDNS        map[string]*dnsQUICClient
	servers        map[string]DNSServer
	pools          map[string]*fakePool
	runtime        *Runtime
	policies       []dnsPolicy
	parallelPolicy bool
	parallelRaces  int
	persistHeader  dnsStoreHeader
	persistWake    chan struct{}
	persistBuffer  int
	persistBytes   uint64
	persistWorkers sync.WaitGroup
	closeOnce      sync.Once
}

func newResolver(config DNSConfig, owner ...*Runtime) (*resolver, error) {
	r := &resolver{config: config, clients: map[string]*http.Client{}, servers: map[string]DNSServer{}, pools: map[string]*fakePool{}}
	r.quicDNS = map[string]*dnsQUICClient{}
	r.dhcp = map[string]*dhcpDNSClient{}
	for _, s := range config.Servers {
		if s.Type == "dhcp" {
			r.dhcp[s.Tag] = &dhcpDNSClient{resolver: r}
		}
	}
	if len(owner) > 0 {
		r.runtime = owner[0]
	}
	r.wireCache = map[string]*list.Element{}
	r.wireInflight = map[string]*dnsWireLookup{}
	r.reverse = map[netip.Addr]fakeEntry{}
	base := context.Background()
	if r.runtime != nil {
		base = r.runtime.ctx
	}
	r.ctx, r.cancel = context.WithCancel(base)
	r.system = net.DefaultResolver
	if r.runtime != nil {
		for _, in := range r.runtime.config.Inbounds {
			if in.Type == "tun" {
				r.systemServers = systemDNSBeforeTUN()
				break
			}
		}
		r.system = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			r.mu.Lock()
			if len(r.systemServers) > 0 {
				address = r.systemServers[0]
			}
			r.mu.Unlock()
			return (&net.Dialer{Control: r.runtime.socketControl}).DialContext(ctx, network, address)
		}}
	}

	if len(config.Servers) > 0 {
		r.server = config.Servers[0]
		for _, s := range config.Servers {
			if s.Type == "hosts" {
				hosts, e := loadDNSHosts(s)
				if e != nil {
					return nil, e
				}
				s.Predefined = hosts
			}
			if len(s.Predefined) > 0 {
				canonical := make(map[string][]string, len(s.Predefined))
				for host, ips := range s.Predefined {
					canonical[strings.TrimSuffix(strings.ToLower(host), ".")] = ips
				}
				s.Predefined = canonical
			}
			r.servers[s.Tag] = s
			if s.Tag == config.Final {
				r.server = s
			}
		}
		r.server = r.servers[r.server.Tag]
	}
	for _, s := range config.Servers {
		if s.Type == "masque" || s.Type == "openconnect" || s.Type == "tailscale" || s.Type == "resolved" {
			if r.runtime == nil {
				r.Close()
				return nil, errors.New("tunnel DNS transport requires a runtime")
			}
			continue
		}
		if s.Type == "fakeip" {
			pool, err := newFakePool(s, config.CacheCapacity)
			if err != nil {
				r.Close()
				return nil, err
			}
			r.pools[s.Tag] = pool
		}
		options := s.TLS
		options.Enabled = true
		secured, err := options.config(false, s.Server)
		if err != nil {
			r.Close()
			return nil, err
		}
		if s.Type == "quic" || s.Type == "h3" {
			r.quicDNS[s.Tag] = &dnsQUICClient{resolver: r, server: s, tlsConfig: secured}
			continue
		}
		transport := &http.Transport{TLSClientConfig: secured, MaxIdleConns: 4, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return r.dialDNS(ctx, s, network)
		}}
		if s.Type == "https" && (s.TLS.KernelTX || s.TLS.KernelRX || s.TLS.ECH != nil && s.TLS.ECH.Enabled || s.TLS.RecordFragment || s.TLS.Fragment) {
			transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
				cfg, err := r.prepareTLS(ctx, s, secured)
				if err != nil {
					return nil, err
				}
				raw, err := r.dialDNS(ctx, s, "tcp")
				if err != nil {
					return nil, err
				}
				conn := clientTLS(raw, cfg, s.TLS)
				if err = conn.HandshakeContext(ctx); err != nil {
					raw.Close()
					return nil, err
				}
				return conn, nil
			}
		}
		r.clients[s.Tag] = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	r.http = r.clients[r.server.Tag]
	var route Route
	var sets map[string]*ruleCollection
	if r.runtime != nil {
		route = r.runtime.config.Route
		sets = r.runtime.ruleSets
	}
	var err error
	r.policies, err = compileDNSRules(config, route, sets)
	if err != nil {
		r.Close()
		return nil, err
	}

	if err = r.loadFakeCache(); err != nil {
		r.Close()
		return nil, err
	}
	for _, p := range r.policies {
		if p.options.Race {
			r.parallelRaces++
		}
		if p.options.Action == "evaluate" {
			r.parallelPolicy = true
		}
	}
	if err = r.loadDNSCache(); err != nil {
		r.wireCache = map[string]*list.Element{}
		r.wireLRU = nil
		r.reverse = map[netip.Addr]fakeEntry{}
		r.runtime.logger.Warn("DNS cache ignored", zap.Error(err))
	}
	r.networkTags = dnsNetworkTags(append(append([]Rule{}, route.Rules...), dnsConditions(config.Rules)...))
	r.preferredTags = dnsPreferredTags(dnsConditions(config.Rules))
	r.cacheReady = true
	r.startDNSPersistence()
	return r, nil
}
func (r *resolver) Close() {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		for _, client := range r.dhcp {
			client.close()
		}
		r.persistWorkers.Wait()
		if r.cacheReady {
			r.saveFakeCache()
			r.saveDNSCache(true)
		}
		for _, client := range r.clients {
			client.CloseIdleConnections()
		}
		for _, client := range r.quicDNS {
			client.close()
		}
	})
}

func (r *resolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupMode(ctx, host, false, "")
}
func (r *resolver) lookupReal(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookupMode(ctx, host, true, "")
}
func (r *resolver) lookupMode(ctx context.Context, host string, real bool, forced string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	options, _ := ctx.Value(dnsQueryOptionsKey{}).(resolverOptions)
	ctx, cancel := context.WithCancel(ctx)
	strategy := r.config.Strategy
	if options.Strategy != "" {
		strategy = options.Strategy
	} else if forced == "" {
		for i := range r.policies {
			p := &r.policies[i]
			if p.options.Strategy != "" && p.rule.matches(request{network: "udp", address: net.JoinHostPort(host, "53"), queryType: 1, dns: true}) {
				strategy = p.options.Strategy
				break
			}
		}
	}
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	type result struct {
		ips []netip.Addr
		err error
	}
	ch := make(chan result, 2)
	types := []uint16{1, 28}
	if strategy == "ipv4_only" {
		types = []uint16{1}
	}
	if strategy == "ipv6_only" {
		types = []uint16{28}
	}
	for _, typ := range types {
		go func() { ips, err := r.queryOn(ctx, host, typ, real, forced); ch <- result{ips, err} }()
	}
	var ips []netip.Addr
	var lookupErr error
	for range types {
		item := <-ch
		ips = append(ips, item.ips...)
		if item.err != nil {
			lookupErr = item.err
		}
	}
	if len(ips) == 0 {
		if lookupErr != nil {
			return nil, lookupErr
		}
		return nil, &net.DNSError{Name: host, Err: "no address records", IsNotFound: true}
	}
	if strategy == "prefer_ipv4" || strategy == "prefer_ipv6" {
		ipv4 := strategy == "prefer_ipv4"
		slices.SortStableFunc(ips, func(a, b netip.Addr) int {
			if a.Is4() == b.Is4() {
				return 0
			}
			if a.Is4() == ipv4 {
				return -1
			}
			return 1
		})
	}
	return ips, nil
}
func (r *resolver) query(ctx context.Context, host string, typ uint16) ([]netip.Addr, error) {
	return r.queryOn(ctx, host, typ, false, "")
}
func (r *resolver) queryOn(ctx context.Context, host string, typ uint16, real bool, forced string) ([]netip.Addr, error) {
	ips, _, err := r.queryAnswer(ctx, host, typ, real, forced)
	return ips, err
}
func (r *resolver) queryAnswer(ctx context.Context, host string, typ uint16, real bool, forced string) ([]netip.Addr, uint32, error) {
	query, e := makeDNSQuery(strings.TrimSuffix(strings.ToLower(host), "."), typ)
	if e != nil {
		return nil, 0, e
	}
	var reply []byte
	if forced == "" {
		reply, e = r.exchangePolicy(ctx, query, real)
	} else {
		reply, e = r.exchangeDNSOn(ctx, forced, query, dnsContextOptions(ctx), real)
	}
	if e != nil {
		return nil, 0, e
	}
	if reply[3]&15 == 5 {
		return nil, 0, ErrRejected
	}
	return parseDNSReply(query, reply)
}

func (r *resolver) exchange(ctx context.Context, query []byte) ([]byte, error) {
	return r.exchangeOn(ctx, r.server, query)
}
func (r *resolver) exchangeOn(ctx context.Context, s DNSServer, query []byte) ([]byte, error) {
	if s.Type == "resolved" {
		return r.exchangeResolvedDNS(ctx, s, query)
	}
	if s.Type == "dhcp" {
		return r.exchangeDHCP(ctx, s, query)
	}
	if s.Type == "mdns" {
		return r.exchangeMDNS(ctx, s, query)
	}
	if s.Type == "tailscale" {
		state, _ := ctx.Value(tsDNSKey{}).(*tsDNSSnapshot)
		if state == nil {
			var err error
			state, err = r.runtime.tailscaleClient(s.Endpoint).dnsSnapshot(ctx)
			if err != nil {
				return nil, err
			}
		}
		return state.exchange(ctx, s, query)
	}
	if s.Type == "openconnect" {
		t, _ := ctx.Value(ocDNSKey{}).(*ocTunnel)
		if t == nil {
			var err error
			t, err = r.runtime.ocClients[s.Endpoint].session(ctx)
			if err != nil {
				return nil, err
			}
		}
		return t.exchangeDNS(ctx, s, query)
	}
	if s.Type == "masque" {
		return r.runtime.exchangeMasqueDNS(ctx, s, query)
	}
	if s.Type == "quic" || s.Type == "h3" {
		client := r.quicDNS[s.Tag]
		if client == nil {
			return nil, errors.New("DNS QUIC client unavailable")
		}
		return client.exchange(ctx, query)
	}
	if s.Type == "https" || s.Type == "http" {
		port := s.ServerPort
		if port == 0 {
			port = 53
			if s.Type == "https" {
				port = 443
			}
		}
		address := portAddress(s.Server, port)
		path := s.Path
		if path == "" {
			path = "/dns-query"
		}
		u, err := url.ParseRequestURI(path)
		if err != nil || u.Scheme != "" || u.Host != "" || u.Fragment != "" {
			return nil, errors.New("invalid DoH relative request URI")
		}
		u.Scheme, u.Host = s.Type, address
		// HTTP transports may finish consuming the body after Do returns.
		req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(bytes.Clone(query)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		client := r.clients[s.Tag]
		if client == nil {
			client = r.http
		}
		if client == nil {
			return nil, errors.New("DNS HTTPS client unavailable")
		}
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH HTTP status %d", response.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if len(body) > 65535 {
			return nil, errors.New("oversized DNS response")
		}
		return body, err
	}
	network := "tcp"
	if s.Type == "udp" {
		network = "udp"
	}
	c, err := r.dialDNS(ctx, s, network)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	raw := c
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	if s.Type == "tls" {
		var cfg *tls.Config
		if client := r.clients[s.Tag]; client != nil {
			cfg = client.Transport.(*http.Transport).TLSClientConfig
		} else {
			cfg, err = s.TLS.config(false, s.Server)
			if err != nil {
				return nil, err
			}
		}
		cfg, err = r.prepareTLS(ctx, s, cfg)
		if err != nil {
			return nil, err
		}
		secured := clientTLS(c, cfg, s.TLS)
		if err := secured.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		c = secured
	}
	if network == "tcp" {
		if err := writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(query)))); err != nil {
			return nil, err
		}
	}
	if err := writeAll(c, query); err != nil {
		return nil, err
	}
	if network == "udp" {
		b := make([]byte, 65535)
		n, err := c.Read(b)
		if err != nil {
			return nil, err
		}
		if n >= 4 && b[2]&2 != 0 {
			fallback := s
			fallback.Type = "tcp"
			return r.exchangeOn(ctx, fallback, query)
		}
		return b[:n], nil
	}
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return nil, err
	}
	b := make([]byte, int(binary.BigEndian.Uint16(size[:])))
	_, err = io.ReadFull(c, b)
	return b, err
}

func makeDNSQuery(host string, typ uint16) ([]byte, error) {
	if len(host) == 0 || len(host) > 253 && (!strings.Contains(host, `\`) || len(host) > 4*253) {
		return nil, errors.New("invalid DNS hostname length")
	}
	b := make([]byte, 12)
	if _, err := rand.Read(b[:2]); err != nil {
		return nil, err
	}
	b[2] = 1
	b[5] = 1
	var err error
	b, err = dnsAppendName(b, host)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, typ)
	return binary.BigEndian.AppendUint16(b, 1), nil
}

func dnsName(b []byte, offset int) (string, int, error) {
	var labels []string
	next := -1
	wireLength := 1
	for steps := 0; steps < 128; steps++ {
		if offset >= len(b) {
			return "", 0, io.ErrUnexpectedEOF
		}
		length := int(b[offset])
		offset++
		if length&0xc0 == 0xc0 {
			if offset >= len(b) {
				return "", 0, io.ErrUnexpectedEOF
			}
			if next < 0 {
				next = offset + 1
			}
			offset = (length&0x3f)<<8 | int(b[offset])
			continue
		}
		if length > 63 || offset+length > len(b) {
			return "", 0, errors.New("invalid DNS label")
		}
		if length == 0 {
			if next < 0 {
				next = offset
			}
			name := strings.ToLower(strings.Join(labels, "."))
			return name, next, nil
		}
		wireLength += length + 1
		if wireLength > 255 {
			return "", 0, errors.New("DNS name too long")
		}
		labels = append(labels, dnsEscapeLabel(b[offset:offset+length]))
		offset += length
	}
	return "", 0, errors.New("DNS compression pointer loop")
}

func parseDNSReply(query, reply []byte) ([]netip.Addr, uint32, error) {
	if len(reply) < 12 || len(query) < 12 || !bytes.Equal(query[:2], reply[:2]) || reply[2]&0x80 == 0 || reply[2]&0x7a != 0 || binary.BigEndian.Uint16(reply[4:6]) != 1 {
		return nil, 0, errors.New("invalid DNS response header")
	}
	if code := reply[3] & 15; code != 0 {
		_, _, _, err := validateDNSQuestionResponse(query, reply)
		if err != nil {
			return nil, 0, err
		}
		return nil, 0, &net.DNSError{Err: fmt.Sprintf("DNS response code %d", code), IsNotFound: code == 3, IsTemporary: code == 2}
	}
	name, end, err := dnsName(reply, 12)
	if err != nil || end+4 > len(reply) {
		return nil, 0, errors.New("invalid DNS question")
	}
	qname, qend, err := dnsName(query, 12)
	if err != nil || name != qname || !bytes.Equal(query[qend:qend+4], reply[end:end+4]) {
		return nil, 0, errors.New("DNS question mismatch")
	}
	typ := binary.BigEndian.Uint16(query[qend : qend+2])
	offset := end + 4
	count := int(binary.BigEndian.Uint16(reply[6:8]))
	if count > 4096 {
		return nil, 0, errors.New("too many DNS answers")
	}
	type answer struct {
		name, target string
		ip           netip.Addr
		ttl          uint32
	}
	answers := make([]answer, 0, count)
	for range count {
		name, next, err := dnsName(reply, offset)
		if err != nil || next+10 > len(reply) {
			return nil, 0, errors.New("invalid DNS resource record")
		}
		kind, class := binary.BigEndian.Uint16(reply[next:]), binary.BigEndian.Uint16(reply[next+2:])
		ttl := binary.BigEndian.Uint32(reply[next+4:])
		size := int(binary.BigEndian.Uint16(reply[next+8:]))
		offset = next + 10
		if offset+size > len(reply) {
			return nil, 0, io.ErrUnexpectedEOF
		}
		a := answer{name: name, ttl: ttl}
		if class == 1 {
			if kind == 5 {
				a.target, _, err = dnsName(reply, offset)
				if err != nil {
					return nil, 0, err
				}
			}
			if kind == typ && (kind == 1 && size == 4 || kind == 28 && size == 16) {
				a.ip, _ = netip.AddrFromSlice(reply[offset : offset+size])
			}
			answers = append(answers, a)
		}
		offset += size
	}
	allowed := map[string]bool{qname: true}
	ttl := uint32(86400)
	for range len(answers) {
		changed := false
		for _, a := range answers {
			if allowed[a.name] && a.target != "" && !allowed[a.target] {
				allowed[a.target] = true
				changed = true
				ttl = min(ttl, a.ttl)
			}
		}
		if !changed {
			break
		}
	}
	var ips []netip.Addr
	for _, a := range answers {
		if allowed[a.name] && a.ip.IsValid() {
			ips = append(ips, a.ip)
			ttl = min(ttl, a.ttl)
		}
	}
	return ips, ttl, nil
}
