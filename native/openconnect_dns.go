package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Immutable for a CSTP session; a reconnect replaces the complete configuration.
type ocDNSConfig struct {
	servers       []netip.Addr
	search, split []string
	all           bool
}

type ocDNSKey struct{}

func dnsPreferredTags(rules []Rule) []string {
	seen := map[string]bool{}
	var walk func([]Rule)
	walk = func(rules []Rule) {
		for _, rule := range rules {
			for _, tag := range rule.PreferredBy {
				seen[tag] = true
			}
			walk(rule.Rules)
		}
	}
	walk(rules)
	return slices.Sorted(maps.Keys(seen))
}

func (r *resolver) dnsPreferences(ctx context.Context, host string) ([]string, error) {
	d, _ := optionDuration(r.config.Timeout, 10*time.Second)
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	var preferred []string
	for _, tag := range r.preferredTags {
		s := r.servers[tag]
		if s.Type == "resolved" {
			_, matched := r.runtime.resolved[s.Service].state.Load().candidates(host, 0, false)
			if matched {
				preferred = append(preferred, tag)
			}
			continue
		}
		if s.Type == "tailscale" {
			state, err := r.runtime.tailscaleClient(s.Endpoint).dnsSnapshot(ctx)
			if err != nil {
				return nil, err
			}
			if state.preferred(host, s.AcceptSearchDomain) {
				preferred = append(preferred, tag)
			}
			continue
		}
		if s.Type == "hosts" {
			if _, ok := s.Predefined[host]; ok {
				preferred = append(preferred, tag)
			}
			continue
		}
		c := r.runtime.ocClients[s.Endpoint]
		t := c.tunnel.Load()
		if t == nil || t.ctx.Err() != nil {
			var err error
			t, err = c.session(ctx)
			if err != nil {
				return nil, err
			}
		}
		// Discovery failure never falls through to a public DNS server.
		if t.dns.matches(host) || s.AcceptSearchDomain && !strings.Contains(host, ".") && len(t.dns.search) > 0 {
			preferred = append(preferred, tag)
		}
	}
	return preferred, nil
}

func (o OpenConnectOptions) dnsHeaders() http.Header {
	h := http.Header{}
	if len(o.DNS) > 0 {
		h["X-CSTP-DNS"] = o.DNS
	}
	if len(o.SearchDomains) > 0 {
		h["X-CSTP-Default-Domain"] = []string{strings.Join(o.SearchDomains, " ")}
	}
	if len(o.SplitDNS) > 0 {
		h["X-CSTP-Split-DNS"] = o.SplitDNS
	}
	if o.TunnelAllDNS {
		h["X-CSTP-Tunnel-All-DNS"] = []string{"true"}
	}
	return h
}

func ocParseDNS(h http.Header) (ocDNSConfig, error) {
	var c ocDNSConfig
	size := 0
	for name, values := range h {
		name = strings.ToLower(name)
		if name != "x-cstp-dns" && name != "x-cstp-dns-ip6" && name != "x-cstp-default-domain" && name != "x-cstp-split-dns" && name != "x-cstp-tunnel-all-dns" {
			continue
		}
		for _, value := range values {
			size += len(name) + len(value) + 4
			if size > 48*1024 {
				return c, errors.New("OpenConnect DNS headers exceed48KiB")
			}
			if strings.ContainsAny(value, "\x00\r\n") {
				return c, errors.New("invalid OpenConnect DNS header")
			}
			if name == "x-cstp-tunnel-all-dns" {
				switch strings.ToLower(value) {
				case "true":
					c.all = true
				case "false":
				default:
					return c, errors.New("invalid OpenConnect tunnel-all-DNS flag")
				}
				continue
			}
			for _, v := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' }) {
				if name == "x-cstp-dns" || name == "x-cstp-dns-ip6" {
					ip, err := netip.ParseAddr(v)
					if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Is4In6() || ip.Zone() != "" {
						return c, fmt.Errorf("invalid OpenConnect DNS address %q", v)
					}
					if !slices.Contains(c.servers, ip) {
						c.servers = append(c.servers, ip)
					}
				} else {
					v = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(v, "."), "."))
					if !masqueDomain(v, false) {
						return c, errors.New("invalid OpenConnect DNS domain")
					}
					dest := &c.split
					if name == "x-cstp-default-domain" {
						dest = &c.search
					}
					if !slices.Contains(*dest, v) {
						*dest = append(*dest, v)
					}
				}
				if len(c.servers) > 128 || len(c.search) > 128 || len(c.split) > 128 {
					return c, errors.New("OpenConnect DNS configuration exceeds128 entries")
				}
			}
		}
	}
	return c, nil
}

func (c ocDNSConfig) matches(host string) bool {
	for _, domains := range [][]string{c.split, c.search} {
		for _, suffix := range domains {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				return true
			}
		}
	}
	return false
}

func (t *ocTunnel) exchangeDNS(ctx context.Context, options DNSServer, query []byte) ([]byte, error) {
	host, end, _, err := dnsQuestion(query)
	if err != nil {
		return nil, err
	}
	if options.AcceptSearchDomain && !strings.Contains(host, ".") {
		// Signed DNS queries cannot have their question rewritten.
		sections, err := dnsRecords(query)
		if err != nil {
			return nil, err
		}
		signed := slices.ContainsFunc(sections[2], func(rr dnsRecord) bool { return rr.typ == 250 || rr.typ == 24 })
		if !signed {
			for _, suffix := range t.dns.search {
				name := host + "." + suffix
				wire, err := dnsAppendName(slices.Clone(query[:12]), name)
				if err != nil {
					continue
				}
				wire = append(wire, query[end-4:]...)
				reply, err := t.queryDNS(ctx, wire)
				if err != nil {
					return nil, err
				}
				if reply[3]&15 != 3 {
					return ocSearchReply(query, reply, name)
				}
			}
		}
	}
	if !t.dns.matches(host) && !(options.AcceptDefaultResolvers && (t.dns.all || len(t.dns.split)+len(t.dns.search) == 0)) {
		return dnsResponse(query, end, nil, 0, 3), nil
	}
	return t.queryDNS(ctx, query)
}

func (t *ocTunnel) queryDNS(ctx context.Context, query []byte) ([]byte, error) {
	if len(t.dns.servers) == 0 {
		return nil, errors.New("OpenConnect server pushed no DNS resolvers")
	}
	// Reuse the wire exchange and TCP fallback without creating an HTTP client or
	// allowing an application-level detour to escape this authenticated IP tunnel.
	r := resolver{tunnelDial: func(ctx context.Context, s DNSServer, network string) (net.Conn, error) {
		return t.stack.dial(ctx, network, portAddress(s.Server, 53))
	}}
	last := errors.New("OpenConnect DNS query failed")
	for i, ip := range t.dns.servers {
		call, cancel := ctx, func() {}
		if deadline, ok := ctx.Deadline(); ok {
			call, cancel = context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(t.dns.servers)-i))
		}
		reply, err := r.exchangeOn(call, DNSServer{Type: "udp", Server: ip.String()}, query)
		cancel()
		if err == nil {
			_, _, _, err = validateDNSQuestionResponse(query, reply)
		}
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

func ocSearchReply(query, reply []byte, expanded string) ([]byte, error) {
	host, end, _, err := dnsQuestion(query)
	if err != nil {
		return nil, err
	}
	sections, err := dnsRecords(reply)
	if err != nil {
		return nil, err
	}
	out := slices.Clone(query[:end])
	copy(out[2:4], reply[2:4])
	out[3] &^= 0x20 // The locally added CNAME is not DNSSEC-authenticated.
	clear(out[6:12])
	if reply[3]&15 == 0 {
		name, err := dnsAppendName(nil, expanded)
		if err != nil {
			return nil, err
		}
		ttl := uint32(60)
		for _, rr := range sections[0] {
			ttl = min(ttl, rr.ttl)
		}
		sections[0] = slices.Insert(sections[0], 0, dnsRecord{name: host, typ: 5, class: 1, ttl: ttl, data: name})
	}
	for i, records := range sections {
		if len(records) > 65535 {
			return nil, errors.New("OpenConnect DNS response has too many records")
		}
		binary.BigEndian.PutUint16(out[6+i*2:], uint16(len(records)))
		for _, rr := range records {
			out, err = dnsAppendName(out, rr.name)
			if err != nil {
				return nil, err
			}
			out = binary.BigEndian.AppendUint16(out, rr.typ)
			out = binary.BigEndian.AppendUint16(out, rr.class)
			out = binary.BigEndian.AppendUint32(out, rr.ttl)
			out = binary.BigEndian.AppendUint16(out, uint16(len(rr.data)))
			out = append(out, rr.data...)
		}
	}
	if len(out) > 65535 {
		return nil, errors.New("OpenConnect DNS response exceeds65535 bytes")
	}
	return out, nil
}
