package native

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const neighborFields = 1<<15 | 1<<16
const neighborLimit = 16384

type neighborEntry struct {
	mac, hostname string
	until         time.Time
	ambiguous     bool
}

func (e neighborEntry) valid(now time.Time) bool {
	return !e.ambiguous && (e.until.IsZero() || now.Before(e.until))
}

type neighborSnapshot struct {
	byIP  map[netip.Addr]neighborEntry
	byMAC map[string]neighborEntry
}

// No polling worker: a shared immutable snapshot is refreshed only on demand.
type neighborCache struct {
	mu    sync.Mutex
	next  time.Time
	state neighborSnapshot
	read  func(context.Context, []string) neighborSnapshot
}

func (c *neighborCache) snapshot(ctx context.Context, paths []string) neighborSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return neighborSnapshot{}
	}
	if now := time.Now(); !now.Before(c.next) {
		read := c.read
		if read == nil {
			read = readNeighbors
		}
		call, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		state := read(call, paths)
		cancel()
		if ctx.Err() != nil {
			return neighborSnapshot{}
		}
		c.state, c.next = state, now.Add(time.Second)
	}
	return c.state
}

func (c *neighborCache) invalidate() {
	c.mu.Lock()
	c.next = time.Time{}
	c.mu.Unlock()
}

func normalizedMAC(s string) string {
	if len(s) == 17 && strings.ContainsRune("02468ace", rune(s[1])) {
		canonical, nonzero := true, false
		for i := range len(s) {
			if i%3 == 2 {
				canonical = canonical && s[i] == ':'
			} else {
				canonical = canonical && (s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f')
				nonzero = nonzero || s[i] != '0'
			}
		}
		if canonical && nonzero {
			return s
		}
	}
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 || m[0]&1 != 0 || slices.Equal(m, []byte{0, 0, 0, 0, 0, 0}) {
		return ""
	}
	return m.String()
}

func neighborHostname(s string) string {
	s = canonicalDomain(s)
	if s == "" || s == "*" || len(s) > 253 {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return ""
			}
		}
	}
	return s
}

func validateNeighborRule(o Rule) error {
	for _, mac := range o.SourceMACAddress {
		if normalizedMAC(mac) == "" {
			return errors.New("source_mac_address requires a unicast Ethernet MAC")
		}
	}
	for _, host := range o.SourceHostname {
		if neighborHostname(host) == "" {
			return errors.New("invalid source_hostname")
		}
	}
	return nil
}

func matchNeighborRule(o Rule, m Metadata) bool {
	if len(o.SourceMACAddress) > 0 && (m.SourceMACAddress == "" || !slices.ContainsFunc(o.SourceMACAddress, func(s string) bool { return normalizedMAC(s) == normalizedMAC(m.SourceMACAddress) })) {
		return false
	}
	return len(o.SourceHostname) == 0 || m.SourceHostname != "" && slices.ContainsFunc(o.SourceHostname, func(s string) bool { return canonicalDomain(s) == canonicalDomain(m.SourceHostname) })
}

func validateNeighborOptions(o Route) error {
	if len(o.DHCPLeaseFiles) > 64 {
		return errors.New("at most64 dhcp_lease_files are allowed")
	}
	for _, p := range o.DHCPLeaseFiles {
		if p == "" || strings.ContainsAny(p, "\x00\r\n") {
			return errors.New("invalid dhcp_lease_files path")
		}
	}
	return nil
}

func (r *Runtime) enrichNeighbor(ctx context.Context, q *request) {
	if !r.config.Route.FindNeighbor && !r.needsMetadata(neighborFields) || q.metadata.SourceMACAddress != "" && q.metadata.SourceHostname != "" {
		return
	}
	source := q.source
	if source == "" && q.origin != nil {
		source = q.origin.source
	}
	peer, err := netip.ParseAddrPort(source)
	if err != nil || !peer.Addr().IsGlobalUnicast() && !peer.Addr().IsLinkLocalUnicast() {
		return
	}
	var entry neighborEntry
	if namespace := r.inboundNamespace(q.inbound); namespace != nil {
		m := namespace.neighborIdentity(ctx, source, r.config.Route.DHCPLeaseFiles)
		entry.mac, entry.hostname = m.SourceMACAddress, m.SourceHostname
	} else {
		state := r.neighbors.snapshot(ctx, r.config.Route.DHCPLeaseFiles)
		entry = state.byIP[peer.Addr().Unmap()]
	}
	if !entry.valid(time.Now()) {
		return
	}
	if q.metadata.SourceMACAddress != "" && entry.mac != "" && normalizedMAC(q.metadata.SourceMACAddress) != entry.mac {
		return
	}
	if q.metadata.SourceMACAddress == "" {
		q.metadata.SourceMACAddress = entry.mac
	}
	if q.metadata.SourceHostname == "" {
		q.metadata.SourceHostname = entry.hostname
	}
}

func readNeighbors(ctx context.Context, paths []string) neighborSnapshot {
	s := neighborSnapshot{byIP: map[netip.Addr]neighborEntry{}, byMAC: map[string]neighborEntry{}}
	if len(paths) == 0 {
		for _, pattern := range []string{"/var/lib/misc/dnsmasq.leases", "/var/lib/dnsmasq/*.leases", "/var/lib/NetworkManager/dnsmasq-*.leases", "/tmp/dhcp.leases", "/tmp/hosts/odhcpd", "/tmp/odhcpd.leases", "/var/lib/dhcp/dhcpd*.leases", "/var/lib/dhcpd/dhcpd*.leases", "/var/lib/kea/kea-leases*.csv", "/var/db/dhcpd_leases"} {
			matches, _ := filepath.Glob(pattern)
			paths = append(paths, matches...)
		}
	}
	for _, path := range paths {
		if ctx.Err() != nil {
			return s
		}
		for ip, e := range readNeighborLeases(path) {
			if old, ok := s.byIP[ip]; ok && (old.mac != e.mac || old.hostname != e.hostname) {
				for _, mac := range []string{old.mac, e.mac} {
					if mac != "" && (len(s.byMAC) < neighborLimit || s.byMAC[mac] != (neighborEntry{})) {
						s.byMAC[mac] = neighborEntry{ambiguous: true}
					}
				}
				e = neighborEntry{ambiguous: true}
			}
			if len(s.byIP) < neighborLimit || s.byIP[ip] != (neighborEntry{}) {
				s.byIP[ip] = e
			}
			if e.mac != "" && e.hostname != "" && !e.ambiguous && (len(s.byMAC) < neighborLimit || s.byMAC[e.mac] != (neighborEntry{})) {
				if old, ok := s.byMAC[e.mac]; ok && (old.ambiguous || old.hostname != e.hostname) {
					e.ambiguous = true
				}
				s.byMAC[e.mac] = e
			}
		}
	}
	// A live kernel mapping wins over a stale lease's MAC, but never inherits its hostname.
	for ip, live := range systemNeighbors(ctx) {
		lease := s.byIP[ip]
		if !live.ambiguous && lease.valid(time.Now()) && (lease.mac == "" || lease.mac == live.mac) {
			live.hostname, live.until = lease.hostname, lease.until
		}
		if live.hostname == "" && !live.ambiguous {
			if same := s.byMAC[live.mac]; same.valid(time.Now()) {
				live.hostname, live.until = same.hostname, same.until
			}
		}
		if len(s.byIP) < neighborLimit || s.byIP[ip] != (neighborEntry{}) {
			s.byIP[ip] = live
		}
	}
	return s
}

func validateNeighborDNS(s DNSServer) error {
	if len(s.NeighborDomain) > 0 && s.Type != "local" {
		return errors.New("neighbor_domain requires a local DNS server")
	}
	for _, suffix := range s.NeighborDomain {
		if suffix != "." && (!strings.HasPrefix(suffix, ".") || neighborHostname(suffix[1:]) == "" || strings.HasSuffix(suffix, ".")) {
			return errors.New("neighbor_domain entries must be . or a suffix such as .lan")
		}
	}
	return nil
}

func (r *resolver) neighborDNS(ctx context.Context, s DNSServer, query []byte, host string, end int, typ uint16) ([]byte, bool, error) {
	if len(s.NeighborDomain) == 0 || typ != 1 && typ != 28 {
		return nil, false, nil
	}
	label := ""
	for _, suffix := range s.NeighborDomain {
		suffix = strings.ToLower(suffix)
		name := canonicalDomain(host)
		if suffix != "." {
			if !strings.HasSuffix(name, suffix) {
				continue
			}
			name = strings.TrimSuffix(name, suffix)
		}
		if name != "" && !strings.Contains(name, ".") {
			label = name
			break
		}
	}
	if label == "" {
		return nil, false, nil
	}
	if r.runtime == nil {
		return nil, true, errors.New("neighbor_domain requires a runtime")
	}
	snapshot := r.runtime.neighbors.snapshot(ctx, r.runtime.config.Route.DHCPLeaseFiles)
	if err := ctx.Err(); err != nil {
		return nil, true, err
	}
	var ips []netip.Addr
	now, ttl, found := time.Now(), uint32(60), false
	for ip, e := range snapshot.byIP {
		if e.hostname != label && e.hostname != canonicalDomain(host) || !e.valid(now) {
			continue
		}
		found = true
		if ip.Zone() != "" || ip.Is4() != (typ == 1) {
			continue
		}
		if !e.until.IsZero() {
			ttl = min(ttl, uint32(max(0, e.until.Sub(now)/time.Second)))
		}
		if len(ips) < 256 && !slices.Contains(ips, ip) {
			ips = append(ips, ip)
		}
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	code := byte(0)
	if !found {
		code = 3
	}
	return dnsResponse(query, end, ips, ttl, code), true, nil
}
