package native

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type tunFlowKey struct {
	source, destination netip.Addr
	sport, dport        uint16
}

// All runtime-owned interfaces share socket protection; closing one must not unprotect another.
func (r *Runtime) retainTUNProtection(mark uint32) uint32 {
	r.tunProtectMu.Lock()
	defer r.tunProtectMu.Unlock()
	r.tunProtectUsers++
	if r.protectMark.Load() == 0 {
		r.protectMark.Store(mark)
	}
	return r.protectMark.Load()
}
func (r *Runtime) releaseTUNProtection() {
	r.tunProtectMu.Lock()
	defer r.tunProtectMu.Unlock()
	r.tunProtectUsers--
	if r.tunProtectUsers == 0 {
		r.protectMark.Store(0)
		r.tunEgress4.Store(0)
		r.tunEgress6.Store(0)
		r.tunRouting.Store(false)
	}
}

type tunTunnel struct {
	namespace        *networkNamespace
	namespaceID      string
	namespaceQueue   *os.File
	namespaceMonitor *os.File
	runtime          *Runtime
	in               Inbound
	device           io.ReadWriteCloser
	queues           []io.ReadWriteCloser
	name             string
	mark             uint32
	cleanup          func()
	ctx              context.Context
	cancel           context.CancelFunc
	local4, local6   netip.Addr
	writeMu          sync.Mutex
	stack            *wgIPStack
	workers          sync.WaitGroup
	once             sync.Once
	packetID         atomic.Uint32
	localAddresses   []netip.Addr
	hostAddresses    []netip.Addr
	hostMu           sync.RWMutex
	platformMu       sync.Mutex
	refreshRoutes    func() error
	routes           *tunRouteState
	refreshEgress    func() error
	networkEvents    <-chan struct{}
	networkKey       string
	monitor          func()
	tpListener       net.Listener
}

func (r *Runtime) startTUN(in Inbound) (*tunTunnel, error) {
	var err error
	in, err = r.tunRouteSets(in)
	if err != nil {
		return nil, err
	}
	t, e := openTUN(r, in)
	if e != nil {
		return nil, e
	}
	t.ctx, t.cancel = context.WithCancel(r.ctx)
	t.installRouteRefresh()
	if e = t.configureDNS(); e != nil {
		t.close()
		return nil, e
	}
	if e = t.configureMonitor(); e != nil {
		t.close()
		return nil, e
	}
	local := []netip.Addr{}
	for _, a := range []netip.Addr{t.local4, t.local6} {
		if a.IsValid() {
			local = append(local, a)
		}
	}
	mtu := in.MTU
	if mtu == 0 {
		mtu = 1500
	}
	if len(t.localAddresses) > 0 {
		local = t.localAddresses
	}
	t.stack = newIPStack(&ipEndpoint{runtime: r, inbound: in.Tag, local: local, mtu: mtu, done: t.ctx.Done(), sendIP: t.writePacket, ensure: func(context.Context) error { return nil }, dnsHijack: t.hijackDNS, loopback: in.LoopbackAddress})
	if in.UDPTimeout != "" {
		t.stack.flows.timeout, _ = optionDuration(in.UDPTimeout, udpTimeout)
	}
	if t.namespace == nil {
		ifaces, _ := net.InterfaceAddrs()
		for _, a := range ifaces {
			if p, e := netip.ParsePrefix(a.String()); e == nil {
				t.hostAddresses = append(t.hostAddresses, p.Addr())
			}
		}
	}
	t.networkKey = t.physicalNetworkKey()
	return t, nil
}
func (t *tunTunnel) start() {
	t.startFilter()
	if t.monitor != nil {
		t.workers.Add(1)
		go func() { defer t.workers.Done(); t.monitor() }()
	}
	if t.tpListener != nil {
		t.workers.Add(1)
		go func() { defer t.workers.Done(); t.serveTransparent() }()
	}
	if len(t.queues) == 0 {
		t.queues = []io.ReadWriteCloser{t.device}
	}
	t.workers.Add(1 + len(t.queues))
	for _, q := range t.queues {
		go func() { defer t.workers.Done(); t.readLoop(q) }()
	}
	go func() {
		defer t.workers.Done()
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-t.ctx.Done():
				return
			case <-t.networkEvents:
				t.platformMu.Lock()
				if t.ctx.Err() == nil && t.refreshEgress != nil {
					if e := t.refreshEgress(); e != nil {
						t.runtime.logger.Warn("refresh TUN physical network", zap.Error(e))
					} else if key := t.physicalNetworkKey(); key != t.networkKey {
						t.networkKey = key
						t.runtime.resetNetworkTransports()
					}
				}
				t.platformMu.Unlock()
			case now := <-timer.C:
				t.stack.expire(now)
				if t.refreshRoutes != nil {
					t.platformMu.Lock()
					if t.ctx.Err() == nil {
						if e := t.refreshRoutes(); e != nil {
							t.runtime.logger.Warn("refresh TUN routes", zap.Error(e))
						}
					}
					t.platformMu.Unlock()
				}
			}
		}
	}()
}
func (t *tunTunnel) close() {
	t.once.Do(func() {
		if t.cancel != nil {
			t.cancel()
		}
		if t.cleanup != nil {
			t.platformMu.Lock()
			t.cleanup()
			t.platformMu.Unlock()
		}
		for _, q := range t.queues {
			q.Close()
		}
		t.device.Close()
		if t.stack != nil {
			t.stack.close()
		}
		if t.namespace == nil && t.runtime != nil {
			t.runtime.network.exclude(t.name, false)
		}
	})
}
func (t *tunTunnel) readLoop(device io.Reader) {
	buffer := make([]byte, 65575)
	for {
		n, e := device.Read(buffer)
		if e != nil {
			return
		}
		p, e := parseTunPacket(buffer[:n])
		if e == nil {
			t.stack.input(p)
		}
	}
}
func (t *tunTunnel) hijackDNS(destination netip.Addr, port uint16) bool {
	if port != 53 {
		return false
	}
	mode := t.dnsMode()
	if mode == "disabled" {
		return false
	}
	if len(t.in.DNSAddress) == 0 {
		for _, a := range []netip.Addr{t.local4, t.local6} {
			if a.IsValid() && a.Next() == destination {
				return true
			}
		}
	}
	t.hostMu.RLock()
	defer t.hostMu.RUnlock()
	for _, a := range t.hostAddresses {
		if destination == a {
			return false
		}
	}
	return mode == "hijack" && !destination.IsLoopback() && destination != t.local4 && destination != t.local6
}

func (t *tunTunnel) dnsMode() string {
	return tunDNSMode(t.in)
}
func tunDNSMode(in Inbound) string {
	if in.DNSMode != "" {
		return in.DNSMode
	}
	if in.AutoRoute {
		return "hijack"
	}
	return "disabled"
}
func (t *tunTunnel) dnsAddresses() []string {
	if len(t.in.DNSAddress) != 0 {
		return t.in.DNSAddress
	}
	var out []string
	for _, a := range []netip.Addr{t.local4, t.local6} {
		if a.IsValid() {
			out = append(out, a.Next().String())
		}
	}
	return out
}
func tunAddresses(in Inbound) []string {
	if len(in.Address) != 0 {
		return in.Address
	}
	return []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}
}
func (t *tunTunnel) addLocal(ip netip.Addr) {
	t.localAddresses = append(t.localAddresses, ip)
	if ip.Is4() && !t.local4.IsValid() {
		t.local4 = ip
	}
	if ip.Is6() && !t.local6.IsValid() {
		t.local6 = ip
	}
}
func tunCommand(path string, input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	if input != "" {
		c.Stdin = strings.NewReader(input)
	}
	b, e := c.CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %w: %s", path, e, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

// Only destination IP predicates can be represented by operating-system routes.
func (r *Runtime) tunRouteSets(in Inbound) (Inbound, error) {
	collect := func(tags []string) ([]string, error) {
		var out []string
		for _, tag := range tags {
			s := r.ruleSets[tag].current.Load()
			if s == nil {
				return nil, fmt.Errorf("TUN rule_set %s is not loaded", tag)
			}
			for _, rule := range s.rules {
				o := rule.rule
				if len(rule.children) != 0 || o.Invert || len(o.SourceIPCIDR)+len(o.Domain)+len(o.DomainSuffix)+len(o.DomainKeyword)+len(o.DomainRegex)+len(o.Port)+len(o.PortRange)+len(o.Network)+len(o.SourcePort)+len(o.SourcePortRange) != 0 || o.domains != nil || o.hasMetadataConditions() || o.IPIsPrivate || o.SourceIPIsPrivate || len(o.sourceRanges) != 0 {
					return nil, fmt.Errorf("TUN rule_set %s must contain only destination IP ranges", tag)
				}
				out = append(out, o.IPCIDR...)
				for _, v := range o.ipRanges {
					for _, p := range rangePrefixes(v.from, v.to) {
						out = append(out, p.String())
					}
				}
			}
		}
		return out, nil
	}
	for _, v := range []struct {
		tags []string
		dst  *[]string
	}{{in.RouteAddressSet, &in.RouteAddress}, {in.RouteExcludeAddressSet, &in.RouteExcludeAddress}} {
		p, e := collect(v.tags)
		if e != nil {
			return in, e
		}
		*v.dst = append(append([]string{}, (*v.dst)...), p...)
	}
	return in, nil
}

func rangePrefixes(from, to netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for from.IsValid() && from.Compare(to) <= 0 {
		p := netip.PrefixFrom(from, from.BitLen())
		for bits := from.BitLen() - 1; bits >= 0; bits-- {
			next := netip.PrefixFrom(from, bits).Masked()
			if next.Addr() != from || prefixLast(next).Compare(to) > 0 {
				break
			}
			p = next
		}
		out = append(out, p)
		from = prefixLast(p).Next()
	}
	return out
}
func prefixLast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for bit := p.Bits(); bit < len(b)*8; bit++ {
		b[bit/8] |= 1 << (7 - bit%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// Split default routes and subtract excluded ranges without replacing the host's routes.
func tunRoutePrefixes(in Inbound) []netip.Prefix {
	values := in.RouteAddress
	if len(values) == 0 && len(in.RouteAddressSet) == 0 {
		for _, v := range tunAddresses(in) {
			p, _ := netip.ParsePrefix(v)
			if p.Addr().Is4() {
				values = append(values, "0.0.0.0/0")
			} else {
				values = append(values, "::/0")
			}
		}
		if in.StrictRoute {
			values = []string{"0.0.0.0/0", "::/0"}
		}
	}
	if tunDNSMode(in) != "disabled" && len(in.DNSAddress) == 0 {
		seen := map[bool]bool{}
		for _, value := range tunAddresses(in) {
			p := netip.MustParsePrefix(value)
			a := p.Addr()
			if !seen[a.Is4()] {
				seen[a.Is4()] = true
				if a.Next().IsValid() {
					values = append(append([]string{}, values...), netip.PrefixFrom(a.Next(), a.BitLen()).String())
				}
			}
		}
	}
	toRanges := func(values []string) []ipRange {
		var ranges []ipRange
		for _, v := range values {
			p := netip.MustParsePrefix(v).Masked()
			ranges = append(ranges, ipRange{p.Addr(), prefixLast(p)})
		}
		slices.SortFunc(ranges, func(a, b ipRange) int {
			if c := a.from.Compare(b.from); c != 0 {
				return c
			}
			return a.to.Compare(b.to)
		})
		var merged []ipRange
		for _, v := range ranges {
			if len(merged) > 0 {
				last := &merged[len(merged)-1]
				if last.from.Is4() == v.from.Is4() && (last.to.Compare(v.from) >= 0 || last.to.Next() == v.from) {
					if v.to.Compare(last.to) > 0 {
						last.to = v.to
					}
					continue
				}
			}
			merged = append(merged, v)
		}
		return merged
	}
	includes, excludes := toRanges(values), toRanges(in.RouteExcludeAddress)
	var ranges []ipRange
	index := 0
	for _, r := range includes {
		cur := r.from
		for index < len(excludes) && excludes[index].to.Compare(cur) < 0 {
			index++
		}
		for i := index; i < len(excludes) && excludes[i].from.Compare(r.to) <= 0; i++ {
			x := excludes[i]
			if x.from.Is4() != cur.Is4() {
				continue
			}
			if x.from.Compare(cur) > 0 {
				ranges = append(ranges, ipRange{cur, x.from.Prev()})
			}
			if x.to.Compare(r.to) >= 0 {
				cur = netip.Addr{}
				break
			}
			cur = x.to.Next()
		}
		if cur.IsValid() && cur.Compare(r.to) <= 0 {
			ranges = append(ranges, ipRange{cur, r.to})
		}
	}
	var prefixes []netip.Prefix
	for _, r := range ranges {
		prefixes = append(prefixes, rangePrefixes(r.from, r.to)...)
	}
	var out []netip.Prefix
	for _, p := range prefixes {
		if p.Bits() == 0 {
			out = append(out, netip.PrefixFrom(p.Addr(), 1), netip.PrefixFrom(prefixLast(netip.PrefixFrom(p.Addr(), 1)).Next(), 1))
		} else {
			out = append(out, p)
		}
	}
	return out
}
func (t *tunTunnel) writePacket(packet []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	// utun injects received IP packets; splitting them needlessly depends on kernel reassembly.
	if device, ok := t.device.(*framedTUN); ok {
		_, err := device.Write(packet)
		return err
	}
	return writeIPFragments(packet, t.in.MTU, t.packetID.Add(1), func(b []byte) error { _, e := t.device.Write(b); return e })
}
func writeIPFragments(packet []byte, mtu int, id uint32, write func([]byte) error) error {
	if mtu == 0 {
		mtu = 1500
	}
	if len(packet) <= mtu {
		return write(packet)
	}
	p, err := parseTunPacket(packet)
	if err != nil {
		return err
	}
	segment := packet[p.header:]
	header := p.header
	extra := 0
	if p.source.Is6() {
		extra = 8
	}
	chunk := (mtu - header - extra) &^ 7
	if chunk < 8 {
		return errors.New("TUN MTU too small")
	}
	for offset := 0; offset < len(segment); offset += chunk {
		n := min(chunk, len(segment)-offset)
		fragment := make([]byte, header+extra+n)
		copy(fragment, packet[:header])
		more := offset+n < len(segment)
		if p.source.Is4() {
			binary.BigEndian.PutUint16(fragment[2:], uint16(len(fragment)))
			binary.BigEndian.PutUint16(fragment[4:], uint16(id))
			flags := uint16(offset / 8)
			if more {
				flags |= 0x2000
			}
			binary.BigEndian.PutUint16(fragment[6:], flags)
			clear(fragment[10:12])
			binary.BigEndian.PutUint16(fragment[10:], checksum(fragment[:header], 0))
		} else {
			fragment[p.nextHeader] = 44
			binary.BigEndian.PutUint16(fragment[4:], uint16(len(fragment)-40))
			fragment[header] = p.protocol
			flags := uint16(offset)
			if more {
				flags |= 1
			}
			binary.BigEndian.PutUint16(fragment[header+2:], flags)
			binary.BigEndian.PutUint32(fragment[header+4:], id)
		}
		copy(fragment[header+extra:], segment[offset:offset+n])
		if err := write(fragment); err != nil {
			return err
		}
	}
	return nil
}
