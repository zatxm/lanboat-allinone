//go:build linux

package native

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

func (t *tunTunnel) redirectRules(table string) string {
	return t.redirectRulesFor(t.in, table)
}
func (t *tunTunnel) redirectRulesFor(in Inbound, table string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)
	for _, v := range []struct {
		name   string
		values []string
	}{{"include", in.RouteAddress}, {"exclude", in.RouteExcludeAddress}} {
		for _, family := range []string{"4", "6"} {
			kind := "ipv4_addr"
			if family == "6" {
				kind = "ipv6_addr"
			}
			fmt.Fprintf(&b, "add set inet %s %s%s { type %s; flags interval; auto-merge; }\n", table, v.name, family, kind)
			var values []string
			for _, value := range v.values {
				p := netip.MustParsePrefix(value)
				if p.Addr().Is4() == (family == "4") {
					values = append(values, p.Masked().String())
				}
			}
			if len(values) > 0 {
				fmt.Fprintf(&b, "add element inet %s %s%s { %s }\n", table, v.name, family, strings.Join(values, ", "))
			}
		}
	}

	input, output, reset, tproxy := in.redirectMarks()
	vi, vo, vr := in.redirectVerdictMarks()
	for _, chain := range []struct{ name, kind string }{{"output", "route"}, {"prerouting", "filter"}} {
		fmt.Fprintf(&b, "add chain inet %s %s { type %s hook %s priority -151; policy accept; }\n", table, "pre_"+chain.name, "filter", chain.name)
		prefix := "add rule inet " + table + " pre_" + chain.name + " "
		fmt.Fprintf(&b, "%smeta mark 0x%x return\n", prefix, output)
		fmt.Fprintf(&b, "%siifname %s meta mark set 0x%x return\n", prefix, strconv.Quote(t.name), output)
		fmt.Fprintf(&b, "%smeta l4proto ipv6-icmp icmpv6 type { 130, 131, 132, 133, 134, 135, 136, 137, 143 } meta mark set 0x%x return\n", prefix, vo)
		fmt.Fprintf(&b, "%sip daddr 224.0.0.0/4 meta mark set 0x%x return\n%sip6 daddr { fe80::/10, ff00::/8 } meta mark set 0x%x return\n", prefix, vo, prefix, vo)
		fmt.Fprintf(&b, "%sfib daddr type { local, broadcast, multicast } meta mark set 0x%x return\n", prefix, vo)
		fmt.Fprintf(&b, "%sip daddr 127.0.0.0/8 meta mark set 0x%x return\n%sip6 daddr ::1 meta mark set 0x%x return\n", prefix, vo, prefix, vo)
		direction := "iifname"
		if chain.name == "output" {
			direction = "oifname"
		}
		for _, name := range in.ExcludeInterface {
			fmt.Fprintf(&b, "%s%s %s meta mark set 0x%x return\n", prefix, direction, strconv.Quote(name), vo)
		}
		if len(in.IncludeInterface) > 0 {
			var names []string
			for _, name := range in.IncludeInterface {
				names = append(names, strconv.Quote(name))
			}
			fmt.Fprintf(&b, "%s%s != { %s } meta mark set 0x%x return\n", prefix, direction, strings.Join(names, ", "), vo)
		}
		if chain.name == "output" {
			for _, filter := range []struct {
				ids     []uint32
				values  []string
				exclude bool
			}{{in.ExcludeUID, in.ExcludeUIDRange, true}, {in.IncludeUID, in.IncludeUIDRange, false}} {
				ranges, _ := uidRanges(filter.ids, filter.values)
				var values []string
				for _, r := range ranges {
					v := strconv.FormatUint(uint64(r[0]), 10)
					if r[1] != r[0] {
						v += "-" + strconv.FormatUint(uint64(r[1]), 10)
					}
					values = append(values, v)
				}
				if len(values) > 0 {
					op := ""
					if !filter.exclude {
						op = "!= "
					}
					fmt.Fprintf(&b, "%smeta skuid %s{ %s } meta mark set 0x%x return\n", prefix, op, strings.Join(values, ", "), vo)
				}
			}
		} else {
			for _, filter := range []struct {
				values  []string
				exclude bool
			}{{in.ExcludeMACAddress, true}, {in.IncludeMACAddress, false}} {
				if len(filter.values) > 0 {
					op := ""
					if !filter.exclude {
						op = "!= "
					}
					fmt.Fprintf(&b, "%sether saddr %s{ %s } meta mark set 0x%x return\n", prefix, op, tunMACValues(filter.values), vo)
				}
			}
		}
		fmt.Fprintf(&b, "%sip daddr @exclude4 meta mark set 0x%x return\n%sip6 daddr @exclude6 meta mark set 0x%x return\n", prefix, vo, prefix, vo)
		if len(in.RouteAddress)+len(in.RouteAddressSet) > 0 {
			fmt.Fprintf(&b, "%smeta nfproto ipv4 ip daddr != @include4 meta mark set 0x%x return\n%smeta nfproto ipv6 ip6 daddr != @include6 meta mark set 0x%x return\n", prefix, vo, prefix, vo)
		}
		// A reused TCP tuple must not inherit the verdict of an earlier connection.
		fmt.Fprintf(&b, "%smeta l4proto tcp tcp flags & (fin | syn | rst | ack) == syn ct mark { 0x%x, 0x%x, 0x%x } ct mark set 0\n", prefix, input, output, tproxy)
		for _, m := range []struct{ stored, temp uint32 }{{input, vi}, {output, vo}, {tproxy, vi}} {
			fmt.Fprintf(&b, "%sct mark 0x%x meta mark set 0x%x\n", prefix, m.stored, m.temp)
		}
		fmt.Fprintf(&b, "%smeta mark != { 0x%x, 0x%x } queue num %d\n", prefix, vi, vo, in.queueNumber())
		fmt.Fprintf(&b, "add chain inet %s %s { type %s hook %s priority mangle; policy accept; }\n", table, chain.name, chain.kind, chain.name)
		prefix = "add rule inet " + table + " " + chain.name + " "
		for _, m := range []struct{ temp, real uint32 }{{vi, input}, {vo, output}, {vr, reset}} {
			fmt.Fprintf(&b, "%smeta mark 0x%x ct mark set 0x%x meta mark set 0x%x\n", prefix, m.temp, m.real, m.real)
		}

		fmt.Fprintf(&b, "%smeta mark 0x%x meta l4proto tcp reject with tcp reset\n", prefix, reset)
		fmt.Fprintf(&b, "%smeta mark 0x%x reject with icmpx type port-unreachable\n", prefix, reset)
		fmt.Fprintf(&b, "%smeta mark != { 0x%x, 0x%x } return\n", prefix, input, tproxy)
		if chain.name == "prerouting" && t.tpListener != nil {
			port := t.tpListener.Addr().(*net.TCPAddr).Port
			fmt.Fprintf(&b, "%smeta nfproto ipv6 meta l4proto tcp meta mark set 0x%x ct mark set 0x%x tproxy ip6 to :%d accept\n", prefix, tproxy, tproxy, port)
		}
		fmt.Fprintf(&b, "%smeta mark set 0x%x\n", prefix, input)
	}

	return b.String()
}
func (t *tunTunnel) configureRedirect() error {

	if e := t.configureTProxy(); e != nil {
		return e
	}
	q, e := openTunQueue(t)
	if e != nil {
		return e
	}
	t.namespaceQueue = q.file
	table := fmt.Sprintf("lanboat_%d_%x", os.Getpid(), t.mark)
	if _, e = tunCommand("/usr/sbin/nft", t.redirectRules(table), "-f", "-"); e != nil {
		q.file.Close()
		return e
	}
	previous := t.cleanup
	t.cleanup = func() {
		if _, e := tunCommand("/usr/sbin/nft", "", "delete", "table", "inet", table); e != nil {
			t.runtime.logger.Warn("remove TUN redirect rules", zap.Error(e))
		}
		q.file.Close()
		previous()
	}
	var base Inbound
	for _, v := range t.runtime.config.Inbounds {
		if v.Tag == t.in.Tag {
			base = v
			break
		}
	}
	tags := append(append([]string{}, base.RouteAddressSet...), base.RouteExcludeAddressSet...)
	if len(tags) > 0 {
		last := make([]*ruleSnapshot, len(tags))
		for i, tag := range tags {
			last[i] = t.runtime.ruleSets[tag].current.Load()
		}
		var nextAttempt time.Time
		t.refreshRoutes = func() error {
			if time.Now().Before(nextAttempt) {
				return nil
			}
			changed := false
			for i, tag := range tags {
				if t.runtime.ruleSets[tag].current.Load() != last[i] {
					changed = true
				}
			}
			if !changed {
				return nil
			}
			now := make([]*ruleSnapshot, len(tags))
			for i, tag := range tags {
				now[i] = t.runtime.ruleSets[tag].current.Load()
			}
			in, e := t.runtime.tunRouteSets(base)
			if e == nil {
				_, e = tunCommand("/usr/sbin/nft", "delete table inet "+table+"\n"+t.redirectRulesFor(in, table), "-f", "-")
			}
			if e != nil {
				nextAttempt = time.Now().Add(30 * time.Second)
				return e
			}
			last = now
			return nil
		}
	}
	return nil
}

func tunMACValues(values []string) string {
	out := make([]string, len(values))
	for i, v := range values {
		mac, _ := net.ParseMAC(v)
		out[i] = mac.String()
	}
	return strings.Join(out, ", ")
}
