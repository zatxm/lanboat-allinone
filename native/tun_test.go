package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"testing"
	"time"
)

type packetMemory struct{ bytes.Buffer }

func (p *packetMemory) Close() error { return nil }

func TestUTUNFraming(t *testing.T) {
	for _, v := range []struct {
		src, dst string
		family   uint32
	}{{"192.0.2.1", "192.0.2.2", 2}, {"2001:db8::1", "2001:db8::2", 30}} {
		packet := makeUDPPacket(netip.MustParseAddr(v.src), netip.MustParseAddr(v.dst), 1, 2, []byte("test"))
		memory := &packetMemory{}
		device := &framedTUN{ReadWriteCloser: memory}
		if n, e := device.Write(packet); e != nil || n != len(packet) {
			t.Fatal(n, e)
		}
		if got := binary.BigEndian.Uint32(memory.Bytes()); got != v.family {
			t.Fatal(got)
		}
		buffer := make([]byte, 65575)
		n, e := device.Read(buffer)
		if e != nil || !bytes.Equal(packet, buffer[:n]) {
			t.Fatal(n, e)
		}
	}
	for _, packet := range [][]byte{nil, {0, 0, 0, 2}, {0, 0, 0, 2, 0x60}, {0, 0, 0, 99, 0x45}} {
		memory := &packetMemory{}
		memory.Write(packet)
		d := &framedTUN{ReadWriteCloser: memory}
		if _, e := d.Read(make([]byte, 1500)); e == nil {
			t.Fatal("invalid family accepted", packet)
		}
	}
	d := &framedTUN{ReadWriteCloser: &packetMemory{}}
	if _, e := d.Write([]byte{0x70}); e == nil {
		t.Fatal("unknown IP version accepted")
	}
}
func TestTUNRoutePlan(t *testing.T) {
	in := Inbound{RouteAddress: []string{"0.0.0.0/0", "::/0"}, RouteExcludeAddress: []string{"192.0.2.0/24", "2001:db8::/32", "10.0.0.0/8"}}
	plan := tunRoutePrefixes(in)
	for _, a := range []string{"192.0.2.1", "10.0.0.1", "2001:db8::1"} {
		ip := netip.MustParseAddr(a)
		for _, p := range plan {
			if p.Contains(ip) {
				t.Fatal("excluded address captured", a, p)
			}
		}
	}
	for _, a := range []string{"192.0.3.1", "9.9.9.9", "2001:db9::1", "::1", "255.255.255.255"} {
		ip := netip.MustParseAddr(a)
		found := false
		for _, p := range plan {
			found = found || p.Contains(ip)
		}
		if !found {
			t.Fatal("route gap", a)
		}
	}
	for _, p := range plan {
		if p.Bits() == 0 {
			t.Fatal("default route would replace host route")
		}
	}
	for _, v := range []struct {
		first, last string
		count       int
	}{{"0.0.0.0", "255.255.255.255", 1}, {"192.0.2.1", "192.0.2.254", 14}, {"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 1}} {
		a, b := netip.MustParseAddr(v.first), netip.MustParseAddr(v.last)
		p := rangePrefixes(a, b)
		if len(p) != v.count || p[0].Addr() != a || prefixLast(p[len(p)-1]) != b {
			t.Fatal(v, p)
		}
	}
}
func TestTUNModernOptions(t *testing.T) {
	if _, e := Parse([]byte(`{"route":{"rules":[{"action":"bypass"}]}}`)); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{`"stack":"system"`, `"dns_hijack":false`, `"gso":false`, `"inet4_address":"172.19.0.1/30"`, `"inet6_route_address":"::/0"`, `"endpoint_independent_nat":true`} {
		if _, e := Parse([]byte(`{"inbounds":[{"type":"tun",` + field + `} ]}`)); e == nil {
			t.Fatal("removed option accepted", field)
		}
	}
	if _, e := Parse([]byte(`{"inbounds":[{"type":"tun","dns_mode":"native","udp_timeout":"30s","loopback_address":"10.7.0.1"}]}`)); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"disabled", "native", "hijack", ""} {
		tun := &tunTunnel{in: Inbound{DNSMode: mode, AutoRoute: true}, local4: netip.MustParseAddr("172.19.0.1"), hostAddresses: []netip.Addr{netip.MustParseAddr("192.168.1.5")}}
		if tun.hijackDNS(netip.MustParseAddr("172.19.0.2"), 53) != (mode != "disabled") {
			t.Fatal(mode)
		}
		if tun.hijackDNS(netip.MustParseAddr("8.8.8.8"), 53) != (mode == "hijack" || mode == "") {
			t.Fatal(mode)
		}
		for _, a := range []string{"127.0.0.53", "192.168.1.5", "172.19.0.1"} {
			if tun.hijackDNS(netip.MustParseAddr(a), 53) {
				t.Fatal("host DNS hijacked", a)
			}
		}
		tun.in.DNSAddress = []string{"172.19.0.9"}
		if mode == "native" && tun.hijackDNS(netip.MustParseAddr("172.19.0.9"), 53) {
			t.Fatal("explicit DNS address requires route action")
		}
	}
}

func TestTUNRoutePlanCoverage(t *testing.T) {
	seed := uint32(17)
	next := func() byte { seed = seed*1664525 + 1013904223; return byte(seed >> 24) }
	for range 64 {
		in := Inbound{DNSMode: "disabled"}
		for range 8 {
			a := netip.AddrFrom4([4]byte{10, 23, 42, next()})
			p := netip.PrefixFrom(a, 24+int(next()%9)).Masked()
			if next()&1 == 0 {
				in.RouteAddress = append(in.RouteAddress, p.String())
			} else {
				in.RouteExcludeAddress = append(in.RouteExcludeAddress, p.String())
			}
		}
		if len(in.RouteAddress) == 0 {
			in.RouteAddress = []string{"10.23.42.0/24"}
		}
		plan := tunRoutePrefixes(in)
		for i := range 256 {
			ip := netip.AddrFrom4([4]byte{10, 23, 42, byte(i)})
			want, got := false, false
			for _, v := range in.RouteAddress {
				want = want || netip.MustParsePrefix(v).Contains(ip)
			}
			for _, v := range in.RouteExcludeAddress {
				if netip.MustParsePrefix(v).Contains(ip) {
					want = false
				}
			}
			for _, p := range plan {
				got = got || p.Contains(ip)
			}
			if got != want {
				t.Fatal("route subtraction", in, ip, want, plan)
			}
		}
	}
}
func TestTUNIPRuleSets(t *testing.T) {
	cfg := Config{Route: Route{RuleSet: []RuleSet{{Type: "inline", Tag: "ip", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24", "2001:db8::/32"}}}}, {Type: "inline", Tag: "domains", Rules: []Rule{{Domain: []string{"example.org"}}}}}}}
	b, _ := json.Marshal(cfg)
	r, e := New(context.Background(), b, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	in, e := r.tunRouteSets(Inbound{RouteAddressSet: []string{"ip"}})
	if e != nil || len(in.RouteAddress) != 2 {
		t.Fatal(in, e)
	}
	if _, e = r.tunRouteSets(Inbound{RouteAddressSet: []string{"domains"}}); e == nil {
		t.Fatal("domain set converted into broad IP route")
	}
}
func TestTUNICMPPolicy(t *testing.T) {
	for _, v := range []struct {
		method string
		want   byte
	}{{"reply", 0}, {"default", 3}, {"drop", 255}} {
		t.Run(v.method, func(t *testing.T) {
			r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Network: []string{"icmp"}, Action: "reject", Method: v.method}}}})
			ctx, cancel := context.WithCancel(r.ctx)
			defer cancel()
			replies := make(chan []byte, 1)
			s := newIPStack(&ipEndpoint{runtime: r, inbound: "tun", done: ctx.Done(), sendIP: func(b []byte) error { replies <- b; return nil }})
			defer func() { cancel(); s.close() }()
			segment := []byte{8, 0, 0, 0, 0, 4, 0, 1, 9}
			binary.BigEndian.PutUint16(segment[2:], checksum(segment, 0))
			packet := makeWGIP(netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("203.0.113.2"), 1, segment)
			p, _ := parseTunPacket(packet)
			s.input(p)
			select {
			case b := <-replies:
				rp, e := parseTunPacket(b)
				if e != nil || rp.data[rp.header] != v.want || checksum(rp.data[rp.header:], 0) != 0 {
					t.Fatal(b, e)
				}
			case <-time.After(100 * time.Millisecond):
				if v.want != 255 {
					t.Fatal("missing ICMP response")
				}
			}
		})
	}
}

var _ io.ReadWriteCloser = (*packetMemory)(nil)

func TestChecksumWideSum(t *testing.T) {
	reference := func(data []byte, initial uint32) uint16 {
		sum := initial
		for len(data) >= 2 {
			sum += uint32(data[0])<<8 | uint32(data[1])
			data = data[2:]
		}
		if len(data) > 0 {
			sum += uint32(data[0]) << 8
		}
		for sum>>16 != 0 {
			sum = sum&65535 + sum>>16
		}
		return ^uint16(sum)
	}
	data := make([]byte, 1600)
	for i := range data {
		data[i] = byte(i*131 + i>>3)
	}
	for _, fill := range []func(int) byte{func(i int) byte { return data[i] }, func(int) byte { return 0xff }, func(int) byte { return 0 }} {
		b := make([]byte, len(data))
		for i := range b {
			b[i] = fill(i)
		}
		for size := 0; size <= len(b); size += 1 + size/64 {
			for _, initial := range []uint32{0, 17, 0x1fffe, 0xffffffff >> 4} {
				if got, want := checksum(b[:size], initial), reference(b[:size], initial); got != want {
					t.Fatalf("size %d initial %d: %#x != %#x", size, initial, got, want)
				}
			}
		}
	}
}
