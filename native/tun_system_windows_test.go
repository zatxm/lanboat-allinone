//go:build windows

package native

import (
	"net/netip"
	"strings"
	"testing"
	"unsafe"
)

func assertTUNSystemDNS(t *testing.T, r *Runtime) {
	path, e := winSystemPath("netsh.exe")
	if e != nil {
		t.Fatal(e)
	}
	text, e := tunCommand(path, "", "interface", "ipv4", "show", "dnsservers", "name="+r.Address("tun"))
	if e != nil || !strings.Contains(text, "172.19.0.2") {
		t.Fatal("Windows interface DNS was not configured", text, e)
	}
}
func TestTUNWindowsABI(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Fatal("TUN Windows currently targets amd64 and arm64")
	}
	for _, v := range []struct{ got, want uintptr }{{unsafe.Sizeof(winRouteRow{}), 104}, {unsafe.Offsetof(winRouteRow{}.Destination), 12}, {unsafe.Offsetof(winRouteRow{}.NextHop), 44}, {unsafe.Offsetof(winRouteRow{}.SitePrefixLength), 72}, {unsafe.Offsetof(winRouteRow{}.Metric), 84}, {unsafe.Offsetof(winRouteRow{}.Protocol), 88}, {unsafe.Offsetof(winRouteRow{}.Loopback), 92}, {unsafe.Sizeof(wfpValue{}), 16}, {unsafe.Sizeof(wfpCondition{}), 40}, {unsafe.Sizeof(wfpSession{}), 72}, {unsafe.Sizeof(wfpSublayer{}), 72}, {unsafe.Sizeof(wfpFilter{}), 200}, {unsafe.Offsetof(wfpFilter{}.Conditions), 120}, {unsafe.Offsetof(wfpFilter{}.Context), 152}} {
		if v.got != v.want {
			t.Fatal("Windows ABI", v)
		}
	}
}

func TestTUNWindowsRouteEntry(t *testing.T) {
	for _, cidr := range []string{"0.0.0.0/0", "203.0.113.21/24", "203.0.113.21/32", "::/0", "2001:db8::21/64", "2001:db8::21/128"} {
		t.Run(cidr, func(t *testing.T) {
			prefix := netip.MustParsePrefix(cidr)
			row := winRouteEntry(123, prefix)
			if row.LUID != 123 || row.Index != 0 || row.Destination != winRouteAddress(prefix.Masked().Addr()) || row.PrefixLength != uint8(prefix.Bits()) {
				t.Fatalf("incorrect TUN route destination: %+v", row)
			}
			next := netip.IPv4Unspecified()
			if prefix.Addr().Is6() {
				next = netip.IPv6Unspecified()
			}
			if row.NextHop != winRouteAddress(next) || row.SitePrefixLength != 0 || row.Metric != 0 || row.Protocol != 3 {
				t.Fatalf("TUN route retained invalid initializer values: %+v", row)
			}
			if row.Loopback != 0 || row.Autoconfigure != 0 || row.Publish != 0 || row.Immortal != 0 {
				t.Fatalf("TUN route must forward packets to the interface: %+v", row)
			}
			if row.ValidLifetime != ^uint32(0) || row.PreferredLifetime != ^uint32(0) {
				t.Fatalf("TUN route should remain valid until removed: %+v", row)
			}
		})
	}
}
