//go:build windows

package native

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func assertTUNSystemConfiguration(t *testing.T, r *Runtime) {
	t.Helper()
	tunnel := r.tunnels[0]
	luid := tunnel.device.(*wintunDevice).luid
	for _, local := range tunnel.localAddresses {
		row := winUnicastAddressRow{LUID: luid, Address: winRouteAddress(local)}
		code, _, _ := tunIPHelper.NewProc("GetUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&row)))
		if code != 0 || row.DadState != 4 || row.SkipAsSource != 0 {
			t.Fatalf("TUN source address %s is not usable: status=%v DAD=%d skip_source=%d", local, syscall.Errno(code), row.DadState, row.SkipAsSource)
		}
	}
	for prefix := range tunnel.routes.current {
		destination := winRouteAddress(prefix.Addr())
		var source [28]byte
		var row winRouteRow
		code, _, _ := tunIPHelper.NewProc("GetBestRoute2").Call(0, 0, 0, uintptr(unsafe.Pointer(&destination)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&source)))
		t.Logf("Windows route %s: status=%v index=%d metric=%d loopback=%d source=%x", prefix, syscall.Errno(code), row.Index, row.Metric, row.Loopback, source)
		if code != 0 || row.LUID != luid || row.Loopback != 0 {
			t.Fatalf("Windows did not select the TUN route for %s: status=%v route=%+v", prefix, syscall.Errno(code), row)
		}
		local := tunnel.local4
		if prefix.Addr().Is6() {
			local = tunnel.local6
		}
		if source != winRouteAddress(local) {
			t.Fatalf("Windows selected the wrong TUN source for %s: %x", prefix, source)
		}
	}
	path, e := winSystemPath("netsh.exe")
	if e != nil {
		t.Fatal(e)
	}
	text, e := tunCommand(path, "", "interface", "ipv4", "show", "dnsservers", "name="+r.Address("tun"))
	if e != nil || !strings.Contains(text, "172.19.0.2") {
		t.Fatal("Windows interface DNS was not configured", text, e)
	}
}

func TestTUNWindowsIPInterfaceABI(t *testing.T) {
	for _, v := range []struct{ got, want uintptr }{
		{unsafe.Sizeof(winIPInterfaceRow{}), 168}, {unsafe.Offsetof(winIPInterfaceRow{}.LUID), 8},
		{unsafe.Offsetof(winIPInterfaceRow{}.RouterDiscovery), 52}, {unsafe.Offsetof(winIPInterfaceRow{}.DadTransmits), 56},
		{unsafe.Offsetof(winIPInterfaceRow{}.SitePrefixLength), 144}, {unsafe.Offsetof(winIPInterfaceRow{}.Metric), 148},
		{unsafe.Offsetof(winIPInterfaceRow{}.MTU), 152}, {unsafe.Offsetof(winIPInterfaceRow{}.DisableDefaultRoutes), 166},
		{unsafe.Sizeof(winUnicastAddressRow{}), 80}, {unsafe.Offsetof(winUnicastAddressRow{}.LUID), 32},
		{unsafe.Offsetof(winUnicastAddressRow{}.PrefixLength), 60}, {unsafe.Offsetof(winUnicastAddressRow{}.DadState), 64},
	} {
		if v.got != v.want {
			t.Fatal("Windows IP Helper ABI", v)
		}
	}
	for _, cidr := range []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"} {
		prefix := netip.MustParsePrefix(cidr)
		row := winAddressEntry(123, prefix)
		if row.LUID != 123 || row.Address != winRouteAddress(prefix.Addr()) || row.PrefixLength != uint8(prefix.Bits()) || row.SkipAsSource != 0 || row.DadState != 4 || row.PrefixOrigin != 1 || row.SuffixOrigin != 1 {
			t.Fatalf("invalid TUN source address: %+v", row)
		}
		if binary.NativeEndian.Uint16(row.Address[:]) != 2 && binary.NativeEndian.Uint16(row.Address[:]) != 23 {
			t.Fatal("invalid source address family")
		}
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
