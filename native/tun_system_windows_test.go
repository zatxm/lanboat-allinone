//go:build windows

package native

import (
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
	for _, v := range []struct{ got, want uintptr }{{unsafe.Sizeof(winRouteRow{}), 104}, {unsafe.Offsetof(winRouteRow{}.Destination), 12}, {unsafe.Offsetof(winRouteRow{}.NextHop), 44}, {unsafe.Offsetof(winRouteRow{}.Metric), 84}, {unsafe.Offsetof(winRouteRow{}.Protocol), 88}, {unsafe.Sizeof(wfpValue{}), 16}, {unsafe.Sizeof(wfpCondition{}), 40}, {unsafe.Sizeof(wfpSession{}), 72}, {unsafe.Sizeof(wfpSublayer{}), 72}, {unsafe.Sizeof(wfpFilter{}), 200}, {unsafe.Offsetof(wfpFilter{}.Conditions), 120}, {unsafe.Offsetof(wfpFilter{}.Context), 152}} {
		if v.got != v.want {
			t.Fatal("Windows ABI", v)
		}
	}
}
