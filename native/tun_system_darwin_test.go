//go:build darwin

package native

import (
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func assertTUNSystemConfiguration(t *testing.T, r *Runtime) {
	text, e := tunCommand("/usr/sbin/scutil", "", "--dns")
	if e != nil || !strings.Contains(text, "172.19.0.2") {
		t.Fatal("macOS DNS resolver was not published", text, e)
	}
}

func TestTUNDarwinRouteMessage(t *testing.T) {
	if unsafe.Sizeof(syscall.RtMsghdr{}) != 92 {
		t.Fatal("Darwin route ABI changed")
	}
	for _, v := range []string{"203.0.113.0/24", "2001:db8::/32"} {
		b := darwinRouteMessage(7, netip.MustParsePrefix(v), true)
		messages, e := syscall.ParseRoutingMessage(b)
		if e != nil || len(messages) != 1 {
			t.Fatal(e, len(messages))
		}
		row := messages[0].(*syscall.RouteMessage)
		addresses, e := syscall.ParseRoutingSockaddr(row)
		if e != nil || row.Header.Index != 7 {
			t.Fatal(row, e)
		}
		gateway, ok := addresses[syscall.RTAX_GATEWAY].(*syscall.SockaddrDatalink)
		if !ok || gateway.Index != 7 {
			t.Fatal("route gateway", gateway)
		}
	}
}
