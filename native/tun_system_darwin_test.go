//go:build darwin

package native

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func assertTUNSystemConfiguration(t *testing.T, r *Runtime) {
	before, _ := exec.Command("/usr/sbin/netstat", "-s", "-p", "ip6").CombinedOutput()
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		after, _ := exec.Command("/usr/sbin/netstat", "-s", "-p", "ip6").CombinedOutput()
		t.Logf("IPv6 statistics before:\n%s\nafter:\n%s", before, after)
		for _, args := range [][]string{{"-s", "-p", "udp"}, {"-rn", "-f", "inet6"}} {
			text, err := exec.Command("/usr/sbin/netstat", args...).CombinedOutput()
			t.Logf("netstat %v: %s %v", args, text, err)
		}
	})
	text, e := tunCommand("/usr/sbin/scutil", "", "--dns")
	if e != nil || !strings.Contains(text, "172.19.0.2") {
		t.Fatal("macOS DNS resolver was not published", text, e)
	}
}

func TestTUNDarwinDNSStartup(t *testing.T) {
	for _, tc := range []struct {
		name, script string
		wantError    string
		timeout      time.Duration
	}{
		{"delayed-session", "sleep 4; exec /usr/sbin/scutil", "", 10 * time.Second},
		{"exited-session", "echo 'fixture scutil failure' >&2; exit 7", "fixture scutil failure", 10 * time.Second},
		{"cancelled-session", "cat >/dev/null", "context deadline exceeded", 200 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, Config{})
			tunnel, err := openTUN(r, Inbound{Type: "tun", Tag: "dns-startup", DNSMode: "native"})
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.close()
			ctx, cancel := context.WithTimeout(r.ctx, tc.timeout)
			defer cancel()
			err = tunnel.configureDarwinDNS(ctx, exec.Command("/bin/sh", "-c", tc.script))
			if tc.wantError == "" && err != nil || tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("DNS startup error: got %v, want %q", err, tc.wantError)
			}
			closed := make(chan struct{})
			go func() { tunnel.close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("DNS session cleanup did not finish")
			}
			key := fmt.Sprintf("State:/Network/Service/lanboat-%d-%s/DNS", os.Getpid(), tunnel.name)
			text, err := tunCommand("/usr/sbin/scutil", "show "+key+"\n")
			if err != nil || strings.Contains(text, "ServerAddresses") {
				t.Fatal("temporary DNS key survived cleanup", text, err)
			}
		})
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

func TestTUNDarwinUDPWithoutKernelReassembly(t *testing.T) {
	const option = "net.inet6.ip6.maxfragpackets"
	previous, err := tunCommand("/usr/sbin/sysctl", "", "-n", option)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tunCommand("/usr/sbin/sysctl", "", "-w", option+"=0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := tunCommand("/usr/sbin/sysctl", "", "-w", option+"="+strings.TrimSpace(previous)); err != nil {
			t.Error("restore IPv6 reassembly policy", err)
		}
	})
	TestTUNSystemDevice(t)
}
