package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func processICMPTestAddress(address netip.AddrPort) string {
	b := address.Addr().AsSlice()
	var text strings.Builder
	for i := 0; i < len(b); i += 4 {
		fmt.Fprintf(&text, "%08X", binary.NativeEndian.Uint32(b[i:]))
	}
	fmt.Fprintf(&text, ":%04X", address.Port())
	return text.String()
}

func TestProcessICMPTable(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			source := netip.AddrPortFrom(netip.MustParseAddr(host), 12345)
			destination := netip.AddrPortFrom(source.Addr(), 0)
			wild := netip.MustParseAddr("0.0.0.0")
			protocol := uint16(1)
			if source.Addr().Is6() {
				wild, protocol = netip.IPv6Unspecified(), 58
			}
			row := func(local, remote netip.AddrPort, inode int) string {
				return fmt.Sprintf("0: %s %s 07 0:0 0:0 0 1000 0 %d 2 0 0\n", processICMPTestAddress(local), processICMPTestAddress(remote), inode)
			}
			unbound := netip.AddrPortFrom(wild, 0)
			valid := row(source, destination, 123)
			for _, tc := range []struct {
				name, rows string
				raw, fail  bool
				want       uint32
			}{
				{name: "exact", rows: valid, want: 123},
				{name: "wildcard", rows: row(netip.AddrPortFrom(wild, source.Port()), unbound, 123), want: 123},
				{name: "unconnected", rows: row(source, unbound, 123), want: 123},
				{name: "duplicate-inode", rows: valid + valid, want: 123},
				{name: "ambiguous", rows: valid + row(source, destination, 124), fail: true},
				{name: "wildcard-ambiguous", rows: valid + row(netip.AddrPortFrom(wild, source.Port()), unbound, 124), fail: true},
				{name: "wrong-id", rows: row(netip.AddrPortFrom(source.Addr(), 54321), destination, 123)},
				{name: "wrong-address", rows: row(netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), source.Port()), destination, 123)},
				{name: "remote-port", rows: row(source, source, 123)},
				{name: "raw-ambiguous", rows: row(netip.AddrPortFrom(wild, protocol), unbound, 0), raw: true, fail: true},
				{name: "other-raw-protocol", rows: row(netip.AddrPortFrom(wild, 6), unbound, 123), raw: true},
				{name: "short", rows: "0: 123\n", fail: true},
				{name: "bad-address", rows: strings.Replace(valid, processICMPTestAddress(source), "INVALID:3039", 1), fail: true},
				{name: "zero-inode", rows: row(source, destination, 0), fail: true},
				{name: "overflow-inode", rows: strings.Replace(valid, " 123 ", " 4294967296 ", 1), fail: true},
				{name: "scanner-limit", rows: strings.Repeat("x", 4097), fail: true},
				{name: "empty"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, err := processICMPTable(context.Background(), strings.NewReader("sl local_address rem_address\n"+tc.rows), source, destination, time.Now().Add(time.Second), tc.raw)
					if (err != nil) != tc.fail || got != tc.want {
						t.Fatal(got, err, tc.want, tc.fail)
					}
				})
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if _, err := processICMPTable(ctx, strings.NewReader("sl local_address\n"+valid), source, destination, time.Now().Add(time.Second), false); err != context.Canceled {
				t.Fatal("cancellation lost", err)
			}
			if _, err := processICMPTable(context.Background(), strings.NewReader("sl local_address\n"+valid), source, destination, time.Now().Add(-time.Second), false); err != context.DeadlineExceeded {
				t.Fatal("deadline lost", err)
			}
		})
	}
	for _, value := range []string{"", "12345678", "1234567:0000", "123456789:0000", "GG000000:0000", "00000000:FFFFF", "00000000:GGGG"} {
		if address, ok := processICMPAddress(value); ok {
			t.Fatal("invalid address", value, address)
		}
	}
}

func TestProcessICMPPayloadIsolation(t *testing.T) {
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "sniff", Sniffer: []string{"http"}}, {Protocol: []string{"http"}, Action: "bypass"}}}})
	tunnel := &tunTunnel{runtime: r, in: Inbound{AutoRedirect: true}}
	input, _, _, _ := tunnel.in.redirectMarks()
	segment := []byte("GET / HTTP/1.1\r\nHost: invalid-tcp.test\r\n\r\n")
	packet := makeWGIP(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), 6, segment)
	if mark, _ := tunnel.preMatchPacket(packet); mark != input {
		t.Fatal("malformed TCP header used as application payload", mark)
	}
}

func processICMPTestNamespace(t *testing.T) bool {
	t.Helper()
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent := os.Getenv("LANBOAT_ICMP_PARENT_NS")
	if parent == "" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_ICMP_PARENT_NS="+current)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated ICMP process test: %v\n%s", err, output)
		}
		t.Log(string(output))
		return false
	}
	if current == parent {
		t.Fatal("refusing to configure the parent network namespace")
	}
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureLink(loopback.Index, 65536); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 0"), 0600); err != nil {
		t.Fatal(err)
	}
	return true
}

func processTestPing(t *testing.T, ipv6, wildcard, connected bool, target string) (socketOrigin, *os.File) {
	t.Helper()
	family, protocol := syscall.AF_INET, syscall.IPPROTO_ICMP
	local := "127.0.0.1"
	if ipv6 {
		family, protocol, local = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, "::1"
	}
	fd, err := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, protocol)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "process-test-ping")
	t.Cleanup(func() { file.Close() })
	bind := local
	if wildcard {
		bind = "0.0.0.0"
		if ipv6 {
			bind = "::"
		}
	}
	addr := func(host string) syscall.Sockaddr {
		ip := netip.MustParseAddr(host)
		if ipv6 {
			return &syscall.SockaddrInet6{Addr: ip.As16()}
		}
		return &syscall.SockaddrInet4{Addr: ip.As4()}
	}
	if err = syscall.Bind(fd, addr(bind)); err != nil {
		t.Fatal(err)
	}
	if connected {
		if err = syscall.Connect(fd, addr(target)); err != nil {
			t.Fatal(err)
		}
	}
	bound, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := 0
	if ipv6 {
		port = bound.(*syscall.SockaddrInet6).Port
		if ip := netip.AddrFrom16(bound.(*syscall.SockaddrInet6).Addr); !ip.IsUnspecified() {
			local = ip.String()
		}
	} else {
		port = bound.(*syscall.SockaddrInet4).Port
		if ip := netip.AddrFrom4(bound.(*syscall.SockaddrInet4).Addr); !ip.IsUnspecified() {
			local = ip.String()
		}
	}
	if port == 0 {
		t.Fatal("kernel did not assign an Echo ID")
	}
	return socketOrigin{network: "icmp", source: netip.AddrPortFrom(netip.MustParseAddr(local), uint16(port)).String(), destination: net.JoinHostPort(target, "0")}, file
}

func TestProcessICMPSocketNamespace(t *testing.T) {
	if !processICMPTestNamespace(t) {
		return
	}
	path := processTestPath(t)
	for _, ipv6 := range []bool{false, true} {
		for _, wildcard := range []bool{false, true} {
			for _, connected := range []bool{false, true} {
				t.Run(fmt.Sprintf("ipv6=%v/wildcard=%v/connected=%v", ipv6, wildcard, connected), func(t *testing.T) {
					target := "127.0.0.1"
					if ipv6 {
						target = "::1"
					}
					origin, file := processTestPing(t, ipv6, wildcard, connected, target)
					finder := &processFinder{}
					for range 2 {
						if name, got := finder.lookup(context.Background(), origin); got != path || name != filepath.Base(path) {
							t.Fatal("ICMP socket not identified", origin, name, got)
						}
					}
					if connected {
						wrong := origin
						wrong.destination = "127.0.0.2:0"
						if ipv6 {
							wrong.destination = "[::2]:0"
						}
						if name, _ := finder.lookup(context.Background(), wrong); name != "" {
							t.Fatal("wrong peer attributed", name)
						}
					}
					if err := file.Close(); err != nil {
						t.Fatal(err)
					}
					if name, _ := finder.lookup(context.Background(), origin); name != "" {
						t.Fatal("closed socket cached", name)
					}
				})
			}
		}
		t.Run(fmt.Sprintf("reused-id/ipv6=%v", ipv6), func(t *testing.T) {
			family, protocol, local := syscall.AF_INET, syscall.IPPROTO_ICMP, "127.0.0.1"
			var bind syscall.Sockaddr = &syscall.SockaddrInet4{Port: 12345}
			if ipv6 {
				family, protocol, local = syscall.AF_INET6, syscall.IPPROTO_ICMPV6, "::1"
				bind = &syscall.SockaddrInet6{Port: 12345}
			}
			var sockets []*os.File
			for range 2 {
				fd, err := syscall.Socket(family, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, protocol)
				if err != nil {
					t.Fatal(err)
				}
				file := os.NewFile(uintptr(fd), "shared-ping-id")
				t.Cleanup(func() { file.Close() })
				sockets = append(sockets, file)
				if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
					t.Fatal(err)
				}
				if err = syscall.Bind(fd, bind); err != nil {
					t.Fatal(err)
				}
			}
			origin := socketOrigin{network: "icmp", source: net.JoinHostPort(local, "12345"), destination: net.JoinHostPort(local, "0")}
			finder := &processFinder{}
			if name, _ := finder.lookup(context.Background(), origin); name != "" {
				t.Fatal("duplicate Echo ID attributed", name)
			}
			sockets[1].Close()
			if _, got := finder.lookup(context.Background(), origin); got != path {
				t.Fatal("unique surviving ping socket not identified", got)
			}
		})
		t.Run(fmt.Sprintf("raw-ambiguous/ipv6=%v", ipv6), func(t *testing.T) {
			target, family, protocol := "127.0.0.1", syscall.AF_INET, syscall.IPPROTO_ICMP
			if ipv6 {
				target, family, protocol = "::1", syscall.AF_INET6, syscall.IPPROTO_ICMPV6
			}
			origin, _ := processTestPing(t, ipv6, false, true, target)
			fd, err := syscall.Socket(family, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, protocol)
			if err != nil {
				t.Fatal(err)
			}
			defer syscall.Close(fd)
			if name, _ := (&processFinder{}).lookup(context.Background(), origin); name != "" {
				t.Fatal("raw socket ambiguity ignored", name)
			}
		})
		t.Run(fmt.Sprint("pre-match/ipv6=", ipv6), func(t *testing.T) {
			local, protocol, kind := "127.0.0.1", byte(1), byte(8)
			if ipv6 {
				local, protocol, kind = "::1", 58, 128
			}
			origin, _ := processTestPing(t, ipv6, false, true, local)
			in := Inbound{Type: "tun", Tag: "tun", AutoRoute: true, AutoRedirect: true}
			data, err := json.Marshal(Config{Inbounds: []Inbound{in}, Route: Route{Rules: []Rule{{ProcessPath: []string{path}, Action: "bypass"}}}})
			if err != nil {
				t.Fatal(err)
			}
			r, err := New(context.Background(), data, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			tunnel := &tunTunnel{runtime: r, in: in}
			input, output, _, _ := in.redirectMarks()
			source := netip.MustParseAddrPort(origin.source)
			segment := []byte{kind, 0, 0, 0, byte(source.Port() >> 8), byte(source.Port()), 0, 1}
			packet := makeWGIP(source.Addr(), source.Addr(), protocol, segment)
			if mark, drop := tunnel.preMatchPacket(packet); mark != output || drop {
				t.Fatal("ICMP process pre-match failed", mark, drop)
			}
			segment[0] = 0
			if mark, _ := tunnel.preMatchPacket(makeWGIP(source.Addr(), source.Addr(), protocol, segment)); mark != input {
				t.Fatal("non-request bypassed by process rule", mark)
			}
		})
	}
}

func TestProcessICMPTUNNamespace(t *testing.T) {
	if !processICMPTestNamespace(t) {
		return
	}
	path := processTestPath(t)
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint("redirect=", redirect), func(t *testing.T) {
			in := Inbound{Type: "tun", Tag: "tun", AutoRoute: true, AutoRedirect: redirect, StrictRoute: true, DNSMode: "disabled"}
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{Network: []string{"icmp"}, ProcessPath: []string{path}, Action: "reject", Method: "reply"}}}})
			defer r.Close()
			for _, ipv6 := range []bool{false, true} {
				t.Run(fmt.Sprint("ipv6=", ipv6), func(t *testing.T) {
					target, kind, reply := "203.0.113.21", byte(8), byte(0)
					if ipv6 {
						target, kind, reply = "2001:db8::21", 128, 129
					}
					origin, file := processTestPing(t, ipv6, true, true, target)
					fd := int(file.Fd())
					if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2}); err != nil {
						t.Fatal(err)
					}
					segment := []byte{kind, 0, 0, 0, 0, 0, 0, 1, 'p', 'i', 'n', 'g'}
					if err := writeAll(file, segment); err != nil {
						t.Fatal(err)
					}
					var b [128]byte
					n, err := syscall.Read(fd, b[:])
					source := netip.MustParseAddrPort(origin.source)
					if err != nil || n != len(segment) || b[0] != reply || binary.BigEndian.Uint16(b[4:]) != source.Port() || string(b[8:n]) != "ping" {
						t.Fatal("TUN process rule did not reply", origin, b[:max(n, 0)], err)
					}
					segment[4], segment[5] = byte(source.Port()>>8), byte(source.Port())
					q := request{inbound: "tun", network: "icmp", source: netip.AddrPortFrom(source.Addr(), 0).String(), address: origin.destination, payload: segment}
					r.enrichProcess(context.Background(), &q)
					if q.metadata.ProcessPath != path || q.source != netip.AddrPortFrom(source.Addr(), 0).String() {
						t.Fatal("Echo ID leaked to routing source port", q.source, q.metadata.ProcessPath)
					}
					for _, inbound := range []string{"remote-wireguard", "remote-tailscale", ""} {
						remote := q
						remote.inbound, remote.metadata = inbound, Metadata{}
						r.enrichProcess(context.Background(), &remote)
						if remote.metadata.ProcessPath != "" {
							t.Fatal("remote ICMP attributed to a local socket", inbound, remote.metadata.ProcessPath)
						}
					}
					for _, bad := range [][]byte{nil, segment[:7], append([]byte{reply}, segment[1:]...), append([]byte{kind, 1}, segment[2:]...)} {
						invalid := q
						invalid.payload, invalid.metadata = bad, Metadata{}
						r.enrichProcess(context.Background(), &invalid)
						if invalid.metadata.ProcessPath != "" {
							t.Fatal("non-Echo request attributed", bad, invalid.metadata.ProcessPath)
						}
					}
					provided := q
					provided.metadata.ProcessPath = "/caller/provided"
					r.enrichProcess(context.Background(), &provided)
					if provided.metadata.ProcessPath != "/caller/provided" {
						t.Fatal("caller identity overwritten")
					}
				})
			}
		})
	}
}

func FuzzProcessICMPTable(f *testing.F) {
	f.Add("0100007F:3039", "0: 0100007F:3039 00000000:0000 07 0:0 0:0 0 0 0 123 2\n")
	f.Add("00000000000000000000000001000000:3039", "")
	f.Fuzz(func(t *testing.T, address, rows string) {
		if len(address)+len(rows) > 16384 {
			return
		}
		if parsed, ok := processICMPAddress(address); ok && !strings.EqualFold(address, processICMPTestAddress(parsed)) {
			t.Fatal("address did not round trip", address, parsed)
		}
		src, dst := netip.MustParseAddrPort("127.0.0.1:12345"), netip.MustParseAddrPort("127.0.0.2:0")
		for _, raw := range []bool{false, true} {
			processICMPTable(context.Background(), strings.NewReader("sl local_address\n"+rows), src, dst, time.Now().Add(time.Second), raw)
		}
	})
}
