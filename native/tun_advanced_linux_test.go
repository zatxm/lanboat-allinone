//go:build linux

package native

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTUNAdvancedNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_TUN_PEER") == "1" {
		tunLANPeer(t)
		return
	}
	if os.Getenv("LANBOAT_TUN_ADVANCED") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestTUNAdvancedNamespace$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_TUN_ADVANCED=1")
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("advanced TUN namespace: %v\n%s", e, b)
		}
		t.Log(string(b))
		return
	}
	lo, e := net.InterfaceByName("lo")
	if e != nil {
		t.Fatal(e)
	}
	if e = configureLink(lo.Index, 65536); e != nil {
		t.Fatal(e)
	}
	t.Run("route-ruleset-refresh", func(t *testing.T) { testTUNRuleSetRefreshMode(t, false) })
	t.Run("kernel-bypass-and-filters", testTUNKernels)
}
func tunIP(t *testing.T, args ...string) {
	t.Helper()
	if b, e := exec.Command("/usr/sbin/ip", args...).CombinedOutput(); e != nil {
		t.Fatalf("ip %v: %v %s", args, e, b)
	}
}
func tunLANPeer(t *testing.T) {
	input := bufio.NewScanner(os.Stdin)
	fmt.Println("LANBOAT-PEER-START")
	if !input.Scan() {
		t.Fatal("missing peer setup")
	}
	tunIP(t, "link", "set", "lo", "up")
	tunIP(t, "addr", "add", "198.51.100.9/32", "dev", "lo")
	if e := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); e != nil {
		t.Fatal(e)
	}
	tunIP(t, "link", "set", "lbpeer", "up")
	tunIP(t, "addr", "add", "10.77.0.2/24", "dev", "lbpeer")
	tunIP(t, "-6", "addr", "add", "fd77::2/64", "dev", "lbpeer", "nodad")
	tunIP(t, "route", "add", "default", "via", "10.77.0.1")
	tunIP(t, "-6", "route", "add", "default", "via", "fd77::1")
	lc := net.ListenConfig{}
	lc.SetMultipathTCP(true)
	listener, e := lc.Listen(context.Background(), "tcp4", ":19001")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	fmt.Println("LANBOAT-PEER-READY")
	for input.Scan() {
		command := input.Text()
		if command == "stop" {
			return
		}
		c, e := net.DialTimeout("tcp", command, 3*time.Second)
		if e == nil {
			c.SetDeadline(time.Now().Add(3 * time.Second))
			_, e = c.Write([]byte("lan"))
			if e == nil {
				b := make([]byte, 3)
				_, e = io.ReadFull(c, b)
				if string(b) != "lan" {
					e = fmt.Errorf("bad echo %q", b)
				}
			}
			c.Close()
		}
		fmt.Println("LANBOAT-RESULT", e == nil)
	}
}
func testTUNKernels(t *testing.T) {
	cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestTUNAdvancedNamespace$", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), "LANBOAT_TUN_PEER=1")
	cmd.Stderr = os.Stderr
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	input, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { input.Close(); cmd.Process.Kill(); cmd.Wait() }()
	scanner := bufio.NewScanner(out)
	read := func(prefix string) string {
		t.Helper()
		for scanner.Scan() {
			if strings.HasPrefix(scanner.Text(), prefix) {
				return strings.TrimSpace(strings.TrimPrefix(scanner.Text(), prefix))
			}
		}
		t.Fatal("peer exited waiting for", prefix, scanner.Err())
		return ""
	}
	read("LANBOAT-PEER-START")
	tunIP(t, "link", "add", "lbhost", "type", "veth", "peer", "name", "lbpeer")
	defer exec.Command("/usr/sbin/ip", "link", "del", "lbhost").Run()
	tunIP(t, "link", "set", "lbpeer", "netns", strconv.Itoa(cmd.Process.Pid))
	tunIP(t, "link", "set", "lbhost", "up")
	tunIP(t, "addr", "add", "10.77.0.1/24", "dev", "lbhost")
	tunIP(t, "-6", "addr", "add", "fd77::1/64", "dev", "lbhost", "nodad")
	io.WriteString(input, "setup\n")
	read("LANBOAT-PEER-READY")
	for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv6/conf/all/forwarding"} {
		if e = os.WriteFile(path, []byte("1"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	host, e := net.InterfaceByName("lbhost")
	if e != nil {
		t.Fatal(e)
	}
	peerMAC := ""
	// The peer link's MAC is available from its neighbor entry after the first handshake.
	dial := func(mptcp bool) (bool, bool) {
		lc := net.Dialer{Timeout: time.Second}
		lc.SetMultipathTCP(mptcp)
		c, e := lc.Dial("tcp4", "10.77.0.2:19001")
		if e != nil {
			return false, false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		_, e = c.Write([]byte("one"))
		if e == nil {
			b := make([]byte, 3)
			_, e = io.ReadFull(c, b)
			if string(b) != "one" {
				e = fmt.Errorf("bad echo")
			}
		}
		multipath, _ := c.(*net.TCPConn).MultipathTCP()
		return e == nil, multipath
	}
	if okay, _ := dial(false); !okay {
		t.Fatal("peer network is not ready")
	}
	neighbors, e := tunCommand("/usr/sbin/ip", "", "neigh", "show", "10.77.0.2")
	if e != nil {
		t.Fatal(e)
	}
	fields := strings.Fields(neighbors)
	for i, v := range fields {
		if v == "lladdr" && i+1 < len(fields) {
			peerMAC = fields[i+1]
		}
	}
	if peerMAC == "" {
		t.Fatal("missing peer MAC", neighbors)
	}

	t.Run("network-events-and-physical-reroute", func(t *testing.T) {
		r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", AutoRoute: true, DNSMode: "disabled"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
		tunIP(t, "route", "add", "198.51.100.9/32", "via", "10.77.0.2", "dev", "lbhost")
		defer exec.Command("/usr/sbin/ip", "route", "del", "198.51.100.9/32").Run()
		echo := func(want bool) {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, e := r.Dial(ctx, "tcp", "198.51.100.9:19001")
			if e == nil {
				c.SetDeadline(time.Now().Add(time.Second))
				_, e = c.Write([]byte("net"))
				if e == nil {
					b := make([]byte, 3)
					_, e = io.ReadFull(c, b)
					if string(b) != "net" {
						t.Fatal("wrong physical peer")
					}
				}
				c.Close()
			}
			if (e == nil) != want {
				t.Fatal("physical reroute", want, e)
			}
		}
		text, e := tunCommand("/usr/sbin/ip", "", "route", "get", "198.51.100.9", "mark", strconv.FormatUint(uint64(r.tunnels[0].mark), 10))
		if e != nil || !strings.Contains(text, "dev lbhost") {
			t.Fatal("protected socket route", text, e)
		}
		echo(true)
		tunIP(t, "route", "replace", "blackhole", "198.51.100.9/32")
		echo(false)
		tunIP(t, "route", "replace", "198.51.100.9/32", "via", "10.77.0.2", "dev", "lbhost")
		echo(true)
		tunnel := r.tunnels[0]
		var events atomic.Uint32
		tunnel.platformMu.Lock()
		refresh := tunnel.refreshEgress
		tunnel.refreshEgress = func() error { events.Add(1); return refresh() }
		tunnel.platformMu.Unlock()
		address := netip.MustParseAddr("192.0.2.77")
		tunIP(t, "addr", "add", address.String()+"/32", "dev", "lo")
		defer exec.Command("/usr/sbin/ip", "addr", "del", address.String()+"/32", "dev", "lo").Run()
		until := time.Now().Add(3 * time.Second)
		for {
			tunnel.hostMu.RLock()
			found := slices.Contains(tunnel.hostAddresses, address)
			tunnel.hostMu.RUnlock()
			if found && events.Load() > 0 {
				break
			}
			if time.Now().After(until) {
				t.Fatal("network event did not refresh interface snapshot")
			}
			time.Sleep(10 * time.Millisecond)
		}
		tunIP(t, "route", "add", "203.0.113.254/32", "via", "10.77.0.2", "dev", "lbhost")
		defer exec.Command("/usr/sbin/ip", "route", "del", "203.0.113.254/32").Run()
		request := []byte{8, 0, 0, 0, 0, 7, 0, 3, 9}
		binary.BigEndian.PutUint16(request[2:], checksum(request, 0))
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		response, e := r.directICMPExchange(ctx, netip.MustParseAddr("203.0.113.254"), request, 1)
		if e != nil || len(response.data) < 8 || response.data[0] != 11 {
			t.Fatal("router ICMP Time Exceeded", response, e)
		}
		r.Close()
	})
	testLocal := func(name string, in Inbound, rules []Rule, mptcp, want bool) {
		t.Run(name, func(t *testing.T) {
			in.Type = "tun"
			in.Tag = "tun"
			in.AutoRoute = true
			in.DNSMode = "disabled"
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "block", Tag: "block"}}, Route: Route{Final: "block", Rules: rules}})
			okay, actualMPTCP := dial(mptcp)
			r.Close()
			if okay != want {
				t.Fatal("kernel route", okay, "want", want)
			}
			if mptcp && want && !actualMPTCP {
				t.Fatal("MPTCP silently fell back to TCP")
			}
		})
	}
	queue := uint16(0)
	testLocal("bypass", Inbound{AutoRedirect: true, AutoRedirectNFQueue: &queue, AutoRedirectFallbackRuleIndex: 33001, AutoRedirectInputMark: 0x1101, AutoRedirectOutputMark: 0x1102, AutoRedirectResetMark: 0x1103, AutoRedirectTProxyMark: 0x1104}, []Rule{{IPCIDR: []string{"10.77.0.2/32"}, Action: "bypass"}}, false, true)
	testLocal("bypass-with-fallback", Inbound{AutoRedirect: true}, []Rule{{IPCIDR: []string{"10.77.0.2/32"}, Action: "bypass", Outbound: "block"}}, false, true)
	testLocal("bypass-normal-fallback", Inbound{}, []Rule{{IPCIDR: []string{"10.77.0.2/32"}, Action: "bypass", Outbound: "block"}}, false, false)
	testLocal("mptcp-bypass", Inbound{AutoRedirect: true, ExcludeMPTCP: true}, nil, true, true)
	testLocal("mptcp-reject", Inbound{AutoRedirect: true}, nil, true, false)
	for _, redirect := range []bool{false, true} {
		suffix := strconv.FormatBool(redirect)
		testLocal("exclude-uid-"+suffix, Inbound{AutoRedirect: redirect, ExcludeUID: []uint32{0}}, nil, false, true)
		if redirect {
			testLocal("include-other-uid-"+suffix, Inbound{AutoRedirect: redirect, IncludeUID: []uint32{12345}}, nil, false, true)
		}
		testLocal("include-current-uid-"+suffix, Inbound{AutoRedirect: redirect, IncludeUID: []uint32{0}}, nil, false, false)
	}
	proxy := socksEchoProxy(t)
	outbound := testOutbound(t, Inbound{Type: "socks"}, proxy)
	outbound.Username, outbound.Password = "", ""
	for _, redirect := range []bool{false, true} {
		for _, v := range []struct {
			name string
			in   Inbound
			want bool
		}{{"data-plane", Inbound{}, true}, {"include-interface", Inbound{IncludeInterface: []string{host.Name}}, true}, {"exclude-interface", Inbound{ExcludeInterface: []string{host.Name}}, false}, {"include-mac", Inbound{IncludeMACAddress: []string{peerMAC}}, true}, {"exclude-mac", Inbound{ExcludeMACAddress: []string{peerMAC}}, false}, {"other-mac", Inbound{IncludeMACAddress: []string{"02:00:00:00:00:01"}}, false}} {
			if !redirect && strings.Contains(v.name, "mac") {
				continue
			}
			t.Run(fmt.Sprintf("%s-redirect-%v", v.name, redirect), func(t *testing.T) {
				in := v.in
				in.Type = "tun"
				in.Tag = "tun"
				in.AutoRoute, in.AutoRedirect = true, redirect
				in.DNSMode = "disabled"
				r := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{outbound}})
				for _, dest := range []string{"203.0.113.21:443", "[2001:db8::21]:443"} {
					io.WriteString(input, dest+"\n")
					okay := read("LANBOAT-RESULT") == "true"
					if okay != v.want {
						t.Fatal(dest, okay, v.want)
					}
				}
				r.Close()
			})
		}
	}
	io.WriteString(input, "stop\n")
}
func TestTUNPreMatch(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Rules: []Rule{{IPCIDR: []string{"203.0.113.1/32"}, Action: "bypass"}, {Domain: []string{"unknown.test"}, Action: "route", Outbound: "direct"}, {Action: "bypass"}}}})
	tun := &tunTunnel{runtime: r, in: Inbound{AutoRedirect: true}}
	input, output, reset, _ := tun.in.redirectMarks()
	p := makeUDPPacket(netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("203.0.113.1"), 1234, 443, []byte("hello"))
	if mark, drop := tun.preMatchPacket(p); mark != output || drop {
		t.Fatal(mark, drop)
	}
	p = makeUDPPacket(netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("203.0.113.2"), 1234, 443, nil)
	if mark, _ := tun.preMatchPacket(p); mark != input {
		t.Fatal("unknown higher-priority rule bypassed", mark)
	}
	segment := make([]byte, 24)
	segment[12] = 6 << 4
	segment[13] = 2
	segment[20], segment[21] = 30, 4
	p = makeWGIP(netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("203.0.113.1"), 6, segment)
	if mark, _ := tun.preMatchPacket(p); mark != reset {
		t.Fatal("MPTCP not rejected", mark)
	}
	tun.in.ExcludeMPTCP = true
	if mark, _ := tun.preMatchPacket(p); mark != output {
		t.Fatal("MPTCP not bypassed", mark)
	}
	for n := 0; n < len(p); n++ {
		tun.preMatchPacket(p[:n])
	}
	binary.BigEndian.PutUint16(p[2:], 65535)
	tun.preMatchPacket(p)
}

func TestTUNPreMatchSnapshotChange(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{RuleSet: []RuleSet{{Type: "inline", Tag: "dynamic", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}}}}}, Rules: []Rule{{RuleSet: []string{"dynamic"}, Outbound: "direct"}}}})
	query := request{preMatch: true, network: "tcp", address: "203.0.113.21:443"}
	if r.rules[0].preMatchNeedsData(query) {
		t.Fatal("pure IP snapshot requires domain")
	}
	snapshot, e := compileRuleSet([]Rule{{Domain: []string{"dynamic.test"}}})
	if e != nil {
		t.Fatal(e)
	}
	r.ruleSets["dynamic"].current.Store(snapshot)
	if r.rules[0].evaluate(query) != matchUnknown {
		t.Fatal("new snapshot bypassed missing metadata guard")
	}
	query.preMatch = false
	if r.rules[0].evaluate(query) != matchNo {
		t.Fatal("normal route semantics changed")
	}
}
