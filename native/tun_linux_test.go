//go:build linux

package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeTUNNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_TUN_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestNativeTUNNamespace$", "-test.v", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "LANBOAT_TUN_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated TUN test: %v\n%s", err, output)
		} else {
			t.Log(string(output))
		}
		return
	}
	for _, redirect := range []bool{false, true} {
		name := "route"
		if redirect {
			name = "nft-redirect"
		}
		t.Run(name, func(t *testing.T) { testNativeTUNNamespace(t, redirect) })
	}
	t.Run("nft-ruleset-refresh", testTUNRuleSetRefresh)
}

func testTUNRuleSetRefresh(t *testing.T) { testTUNRuleSetRefreshMode(t, true) }
func testTUNRuleSetRefreshMode(t *testing.T, redirect bool) {
	path := filepath.Join(t.TempDir(), "ip.json")
	write := func(cidr string) {
		s := `{"version":1,"rules":[{"ip_cidr":"` + cidr + `"}]}`
		if cidr == "" {
			s = `{"version":1,"rules":[]}`
		}
		if e := os.WriteFile(path, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("203.0.113.21/32")
	proxy := socksEchoProxy(t)
	out := testOutbound(t, Inbound{Type: "socks"}, proxy)
	out.Username, out.Password = "", ""
	r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", AutoRoute: true, AutoRedirect: redirect, DNSMode: "disabled", RouteAddressSet: []string{"include"}}}, Outbounds: []Outbound{out}, Route: Route{RuleSet: []RuleSet{{Type: "local", Tag: "include", Format: "source", Path: path}}}})
	reusedPort, targetCalls := unusedPort(t), 0
	dial := func(ip string, want bool) {
		dialer := net.Dialer{Timeout: time.Second}
		if ip == "203.0.113.23" {
			targetCalls++
			if targetCalls <= 2 {
				dialer.LocalAddr = &net.TCPAddr{IP: net.IP(r.tunnels[0].local4.AsSlice()), Port: int(reusedPort)}
			}
		}
		c, e := dialer.Dial("tcp", ip+":443")
		if e == nil {
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte("x"))
			b := make([]byte, 1)
			_, e = io.ReadFull(c, b)
		}
		if (e == nil) != want {
			if text, err := tunCommand("/usr/sbin/nft", "", "list", "ruleset"); err == nil {
				t.Log(text)
			}
			if text, err := os.ReadFile("/proc/net/nf_conntrack"); err == nil {
				t.Log(string(text))
			}
			t.Fatal("route membership", ip, want, e)
		}
	}
	refresh := func() {
		if e := r.ReloadRuleSets(context.Background()); e != nil {
			t.Fatal(e)
		}
		tun := r.tunnels[0]
		tun.platformMu.Lock()
		e := tun.refreshRoutes()
		tun.platformMu.Unlock()
		if e != nil {
			t.Fatal(e)
		}
	}
	dial("203.0.113.21", true)
	dial("203.0.113.23", false)
	write("203.0.113.23/32")
	refresh()
	dial("203.0.113.21", false)
	dial("203.0.113.23", true)
	if e := os.WriteFile(path, []byte("invalid"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.ReloadRuleSets(context.Background()); e == nil {
		t.Fatal("invalid update accepted")
	}
	dial("203.0.113.23", true)
	write("")
	refresh()
	dial("203.0.113.23", false)
	r.Close()
	text, e := tunCommand("/usr/sbin/nft", "", "list", "tables")
	if e != nil || strings.Contains(text, "lanboat_") {
		t.Fatal("nftables not cleaned", text, e)
	}
}

func testNativeTUNNamespace(t *testing.T, redirect bool) {
	loopback, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := configureLink(loopback.Index, 65536); err != nil {
		t.Fatal(err)
	}
	proxy := socksEchoProxy(t)
	out := testOutbound(t, Inbound{Type: "socks"}, proxy)
	out.Username, out.Password = "", ""
	cfg := Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", InterfaceName: "lbtest0", AutoRoute: true, AutoRedirect: redirect, StrictRoute: true, MTU: 1500, MultiQueue: true, IPRoute2TableIndex: 2023, IPRoute2RuleIndex: 9010, RouteExcludeAddress: []string{"192.0.2.0/24"}}}, Outbounds: []Outbound{out}, Route: Route{Rules: []Rule{{Network: []string{"icmp"}, IPCIDR: []string{"203.0.113.25/32", "2001:db8::25/128"}, Action: "reject", Method: "reply"}, {Network: []string{"icmp"}, Action: "reject"}, {Network: []string{"udp"}, IPCIDR: []string{"203.0.113.25/32"}, Action: "reject"}}}, DNS: DNSConfig{Final: "hosts", Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"tun.test": {"192.0.2.9"}}}}}}
	runtime := newTestRuntime(t, cfg)
	if c, e := net.DialTimeout("tcp", "192.0.2.33:9000", 200*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("excluded route was captured by TUN")
	}
	for _, address := range []string{"203.0.113.21:443", "[2001:db8::21]:443"} {
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			t.Fatal("TUN TCP", address, err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		want := bytes.Repeat([]byte("kernel TUN TCP echo\n"), 5000)
		if err := writeAll(conn, want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
			t.Fatal("TUN TCP data", address, len(got), err)
		}
		conn.Close()
	}
	for _, address := range []string{"203.0.113.22:9000", "[2001:db8::22]:9000"} {
		conn, err := net.DialTimeout("udp", address, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		for _, size := range []int{1, 4096, 60000} {
			want := bytes.Repeat([]byte{byte(size)}, size)
			if _, err := conn.Write(want); err != nil {
				t.Fatal("TUN UDP write", address, size, err)
			}
			got := make([]byte, 65535)
			n, err := conn.Read(got)
			if err != nil || !bytes.Equal(got[:n], want) {
				t.Fatal("TUN UDP echo", address, size, n, err)
			}
		}
		conn.Close()
	}
	dns, err := net.DialTimeout("udp", "9.9.9.9:53", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = dns.SetDeadline(time.Now().Add(3 * time.Second))
	query, _ := makeDNSQuery("tun.test", 1)
	dns.Write(query)
	reply := make([]byte, 4096)
	n, err := dns.Read(reply)
	dns.Close()
	if err != nil {
		t.Fatal("TUN DNS hijack", err)
	}
	ips, _, err := parseDNSReply(query, reply[:n])
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
		t.Fatal("TUN DNS answer", ips, err)
	}
	for _, address := range []string{"9.9.9.9:53", "[2001:4860:4860::8888]:53"} {
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			t.Fatal("TUN DNS TCP", err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := writeAll(conn, binary.BigEndian.AppendUint16(nil, uint16(len(query)))); err != nil {
			t.Fatal(err)
		}
		if err := writeAll(conn, query); err != nil {
			t.Fatal(err)
		}
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			t.Fatal(err)
		}
		answer := make([]byte, int(binary.BigEndian.Uint16(length[:])))
		if _, err := io.ReadFull(conn, answer); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		ips, _, err := parseDNSReply(query, answer)
		if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
			t.Fatal("TUN DNS TCP answer", ips, err)
		}
	}
	for _, ip := range []string{"203.0.113.25", "2001:db8::25"} {
		network := "ip4:icmp"
		if strings.Contains(ip, ":") {
			network = "ip6:ipv6-icmp"
		}
		c, e := net.Dial(network, ip)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		segment := []byte{8, 0, 0, 0, 0, 45, 0, 1, 1, 2, 3, 4}
		if strings.Contains(ip, ":") {
			segment[0] = 128
		} else {
			binary.BigEndian.PutUint16(segment[2:], checksum(segment, 0))
		}
		if _, e = c.Write(segment); e != nil {
			t.Fatal(e)
		}
		buffer := make([]byte, 4096)
		n, e := c.Read(buffer)
		c.Close()
		if e != nil {
			t.Fatal("TUN ICMP echo", ip, e)
		}
		b := buffer[:n]
		if len(b) > 20 && b[0]>>4 == 4 {
			b = b[int(b[0]&15)*4:]
		}
		want := byte(0)
		if strings.Contains(ip, ":") {
			want = 129
		}
		if len(b) < 8 || b[0] != want || !bytes.Equal(b[8:], segment[8:]) {
			t.Fatal("TUN ICMP reply", ip, b)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		segment := []byte{8, 0, 0, 0, 0, 3, 0, 1, 1, 2, 3, 4}
		if ip == "::1" {
			segment[0] = 128
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		b, e := runtime.directICMPEcho(ctx, netip.MustParseAddr(ip), segment, 64)
		cancel()
		if e != nil || !bytes.Equal(b[4:], segment[4:]) {
			t.Fatal("direct ICMP transport", ip, b, e)
		}
	}
	denied, e := net.DialTimeout("udp", "203.0.113.25:2000", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	denied.SetDeadline(time.Now().Add(time.Second))
	denied.Write([]byte("reject"))
	_, e = denied.Read(make([]byte, 100))
	denied.Close()
	if e == nil {
		t.Fatal("UDP rejection was not delivered")
	}
	name := runtime.Address("tun")
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatal("TUN device survived shutdown")
	}
}
