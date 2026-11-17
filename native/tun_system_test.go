//go:build darwin || windows

package native

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Run on an administrator/root disposable machine: this test creates a real TUN.
func TestTUNSystemDevice(t *testing.T) {
	proxy := socksEchoProxy(t)
	out := testOutbound(t, Inbound{Type: "socks"}, proxy)
	out.Username, out.Password = "", ""
	path := filepath.Join(t.TempDir(), "ip.json")
	writeRules := func(ipv4, ipv6 string) {
		t.Helper()
		if e := os.WriteFile(path, []byte(`{"version":1,"rules":[{"ip_cidr":["`+ipv4+`","`+ipv6+`"]}]}`), 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeRules("203.0.113.21/32", "2001:db8::21/128")
	cfg := Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", AutoRoute: true, StrictRoute: true, DNSMode: "native", RouteAddressSet: []string{"capture"}}}, Outbounds: []Outbound{out}, Route: Route{RuleSet: []RuleSet{{Type: "local", Tag: "capture", Path: path, Format: "source"}}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"tun.test": {"192.0.2.9"}}}}, Final: "hosts"}}
	r := newTestRuntime(t, cfg)
	assertTUNSystemConfiguration(t, r)
	for _, address := range []string{"203.0.113.21:443", "[2001:db8::21]:443"} {
		c, e := net.DialTimeout("tcp", address, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		want := bytes.Repeat([]byte("native system TUN"), 4000)
		if e = writeAll(c, want); e != nil {
			t.Fatal(e)
		}
		got := make([]byte, len(want))
		_, e = io.ReadFull(c, got)
		c.Close()
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("TCP", address, e)
		}
	}
	for _, address := range []string{"203.0.113.21:9000", "[2001:db8::21]:9000"} {
		c, e := net.DialTimeout("udp", address, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		want := bytes.Repeat([]byte{9}, 4096)
		t.Logf("TUN UDP %s -> %s at %s", c.LocalAddr(), address, time.Now().Format(time.RFC3339Nano))
		if n, err := c.Write(want); err != nil || n != len(want) {
			t.Fatalf("UDP send %s: %d %v", address, n, err)
		}
		got := make([]byte, 65535)
		n, e := c.Read(got)
		c.Close()
		if e != nil || !bytes.Equal(want, got[:n]) {
			t.Fatal("UDP", address, n, e)
		}
	}
	for _, address := range []string{"172.19.0.2:53", "[fdfe:dcba:9876::2]:53"} {
		c, e := net.DialTimeout("udp", address, 3*time.Second)
		if e != nil {
			t.Fatal(e)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		query, _ := makeDNSQuery("tun.test", 1)
		c.Write(query)
		got := make([]byte, 4096)
		n, e := c.Read(got)
		c.Close()
		if e != nil {
			t.Fatal("native DNS", address, e)
		}
		ips, _, e := parseDNSReply(query, got[:n])
		if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
			t.Fatal(ips, e)
		}
	}

	writeRules("203.0.113.23/32", "2001:db8::23/128")
	if e := r.ReloadRuleSets(context.Background()); e != nil {
		t.Fatal(e)
	}
	tunnel := r.tunnels[0]
	tunnel.platformMu.Lock()
	e := tunnel.refreshRoutes()
	tunnel.platformMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	for _, address := range []string{"203.0.113.23:443", "[2001:db8::23]:443"} {
		c, e := net.DialTimeout("tcp", address, 3*time.Second)
		if e != nil {
			t.Fatal("refreshed route", address, e)
		}
		c.SetDeadline(time.Now().Add(time.Second))
		_, e = c.Write([]byte("new"))
		if e == nil {
			b := make([]byte, 3)
			_, e = io.ReadFull(c, b)
			if string(b) != "new" {
				t.Fatal("refreshed route reply")
			}
		}
		c.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	if c, e := net.DialTimeout("tcp", "203.0.113.21:443", 500*time.Millisecond); e == nil {
		c.Close()
		t.Fatal("old route remained captured")
	}
	assertTUNSystemConfiguration(t, r)
	name := r.Address("tun")
	r.Close()
	if _, e := net.InterfaceByName(name); e == nil {
		t.Fatal("TUN interface survived Close")
	}
}

func TestTUNEgressCannotLoop(t *testing.T) {
	r := &Runtime{}
	r.tunRouting.Store(true)
	var controlCalled bool
	raw := tunRawControl{call: func() { controlCalled = true }}
	if e := r.socketControl("tcp6", "[2001:db8::2]:443", raw); e == nil || controlCalled {
		t.Fatal("missing physical egress was not rejected", e)
	}
	if e := r.socketControl("tcp4", "127.0.0.1:1000", raw); e != nil || controlCalled {
		t.Fatal("loopback incorrectly bound to physical interface", e)
	}
}

type tunRawControl struct{ call func() }

func (r tunRawControl) Control(f func(uintptr)) error    { r.call(); return nil }
func (r tunRawControl) Read(f func(uintptr) bool) error  { return nil }
func (r tunRawControl) Write(f func(uintptr) bool) error { return nil }
