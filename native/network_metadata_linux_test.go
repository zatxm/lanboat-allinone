package native

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNetworkMetadataRuntime(t *testing.T) {
	r := newTestRuntime(t, Config{
		Outbounds: []Outbound{{Type: "direct", Tag: "allowed"}, {Type: "block", Tag: "denied"}},
		Route:     Route{Final: "denied", Rules: []Rule{{NetworkType: []string{"wifi"}, WiFiBSSID: []string{"AA:BB:CC:DD:EE:FF"}, Outbound: "allowed"}}},
		DNS:       DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "fallback", Predefined: map[string][]string{"network.test": {"192.0.2.8"}}}}, Rules: []DNSRule{{Rule: Rule{WiFiSSID: []string{"test-network"}, Action: "predefined"}, Answer: []string{"network.test. 60 IN A 192.0.2.9"}}}},
	})
	var reads atomic.Int32
	r.network.read = func(context.Context, *Runtime) Metadata {
		reads.Add(1)
		return Metadata{NetworkType: "wifi", WiFiSSID: "test-network", WiFiBSSID: "aa:bb:cc:dd:ee:ff", NetworkIsExpensive: true, NetworkInterfaceAddress: map[string][]netip.Addr{"wifi": {netip.MustParseAddr("192.0.2.2")}}, DefaultInterfaceAddress: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
	}
	query, _ := makeDNSQuery("network.test", 1)
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			for range 20 {
				q, tag, err := r.routeTarget(context.Background(), request{network: "tcp", address: "192.0.2.10:80"})
				if err != nil || tag != "allowed" || !q.metadata.NetworkIsExpensive {
					t.Error("routing ignored network", tag, err)
				}
				reply, err := r.ExchangeDNS(context.Background(), query, "")
				ips, _, parseErr := parseDNSReply(query, reply)
				if err != nil || parseErr != nil || len(ips) != 1 || ips[0].String() != "192.0.2.9" {
					t.Error("DNS ignored network", ips, err, parseErr)
				}
			}
		})
	}
	workers.Wait()
	if reads.Load() != 1 {
		t.Fatal("discovery repeated per connection", reads.Load())
	}
	provided := Metadata{NetworkType: "ethernet", WiFiSSID: "supplied", NetworkInterfaceAddress: map[string][]netip.Addr{}, DefaultInterfaceAddress: []netip.Addr{}}
	r.enrichNetworkMetadata(context.Background(), &provided)
	if provided.NetworkType != "ethernet" || provided.NetworkIsExpensive || provided.WiFiSSID != "supplied" || len(provided.NetworkInterfaceAddress) != 0 || len(provided.DefaultInterfaceAddress) != 0 {
		t.Fatal("caller snapshot overwritten", provided)
	}
	r.network.mu.Lock()
	r.network.read = func(context.Context, *Runtime) Metadata { reads.Add(1); return Metadata{} }
	r.network.mu.Unlock()
	r.network.invalidate()
	_, tag, err := r.routeTarget(context.Background(), request{network: "tcp", address: "192.0.2.10:80"})
	if err != nil || tag != "denied" || reads.Load() != 2 {
		t.Fatal("network change not applied", tag, err, reads.Load())
	}
	reply, err := r.ExchangeDNS(context.Background(), query, "")
	ips, _, parseErr := parseDNSReply(query, reply)
	if err != nil || parseErr != nil || len(ips) != 1 || ips[0].String() != "192.0.2.8" {
		t.Fatal("DNS retained old network policy", ips, err, parseErr)
	}
}

func TestNetworkMetadataDynamicSetsAndDisabled(t *testing.T) {
	r := newTestRuntime(t, Config{Route: Route{RuleSet: []RuleSet{{Type: "inline", Tag: "dynamic", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}}}}}, Rules: []Rule{{RuleSet: []string{"dynamic"}, Outbound: "direct"}}}})
	r.network.read = func(context.Context, *Runtime) Metadata { t.Error("unneeded discovery"); return Metadata{} }
	m := Metadata{}
	r.enrichNetworkMetadata(context.Background(), &m)
	for _, condition := range []Rule{{NetworkType: []string{"wifi"}}, {WiFiSSID: []string{"x"}}, {WiFiBSSID: []string{"x"}}, {NetworkIsExpensive: true}, {NetworkInterfaceAddress: map[string][]string{"wifi": {"192.0.2.0/24"}}}, {DefaultInterfaceAddress: []string{"192.0.2.0/24"}}} {
		s, err := compileRuleSet([]Rule{condition})
		if err != nil {
			t.Fatal(err)
		}
		r.ruleSets["dynamic"].store(s)
		if !r.needsMetadata(networkFields) {
			t.Fatal("new condition undiscovered", condition)
		}
	}
	s, _ := compileRuleSet([]Rule{{IPCIDR: []string{"192.0.2.0/24"}}})
	r.ruleSets["dynamic"].store(s)
	if r.needsMetadata(networkFields) {
		t.Fatal("removed network condition retained")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = r.network.snapshot(ctx, r)
}

func TestNetworkMetadataPreMatch(t *testing.T) {
	for _, condition := range []Rule{{NetworkType: []string{"wifi"}}, {WiFiSSID: []string{"test"}}, {NetworkInterfaceAddress: map[string][]string{"wifi": {"192.0.2.0/24"}}}, {DefaultInterfaceAddress: []string{"192.0.2.0/24"}}} {
		condition.Action, condition.Method = "reject", "drop"
		r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{condition}}})
		r.network.read = func(context.Context, *Runtime) Metadata {
			return Metadata{NetworkType: "wifi", WiFiSSID: "test", NetworkInterfaceAddress: map[string][]netip.Addr{"wifi": {netip.MustParseAddr("192.0.2.2")}}, DefaultInterfaceAddress: []netip.Addr{netip.MustParseAddr("192.0.2.2")}}
		}
		packet := makeUDPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.9"), 12345, 443, []byte("network"))
		if _, drop := (&tunTunnel{runtime: r}).preMatchPacket(packet); !drop {
			t.Fatal("pre-match ignored discovered network", condition)
		}
	}
}

func TestNetworkManagerProperties(t *testing.T) {
	resolvedPrivateBus(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, err := connectResolvedBus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer server.close()
	if _, err = server.call(ctx, "RequestName", "su", []any{networkManagerName, uint32(4)}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                 string
		kind, metered, state uint32
		want                 string
		expensive            bool
	}{
		{"wifi-metered", 2, 3, 100, "wifi", true},
		{"ethernet-metered", 1, 1, 100, "ethernet", true},
		{"cellular", 8, 2, 100, "cellular", false},
		{"virtual", 14, 4, 100, "other", false},
		{"unknown", 0, 1, 100, "", false},
		{"wifi-disconnected", 2, 1, 30, "wifi", false},
	}
	var selected atomic.Int32
	go func() {
		prop := func(name, sig string, value any) any { return []any{name, busVariant{sig, value}} }
		for {
			select {
			case <-server.ctx.Done():
				return
			case m := <-server.requests:
				if m.member == "GetDeviceByIpIface" {
					server.respond(m, "", "o", []any{networkManagerPath + "/Devices/1"}, "", "")
					continue
				}
				var props []any
				tc := cases[selected.Load()]
				switch m.values[0].(string) {
				case networkManagerName + ".Device":
					props = []any{prop("DeviceType", "u", tc.kind), prop("Metered", "u", tc.metered), prop("State", "u", tc.state)}
				case networkManagerName + ".Device.Wireless":
					props = []any{prop("ActiveAccessPoint", "o", networkManagerPath+"/AccessPoint/1"), prop("LastScan", "x", int64(-1))}
				case networkManagerName + ".AccessPoint":
					props = []any{prop("Ssid", "ay", []byte("测试WiFi")), prop("HwAddress", "s", "AA:BB:CC:DD:EE:FF")}
				}
				server.respond(m, "", "a{sv}", []any{props}, "", "")
			}
		}
	}()
	client, err := connectNetworkManager(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.conn.Close()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selected.Store(int32(i))
			m := client.device("test0", true)
			if m.NetworkType != tc.want || m.NetworkIsExpensive != tc.expensive {
				t.Fatal(m)
			}
			if tc.kind == 2 && tc.state == 100 {
				if m.WiFiSSID != "测试WiFi" || m.WiFiBSSID != "aa:bb:cc:dd:ee:ff" {
					t.Fatal(m)
				}
			} else if m.WiFiSSID != "" || m.WiFiBSSID != "" {
				t.Fatal("inactive WiFi used", m)
			}
		})
	}
	selected.Store(0)
	if m := client.device("test0", false); m.NetworkType != "wifi" || m.NetworkIsExpensive || m.WiFiSSID != "" {
		t.Fatal("inactive network used", m)
	}
}

func TestNetworkManagerRejectSender(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	go func() {
		m, err := busRead(peer)
		if err == nil {
			writeAll(peer, (busMessage{kind: 2, serial: 1, reply: m.serial, sender: ":other", signature: "s", values: []any{"untrusted"}}).encode())
		}
	}()
	b := &networkManagerBus{conn: client, reader: bufio.NewReader(client)}
	if _, err := b.call(":expected", "/", "x", "x", "", nil); err == nil {
		t.Fatal("untrusted service response accepted")
	}
}

func TestNetworkMetadataLinuxNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_NETWORK_NAMESPACE") != "1" {
		ns, _ := os.Readlink("/proc/self/ns/net")
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestNetworkMetadataLinuxNamespace$", "-test.v", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "LANBOAT_NETWORK_NAMESPACE=1", "LANBOAT_NETWORK_PARENT_NS="+ns)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated network metadata: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	parent := os.Getenv("LANBOAT_NETWORK_PARENT_NS")
	if ns == "" || parent == "" || ns == parent {
		t.Fatal("test requires a private network namespace")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "add", "net0", "type", "dummy"}, {"addr", "add", "192.0.2.2/24", "dev", "net0"}, {"link", "set", "net0", "up"}, {"route", "add", "default", "via", "192.0.2.1", "dev", "net0"}} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatal(args, err, string(out))
		}
	}
	ip := netip.MustParseAddr("192.0.2.2")
	r := &Runtime{}
	m := systemNetworkMetadata(context.Background(), r)
	if m.NetworkType != "other" || !slices.Contains(m.DefaultInterfaceAddress, ip) || !slices.Contains(m.NetworkInterfaceAddress["other"], ip) || m.WiFiSSID != "" {
		t.Fatal("wrong namespace/route snapshot", m)
	}
	for _, redirect := range []bool{false, true} {
		t.Run(fmt.Sprint("tun/redirect=", redirect), func(t *testing.T) {
			proxy := socksEchoProxy(t)
			out := testOutbound(t, Inbound{Type: "socks"}, proxy)
			out.Username, out.Password = "", ""
			r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "tun", Tag: "tun", AutoRoute: true, AutoRedirect: redirect, StrictRoute: true, DNSMode: "hijack"}}, Outbounds: []Outbound{out, {Type: "block", Tag: "denied"}}, Route: Route{Final: "denied", Rules: []Rule{{DefaultInterfaceAddress: []string{"192.0.2.2/32"}, Outbound: "proxy"}}}, DNS: DNSConfig{Rules: []DNSRule{{Rule: Rule{DefaultInterfaceAddress: []string{"192.0.2.2/32"}, Action: "predefined"}, Answer: []string{"process.test. 60 IN A 192.0.2.9"}}, {Rule: Rule{Action: "reject"}}}}})
			defer r.Close()
			for _, network := range []string{"tcp4", "udp4"} {
				c, err := net.DialTimeout(network, "203.0.113.20:9000", 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				c.SetDeadline(time.Now().Add(3 * time.Second))
				if err = writeAll(c, []byte("network")); err != nil {
					t.Fatal(err)
				}
				var reply [7]byte
				_, err = io.ReadFull(c, reply[:])
				c.Close()
				if err != nil || string(reply[:]) != "network" {
					t.Fatal(string(reply[:]), err)
				}
				checkProcessDNS(t, network, "9.9.9.9:53")
			}
		})
	}
	if out, err := exec.Command("ip", "route", "del", "default").CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	m = systemNetworkMetadata(context.Background(), &Runtime{})
	if m.NetworkType != "" || len(m.DefaultInterfaceAddress) != 0 {
		t.Fatal("withdrawn default route retained", m)
	}
}

func TestNetworkMetadataHost(t *testing.T) {
	r := &Runtime{metadataFields: networkFields}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m := systemNetworkMetadata(ctx, r)
	if m.NetworkInterfaceAddress == nil || m.DefaultInterfaceAddress == nil {
		t.Fatal("host snapshot unavailable")
	}
	// Do not write local SSIDs, MACs or addresses into test logs.
	t.Logf("type=%s,default_addresses=%d,wifi_identity=%v", m.NetworkType, len(m.DefaultInterfaceAddress), m.WiFiSSID != "" && m.WiFiBSSID != "")
	if strings.Contains(m.WiFiBSSID, "-") {
		t.Fatal("BSSID not canonical")
	}
}

func TestNetworkDefaultInterfaceParser(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
		ipv6             bool
	}{
		{"ipv4", "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth1 00000000 00000000 0001 0 0 600 00000000\neth0 00000000 00000000 0003 0 0 100 00000000\n", "eth0", false},
		{"invalid", "bad 00000000 00000000 0001 0 0 invalid 00000000\n", "", false},
		{"reject", "bad 00000000 00000000 0201 0 0 0 00000000\n", "", false},
		{"subnet", "eth0 000200C0 00000000 0001 0 0 0 00FFFFFF\n", "", false},
		{"ipv6", "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000200 0 0 00000003 eth0\n", "eth0", true},
		{"ipv6-reject", "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 0 0 00200200 lo\n", "", true},
		{"ipv6-source-route", "00000000000000000000000000000000 00 20010db8000000000000000000000000 40 fe800000000000000000000000000001 00000200 0 0 00000003 eth0\n", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := linuxDefaultInterface(strings.NewReader(tc.data), tc.ipv6); got != tc.want {
				t.Fatal(got, tc.want)
			}
		})
	}
}

func TestNetworkMetadataCacheExpiryAndCancel(t *testing.T) {
	var reads int
	c := networkMetadataCache{read: func(context.Context, *Runtime) Metadata {
		reads++
		return Metadata{NetworkType: fmt.Sprint(reads)}
	}}
	if c.snapshot(context.Background(), &Runtime{}).NetworkType != "1" {
		t.Fatal(reads)
	}
	c.next = time.Now().Add(-time.Second)
	if c.snapshot(context.Background(), &Runtime{}).NetworkType != "2" {
		t.Fatal("expired cache not refreshed")
	}
	c.invalidate()
	c.read = func(ctx context.Context, _ *Runtime) Metadata { <-ctx.Done(); return Metadata{NetworkType: "stale"} }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if m := c.snapshot(ctx, &Runtime{}); m.NetworkType != "" || c.state.NetworkType != "2" {
		t.Fatal("cancelled result cached", m)
	}
}

func TestNetworkManagerReadDeadline(t *testing.T) {
	listener, err := net.Listen("unix", t.TempDir()+"/bus")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+listener.Addr().String())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		r.ReadString('\n')
		writeAll(c, []byte("OK 1234\r\n"))
		r.ReadString('\n')
		io.Copy(io.Discard, r)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := connectNetworkManager(ctx); err == nil {
		t.Fatal("unresponsive bus accepted")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("bus connection leaked after timeout")
	}
}

func BenchmarkNetworkMetadataDisabled(b *testing.B) {
	r := &Runtime{}
	m := Metadata{}
	b.ReportAllocs()
	for b.Loop() {
		r.enrichNetworkMetadata(context.Background(), &m)
	}
}
