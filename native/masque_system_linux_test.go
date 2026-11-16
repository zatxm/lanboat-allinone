//go:build linux

package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestMasqueSystemNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_MASQUE_SYSTEM_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=120s")
		cmd.Env = append(os.Environ(), "LANBOAT_MASQUE_SYSTEM_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated MASQUE system interfaces: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	masqueSystemCommand(t, "link", "set", "lo", "up")
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("client/http%d", version), func(t *testing.T) { masqueSystemClientTraffic(t, version) })
		t.Run(fmt.Sprintf("server/http%d", version), func(t *testing.T) { masqueSystemServerTraffic(t, version) })
	}
	t.Run("failure-cleanup", masqueSystemFailureCleanup)
}

func masqueSystemCommand(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func masqueSystemWait(t *testing.T, c *masqueClient) *masqueIP {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := c.ipSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p.system.Load() == nil {
		t.Fatal("missing system interface")
	}
	return p
}

func masqueSystemClientTraffic(t *testing.T, version int) {
	t.Helper()
	port, socksPort := unusedPort(t), unusedPort(t)
	endpoint := map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "listen_port": port, "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": certificate(t)}
	masqueOfficial(t, map[string]any{"endpoints": []any{endpoint}, "inbounds": []Inbound{{Type: "socks", Listen: "127.0.0.1", ListenPort: socksPort}}, "outbounds": []Outbound{{Type: "direct", Tag: "direct"}}, "route": Route{Final: "direct", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24", "2001:db8:44::/64"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}}}, portAddress("127.0.0.1", socksPort))
	c := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "version": version, "disable_version_fallback": true, "username": "client", "password": "private", "system": true, "name": "lbmc0", "on_demand": true, "tls": TLSOptions{Enabled: true, Insecure: true}})
	p := masqueSystemWait(t, c.masqueClients["proxy"])
	iface, err := net.InterfaceByName("lbmc0")
	if err != nil || iface.MTU != 1280 {
		t.Fatal(iface, err)
	}
	for _, route := range []string{"10.44.0.1/32", "fd44::1/128", "192.0.2.0/24", "2001:db8:44::/64"} {
		masqueSystemCommand(t, "route", "add", route, "dev", iface.Name)
	}
	for _, ip := range []string{"10.44.0.1", "fd44::1"} {
		if out, err := exec.Command("ping", "-c", "1", "-W", "3", ip).CombinedOutput(); err != nil {
			t.Fatalf("kernel ICMP %s: %v %s", ip, err, out)
		}
	}
	tcpTarget, udpTarget := relayEchoTCP(t), echoUDP(t)
	_, tcpPort, _ := net.SplitHostPort(tcpTarget)
	_, udpPort, _ := net.SplitHostPort(udpTarget)
	for _, ip := range []string{"192.0.2.42", "2001:db8:44::42"} {
		masqueSystemRoundtrip(t, "tcp", net.JoinHostPort(ip, tcpPort))
		masqueSystemRoundtrip(t, "udp", net.JoinHostPort(ip, udpPort))
	}
	// API and kernel flows coexist; API source ports must be unavailable to host sockets.
	for _, network := range []string{"tcp", "udp"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		target := net.JoinHostPort("192.0.2.42", tcpPort)
		if network == "udp" {
			target = net.JoinHostPort("192.0.2.42", udpPort)
		}
		conn, err := c.Dial(ctx, network, target)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if network == "tcp" {
			l, err := net.Listen(network, conn.LocalAddr().String())
			if err == nil {
				l.Close()
				t.Fatal("API port was not reserved")
			}
		} else {
			l, err := net.ListenPacket(network, conn.LocalAddr().String())
			if err == nil {
				l.Close()
				t.Fatal("API UDP port was not reserved")
			}
		}
		masqueSystemEcho(t, conn, 4096)
		conn.Close()
	}
	if routes := masqueSystemCommand(t, "route", "show", "default"); routes != "" {
		t.Fatal("unexpected default route", routes)
	}
	if c.protectMark.Load() != 0 {
		t.Fatal("system endpoint changed socket protection")
	}
	c.resetNetworkTransports()
	q := masqueSystemWait(t, c.masqueClients["proxy"])
	if p == q || p.system.Load() != nil {
		t.Fatal("old system interface survived reset")
	}
	if err = c.DisconnectMasque("proxy"); err != nil {
		t.Fatal(err)
	}
	if _, err = net.InterfaceByName("lbmc0"); err == nil {
		t.Fatal("on-demand disconnect left the interface")
	}
	p = masqueSystemWait(t, c.masqueClients["proxy"])
	// A withdrawn address must close the interface and stop accepting old addresses.
	if err = p.control(1, nil); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(time.Second); p.system.Load() != nil; {
		if time.Now().After(until) {
			t.Fatal("withdrawn address retained its system interface")
		}
		time.Sleep(time.Millisecond)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
}

func masqueSystemServerTraffic(t *testing.T, version int) {
	t.Helper()
	s := masqueReverseRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "system": true, "name": "lbms0", "tls": certificate(t)}, Route{Final: "server"})
	host, port, _ := net.SplitHostPort(s.Address("server"))
	n, _ := shadowPort(port)
	socksPort := unusedPort(t)
	masqueOfficial(t, map[string]any{"endpoints": []any{map[string]any{"type": "masque-client", "tag": "client", "server": host, "server_port": n, "version": version, "username": "client", "password": "private", "advertise_routes": []string{"192.0.2.0/24"}, "tls": TLSOptions{Enabled: true, Insecure: true}}}, "inbounds": []Inbound{{Type: "socks", Listen: "127.0.0.1", ListenPort: socksPort}}, "route": Route{Final: "client"}}, portAddress("127.0.0.1", socksPort))
	masqueWaitPeer(t, s, "192.0.2.42")
	probe := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: socksPort}}})
	for _, ip := range []string{"10.44.0.1", "fd44::1"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := probe.Dial(ctx, "tcp", masqueEcho(t, "tcp", net.JoinHostPort(ip, "0")))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		masqueSystemEcho(t, conn, 70000)
		conn.Close()
		assertUDPAddress(t, probe, []int{0, 1, 4096, 14000}, masqueEcho(t, "udp", net.JoinHostPort(ip, "0")))
	}
	// The kernel server also serves a second independent client and real ICMP.
	c := masqueReverseRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "version": version, "username": "client", "password": "private", "advertise_routes": []string{"10.44.0.0/24", "fd44::/64", "198.51.100.0/24"}, "tls": TLSOptions{Enabled: true, Insecure: true}}, Route{Final: "direct", Rules: []Rule{{Inbound: []string{"proxy"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := c.masqueClients["proxy"].ipSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	masqueWaitPeer(t, s, "198.51.100.42")
	target := relayEchoTCP(t)
	_, targetPort, _ := net.SplitHostPort(target)
	conn, err := s.Dial(ctx, "tcp", net.JoinHostPort("198.51.100.42", targetPort))
	if err != nil {
		t.Fatal("system server reverse API", err)
	}
	masqueSystemEcho(t, conn, 4096)
	conn.Close()
	for _, ip := range []string{"10.44.0.1", "fd44::1"} {
		destination := netip.MustParseAddr(ip)
		kind := byte(8)
		if destination.Is6() {
			kind = 128
		}
		response, err := p.stack.exchangeICMP(ctx, destination, []byte{kind, 0, 0, 0, 1, 2, 0, 1, 42}, 64)
		if err != nil || response.source != destination || len(response.data) != 9 || response.data[8] != 42 {
			t.Fatal("kernel server ICMP", ip, response, err)
		}
	}
	server := s.masqueServers["server"]
	clientIP := p.addresses()[0]
	owner := server.systemPeer(clientIP, 17)
	if owner == nil || !server.systemSource(owner, clientIP) || server.systemSource(owner, netip.MustParseAddr("10.44.0.1")) {
		t.Fatal("client ownership checks failed")
	}
	server.mu.Lock()
	var foreign netip.Addr
	for f, addresses := range server.allocated {
		if server.sessions[f] != owner {
			foreign = addresses[0]
		}
	}
	server.mu.Unlock()
	if !foreign.IsValid() || server.systemSource(owner, foreign) {
		t.Fatal("advertised subnet stole another client's address", foreign)
	}
	sink, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.44.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	probePort := uint16(sink.LocalAddr().(*net.UDPAddr).Port)
	data := []byte("source-ownership")
	if err = p.writePacket(makeUDPPacket(foreign, netip.MustParseAddr("10.44.0.1"), 17001, probePort, data)); err != nil {
		t.Fatal(err)
	}
	sink.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err = sink.ReadFromUDP(make([]byte, 256)); !os.IsTimeout(err) {
		t.Fatal("foreign allocated source reached kernel socket", err)
	}
	if err = p.writePacket(makeUDPPacket(clientIP, netip.MustParseAddr("10.44.0.1"), 17001, probePort, data)); err != nil {
		t.Fatal(err)
	}
	sink.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 256)
	count, from, err := sink.ReadFromUDP(buffer)
	if err != nil || !bytes.Equal(buffer[:count], data) || from.AddrPort().Addr() != clientIP {
		t.Fatal("legitimate source blocked", from, err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(time.Second); server.systemPeer(clientIP, 17) != nil; {
		if time.Now().After(until) {
			t.Fatal("disconnected client remained reachable")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err = net.InterfaceByName("lbms0"); err != nil {
		t.Fatal("one client closed the shared server interface", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = net.InterfaceByName("lbms0"); err == nil {
		t.Fatal("server interface leaked")
	}
}

func masqueSystemRoundtrip(t *testing.T, network, address string) {
	t.Helper()
	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		t.Fatal(network, address, err)
	}
	defer conn.Close()
	size := 14000
	if network == "tcp" {
		size = 70000
	}
	masqueSystemEcho(t, conn, size)
}

func masqueSystemEcho(t *testing.T, conn net.Conn, size int) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	want := bytes.Repeat([]byte{42}, size)
	if _, err := conn.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
		t.Fatal("system round trip", len(got), err)
	}
}

func masqueSystemFailureCleanup(t *testing.T) {
	endpoint := map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 1, "address": []string{"10.55.0.1/24"}, "system": true, "name": "lo"}
	raw, _ := json.Marshal(map[string]any{"endpoints": []any{endpoint}})
	r, err := New(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatal("accepted existing interface", err)
	}
	r.Close()
	masqueSystemCommand(t, "link", "show", "lo")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := shadowPort(port)
	endpoint["name"] = "lbrollback0"
	raw, _ = json.Marshal(map[string]any{"endpoints": []any{endpoint}, "inbounds": []Inbound{{Type: "socks", Listen: "127.0.0.1", ListenPort: n}}})
	r, err = New(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(); err == nil {
		t.Fatal("accepted occupied port")
	}
	r.Close()
	if _, err = net.InterfaceByName("lbrollback0"); err == nil {
		t.Fatal("start failure retained a system interface")
	}
}
