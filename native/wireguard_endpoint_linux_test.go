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
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWireGuardEndpointKernelNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_WG_ENDPOINT_NAMESPACE") != "1" {
		path, err := exec.LookPath("wg")
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		reference := filepath.Join(t.TempDir(), "wg-reference")
		if err := os.WriteFile(reference, data, 0700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestWireGuardEndpointKernelNamespace$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_WG_ENDPOINT_NAMESPACE=1", "LANBOAT_TEST_WG="+reference)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("WireGuard endpoint namespace: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	runWGTest(t, "ip", "link", "set", "lo", "up")
	for _, mode := range []string{"kernel-server", "kernel-client", "system"} {
		t.Run(mode, func(t *testing.T) { wgEndpointKernelMode(t, mode) })
	}
}

func wgEndpointKernelMode(t *testing.T, mode string) {
	key, pub := wgTestKey(t)
	otherKey, otherPub := wgTestKey(t)
	psk, _ := wgTestKey(t)
	dir := t.TempDir()
	keyFile, pskFile := filepath.Join(dir, "key"), filepath.Join(dir, "psk")
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pskFile, []byte(psk), 0600); err != nil {
		t.Fatal(err)
	}
	runWGTest(t, "ip", "link", "add", "lbwgref", "type", "wireguard")
	defer exec.Command("ip", "link", "del", "lbwgref").Run()
	runWGTest(t, "ip", "addr", "add", "10.55.0.1/24", "dev", "lbwgref")
	runWGTest(t, "ip", "-6", "addr", "add", "fd55::1/64", "dev", "lbwgref", "nodad")
	runWGTest(t, "ip", "link", "set", "lbwgref", "up")
	port := unusedPort(t)
	runWGTest(t, "wg", "set", "lbwgref", "listen-port", strconv.Itoa(int(port)), "private-key", keyFile, "peer", otherPub, "preshared-key", pskFile, "allowed-ips", "10.55.0.2/32,fd55::2/128")
	ep := wgEndpointOptions{Tag: "proxy", PrivateKey: []string{otherKey}, Address: []string{"10.55.0.2/32", "fd55::2/128"}, Workers: 2, Peers: []WireGuardPeer{{Address: "127.0.0.1", Port: port, PublicKey: pub, PreSharedKey: psk, AllowedIPs: []string{"10.55.0.1/32", "fd55::1/128"}}}}
	if mode == "kernel-server" {
		c := wgEndpointRuntime(t, ep, Config{})
		for _, ip := range []string{"10.55.0.1", "fd55::1"} {
			tcp, udp := wgEndpointEcho(t, ip)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err := c.Dial(ctx, "tcp", tcp)
			cancel()
			if err != nil {
				t.Fatal(ip, err)
			}
			wgRoundtripTCP(t, conn)
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			conn, err = c.Dial(ctx, "udp", udp)
			cancel()
			if err != nil {
				t.Fatal(ip, err)
			}
			wgRoundtripUDP(t, conn)
		}
	} else if mode == "kernel-client" {
		ep.Tag = "server"
		ep.Peers[0].Address = ""
		ep.Peers[0].Port = 0
		originTCP, originUDP := wgEndpointEcho(t, "127.0.0.1")
		_, tcpPort, _ := net.SplitHostPort(originTCP)
		tcpPN, _ := strconv.Atoi(tcpPort)
		_, udpPort, _ := net.SplitHostPort(originUDP)
		udpPN, _ := strconv.Atoi(udpPort)
		s := wgEndpointRuntime(t, ep, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct", Rules: []Rule{{Network: []string{"tcp"}, OverrideAddress: "127.0.0.1", OverridePort: uint16(tcpPN), Outbound: "direct"}, {Network: []string{"udp"}, OverrideAddress: "127.0.0.1", OverridePort: uint16(udpPN), Outbound: "direct"}}}})
		_, epPort, _ := net.SplitHostPort(s.Address("server"))
		runWGTest(t, "wg", "set", "lbwgref", "peer", otherPub, "endpoint", net.JoinHostPort("127.0.0.1", epPort))
		for _, ip := range []string{"10.55.0.2", "fd55::2"} {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, tcpPort), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
			conn, err = net.DialTimeout("udp", net.JoinHostPort(ip, udpPort), 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripUDP(t, conn)
		}
	} else {
		ep.System = true
		ep.Name = "lbwge0"
		ep.Address = []string{"10.55.0.2/32"}
		ep.Peers[0].AllowedIPs = []string{"10.55.0.1/32"}
		c := wgEndpointRuntime(t, ep, Config{})
		// These private policy tables force local test sockets through both tunnel ends.
		runWGTest(t, "ip", "rule", "del", "pref", "0", "lookup", "local")
		defer exec.Command("ip", "rule", "add", "pref", "0", "lookup", "local").Run()
		runWGTest(t, "ip", "rule", "add", "pref", "10", "lookup", "local")
		defer exec.Command("ip", "rule", "del", "pref", "10", "lookup", "local").Run()
		for _, args := range [][]string{{"rule", "add", "pref", "1", "iif", "lo", "from", "10.55.0.2/32", "to", "10.55.0.1/32", "lookup", "100"}, {"route", "add", "table", "100", "10.55.0.1/32", "dev", "lbwge0"}, {"rule", "add", "pref", "2", "iif", "lo", "from", "10.55.0.1/32", "to", "10.55.0.2/32", "lookup", "101"}, {"route", "add", "table", "101", "10.55.0.2/32", "dev", "lbwgref"}} {
			runWGTest(t, "ip", args...)
		}
		defer exec.Command("ip", "rule", "del", "pref", "1").Run()
		defer exec.Command("ip", "rule", "del", "pref", "2").Run()
		tcp, udp := wgEndpointEcho(t, "10.55.0.1")
		for _, network := range []string{"tcp", "udp"} {
			address := tcp
			if network == "udp" {
				address = udp
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			if network == "tcp" {
				dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP("10.55.0.2")}
			} else {
				dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP("10.55.0.2")}
			}
			conn, err := dialer.DialContext(context.Background(), network, address)
			if err != nil {
				t.Fatal("host socket", err)
			}
			if network == "tcp" {
				wgRoundtripTCP(t, conn)
			} else {
				wgRoundtripUDP(t, conn)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			conn, err = c.Dial(ctx, network, address)
			cancel()
			if err != nil {
				t.Fatal("core API socket", err)
			}
			if network == "tcp" {
				wgRoundtripTCP(t, conn)
			} else {
				wgRoundtripUDP(t, conn)
			}
		}
		request := []byte{8, 0, 0, 0, 0, 7, 0, 1, 'w', 'g'}
		binary.BigEndian.PutUint16(request[2:], checksum(request, 0))
		peer, err := c.wireGuardSession(context.Background(), "proxy", netip.MustParseAddr("10.55.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		reply, err := peer.stack.exchangeICMP(ctx, netip.MustParseAddr("10.55.0.1"), request, 64)
		cancel()
		if err != nil || len(reply.data) < 8 || reply.data[0] != 0 {
			t.Fatal("endpoint ICMP", reply, err)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := net.InterfaceByName("lbwge0"); err == nil {
			t.Fatal("system interface leaked after Close")
		}
	}
	out, err := exec.Command("wg", "show", "lbwgref", "latest-handshakes").CombinedOutput()
	if err != nil || strings.HasSuffix(strings.TrimSpace(string(out)), "\t0") {
		t.Fatal("kernel did not authenticate endpoint", string(out), err)
	}
}

func wgEndpointEcho(t *testing.T, ip string) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	udp, err := net.ListenPacket("udp", net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	udp.(*net.UDPConn).SetReadBuffer(1 << 20)
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			udp.WriteTo(buffer[:n], peer)
		}
	}()
	return tcp.Addr().String(), udp.LocalAddr().String()
}

func TestWireGuardEndpointUDPFragmentsRepeated(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.44.0.2/32"}}}}}}})
	_, port, _ := net.SplitHostPort(s.Address("server"))
	pn, _ := strconv.Atoi(port)
	c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "proxy", PrivateKey: []string{clientKey}, Address: []string{"10.44.0.2/32"}, Workers: 1, Peers: []WireGuardPeer{{Address: "127.0.0.1", Port: uint16(pn), PublicKey: serverPub, AllowedIPs: []string{"0.0.0.0/0"}}}}, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := c.Dial(ctx, "udp", echoUDP(t))
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for range 20 {
		payload := bytes.Repeat([]byte{0x57}, 60000)
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 65535)
		n, err := conn.Read(reply)
		if err != nil || !bytes.Equal(reply[:n], payload) {
			t.Fatal(n, err)
		}
	}
}
