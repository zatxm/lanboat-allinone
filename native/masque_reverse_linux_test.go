//go:build linux

package native

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestMasqueReverseOfficial(t *testing.T) {
	if os.Getenv("LANBOAT_MASQUE_REVERSE_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_MASQUE_REVERSE_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated reverse interoperability: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	loop, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureLink(loop.Index, 65536); err != nil {
		t.Fatal(err)
	}

	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("native-client/%d", version), func(t *testing.T) {
			port, socksPort := unusedPort(t), unusedPort(t)
			endpoint := map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "listen_port": port, "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": certificate(t)}
			masqueOfficial(t, map[string]any{"log": map[string]any{"level": "debug"}, "endpoints": []any{endpoint}, "inbounds": []Inbound{{Type: "socks", Tag: "socks", Listen: "127.0.0.1", ListenPort: socksPort, Users: []User{{Username: "client", Password: "private"}}}}, "outbounds": []Outbound{{Type: "direct", Tag: "direct"}}, "route": Route{Final: "server", Rules: []Rule{{Inbound: []string{"server"}, Outbound: "direct"}}}}, portAddress("127.0.0.1", socksPort))
			masqueReverseRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "version": version, "disable_version_fallback": true, "username": "client", "password": "private", "advertise_routes": []string{"192.0.2.0/24", "2001:db8:44::/64"}, "tls": TLSOptions{Enabled: true, Insecure: true}}, Route{Final: "direct", Rules: []Rule{{Inbound: []string{"proxy"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}})
			probe := newTestRuntime(t, Config{Outbounds: []Outbound{testOutbound(t, Inbound{Type: "socks"}, portAddress("127.0.0.1", socksPort))}})
			masqueReverseOfficialTraffic(t, probe)
		})
		t.Run(fmt.Sprintf("native-server/%d", version), func(t *testing.T) {
			s := masqueReverseServer(t, version, false)
			host, port, _ := net.SplitHostPort(s.Address("server"))
			n, _ := shadowPort(port)
			socksPort := unusedPort(t)
			masqueOfficial(t, map[string]any{"log": map[string]any{"level": "debug"}, "endpoints": []any{map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "version": version, "disable_version_fallback": true, "username": "client", "password": "private", "advertise_routes": []string{"192.0.2.0/24", "2001:db8:44::/64"}, "tls": TLSOptions{Enabled: true, Insecure: true}}}, "inbounds": []Inbound{{Type: "socks", Tag: "socks", Listen: "127.0.0.1", ListenPort: socksPort, Users: []User{{Username: "client", Password: "private"}}}}, "outbounds": []Outbound{{Type: "direct", Tag: "direct"}}, "route": Route{Final: "direct", Rules: []Rule{{Inbound: []string{"proxy"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}}}, portAddress("127.0.0.1", socksPort))
			masqueWaitPeer(t, s, "192.0.2.42")
			masqueReverseOfficialTraffic(t, s)
		})
	}
}

func masqueReverseOfficialTraffic(t *testing.T, r *Runtime) {
	t.Helper()
	tcpTarget, udpTarget := relayEchoTCP(t), echoUDP(t)
	_, tcpPort, _ := net.SplitHostPort(tcpTarget)
	_, udpPort, _ := net.SplitHostPort(udpTarget)
	for _, host := range []string{"192.0.2.42", "2001:db8:44::42"} {
		var conn net.Conn
		var err error
		for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			conn, err = r.Dial(ctx, "tcp", net.JoinHostPort(host, tcpPort))
			cancel()
			if err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatal("reverse route unavailable", host, err)
		}
		masqueReverseRoundtrip(t, conn)
		assertUDPAddress(t, r, []int{1, 511, 4096, 14000}, net.JoinHostPort(host, udpPort))
	}
}
