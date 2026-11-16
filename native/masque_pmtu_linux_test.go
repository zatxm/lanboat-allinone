//go:build linux

package native

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestMasquePMTUNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_PMTU_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_PMTU_CHILD=1")
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("PMTU namespace: %v\n%s", err, b)
		}
		t.Log(string(b))
		return
	}
	masqueSystemCommand(t, "link", "set", "lo", "up")
	masqueSystemCommand(t, "link", "set", "lo", "mtu", "1280")
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			server := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": host, "version": 3, "initial_packet_size": 1200, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "tls": certificate(t)})
			_, port, _ := net.SplitHostPort(server.Address("server"))
			n, _ := shadowPort(port)
			client := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "version": 3, "disable_version_fallback": true, "initial_packet_size": 1200, "tls": TLSOptions{Enabled: true, Insecure: true}})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			p, err := client.masqueClients["proxy"].ipSession(ctx)
			if err != nil {
				t.Fatal(err)
			}
			maximum := 1252
			if host == "::1" {
				maximum = 1232
			}
			waitPMTU(t, p.flow.session.q, maximum-16, maximum)
			assertTCP(t, client)
			assertUDPAddress(t, client, []int{1, 1232, 4096, 60000}, masqueEcho(t, "udp", "127.0.0.1:0"))
			assertUDPAddress(t, client, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
			client.resetNetworkTransports()
			assertTCP(t, client)
		})
	}
}

func TestQUICSocketDF(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			p, err := net.ListenPacket(network, ":0")
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			wrapped := &ownedConn{Conn: &groupConn{Conn: &ownedConn{Conn: p.(*net.UDPConn)}}}
			if err = quicDontFragment(wrapped); err != nil {
				t.Fatal(err)
			}
			raw, err := p.(*net.UDPConn).SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var check error
			raw.Control(func(fd uintptr) {
				levels := [][2]int{{syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER}}
				if network == "udp6" {
					levels = append(levels, [2]int{syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER})
				}
				for _, v := range levels {
					n, e := syscall.GetsockoptInt(int(fd), v[0], v[1])
					if e != nil || n != syscall.IP_PMTUDISC_PROBE {
						check = fmt.Errorf("DF=%d error=%v", n, e)
					}
				}
			})
			if check != nil {
				t.Fatal(check)
			}
		})
	}
}

func TestMasquePMTUOfficial(t *testing.T) { testMasqueHTTPOfficial(t, false, true, true) }
