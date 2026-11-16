//go:build linux

package native

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func masqueOfficial(t *testing.T, document map[string]any, address string) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required for MASQUE HTTP interoperability")
	}
	data, e := json.Marshal(document)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "reference.json")
	if e = os.WriteFile(config, data, 0600); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.Command(binary, "check", "-c", config).CombinedOutput(); e != nil {
		t.Fatalf("reference config: %v %s", e, out)
	}
	log, e := os.Create(filepath.Join(dir, "reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "run", "-c", config)
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	})
	waitPort(t, address)
}
func TestMasqueHTTPOfficial(t *testing.T) {
	testMasqueHTTPOfficial(t, false)
}

func TestMasqueCleartextOfficial(t *testing.T) {
	testMasqueHTTPOfficial(t, true)
}

func TestMasqueConnectionOfficial(t *testing.T) {
	testMasqueHTTPOfficial(t, false, true)
}

func testMasqueHTTPOfficial(t *testing.T, cleartext bool, tune ...bool) {
	tuning := len(tune) != 0 && tune[0]
	pmtu := len(tune) > 1 && tune[1]
	nat := len(tune) > 2 && tune[2]
	settings := func(ep map[string]any) map[string]any {
		if tuning {
			ep["idle_timeout"], ep["keep_alive_period"] = "3s", "100ms"
			ep["stream_receive_window"], ep["connection_receive_window"] = "512KB", "2MB"
			ep["max_concurrent_streams"] = 8
		}
		if pmtu {
			// The reference CONNECT-IP implementation requires room for an
			// IPv6-minimum packet before its asynchronous MTU discovery runs.
			ep["initial_packet_size"], ep["disable_path_mtu_discovery"] = 1400, false
		}
		if nat {
			ep["udp_timeout"], ep["udp_nat_max"] = "1m", 16
			ep["udp_mapping"], ep["udp_filtering"] = "address_and_port_dependent", "address_and_port_dependent"
		}
		return ep
	}
	if os.Getenv("LANBOAT_MASQUE_HTTP_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "LANBOAT_MASQUE_HTTP_CHILD=1")
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("isolated MASQUE HTTP: %v\n%s", e, out)
		} else {
			t.Log(string(out))
		}
		return
	}
	loop, e := net.InterfaceByName("lo")
	if e != nil {
		t.Fatal(e)
	}
	if e = configureLink(loop.Index, 65536); e != nil {
		t.Fatal(e)
	}
	for _, address := range []string{"192.0.2.1/32", "fd00:44::1/128"} {
		if out, e := exec.Command("ip", "addr", "add", address, "dev", "lo").CombinedOutput(); e != nil {
			t.Fatalf("fixture IP: %v %s", e, out)
		}
	}

	versionsToTest := []int{1, 2}
	if tuning {
		versionsToTest = []int{2, 3}
	}
	if pmtu {
		versionsToTest = []int{3}
	}
	for _, version := range versionsToTest {
		t.Run(fmt.Sprintf("native-client/%d", version), func(t *testing.T) {
			tls := TLSOptions{}
			if !cleartext {
				tls = certificate(t)
			}
			port := unusedPort(t)
			endpoint := map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "listen_port": port, "version": []int{version}, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": tls}
			if version == 3 {
				endpoint["version"] = []int{2, 3}
			}
			masqueOfficial(t, map[string]any{"log": map[string]any{"level": "debug"}, "endpoints": []any{settings(endpoint)}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}, portAddress("127.0.0.1", port))
			clientVersion := 3
			if cleartext || tuning {
				clientVersion = version
			}
			c := masqueEndpointRuntime(t, settings(map[string]any{"type": "masque-client", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "username": "client", "password": "private", "version": clientVersion, "disable_version_fallback": tuning, "tls": TLSOptions{Enabled: !cleartext, Insecure: !cleartext}}))
			if pmtu {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				p, err := c.masqueClients["proxy"].ipSession(ctx)
				if err != nil {
					t.Fatal(err)
				}
				maximum := min(1472, int(p.flow.session.q.peer.maxUDPPayload))
				waitPMTU(t, p.flow.session.q, maximum, maximum)
			}
			if nat {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				p, err := c.masqueClients["proxy"].ipSession(ctx)
				if err != nil {
					t.Fatal(err)
				}
				natWireCheck(t, p, "address_and_port_dependent", "address_and_port_dependent", "192.0.2.1", 14000)
			}
			target := masqueEcho(t, "tcp", "192.0.2.1:0")
			var conn net.Conn
			var err error
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
				conn, err = c.Dial(context.Background(), "tcp", target)
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
			assertUDPAddress(t, c, []int{1, 511, 4096, 14000}, masqueEcho(t, "udp", "192.0.2.1:0"))
			conn, err = c.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "[fd00:44::1]:0"))
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
			assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[fd00:44::1]:0"))
		})
		serverCase := fmt.Sprintf("native-server/%d", version)
		if cleartext && version == 2 {
			serverCase = "reference-strict-http2-client-capability"
		}
		t.Run(serverCase, func(t *testing.T) {
			if cleartext && version == 2 {
				// The pinned upstream client rejects this mode before opening a socket.
				binary := os.Getenv("LANBOAT_TEST_SINGBOX15")
				path := filepath.Join(t.TempDir(), "unsupported-http2-client.json")
				data := []byte(`{"endpoints":[{"type":"masque-client","server":"127.0.0.1","server_port":443,"version":2,"disable_version_fallback":true}]}`)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command(binary, "check", "-c", path).CombinedOutput()
				if err == nil || !strings.Contains(string(out), "HTTP/2 requires TLS") {
					t.Fatal("reference capability changed; add live HTTP2 client interoperability", err, string(out))
				}
				t.Log("Reference HTTP2 cleartext client unsupported;this is a capability check,not live interoperability")
				return
			}
			tls := TLSOptions{}
			versions := []int{1, 2}
			if !cleartext {
				tls = certificate(t)
				versions = append(versions, 3)
			}
			s := masqueEndpointRuntime(t, settings(map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": versions, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": tls}))
			host, p, _ := net.SplitHostPort(s.Address("server"))
			port, _ := shadowPort(p)
			local := unusedPort(t)
			endpoint := map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": port, "username": "client", "password": "private", "version": version, "disable_version_fallback": true, "tls": TLSOptions{Enabled: !cleartext, Insecure: !cleartext}}
			masqueOfficial(t, map[string]any{"log": map[string]any{"level": "debug"}, "endpoints": []any{settings(endpoint)}, "inbounds": []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": local}}, "route": map[string]any{"final": "proxy"}}, portAddress("127.0.0.1", local))
			c := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: local}}})
			target := masqueEcho(t, "tcp", "192.0.2.1:0")
			var conn net.Conn
			var err error
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
				conn, err = c.Dial(context.Background(), "tcp", target)
				if err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
			assertUDPAddress(t, c, []int{1, 511, 4096, 14000}, masqueEcho(t, "udp", "192.0.2.1:0"))
			conn, err = c.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "[fd00:44::1]:0"))
			if err != nil {
				t.Fatal(err)
			}
			wgRoundtripTCP(t, conn)
			assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[fd00:44::1]:0"))
		})
	}
}

func TestMasqueNATOfficial(t *testing.T) { testMasqueHTTPOfficial(t, false, true, false, true) }
