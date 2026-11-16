package native

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startTrustReference(t *testing.T, env string, args ...string) {
	t.Helper()
	binary := os.Getenv(env)
	if binary == "" {
		t.Skip(env + " required for official TrustTunnel interoperability")
	}
	log, e := os.Create(filepath.Join(t.TempDir(), "trust.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		_ = cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	})
}
func trustReferenceFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if e := os.WriteFile(path, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
	return path
}
func TestTrustTunnelOfficialReference(t *testing.T) {
	for _, version := range []int{2, 3} {
		for _, direction := range []string{"client", "server"} {
			t.Run(fmt.Sprintf("http%d/%s", version, direction), func(t *testing.T) {
				f := newMutualTLSFixture(t)
				dir := t.TempDir()
				serverTLS := f.server()
				serverTLS.ClientAuthentication = ""
				serverTLS.ClientCertificate = nil
				in := Inbound{Type: "trusttunnel", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, TLS: serverTLS, Users: []User{{Username: "client", Password: "private"}}}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					startTrustEndpoint(t, f, in, false)
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = f.client()
					out.TLS.ClientCertificate = nil
					out.TLS.ClientKey = nil
					out.HTTPVersion = version
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					address := portAddress("127.0.0.1", unusedPort(t))
					config := trustReferenceFile(t, dir, "client.toml", fmt.Sprintf("loglevel = \"debug\"\nvpn_mode = \"general\"\nkillswitch_enabled = true\npost_quantum_group_enabled = false\nexclusions = []\n[endpoint]\nhostname = \"example.com\"\naddresses = [%q]\nusername = \"client\"\npassword = \"private\"\nskip_verification = false\ncertificate = '''%s'''\nupstream_protocol = \"http%d\"\ntls_profile = \"default\"\nhas_ipv6 = true\ndns_upstreams = [\"1.1.1.1\"]\n[listener.socks]\naddress = %q\n", server.Address("server"), f.ca, version, address))
					startTrustReference(t, "LANBOAT_TEST_TRUST_CLIENT", "-c", config)
					waitPort(t, address)
					out := testOutbound(t, Inbound{Type: "socks"}, address)
					out.Username, out.Password = "", ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
				if direction == "client" {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					check, e := client.trustClients["proxy"].connect(ctx, "_check")
					if e != nil {
						t.Fatal(e)
					}
					check.Close()
					o := client.config.Outbounds[0]
					o.Password = "bad"
					bad := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
					c, e := bad.Dial(ctx, "tcp", "127.0.0.1:1")
					if e == nil {
						c.Close()
						t.Fatal("bad authentication accepted")
					}
				}
			})
		}
	}
}
func TestTrustTunnelValidation(t *testing.T) {
	good := `{"outbounds":[{"type":"trusttunnel","tag":"proxy","server":"example.com","server_port":443,"username":"a","password":"b","tls":{"enabled":true}}]}`
	if _, e := Parse([]byte(good)); e != nil {
		t.Fatal(e)
	}
	for _, change := range [][2]string{{`"enabled":true`, `"enabled":false`}, {`"username":"a"`, `"username":""`}, {`"username":"a"`, `"username":"a:b"`}, {`"enabled":true`, `"enabled":true,"disable_sni":true`}, {`"tls":`, `"http_version":1,"tls":`}, {`"tls":`, `"http_version":3,"tls":`}} {
		data := strings.Replace(good, change[0], change[1], 1)
		if change[1] == `"http_version":3,"tls":` {
			data = strings.Replace(data, `"enabled":true`, `"enabled":true,"max_version":"1.2"`, 1)
		}
		if _, e := Parse([]byte(data)); e == nil {
			t.Fatal("invalid TrustTunnel config", data)
		}
	}
}

func startTrustEndpoint(t *testing.T, f mutualTLSFixture, in Inbound, icmp bool) {
	t.Helper()
	dir := t.TempDir()
	cp := trustReferenceFile(t, dir, "cert.pem", f.serverCert)
	kp := trustReferenceFile(t, dir, "key.pem", f.serverKey)
	credentials := trustReferenceFile(t, dir, "credentials.toml", "[[client]]\nusername = \"client\"\npassword = \"private\"\n")
	hosts := trustReferenceFile(t, dir, "hosts.toml", fmt.Sprintf("[[main_hosts]]\nhostname = \"example.com\"\ncert_chain_path = %q\nprivate_key_path = %q\n", cp, kp))
	text := fmt.Sprintf("listen_address = %q\nallow_private_network_connections = true\nipv6_available = true\ncredentials_file = %q\n[listen_protocols.http2]\n[listen_protocols.quic]\n", portAddress(in.Listen, in.ListenPort), credentials)
	if icmp {
		text += "[icmp]\ninterface_name = \"lo\"\n"
	}
	config := trustReferenceFile(t, dir, "vpn.toml", text)
	startTrustReference(t, "LANBOAT_TEST_TRUST_SERVER", config, hosts, "--jobs", "2")
	waitPort(t, portAddress(in.Listen, in.ListenPort))
}
