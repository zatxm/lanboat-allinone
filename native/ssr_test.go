package native

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSRIndependentMatrix(t *testing.T) {
	for _, protocol := range SSRProtocols() {
		for _, obfs := range SSRObfuscations() {
			t.Run(protocol+"/"+obfs, func(t *testing.T) {
				in := Inbound{Type: "shadowsocksr", Tag: "server", Listen: "127.0.0.1", Method: "aes-256-cfb", Password: "private", Protocol: protocol, Obfs: Obfuscation(obfs), ObfsParam: "example.com"}
				if strings.HasPrefix(protocol, "auth_aes128_") || strings.HasPrefix(protocol, "auth_chain_") {
					in.ProtocolParam = "123:private-user"
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Obfs = Obfuscation(obfs)
				out.ObfsParam = "example.com"
				out.Protocol = protocol
				out.ProtocolParam = in.ProtocolParam
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func startSSRReference(t *testing.T, config map[string]any, local bool) {
	t.Helper()
	reference := os.Getenv("LANBOAT_TEST_SSR")
	ota := config["protocol"] == "verify_sha1"
	if ota {
		reference = os.Getenv("LANBOAT_TEST_SS_OTA")
		config["one_time_auth"] = true
		delete(config, "protocol")
	}
	if reference == "" {
		if ota {
			t.Fatal("LANBOAT_TEST_SS_OTA required for official Shadowsocks2.9.1 OTA interoperability")
		}
		t.Skip("LANBOAT_TEST_SSR required for Python SSR interoperability")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	module := "server"
	if local {
		module = "local"
	}
	boot := "import sys,collections,collections.abc,ctypes,ctypes.util; collections.MutableMapping=collections.abc.MutableMapping; crypto=ctypes.CDLL(ctypes.util.find_library('crypto')); crypto.OSSL_PROVIDER_load.restype=ctypes.c_void_p; crypto.OSSL_PROVIDER_load.argtypes=[ctypes.c_void_p,ctypes.c_char_p]; providers=[crypto.OSSL_PROVIDER_load(None,n) for n in [b'default',b'legacy']]; sys.path.insert(0,sys.argv.pop(1)); "
	if ota {
		// Adapt the removed OpenSSL cleanup symbol, leaving OTA framing unchanged.
		boot += "from shadowsocks.crypto import util; crypto.EVP_CIPHER_CTX_cleanup=crypto.EVP_CIPHER_CTX_reset; util.find_library=lambda *a:crypto; "
	}
	boot += "from shadowsocks." + module + " import main; main()"
	log, err := os.Create(filepath.Join(t.TempDir(), "reference.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", boot, reference, "-c", path)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
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
}
func TestSSRPythonReference(t *testing.T) {
	for _, protocol := range []string{"origin", "verify_deflate", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"} {
		for _, obfs := range SSRObfuscations() {
			for _, direction := range []string{"client", "server"} {
				t.Run(protocol+"/"+obfs+"/"+direction, func(t *testing.T) {
					port := unusedPort(t)
					cfg := map[string]any{"server": "127.0.0.1", "server_port": port, "password": "private", "method": "aes-256-cfb", "protocol": protocol, "obfs": obfs, "obfs_param": "example.com", "timeout": 30, "dns_ipv6": false, "forbidden_ip": "", "forbidden_port": ""}
					var client *Runtime
					if direction == "client" {
						startSSRReference(t, cfg, false)
						waitPort(t, portAddress("127.0.0.1", port))
						client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "shadowsocksr", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Password: "private", Method: "aes-256-cfb", Protocol: protocol, Obfs: Obfuscation(obfs), ObfsParam: "example.com"}}})
					} else {
						in := Inbound{Type: "shadowsocksr", Tag: "server", Listen: "127.0.0.1", Password: "private", Method: "aes-256-cfb", Protocol: protocol, Obfs: Obfuscation(obfs), ObfsParam: "example.com"}
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						_, actualPort, _ := net.SplitHostPort(server.Address("server"))
						port = unusedPort(t)
						cfg["server_port"] = json.Number(actualPort)
						cfg["local_address"] = "127.0.0.1"
						cfg["local_port"] = port
						startSSRReference(t, cfg, true)
						waitPort(t, portAddress("127.0.0.1", port))
						client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: port}}})
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 511, 4096})
				})
			}
		}
	}
}
