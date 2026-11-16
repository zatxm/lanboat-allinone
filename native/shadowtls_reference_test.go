package native

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

func shadowReference(t *testing.T, cfg Config) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if binary == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required for external ShadowTLS interoperability")
	}
	cfg.Log.Disabled = true
	data, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	var document map[string]any
	json.Unmarshal(data, &document)
	for _, kind := range []string{"inbounds", "outbounds"} {
		if nodes, ok := document[kind].([]any); ok {
			for _, node := range nodes {
				n := node.(map[string]any)
				if n["type"] == "shadowtls" {
					version, _ := strconv.Atoi(n["version"].(string))
					n["version"] = version
				}
			}
		}
	}
	data, e = json.Marshal(document)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "shadowtls-reference.json")
	if e = os.WriteFile(path, data, 0600); e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(t.TempDir(), "reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "run", "-c", path)
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
	waitPort(t, portAddress("127.0.0.1", cfg.Inbounds[0].ListenPort))
}
func shadowReferencePair(t *testing.T, v int, tlsVersion uint16, side string, plugin bool, kind string, profiles ...string) *Runtime {
	t.Helper()
	h, security := shadowCover(t, tlsVersion)
	if len(profiles) != 0 {
		security.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profiles[0]}
	}
	inner := testInbound(t, kind)
	inner.Tag = "inner"
	inner.TLS = TLSOptions{}
	st := Inbound{Type: "shadowtls", Tag: "st", Listen: "127.0.0.1", ListenPort: unusedPort(t), Version: strconv.Itoa(v), Detour: "inner", ShadowTLSOptions: ShadowTLSOptions{Handshake: &h}}
	if v == 2 {
		st.Password = "outer-secret"
	}
	if v == 3 {
		st.Users = []User{{Name: "alice", Password: "outer-secret"}}
		st.StrictMode = tlsVersion == tls.VersionTLS13
	}
	var address string
	if side == "client" {
		shadowReference(t, Config{Inbounds: []Inbound{st, inner}})
		address = portAddress(st.Listen, st.ListenPort)
	} else {
		var s *Runtime
		if plugin {
			pass := ""
			if v > 1 {
				pass = ";password=outer-secret"
			}
			inner.Plugin = "shadow-tls"
			inner.PluginOpts = fmt.Sprintf("version=%d%s;handshake=%s", v, pass, portAddress(h.Server, h.ServerPort))
			s = newTestRuntime(t, Config{Inbounds: []Inbound{inner}})
			address = s.Address("inner")
		} else {
			s = newTestRuntime(t, Config{Inbounds: []Inbound{st, inner}})
			address = s.Address("st")
		}
	}
	host, text, _ := net.SplitHostPort(address)
	port, _ := shadowPort(text)
	outer := Outbound{Type: "shadowtls", Tag: "outer", Server: host, ServerPort: port, Version: strconv.Itoa(v), TLS: security}
	if v > 1 {
		outer.Password = "outer-secret"
	}
	target := Outbound{Type: kind, Tag: "proxy", Server: host, ServerPort: port, Method: inner.Method, Password: inner.Password, Detour: "outer"}
	if kind == "vless" || kind == "vmess" {
		target.UUID = testUUID
	}
	if side == "client" {
		if plugin {
			target.Detour = ""
			target.TLS = security
			pass := ""
			if v > 1 {
				pass = ";password=outer-secret"
			}
			target.Plugin = "shadow-tls"
			target.PluginOpts = fmt.Sprintf("version=%d%s;host=example.com", v, pass)
			return newTestRuntime(t, Config{Outbounds: []Outbound{target}})
		}
		return newTestRuntime(t, Config{Outbounds: []Outbound{target, outer}})
	}
	socks := Inbound{Type: "socks", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
	shadowReference(t, Config{Inbounds: []Inbound{socks}, Outbounds: []Outbound{target, outer}})
	return newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: socks.ListenPort}}})
}
func TestShadowTLSOfficial(t *testing.T) {
	for _, v := range []int{1, 2, 3} {
		for _, tlsVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			if v == 1 && tlsVersion == tls.VersionTLS13 {
				continue
			}
			for _, side := range []string{"client", "server"} {
				for _, plugin := range []bool{false, true} {
					t.Run(fmt.Sprintf("v%d/tls%d/%s/plugin%v", v, tlsVersion, side, plugin), func(t *testing.T) {
						c := shadowReferencePair(t, v, tlsVersion, side, plugin, "shadowsocks")
						assertTCP(t, c)
						assertTCP(t, c)
					})
				}
			}
		}
	}
}
func TestShadowTLSOfficialUDP(t *testing.T) {
	for _, v := range []int{1, 2, 3} {
		for _, side := range []string{"client", "server"} {
			t.Run(fmt.Sprintf("v%d/%s", v, side), func(t *testing.T) {
				ver := uint16(tls.VersionTLS13)
				if v == 1 {
					ver = tls.VersionTLS12
				}
				c := shadowReferencePair(t, v, ver, side, false, "vless")
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 511, 4096})
			})
		}
	}
}
