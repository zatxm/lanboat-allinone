//go:build linux

package native

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

func shadowRust(t *testing.T, args []string, trust TLSOptions, port uint16) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_SHADOWTLS")
	if binary == "" {
		t.Skip("LANBOAT_TEST_SHADOWTLS required for official Rust ShadowTLS interoperability")
	}
	if slices.Contains(args, "client") {
		binary = filepath.Join(filepath.Dir(binary), "shadow-tls-test-ca")
		if _, e := os.Stat(binary); e != nil {
			t.Fatal("build the test-CA Rust reference first", e)
		}
	}
	dir := t.TempDir()
	log, e := os.Create(filepath.Join(dir, "shadowtls.log"))
	if e != nil {
		t.Fatal(e)
	}
	cert := filepath.Join(dir, "ca.pem")
	if e = os.WriteFile(cert, func() []byte { block, _ := pem.Decode([]byte(trust.Certificate[0])); return block.Bytes }(), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, append([]string{"--threads", "1"}, args...)...)
	cmd.Env = append(os.Environ(), "LANBOAT_TEST_SHADOWTLS_CA_DER="+cert)
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
	waitPort(t, portAddress("127.0.0.1", port))
}
func TestShadowTLSRust(t *testing.T) {
	for _, v := range []int{2, 3} {
		for _, side := range []string{"client", "server"} {
			for _, kind := range []string{"shadowsocks", "vless"} {
				t.Run(fmt.Sprintf("v%d/%s/%s", v, side, kind), func(t *testing.T) {
					h, security := shadowCover(t, tls.VersionTLS13)
					inner := testInbound(t, kind)
					inner.Tag = "inner"
					inner.TLS = TLSOptions{}
					port := unusedPort(t)
					address := portAddress("127.0.0.1", port)
					prefix := []string{}
					if v == 3 {
						prefix = append(prefix, "--v3", "--strict")
					}
					var c *Runtime
					if side == "client" {
						s := newTestRuntime(t, Config{Inbounds: []Inbound{inner}})
						shadowRust(t, append(prefix, "server", "--listen", address, "--server", s.Address("inner"), "--tls", portAddress(h.Server, h.ServerPort), "--password", "outer-secret"), security, port)
						o := testOutbound(t, inner, address)
						o.TLS = TLSOptions{}
						o.Detour = "outer"
						outer := Outbound{Type: "shadowtls", Tag: "outer", Version: strconv.Itoa(v), Server: "127.0.0.1", ServerPort: port, Password: "outer-secret", TLS: security}
						c = newTestRuntime(t, Config{Outbounds: []Outbound{o, outer}})
					} else {
						st := Inbound{Type: "shadowtls", Tag: "st", Version: strconv.Itoa(v), Detour: "inner", Password: "outer-secret", ShadowTLSOptions: ShadowTLSOptions{Handshake: &h, StrictMode: v == 3}}
						if v == 3 {
							st.Password = ""
							st.Users = []User{{Password: "outer-secret"}}
						}
						s := newTestRuntime(t, Config{Inbounds: []Inbound{st, inner}})
						shadowRust(t, append(prefix, "client", "--listen", address, "--server", s.Address("st"), "--sni", "example.com", "--password", "outer-secret"), security, port)
						o := testOutbound(t, inner, address)
						o.TLS = TLSOptions{}
						c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
					}
					assertTCP(t, c)
					if kind == "vless" {
						assertUDPSizes(t, c, []int{1, 511, 4096, 60000})
					}
					assertTCP(t, c)
				})
			}
		}
	}
}

func TestShadowTLSBrowserRust(t *testing.T) {
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		for _, v := range []int{2, 3} {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				for _, kind := range []string{"shadowsocks", "vless"} {
					t.Run(fmt.Sprintf("%s/v%d/TLS%x/%s", profile, v, version, kind), func(t *testing.T) {
						h, security := shadowCover(t, version)
						security.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
						inner := testInbound(t, kind)
						inner.Tag, inner.TLS = "inner", TLSOptions{}
						s := newTestRuntime(t, Config{Inbounds: []Inbound{inner}})
						port := unusedPort(t)
						address := portAddress("127.0.0.1", port)
						var prefix []string
						if v == 3 {
							prefix = append(prefix, "--v3")
							if version == tls.VersionTLS13 {
								prefix = append(prefix, "--strict")
							}
						}
						shadowRust(t, append(prefix, "server", "--listen", address, "--server", s.Address("inner"), "--tls", portAddress(h.Server, h.ServerPort), "--password", "outer-secret"), security, port)
						o := testOutbound(t, inner, address)
						o.TLS, o.Detour = TLSOptions{}, "outer"
						outer := Outbound{Type: "shadowtls", Tag: "outer", Version: strconv.Itoa(v), Server: "127.0.0.1", ServerPort: port, Password: "outer-secret", TLS: security}
						c := newTestRuntime(t, Config{Outbounds: []Outbound{o, outer}})
						assertTCP(t, c)
						if kind == "vless" {
							assertUDPSizes(t, c, []int{1, 511, 4096, 60000})
						}
						assertTCP(t, c)
					})
				}
			}
		}
	}
}
