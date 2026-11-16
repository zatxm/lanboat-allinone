package native

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTUIC4Reference(t *testing.T) {
	testTUIC4ControllerReference(t, "")
}

func TestTUIC4BBRReference(t *testing.T) {
	testTUIC4ControllerReference(t, "bbr")
}

func testTUIC4ControllerReference(t *testing.T, algorithm string) {
	serverBinary := os.Getenv("LANBOAT_TEST_TUIC4")
	clientBinary := os.Getenv("LANBOAT_TEST_TUIC4_CLIENT")
	if serverBinary == "" || clientBinary == "" {
		t.Skip("TUIC4 official server and client required")
	}
	for _, mode := range []string{"native", "quic"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(mode+"/"+direction, func(t *testing.T) {
				options := certificate(t)
				pair, e := tls.X509KeyPair([]byte(strings.Join(options.Certificate, "\n")), []byte(strings.Join(options.Key, "\n")))
				if e != nil {
					t.Fatal(e)
				}
				ca, e := x509.ParseCertificate(pair.Certificate[0])
				if e != nil {
					t.Fatal(e)
				}
				leaf := &x509.Certificate{SerialNumber: big.NewInt(12345), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"example.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
				der, e := x509.CreateCertificate(rand.Reader, leaf, ca, pair.PrivateKey.(crypto.Signer).Public(), pair.PrivateKey)
				if e != nil {
					t.Fatal(e)
				}
				options.Certificate = append([]string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, options.Certificate...)
				cert := filepath.Join(t.TempDir(), "cert.pem")
				key := filepath.Join(t.TempDir(), "key.pem")
				caFile := filepath.Join(t.TempDir(), "ca.pem")
				os.WriteFile(caFile, []byte(options.Certificate[len(options.Certificate)-1]), 0600)
				os.WriteFile(cert, []byte(strings.Join(options.Certificate, "\n")), 0600)
				os.WriteFile(key, []byte(strings.Join(options.Key, "\n")), 0600)
				var client *Runtime
				if direction == "client" {
					port := unusedPort(t)
					cmd := exec.Command(serverBinary, "--ip", "127.0.0.1", "--port", strconv.Itoa(int(port)), "--token", "private", "--certificate", cert, "--private-key", key, "--alpn", "h3", "--max-udp-relay-packet-size", "65535")
					startTUIC4Reference(t, cmd, port, false)
					client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "tuic", Version: "4", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Token: "private", UDPRelayMode: mode, CongestionControl: algorithm, TLS: TLSOptions{Enabled: true, Insecure: true, ServerName: "example.com"}}}})
				} else {
					in := Inbound{Type: "tuic", Version: "4", Tag: "server", Listen: "127.0.0.1", TLS: options, Users: []User{{Token: "private"}}, CongestionControl: algorithm}
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					_, p, _ := net.SplitHostPort(server.Address("server"))
					port, _ := strconv.Atoi(p)
					localPort := unusedPort(t)
					cfg := map[string]any{"relay": map[string]any{"server": "example.com", "ip": "127.0.0.1", "port": port, "token": "private", "certificates": []string{caFile}, "alpn": []string{"h3"}, "udp_relay_mode": mode, "max_udp_relay_packet_size": 65535}, "local": map[string]any{"ip": "127.0.0.1", "port": localPort}}
					raw, _ := json.Marshal(cfg)
					path := filepath.Join(t.TempDir(), "client.json")
					os.WriteFile(path, raw, 0600)
					cmd := exec.Command(clientBinary, "-c", path)
					startTUIC4Reference(t, cmd, localPort, true)
					client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: localPort}}})
				}
				assertTCP(t, client)
				sizes := []int{1, 511, 4096}
				if mode == "native" {
					sizes = []int{1, 511}
				}
				assertUDPSizes(t, client, sizes)
			})
		}
	}
}
func startTUIC4Reference(t *testing.T, cmd *exec.Cmd, port uint16, tcp bool) {
	t.Helper()
	log, e := os.CreateTemp(t.TempDir(), "tuic4-log")
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stdout = log
	cmd.Stderr = log
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
	for range 300 {
		if tcp {
			c, e := net.DialTimeout("tcp", portAddress("127.0.0.1", port), time.Millisecond*10)
			if e == nil {
				c.Close()
				return
			}
		} else {
			p, e := net.ListenPacket("udp", portAddress("127.0.0.1", port))
			if e != nil {
				return
			}
			p.Close()
		}
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("TUIC4 reference not ready")
}
