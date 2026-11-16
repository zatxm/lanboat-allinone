//go:build linux

package native

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"
	"testing"
	"time"
)

func TestOpenConnectDTLSGnuTLSCipherReference(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		modes := []bool{true}
		if ocDTLSIsCBC(spec.id) {
			modes = append(modes, false)
		}
		for _, etm := range modes {
			name := spec.name
			if ocDTLSIsCBC(spec.id) {
				if etm {
					name += "/EtM"
				} else {
					name += "/MtE"
				}
			}
			t.Run(name, func(t *testing.T) {
				cipherName := map[uint16]string{0xa8: "AES-128-GCM", 0xa9: "AES-256-GCM", 0xccab: "CHACHA20-POLY1305", 0xc0a4: "AES-128-CCM", 0xc0a5: "AES-256-CCM", 0xc0a8: "AES-128-CCM-8", 0xc0a9: "AES-256-CCM-8", 0x8c: "AES-128-CBC", 0x8d: "AES-256-CBC", 0xae: "AES-128-CBC", 0xaf: "AES-256-CBC"}[spec.id]
				macName := "AEAD"
				if spec.id == 0x8c || spec.id == 0x8d {
					macName = "SHA1"
				}
				if spec.id == 0xae {
					macName = "SHA256"
				}
				if spec.id == 0xaf {
					macName = "SHA384"
				}
				r := newTestRuntime(t, Config{})
				packet, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				listener := newOCDTLSListener(r, packet)
				listener.suites = []uint16{spec.id}
				left, right := net.Pipe()
				tunnel := newOCTunnel(r, left, "server", []netip.Addr{netip.MustParseAddr("10.44.0.2"), netip.MustParseAddr("fd44::2")}, 16376, "client", time.Hour)
				tunnel.dtlsMTU = 16376
				psk, id := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
				tunnel.conn = &ocTestTLSExporter{Conn: left, psk: bytes.Clone(psk)}
				listener.bindings[string(id)] = &ocDTLSBinding{tunnel: tunnel}
				done := make(chan struct{})
				go func() { listener.run(); close(done) }()
				tunnel.start()
				t.Cleanup(func() { tunnel.close(); right.Close(); packet.Close(); <-done; <-tunnel.finished })
				packets := []string{hex.EncodeToString([]byte{3, 1, 2, 3})}
				var expected [][]byte
				for family, address := range []string{echoUDP(t), masqueEcho(t, "udp", "[::1]:0")} {
					remote, err := net.ResolveUDPAddr("udp", address)
					if err != nil {
						t.Fatal(err)
					}
					for _, size := range []int{0, 1, 511, 4096, 14000} {
						payload := bytes.Repeat([]byte{byte(size)}, size)
						ip := makeUDPPacket(tunnel.local[family], remote.AddrPort().Addr(), 54321, uint16(remote.Port), payload)
						packets = append(packets, hex.EncodeToString(append([]byte{0}, ip...)))
						expected = append(expected, payload)
					}
				}
				input, _ := json.Marshal(map[string]any{"port": packet.LocalAddr().(*net.UDPAddr).Port, "cipher": cipherName, "mac": macName, "disable_etm": !etm, "psk": hex.EncodeToString(psk), "app_id": hex.EncodeToString(id), "packets": packets})
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "python3", "../tests/openconnect-dtls-reference.py")
				cmd.Stdin = bytes.NewReader(input)
				output, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("public GnuTLS reference: %v %s", err, output)
				}
				var result struct {
					Cipher  string
					MAC     string
					EtM     bool
					Version string
					Replies []string
				}
				if err = json.Unmarshal(output, &result); err != nil || result.Cipher != cipherName || result.MAC != macName || result.EtM != (ocDTLSIsCBC(spec.id) && etm) || len(result.Replies) != len(packets) {
					t.Fatal(string(output), err)
				}
				if result.Replies[0] != "04010203" {
					t.Fatal("DTLS DPD response", result.Replies[0])
				}
				for i, payload := range expected {
					b, _ := hex.DecodeString(result.Replies[i+1])
					if len(b) < 1 || b[0] != 0 {
						t.Fatal("missing DTLS IP response", i)
					}
					ip, err := parseTunPacket(b[1:])
					if err != nil || ip.protocol != 17 || len(ip.data) < ip.header+8 || !bytes.Equal(ip.data[ip.header+8:], payload) {
						t.Fatal("external UDP payload", i, err)
					}
				}
				d := ocWaitDTLS(t, tunnel)
				if d.suite != spec.id || d.etm != (ocDTLSIsCBC(spec.id) && etm) || d.sent.Load() == 0 || d.received.Load() == 0 {
					t.Fatal("reference did not transfer DTLS IP data")
				}
				t.Log("GnuTLS", result.Version, "cipher", result.Cipher, "MAC", result.MAC, "EtM", result.EtM)
			})
		}
	}
}
