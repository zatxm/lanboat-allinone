//go:build linux

package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDTLS12RenegotiationGnuTLS(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		cipherName := map[uint16]string{0xa8: "AES-128-GCM", 0xa9: "AES-256-GCM", 0xccab: "CHACHA20-POLY1305", 0xc0a4: "AES-128-CCM", 0xc0a5: "AES-256-CCM", 0xc0a8: "AES-128-CCM-8", 0xc0a9: "AES-256-CCM-8", 0x8c: "AES-128-CBC", 0x8d: "AES-256-CBC", 0xae: "AES-128-CBC", 0xaf: "AES-256-CBC"}[spec.id]
		mac := "AEAD"
		switch spec.id {
		case 0x8c, 0x8d:
			mac = "SHA1"
		case 0xae:
			mac = "SHA256"
		case 0xaf:
			mac = "SHA384"
		}
		for _, mode := range []string{"client", "server", "client-mte", "server-mte"} {
			role := strings.TrimSuffix(mode, "-mte")
			mte := strings.HasSuffix(mode, "-mte")
			if mte && !ocDTLSIsCBC(spec.id) {
				continue
			}
			for _, initiator := range []string{"native", "reference"} {
				t.Run(spec.name+"/native-"+mode+"/"+initiator, func(t *testing.T) {
					socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					address := socket.LocalAddr().(*net.UDPAddr)
					referenceRole := "client"
					if role == "client" {
						referenceRole = "server"
						socket.Close()
					}
					psk, id := bytes.Repeat([]byte{9}, 32), bytes.Repeat([]byte{3}, 32)
					request, _ := json.Marshal(map[string]any{"disable_etm": mte, "role": referenceRole, "initiator": initiator, "port": address.Port, "app_id": hex.EncodeToString(id), "psk": hex.EncodeToString(psk), "cipher": cipherName, "mac": mac})
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, "python3", "../tests/dtls12-rekey-reference.py")
					cmd.Stdin = bytes.NewReader(request)
					stdout, err := cmd.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					var logs bytes.Buffer
					cmd.Stderr = &logs
					if err = cmd.Start(); err != nil {
						t.Fatal(err)
					}
					defer func() {
						cmd.Process.Kill()
						_ = cmd.Wait()
						if t.Failed() {
							t.Log(logs.String())
						}
					}()
					output := bufio.NewReader(stdout)
					var raw net.Conn
					if role == "client" {
						if line, err := output.ReadString('\n'); err != nil || line != "READY\n" {
							t.Fatal(line, err)
						}
						raw, err = net.DialUDP("udp4", nil, address)
					} else {
						socket.SetDeadline(time.Now().Add(5 * time.Second))
						b := make([]byte, 18432)
						n, peer, e := socket.ReadFromUDP(b)
						if e != nil {
							t.Fatal(e)
						}
						socket.Close()
						raw, err = net.DialUDP("udp4", address, peer)
						if err == nil {
							raw = &bufferedDatagram{Conn: raw, first: bytes.Clone(b[:n])}
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					d := &ocDTLS{conn: raw, client: role == "client", psk: psk, appID: id, suites: []uint16{spec.id}}
					if err = d.handshake(ctx); err != nil {
						t.Fatal("native handshake", err)
					}
					defer clear(d.secret[:])
					if line, err := output.ReadString('\n'); err != nil || line != "HANDSHAKE\n" {
						t.Fatal(line, err)
					}
					for round, size := range []int{1, 513, 1200} {
						raw.SetDeadline(time.Now().Add(5 * time.Second))
						kind, body, e := d.read()
						if e != nil || kind != 3 || len(body) != size {
							t.Fatal("native read", round, kind, len(body), e)
						}
						for j, v := range body {
							if v != byte(j+round) {
								t.Fatal("bad payload")
							}
						}
						if err = d.write(4, body); err != nil {
							t.Fatal(err)
						}
						if round < 2 && initiator == "native" {
							if err = d.renegotiate(ctx, nil); err != nil {
								t.Fatal("native rekey", err)
							}
						}
					}
					if d.generation.Load() != 2 || d.writeEpoch != 3 {
						t.Fatal("native rekey count", d.generation.Load(), d.writeEpoch)
					}
					line, err := output.ReadString('\n')
					var result struct {
						Passed  bool
						Rekeys  int
						Version string
					}
					if err != nil || json.Unmarshal([]byte(line), &result) != nil || !result.Passed || result.Rekeys != 2 {
						t.Fatal(line, err)
					}
					if err = cmd.Wait(); err != nil {
						t.Fatal(err, logs.String())
					}
					t.Log("GnuTLS", result.Version, "two in-place rekeys")
				})
			}
		}
	}
}

type bufferedDatagram struct {
	net.Conn
	first []byte
}

func (c *bufferedDatagram) Read(b []byte) (int, error) {
	if c.first != nil {
		n := copy(b, c.first)
		c.first = nil
		return n, nil
	}
	return c.Conn.Read(b)
}
