//go:build linux

package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestOpenConnectDTLSResumeGnuTLS(t *testing.T) {
	for _, version := range []string{"DTLS0.9", "DTLS1.2"} {
		for i, spec := range ocDTLSResumeSuites {
			if version == "DTLS0.9" && i > 4 || version == "DTLS1.2" && i == 4 {
				continue
			}
			cipher, kx, mac := "AES-128-CBC", "RSA", "SHA1"
			switch spec.id {
			case 0x0035:
				cipher = "AES-256-CBC"
			case 0x0033:
				kx = "DHE-RSA"
			case 0x0039:
				cipher, kx = "AES-256-CBC", "DHE-RSA"
			case 0x000a:
				cipher = "3DES-CBC"
			case 0x009c:
				cipher, mac = "AES-128-GCM", "AEAD"
			case 0x009d:
				cipher, mac = "AES-256-GCM", "AEAD"
			case 0xc02f:
				cipher, kx, mac = "AES-128-GCM", "ECDHE-RSA", "AEAD"
			case 0xc030:
				cipher, kx, mac = "AES-256-GCM", "ECDHE-RSA", "AEAD"
			case 0xccab:
				cipher, kx, mac = "CHACHA20-POLY1305", "PSK", "AEAD"
			}
			for _, client := range []bool{true, false} {
				role := "client"
				if !client {
					role = "server"
				}
				t.Run(version+"/"+spec.name+"/native-"+role, func(t *testing.T) {
					socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
					if err != nil {
						t.Fatal(err)
					}
					defer socket.Close()
					address := socket.LocalAddr().(*net.UDPAddr)
					referenceRole := "client"
					if client {
						referenceRole = "server"
						socket.Close()
					}
					resume := &ocDTLSResume{version: 0xfefd, suite: spec.id}
					if version == "DTLS0.9" {
						resume.version = 0x0100
					}
					copy(resume.master[:], bytes.Repeat([]byte{7}, 48))
					id := bytes.Repeat([]byte{3}, 32)
					request, _ := json.Marshal(map[string]any{"role": referenceRole, "port": address.Port, "version": version, "cipher": cipher, "kx": kx, "mac": mac, "master": hex.EncodeToString(resume.master[:]), "id": hex.EncodeToString(id)})
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, "python3", "../tests/dtls-resume-reference.py")
					cmd.Env = append(os.Environ(), "GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null")
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
					if client {
						if line, e := output.ReadString('\n'); e != nil || line != "READY\n" {
							t.Fatal(line, e)
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
					d := &ocDTLS{conn: raw, client: client, resume: resume, appID: id}
					if err = d.handshake(ctx); err != nil {
						t.Fatal("native handshake", err)
					}
					if line, e := output.ReadString('\n'); e != nil || line != "HANDSHAKE\n" {
						t.Fatal(line, e)
					}
					for _, size := range []int{1, 513, 1200} {
						raw.SetDeadline(time.Now().Add(3 * time.Second))
						kind, body, e := d.read()
						if e != nil || kind != 3 || len(body) != size {
							t.Fatal(kind, len(body), e)
						}
						for j, v := range body {
							if v != byte(j%251) {
								t.Fatal("payload corruption")
							}
						}
						if e = d.write(4, body); e != nil {
							t.Fatal(e)
						}
					}
					line, e := output.ReadString('\n')
					var result struct {
						Passed  bool
						Version string
					}
					if e != nil || json.Unmarshal([]byte(line), &result) != nil || !result.Passed {
						t.Fatal(line, e)
					}
					if err = cmd.Wait(); err != nil {
						t.Fatal(err, logs.String())
					}
					t.Log("GnuTLS", result.Version, "resumed and exchanged UDP payloads")
				})
			}
		}
	}
}
