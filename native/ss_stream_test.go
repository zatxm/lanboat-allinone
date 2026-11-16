package native

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os/exec"
	"testing"
)

func TestSSStreamCipherMatrix(t *testing.T) {
	methods := []string{"none", "table", "rc4", "rc4-md5", "rc4-md5-6", "chacha20", "chacha20-ietf", "salsa20", "des-cfb", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "idea-cfb", "rc2-cfb", "seed-cfb"}
	for _, bits := range []string{"128", "192", "256"} {
		for _, mode := range []string{"cfb", "cfb1", "cfb8", "ctr"} {
			methods = append(methods, "aes-"+bits+"-"+mode)
		}
	}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Method = method
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDP(t, client)
		})
	}
}

func TestShadowsocksCapabilityList(t *testing.T) {
	seen := map[string]bool{}
	for _, method := range ShadowsocksMethods() {
		if seen[method] {
			t.Fatal("duplicate cipher", method)
		}
		seen[method] = true
		password := "test-password"
		if isSS2022(method) {
			size := 32
			if method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			password = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, size))
		}
		if _, err := newSSKey(method, password); err != nil {
			t.Fatal("reported unimplemented cipher", method, err)
		}
	}
}

func TestSSAESFeedbackOpenSSL(t *testing.T) {
	for _, bits := range []string{"128", "192", "256"} {
		for _, mode := range []string{"cfb", "cfb1", "cfb8", "ctr"} {
			t.Run(bits+"/"+mode, func(t *testing.T) {
				method := "aes-" + bits + "-" + mode
				key, err := newSSKey(method, "oracle-password")
				if err != nil {
					t.Fatal(err)
				}
				iv := bytes.Repeat([]byte{0x57}, 16)
				plain := bytes.Repeat([]byte("feedback-stream-modes\n"), 157)
				stream, err := key.stream(iv, false)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(plain))
				stream.XORKeyStream(got[:13], plain[:13])
				stream.XORKeyStream(got[13:], plain[13:])
				command := exec.Command("openssl", "enc", "-"+method, "-K", hex.EncodeToString(key.master), "-iv", hex.EncodeToString(iv), "-nosalt")
				command.Stdin = bytes.NewReader(plain)
				expected, err := command.Output()
				if err != nil {
					t.Fatal("OpenSSL cipher oracle", err)
				}
				if !bytes.Equal(got, expected) {
					t.Fatal("feedback cipher differs from independent OpenSSL implementation")
				}
			})
		}
	}
}

func TestSSBlowfishOpenSSL(t *testing.T) {
	key, err := newSSKey("bf-cfb", "oracle-password")
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0x57}, 8)
	plain := bytes.Repeat([]byte("blowfish-feedback"), 157)
	stream, err := key.stream(iv, false)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(plain))
	stream.XORKeyStream(got[:13], plain[:13])
	stream.XORKeyStream(got[13:], plain[13:])
	cmd := exec.Command("openssl", "enc", "-provider", "legacy", "-bf-cfb", "-K", hex.EncodeToString(key.master), "-iv", hex.EncodeToString(iv), "-nosalt")
	cmd.Stdin = bytes.NewReader(plain)
	want, e := cmd.Output()
	if e != nil || !bytes.Equal(got, want) {
		t.Fatalf("Blowfish OpenSSL mismatch: %v", e)
	}
}
