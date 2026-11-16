package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"net"
	"os/exec"
	"strings"
	"testing"
)

var addedSSMethods = []string{"camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "idea-cfb", "rc2-cfb", "seed-cfb"}

func TestLegacyBlockVectors(t *testing.T) {
	for _, v := range []struct{ method, key, plain, encrypted string }{
		{"camellia-128-cfb", "0123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543210", "67673138549669730857065648eabe43"},
		{"camellia-192-cfb", "0123456789abcdeffedcba98765432100011223344556677", "0123456789abcdeffedcba9876543210", "b4993401b3e996f84ee5cee7d79b09b9"},
		{"camellia-256-cfb", "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff", "0123456789abcdeffedcba9876543210", "9acc237dff16d76c20ef7c919e3a7509"},
		{"cast5-cfb", "0123456712345678234567893456789a", "0123456789abcdef", "238b4fe5847e44b2"},
		{"cast5-cfb", "01234567123456782345", "0123456789abcdef", "eb6a711a2c02271b"},
		{"cast5-cfb", "0123456712", "0123456789abcdef", "7ac816d16e9b302e"},
		{"idea-cfb", "00010002000300040005000600070008", "0000000100020003", "11fbed2b01986de5"},
		{"seed-cfb", "00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb"},
		{"seed-cfb", "000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "c11f22f20140505084483597e4370f43"},
		{"seed-cfb", "4706480851e61be85d74bfb3fd956185", "83a2f8a288641fb9a4e9a5cc2f131c7d", "ee54d13ebcae706d226bc3142cd40d4a"},
		{"seed-cfb", "28dbc3bc49ffd87dcfa509b11d422be7", "b41e6be2eba84a148e2eed84593c5ec7", "9b9b7bfcd1813cb95d0b3618f40f5122"},
	} {
		t.Run(v.method+"/"+v.key, func(t *testing.T) {
			block, err := newSSStreamBlock(v.method, unhex(t, v.key))
			if err != nil {
				t.Fatal(err)
			}
			plain, want := unhex(t, v.plain), unhex(t, v.encrypted)
			buf := append([]byte{}, plain...)
			block.Encrypt(buf, buf)
			if !bytes.Equal(buf, want) {
				t.Fatalf("published vector: got%x want%x", buf, want)
			}
			block.Decrypt(buf, buf)
			if !bytes.Equal(buf, plain) {
				t.Fatalf("inverse block: got%x want%x", buf, plain)
			}
		})
	}
}

func TestLegacyBlockKeyBounds(t *testing.T) {
	for _, method := range []string{"idea-cfb", "cast5-cfb", "seed-cfb", "camellia-128-cfb"} {
		for _, size := range []int{0, 1, 4, 17, 33} {
			if _, err := newSSStreamBlock(method, make([]byte, size)); err == nil {
				t.Fatalf("%s accepted invalid key length%d", method, size)
			}
		}
	}
}

func legacyCipherOracle(t *testing.T, method, mode string, key, iv, plain []byte) []byte {
	t.Helper()
	if method == "idea-cfb" {
		body, _ := json.Marshal(map[string]string{"mode": mode, "key": hex.EncodeToString(key), "iv": hex.EncodeToString(iv), "data": hex.EncodeToString(plain)})
		cmd := exec.Command("python3", "../tests/cipher-reference.py")
		cmd.Stdin = bytes.NewReader(body)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("libgcrypt IDEA oracle: %v: %s", err, out)
		}
		return unhex(t, strings.TrimSpace(string(out)))
	}
	name := strings.TrimSuffix(method, "-cfb") + "-" + mode
	args := []string{"enc", "-provider", "default", "-provider", "legacy", "-" + name, "-K", hex.EncodeToString(key), "-nosalt", "-nopad"}
	if mode == "cfb" {
		args = append(args, "-iv", hex.EncodeToString(iv))
	}
	cmd := exec.Command("openssl", args...)
	cmd.Stdin = bytes.NewReader(plain)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("OpenSSL%s oracle: %v", name, err)
	}
	return out
}

func TestLegacyCiphersIndependentOracles(t *testing.T) {
	for _, method := range addedSSMethods {
		t.Run(method, func(t *testing.T) {
			key, err := newSSKey(method, "cipher-oracle-password")
			if err != nil {
				t.Fatal(err)
			}
			block := key.streamBlock
			size := block.BlockSize()
			random := rand.New(rand.NewPCG(123, 456))
			plain := make([]byte, 257*size)
			for i := range plain {
				plain[i] = byte(random.Uint32())
			}
			want := legacyCipherOracle(t, method, "ecb", key.master, nil, plain)
			buf := make([]byte, len(plain))
			for i := 0; i < len(plain); i += size {
				block.Encrypt(buf[i:], plain[i:])
			}
			if !bytes.Equal(buf, want) {
				t.Fatal("ECB encryption differs from independent oracle")
			}
			for i := 0; i < len(buf); i += size {
				block.Decrypt(buf[i:], buf[i:])
			}
			if !bytes.Equal(buf, plain) {
				t.Fatal("ECB decryption differs from independent oracle")
			}
			iv := bytes.Repeat([]byte{0x57}, size)
			plain = plain[:len(plain)-3]
			want = legacyCipherOracle(t, method, "cfb", key.master, iv, plain)
			for _, decrypt := range []bool{false, true} {
				stream, err := key.stream(iv, decrypt)
				if err != nil {
					t.Fatal(err)
				}
				input, expected := plain, want
				if decrypt {
					input, expected = want, plain
				}
				buf := append([]byte{}, input...)
				for i := 0; i < len(buf); {
					n := min(1+random.IntN(77), len(buf)-i)
					stream.XORKeyStream(buf[i:i+n], buf[i:i+n])
					i += n
				}
				if !bytes.Equal(buf, expected) {
					t.Fatalf("fragmented CFB decrypt=%v differs from independent oracle", decrypt)
				}
			}
		})
	}
}

func TestLegacySSAndSSRReference(t *testing.T) {
	for _, method := range addedSSMethods {
		// The reference's system OpenSSL build disables IDEA; libgcrypt is its cipher oracle.
		if method == "idea-cfb" {
			continue
		}
		for _, protocol := range []string{"origin", "auth_sha1_v4", "verify_sha1"} {
			for _, direction := range []string{"client", "server"} {
				t.Run(method+"/"+protocol+"/"+direction, func(t *testing.T) {
					port := unusedPort(t)
					cfg := map[string]any{"server": "127.0.0.1", "server_port": port, "password": "private", "method": method, "protocol": protocol, "obfs": "plain", "timeout": 30, "dns_ipv6": false, "forbidden_ip": "", "forbidden_port": ""}
					in := Inbound{Type: "shadowsocksr", Tag: "server", Listen: "127.0.0.1", Method: method, Password: "private", Protocol: protocol}
					if protocol == "origin" {
						in.Type, in.Protocol = "shadowsocks", ""
					}
					if protocol == "verify_sha1" {
						in.Type, in.Protocol, in.OTA = "shadowsocks", "", true
					}
					var client *Runtime
					if direction == "client" {
						startSSRReference(t, cfg, false)
						waitPort(t, portAddress("127.0.0.1", port))
						client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: in.Type, Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Method: method, Password: "private", Protocol: in.Protocol, OTA: in.OTA}}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						_, actualPort, _ := net.SplitHostPort(server.Address("server"))
						port = unusedPort(t)
						cfg["server_port"] = json.Number(actualPort)
						cfg["local_address"], cfg["local_port"] = "127.0.0.1", port
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

func BenchmarkLegacyCFB(b *testing.B) {
	for _, method := range append([]string{"aes-256-cfb"}, addedSSMethods...) {
		key, err := newSSKey(method, "benchmark-key")
		if err != nil {
			b.Fatal(err)
		}
		b.Run(method, func(b *testing.B) {
			stream, err := key.stream(make([]byte, key.streamBlock.BlockSize()), false)
			if err != nil {
				b.Fatal(err)
			}
			data := make([]byte, 32768)
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				stream.XORKeyStream(data, data)
			}
		})
	}
}
