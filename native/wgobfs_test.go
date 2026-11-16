package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWGObfsChaCha6(t *testing.T) {
	key := "\x01\x02\x03\x04\x05\x06\x07\x08"
	mask := newWGMask(key)
	input, _ := hex.DecodeString("00ff000000ff000000ff000000ff0000")
	got := mask.hash(input)
	if hex.EncodeToString(got[:]) != "c5925587ca38aac431e72eed19723193511396ee67ea0843d73c9ea396d4831f" {
		t.Fatal("ChaCha6 reference vector mismatch")
	}
	for _, password := range []string{"", "key", strings.Repeat("abc", 30), "岚舟测试"} {
		m := newWGMask(password)
		for i, value := range m.key {
			want := byte(0)
			if password != "" {
				want = password[i%len(password)]
			}
			if value != want {
				t.Fatal("password byte expansion")
			}
		}
	}
}

func wgMaskFixture(kind uint32, size, variation int) []byte {
	packet := make([]byte, size, size+32)
	for i := range packet {
		packet[i] = byte(i*37 + variation)
	}
	binary.LittleEndian.PutUint32(packet, kind)
	if (kind == 1 && size == 148 || kind == 2 && size == 92) && variation&1 == 0 {
		clear(packet[size-16:])
	}
	return packet
}

func TestWGObfsCodec(t *testing.T) {
	m := newWGMask("codec-test")
	for _, test := range []struct {
		kind uint32
		size int
	}{{1, 148}, {2, 92}, {3, 64}, {4, 32}, {4, 48}, {4, 192}, {4, 208}, {4, 1424}, {4, 1452}, {4, 65488}} {
		dropped := 0
		for n := range 1024 {
			original := wgMaskFixture(test.kind, test.size, n)
			encoded := m.encode(bytes.Clone(original))
			if encoded == nil {
				if test.kind != 4 || test.size != 32 {
					t.Fatal("dropped application packet")
				}
				dropped++
				continue
			}
			extra := len(encoded) - len(original)
			if extra < 4 || extra > 32 || test.size > 200 && extra > 8 || bytes.Equal(encoded[:16], original[:16]) {
				t.Fatal("header masking or padding")
			}
			decoded, kind := m.decode(encoded)
			if kind != test.kind || !bytes.Equal(decoded, original) {
				t.Fatalf("round trip type%d length%d variation%d", test.kind, test.size, n)
			}
		}
		if test.size == 32 && (dropped < 700 || dropped > 900) {
			t.Fatal("keepalive filtering", dropped)
		}
	}
	for _, packet := range [][]byte{nil, {4}, make([]byte, 32), make([]byte, 36), make([]byte, 65508)} {
		if _, kind := m.decode(packet); kind != 0 {
			t.Fatal("malformed packet accepted")
		}
	}
	for _, kind := range []uint32{1, 2, 3, 9, 0x13} {
		packet := m.encode(wgMaskFixture(kind, 144, 0))
		if _, got := m.decode(packet); got != 0 {
			t.Fatal("invalid message size/type accepted", kind)
		}
	}
}

func TestWGObfsConfiguration(t *testing.T) {
	if _, err := newWGObfuscation(nil, &WGObfsOptions{}, 65456); err != nil {
		t.Fatal(err)
	}
	for _, mtu := range []int{65457, 65472, 65507} {
		if _, err := newWGObfuscation(nil, &WGObfsOptions{}, mtu); err == nil {
			t.Fatal("accepted oversized masked datagram", mtu)
		}
	}
	if _, err := newWGObfuscation(&AmneziaWGOptions{}, &WGObfsOptions{}, 1420); err == nil {
		t.Fatal("accepted incompatible obfuscation modes")
	}
	for _, side := range []string{"inbounds", "outbounds"} {
		protocol := "direct"
		if side == "inbounds" {
			protocol = "socks"
		}
		_, err := Parse([]byte(`{"` + side + `":[{"type":"` + protocol + `","tag":"d","wgobfs":{}}]}`))
		if err == nil || !strings.Contains(err.Error(), "wgobfs options require wireguard") {
			t.Fatal("ignored WireGuard option on another protocol")
		}
	}
}

func TestWGObfsIndependent(t *testing.T) {
	for i, password := range []string{"", "short", "exactly-32-bytes-of-wgobfs-key-123", strings.Repeat("long", 20), "岚舟测试"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			serverKey, serverPub := wgTestKey(t)
			clientKey, clientPub := wgTestKey(t)
			psk, _ := wgTestKey(t)
			options := &WGObfsOptions{Password: password}
			in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{WGObfs: options, Peers: []WireGuardPeer{{PublicKey: clientPub, PreSharedKey: psk, AllowedIPs: []string{"10.57.0.2/32"}}}}}
			if i == 4 {
				in.Listen = "::1"
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Password, out.Username, out.UUID = "", "", ""
			out.PrivateKey = []string{clientKey}
			out.WireGuardOptions = WireGuardOptions{PublicKey: serverPub, PreSharedKey: psk, LocalAddress: []string{"10.57.0.2/32"}, WGObfs: options}
			data, _ := json.Marshal(Config{Outbounds: []Outbound{out}})
			if _, err := Parse(data); err != nil {
				t.Fatal(err)
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
		})
	}
}

func TestWGObfsWrongPassword(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{WGObfs: &WGObfsOptions{Password: "correct"}, Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.57.0.2/32"}}}}}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Password, out.Username, out.UUID = "", "", ""
	out.PrivateKey = []string{clientKey}
	out.WireGuardOptions = WireGuardOptions{PublicKey: serverPub, LocalAddress: []string{"10.57.0.2/32"}, WGObfs: &WGObfsOptions{Password: "wrong"}}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if c, err := client.Dial(ctx, "tcp", origin.Addr().String()); err == nil {
		c.Close()
		t.Fatal("wrong obfuscation password did not fail closed")
	}
}

func TestWGObfsAuthenticatedWire(t *testing.T) {
	a, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b, _ := ecdh.X25519().GenerateKey(rand.Reader)
	o, _ := newWGObfuscation(nil, &WGObfsOptions{Password: "auth-test"}, 1420)
	handshake, err := wgInitiate(a, b.PublicKey().Bytes(), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	init, kind := o.decode(o.wrap(1, handshake.message))
	if kind != 1 || !bytes.Equal(init, handshake.message) {
		t.Fatal("cached initiation changed")
	}
	pub, _, ck, h, err := wgReadInitiation(b, init)
	if err != nil {
		t.Fatal(err)
	}
	reply, server, err := wgRespond(b, pub, make([]byte, 32), ck, h, init)
	if err != nil {
		t.Fatal(err)
	}
	reply, kind = o.decode(o.wrap(2, reply))
	client, err := handshake.response(reply)
	if err != nil || kind != 2 {
		t.Fatal("masked response", err)
	}
	cookie := bytes.Repeat([]byte{0x59}, 16)
	key := blake2s(append([]byte("cookie--"), handshake.remote...), nil, 32)
	aead, _ := newChaChaAEAD(key, true)
	nonce := bytes.Repeat([]byte{0x27}, 24)
	response := binary.LittleEndian.AppendUint32(nil, 3)
	response = binary.LittleEndian.AppendUint32(response, handshake.index)
	response = append(response, nonce...)
	response = aead.Seal(response, nonce, cookie, handshake.message[116:132])
	response, kind = o.decode(o.wrap(3, response))
	if kind != 3 {
		t.Fatal("masked cookie reply rejected")
	}
	if err := handshake.cookie(response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(handshake.message[132:], blake2s(handshake.message[:132], cookie, 16)) {
		t.Fatal("cookie MAC2 authentication")
	}
	withCookie, k := o.decode(o.wrap(1, handshake.message))
	if k != 1 || !bytes.Equal(withCookie, handshake.message) {
		t.Fatal("nonzero cookie MAC2 changed")
	}
	response[40] ^= 1
	if err := handshake.cookie(response); err == nil {
		t.Fatal("tampered cookie accepted")
	}
	for range 256 {
		raw, err := client.seal(nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded := o.mask.encode(raw)
		if encoded == nil {
			continue
		}
		corrupt := bytes.Clone(encoded)
		corrupt[20] ^= 1
		if bad, k := o.decode(corrupt); k == 4 {
			if _, err := server.open(bad); err == nil {
				t.Fatal("tampered authenticated packet accepted")
			}
		}
		decoded, k := o.decode(encoded)
		if k != 4 {
			t.Fatal("valid transport rejected")
		}
		if _, err := server.open(decoded); err != nil {
			t.Fatal(err)
		}
		if _, err := server.open(decoded); err == nil {
			t.Fatal("replayed transport accepted")
		}
		return
	}
	t.Fatal("all key-confirmation packets filtered")
}

func startWGObfsReference(t *testing.T, mode, forward, password string) string {
	t.Helper()
	ref := os.Getenv("LANBOAT_TEST_WGOBFS")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_WGOBFS required for rs-wgobfs interoperability")
	}
	port := unusedPort(t)
	address := portAddress("127.0.0.1", port)
	log, err := os.Create(filepath.Join(t.TempDir(), "reference.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(ref, "-l", address, "-f", forward, "-k", password, "-m", mode)
	cmd.Stderr = log
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Close()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(log.Name())
			t.Log(string(raw))
		}
	})
	ready := make(chan error, 1)
	go func() {
		_, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal("reference startup", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("reference startup timeout")
	}
	return address
}

func TestWGObfsReferenceWire(t *testing.T) {
	for _, mode := range []string{"obfs", "unobfs"} {
		for i, password := range []string{"short", "岚舟测试", strings.Repeat("long", 20)} {
			t.Run(fmt.Sprintf("%s/%d", mode, i), func(t *testing.T) {
				remote, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer remote.Close()
				ref := startWGObfsReference(t, mode, remote.LocalAddr().String(), password)
				local, err := net.Dial("udp", ref)
				if err != nil {
					t.Fatal(err)
				}
				defer local.Close()
				m := newWGMask(password)
				for _, test := range []struct {
					kind uint32
					size int
				}{{1, 148}, {2, 92}, {3, 64}, {4, 48}, {4, 192}, {4, 208}, {4, 1424}, {4, 1452}} {
					for variation := range 4 {
						plain := wgMaskFixture(test.kind, test.size, variation)
						encoded := m.encode(bytes.Clone(plain))
						request, expected := plain, encoded
						if mode == "unobfs" {
							request, expected = encoded, plain
						}
						local.SetDeadline(time.Now().Add(3 * time.Second))
						remote.SetDeadline(time.Now().Add(3 * time.Second))
						if _, err := local.Write(request); err != nil {
							t.Fatal(err)
						}
						buffer := make([]byte, 2048)
						n, addr, err := remote.ReadFrom(buffer)
						if err != nil || !bytes.Equal(buffer[:n], expected) {
							t.Fatalf("reference%s type%d size%d variation%d: %v", mode, test.kind, test.size, variation, err)
						}
						if _, err := remote.WriteTo(expected, addr); err != nil {
							t.Fatal(err)
						}
						n, err = local.Read(buffer)
						if err != nil || !bytes.Equal(buffer[:n], request) {
							t.Fatalf("reference%s response: %v", mode, err)
						}
					}
				}
			})
		}
	}
}

func FuzzWGObfs(f *testing.F) {
	f.Add([]byte("wireguard-mask-test"), byte(0))
	m := newWGMask("fuzz-key")
	f.Add(m.encode(wgMaskFixture(1, 148, 0)), byte(1))
	f.Add(m.encode(wgMaskFixture(4, 1424, 0)), byte(1))
	f.Fuzz(func(t *testing.T, data []byte, which byte) {
		if which&1 != 0 {
			body, kind := m.decode(data)
			if kind != 0 && len(body) < 32 {
				t.Fatal("short decoded packet")
			}
			return
		}
		if len(data) < 32 || len(data) > 65488 {
			return
		}
		packet := append(make([]byte, 0, len(data)+32), data...)
		binary.LittleEndian.PutUint32(packet, 4)
		original := bytes.Clone(packet)
		if encoded := m.encode(packet); encoded != nil {
			decoded, kind := m.decode(encoded)
			if kind != 4 || !bytes.Equal(decoded, original) {
				t.Fatal("transport codec round trip")
			}
		}
	})
}

func BenchmarkWGObfs(b *testing.B) {
	m := newWGMask("benchmark-key")
	plain := wgMaskFixture(4, 1452, 1)
	encoded := m.encode(bytes.Clone(plain))
	for _, which := range []string{"encode", "decode"} {
		b.Run(which, func(b *testing.B) {
			buffer := make([]byte, len(plain), len(plain)+32)
			b.ReportAllocs()
			b.SetBytes(int64(len(plain)))
			b.ResetTimer()
			for range b.N {
				if which == "encode" {
					buffer = buffer[:len(plain)]
					copy(buffer, plain)
					if m.encode(buffer) == nil {
						b.Fatal("unexpected drop")
					}
				} else {
					buffer = buffer[:len(encoded)]
					copy(buffer, encoded)
					if _, kind := m.decode(buffer); kind != 4 {
						b.Fatal("invalid decode")
					}
				}
			}
		})
	}
}
