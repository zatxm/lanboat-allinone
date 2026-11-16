package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func legacyRuntime(t testing.TB) (*Runtime, vmessUser) {
	t.Helper()
	user, err := newVMessUser(testUUID)
	if err != nil {
		t.Fatal(err)
	}
	user.legacy = true
	users := []vmessUser{user}
	return &Runtime{vmessUsers: map[string][]vmessUser{"in:s": users}, vmessLegacy: map[string]*vmessLegacyIndex{"s": newVMessLegacyIndex(users)}, replay: replayWindow{}}, user
}

func legacyRequest() vmessRequest {
	q := vmessRequest{legacy: true, security: 3, options: 13, command: 1, address: "example.org:443", response: 79}
	_, _ = rand.Read(q.key[:])
	_, _ = rand.Read(q.iv[:])
	return q
}

func TestVMessLegacyHeader(t *testing.T) {
	for _, address := range []string{"example.org:443", "127.0.0.1:80", "[2001:db8::1]:53", ""} {
		t.Run(address, func(t *testing.T) {
			r, user := legacyRuntime(t)
			q := legacyRequest()
			q.address = address
			if address == "" {
				q.command = 3
			}
			var wire bytes.Buffer
			if err := writeVMessRequest(&wire, user, q); err != nil {
				t.Fatal(err)
			}
			wire.WriteString("body must not be consumed")
			got, err := r.readVMessRequest(&wire, "s")
			if err != nil || got != q || wire.String() != "body must not be consumed" {
				t.Fatal(got, err, wire.String())
			}
			response := vmessResponseHeader(q)
			if err := readVMessResponse(bytes.NewReader(response), q); err != nil {
				t.Fatal(err)
			}
			response[0] ^= 1
			if err := readVMessResponse(bytes.NewReader(response), q); err == nil {
				t.Fatal("response token accepted")
			}
		})
	}
}

func TestVMessLegacyAuthentication(t *testing.T) {
	r, user := legacyRuntime(t)
	q := legacyRequest()
	plain, _ := q.plaintext()
	now := time.Now().Unix()
	var wire bytes.Buffer
	_ = writeVMessLegacy(&wire, user, plain, now)
	valid := bytes.Clone(wire.Bytes())
	for i := 0; i < len(valid); i++ {
		truncated := valid[:i]
		if _, err := r.readVMessRequest(bytes.NewReader(truncated), "s"); err == nil {
			t.Fatal("accepted truncated header", i)
		}
	}
	for _, offset := range []int{0, 16, 32, len(valid) - 1} {
		bad := bytes.Clone(valid)
		bad[offset] ^= 1
		if _, err := r.readVMessRequest(bytes.NewReader(bad), "s"); err == nil {
			t.Fatal("accepted corruption", offset)
		}
	}
	if _, err := r.readVMessRequest(bytes.NewReader(valid), "s"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.readVMessRequest(bytes.NewReader(valid), "s"); err == nil {
		t.Fatal("replay accepted")
	}
	wire.Reset()
	_ = writeVMessLegacy(&wire, user, plain, now+1)
	if _, err := r.readVMessRequest(&wire, "s"); err == nil {
		t.Fatal("same session keys with changed timestamp accepted")
	}
	q = legacyRequest()
	plain, _ = q.plaintext()
	wire.Reset()
	_ = writeVMessLegacy(&wire, user, plain, now)
	if _, err := r.readVMessRequest(&wire, "s"); err != nil {
		t.Fatal("same-second distinct session rejected", err)
	}
	for _, stamp := range []int64{now - 121, now + 121} {
		wire.Reset()
		_ = writeVMessLegacy(&wire, user, plain, stamp)
		if _, err := r.readVMessLegacy(&wire, "s", [16]byte(valid[:16]), stamp+500); err == nil {
			t.Fatal("expired identity accepted")
		}
		wire.Reset()
		_ = writeVMessLegacy(&wire, user, plain, stamp)
		if _, err := r.readVMessLegacy(bytes.NewReader(wire.Bytes()[16:]), "s", [16]byte(wire.Bytes()[:16]), now); err == nil {
			t.Fatal("timestamp outside window accepted")
		}
	}
	disabled := &Runtime{vmessUsers: r.vmessUsers, replay: replayWindow{}}
	if _, err := disabled.readVMessRequest(bytes.NewReader(valid), "s"); err == nil {
		t.Fatal("legacy accepted without opt-in")
	}
	other, _ := newVMessUser("00000000-0000-0000-0000-000000000001")
	wire.Reset()
	_ = writeVMessLegacy(&wire, other, plain, now)
	if _, err := r.readVMessRequest(&wire, "s"); err == nil {
		t.Fatal("unknown identity accepted")
	}
}

func TestVMessLegacyIndex(t *testing.T) {
	r, user := legacyRuntime(t)
	index := r.vmessLegacy["s"]
	token := func(stamp int64) [16]byte {
		var clock [8]byte
		binary.BigEndian.PutUint64(clock[:], uint64(stamp))
		id := vmessLegacyID(user.id)
		mac := hmac.New(md5.New, id[:])
		mac.Write(clock[:])
		return [16]byte(mac.Sum(nil))
	}
	for _, now := range []int64{1000, 1000, 1001, 1120, 1600, 1400} {
		for _, stamp := range []int64{now - 120, now, now + 120} {
			got, ok := index.lookup(token(stamp), now)
			if !ok || got.user != 0 || got.stamp != stamp {
				t.Fatal(now, stamp, got, ok)
			}
		}
		for _, stamp := range []int64{now - 121, now + 121} {
			if _, ok := index.lookup(token(stamp), now); ok {
				t.Fatal("stale token", now, stamp)
			}
		}
		if len(index.tokens) != 482 {
			t.Fatal("unbounded token table", len(index.tokens))
		}
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 100 {
				if _, ok := index.lookup(token(1400), 1400); !ok {
					t.Error("parallel authentication failed")
				}
			}
		})
	}
	wg.Wait()
}

func TestVMessLegacyWireVector(t *testing.T) {
	// Fixed HMAC/CFB bytes are generated independently with Python/OpenSSL.
	user, _ := newVMessUser(testUUID)
	q := legacyRequest()
	plain := []byte("independent legacy header")
	var wire bytes.Buffer
	if err := writeVMessLegacy(&wire, user, plain, 1700000000); err != nil {
		t.Fatal(err)
	}
	const expected = "4cb1c69b1f6f65d6c0676b279fe73a943a9dc5ffa020a9da79a188b4c67ae2fde85c6e3aa9b9205e7e"
	if hex.EncodeToString(wire.Bytes()) != expected {
		t.Fatal(hex.EncodeToString(wire.Bytes()))
	}
	q.legacy = true
	key, iv := vmessResponseKeys(q)
	if key != md5.Sum(q.key[:]) || iv != md5.Sum(q.iv[:]) {
		t.Fatal("legacy response derivation")
	}
	block, _ := aes.NewCipher(key[:])
	header := []byte{q.response, 0, 0, 0}
	cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(header, header)
	if !bytes.Equal(header, vmessResponseHeader(q)) {
		t.Fatal("response wire")
	}
}

func TestVMessLegacyConfiguration(t *testing.T) {
	for _, name := range []string{"alterId", "alter_id"} {
		for _, count := range []int{0, 1, 64, 65535} {
			raw := fmt.Sprintf(`{"uuid":%q,%q:%d}`, testUUID, name, count)
			var u User
			if err := json.Unmarshal([]byte(raw), &u); err != nil || u.AlterID != count || u.UUID != testUUID {
				t.Fatal(raw, u, err)
			}
			data, _ := json.Marshal(u)
			if count != 0 && !bytes.Contains(data, []byte(`"alterId":`)) {
				t.Fatal(string(data))
			}
		}
	}
	for _, raw := range []string{`{"alterId":1,"alter_id":2}`, `{"alterId":0,"alter_id":2}`, `{"alterId":1,"unknown":true}`} {
		var u User
		if err := json.Unmarshal([]byte(raw), &u); err == nil {
			t.Fatal("accepted", raw)
		}
	}
	for _, count := range []int{-1, 0, 1, 64} {
		in := testInbound(t, "vmess")
		in.Users[0].AlterID = count
		if err := (Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "d"}}, Route: Route{Final: "d"}}).validate(); (err == nil) != (count >= 0) {
			t.Fatal(count, err)
		}
		out := testOutbound(t, in, "127.0.0.1:443")
		out.AlterID = count
		if err := (Config{Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}}).validate(); (err == nil) != (count >= 0) {
			t.Fatal(count, err)
		}
	}
}

func TestVMessLegacyIndependent(t *testing.T) {
	for _, security := range []string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprint(security, "/mux", mux), func(t *testing.T) {
				in := testInbound(t, "vmess")
				in.Users[0].AlterID = 64
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				for _, count := range []int{0, 1, 64} {
					out := testOutbound(t, in, server.Address("server"))
					out.Security = security
					out.AlterID = count
					out.Multiplex.Enabled = mux
					out.Multiplex.Protocol = "mux.cool"
					if security == "auto" {
						out.GlobalPadding = true
						out.AuthenticatedLength = true
					}
					client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 511, 4096, 14000})
				}
			})
		}
	}
}

func TestVMessLegacyTransports(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "http", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, "vmess")
			in.Users[0].AlterID = 1
			in.Transport = Transport{Type: kind, Path: "/legacy"}
			if kind == "grpc" {
				in.Transport.Path = ""
				in.Transport.ServiceName = "legacy"
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.AlterID = 1
			out.Transport = in.Transport
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096})
		})
	}
}

func TestVMessLegacyReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required for legacy VMess interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, security := range []string{"aes-128-gcm", "chacha20-poly1305", "none", "zero"} {
		for _, count := range []int{1, 64} {
			for _, direction := range []string{"client", "server"} {
				t.Run(fmt.Sprint(security, "/", count, "/", direction), func(t *testing.T) {
					in := testInbound(t, "vmess")
					in.Users[0].AlterID = count
					var client *Runtime
					if direction == "client" {
						in.ListenPort = unusedPort(t)
						referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "d"}}})
						out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
						out.Security = security
						out.AlterID = count
						if security == "aes-128-gcm" {
							out.GlobalPadding = true
							out.AuthenticatedLength = true
						}
						client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						out := testOutbound(t, in, server.Address("server"))
						out.Security = security
						out.AlterID = count
						out.Username = ""
						out.Password = ""
						if security == "aes-128-gcm" {
							out.GlobalPadding = true
							out.AuthenticatedLength = true
						}
						local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}})
						front := Outbound{Type: "socks", Tag: "front", Server: local.Listen, ServerPort: local.ListenPort}
						client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 511, 4096, 14000})
				})
			}
		}
	}
}

func FuzzVMessLegacyHeader(f *testing.F) {
	_, user := legacyRuntime(f)
	q := legacyRequest()
	plain, _ := q.plaintext()
	var seed bytes.Buffer
	_ = writeVMessLegacy(&seed, user, plain, time.Now().Unix())
	f.Add(seed.Bytes())
	f.Add([]byte("malformed"))
	users := []vmessUser{user}
	index := newVMessLegacyIndex(users)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2048 {
			return
		}
		r := &Runtime{vmessUsers: map[string][]vmessUser{"in:s": users}, vmessLegacy: map[string]*vmessLegacyIndex{"s": index}, replay: replayWindow{}}
		_, _ = r.readVMessRequest(bytes.NewReader(data), "s")
	})
}

func BenchmarkVMessLegacyLookup(b *testing.B) {
	r, user := legacyRuntime(b)
	q := legacyRequest()
	plain, _ := q.plaintext()
	var wire bytes.Buffer
	now := time.Now().Unix()
	_ = writeVMessLegacy(&wire, user, plain, now)
	auth := [16]byte(wire.Bytes()[:16])
	index := r.vmessLegacy["s"]
	_, _ = index.lookup(auth, now)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, ok := index.lookup(auth, now); !ok {
			b.Fatal("lookup")
		}
	}
}
