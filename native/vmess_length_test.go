package native

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

func TestVMessAuthenticatedLengthIndependent(t *testing.T) {
	for _, cipher := range []string{"aes-128-gcm", "chacha20-poly1305"} {
		for _, padding := range []bool{false, true} {
			t.Run(fmt.Sprint(cipher, "/", padding), func(t *testing.T) {
				in := testInbound(t, "vmess")
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Security, out.AuthenticatedLength, out.GlobalPadding = cipher, true, padding
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 16000})
			})
		}
	}
}

func TestVMessLengthReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required for official VMess length interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, cipher := range []string{"aes-128-gcm", "chacha20-poly1305"} {
		for _, auth := range []bool{false, true} {
			for _, padding := range []bool{false, true} {
				for _, direction := range []string{"client", "server"} {
					t.Run(fmt.Sprint(cipher, "/auth", auth, "/pad", padding, "/", direction), func(t *testing.T) {
						in := testInbound(t, "vmess")
						var client *Runtime
						if direction == "client" {
							in.ListenPort = unusedPort(t)
							referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
							out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
							out.Security, out.AuthenticatedLength, out.GlobalPadding = cipher, auth, padding
							client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						} else {
							server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
							out := testOutbound(t, in, server.Address("server"))
							out.Username, out.Password = "", ""
							out.Security, out.AuthenticatedLength, out.GlobalPadding = cipher, auth, padding
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
}

func TestVMessLengthConfiguration(t *testing.T) {
	for _, field := range []string{"global_padding", "authenticated_length"} {
		for _, protocol := range []string{"direct", "vmess"} {
			raw := fmt.Sprintf(`{"outbounds":[{"type":%q,"tag":"p","%s":true`, protocol, field)
			if protocol == "vmess" {
				raw += `,"server":"127.0.0.1","server_port":443,"uuid":"` + testUUID + `","security":"none"`
			}
			raw += `}]}`
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("accepted ineffective option", raw)
			}
		}
	}
	q := vmessRequest{security: 3, options: 21, command: 1, address: "example.com:443"}
	plain, err := q.plaintext()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseVMessPlaintext(plain); err != nil {
		t.Fatal(err)
	}
	q.security = 5
	plain, _ = q.plaintext()
	if _, err := parseVMessPlaintext(plain); err == nil {
		t.Fatal("none body accepted experimental AEAD length")
	}
	var out Outbound
	if err := json.Unmarshal([]byte(`{"type":"vmess","global_padding":true,"authenticated_length":true}`), &out); err != nil || !out.GlobalPadding || !out.AuthenticatedLength {
		t.Fatal(err)
	}
}

func TestVMessLengthAuthenticationAndBounds(t *testing.T) {
	for _, cipher := range []byte{3, 4} {
		for _, padding := range []byte{0, 8} {
			q := vmessRequest{security: cipher, options: 21 | padding, command: 2}
			copy(q.key[:], []byte("key-for-vmess-test"))
			copy(q.iv[:], []byte("iv-for-vmess-test!"))
			var wire bytes.Buffer
			writer := newVMessBody(&wire, q.key, q.iv, q)
			if err := writer.writeChunk([]byte("authenticated payload")); err != nil {
				t.Fatal(err)
			}
			original := bytes.Clone(wire.Bytes())
			for _, offset := range []int{0, 9, 17, 19} {
				bad := bytes.Clone(original)
				bad[offset] ^= 1
				reader := newVMessBody(bytes.NewBuffer(bad), q.key, q.iv, q)
				if _, err := reader.readChunk(); err == nil {
					t.Fatal("tampered length/body accepted", offset)
				}
			}
			reader := newVMessBody(bytes.NewBuffer(original), q.key, q.iv, q)
			if data, err := reader.readChunk(); err != nil || string(data) != "authenticated payload" {
				t.Fatal(err)
			}
			if err := writer.writeChunk(make([]byte, 16384)); err == nil {
				t.Fatal("oversize accepted")
			}
			wire.Reset()
			if err := writer.writeChunk([]byte("still synchronized")); err != nil {
				t.Fatal(err)
			}
			reader.ReadWriter = &wire
			if data, err := reader.readChunk(); err != nil || string(data) != "still synchronized" {
				t.Fatal("rejection consumed state", err)
			}
			writer.counter, reader.counter = 65535, 65535
			if err := writer.writeChunk([]byte("last")); err != nil {
				t.Fatal(err)
			}
			if _, err := reader.readChunk(); err != nil {
				t.Fatal(err)
			}
			if err := writer.writeChunk([]byte("nonce reused")); err == nil {
				t.Fatal("exhausted nonce accepted")
			}
		}
	}
	q := vmessRequest{security: 3, options: 21, command: 1}
	var wire bytes.Buffer
	b := newVMessBody(&wire, q.key, q.iv, q)
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], 65535)
	wire.Write(b.lengthAEAD.Seal(nil, q.iv[:12], raw[:], nil))
	if _, err := b.readChunk(); err == nil || !strings.Contains(err.Error(), "chunk size") {
		t.Fatal("unbounded encrypted length", err)
	}
	if len(b.buffer) != 0 {
		t.Fatal("allocated body before validating length")
	}
	plain := newVMessBody(bytes.NewBuffer([]byte{255, 255}), q.key, q.iv, vmessRequest{security: 3, options: 1})
	if _, err := plain.readChunk(); err == nil || len(plain.buffer) != 0 {
		t.Fatal("unbounded plain length", err)
	}
}

func TestVMessNoneLargeTCPChunks(t *testing.T) {
	for _, options := range []byte{1, 5} {
		q := vmessRequest{security: 5, options: options, command: 1}
		var wire bytes.Buffer
		encoder := newVMessBody(&wire, q.key, q.iv, q)
		reader := newVMessBody(&wire, q.key, q.iv, q)
		for _, size := range []int{20480, 32768, 65535, 3} {
			want := bytes.Repeat([]byte{byte(size)}, size)
			_, mask := encoder.framing()
			wire.Write(binary.BigEndian.AppendUint16(nil, uint16(size)^mask))
			wire.Write(want)
			got, err := reader.readChunk()
			if err != nil || !bytes.Equal(want, got) || cap(reader.buffer) > 65535 {
				t.Fatal("coalesced none chunk", options, size, len(got), err)
			}
		}
	}
	for _, q := range []vmessRequest{{security: 5, options: 1, command: 2}, {security: 3, options: 1, command: 1}, {security: 4, options: 1, command: 1}} {
		wire := bytes.NewBuffer(binary.BigEndian.AppendUint16(nil, 20480))
		reader := newVMessBody(wire, q.key, q.iv, q)
		if _, err := reader.readChunk(); err == nil || len(reader.buffer) != 0 {
			t.Fatal("large chunk accepted outside none TCP compatibility", q)
		}
	}
}

func FuzzVMessBodyLength(f *testing.F) {
	f.Add([]byte{0, 0}, byte(0))
	for _, security := range []byte{3, 4, 5} {
		var wire bytes.Buffer
		q := vmessRequest{security: security, options: 29, command: 1}
		if security == 5 {
			q.options = 5
		}
		body := newVMessBody(&wire, q.key, q.iv, q)
		body.writeChunk([]byte("VMess authenticated length"))
		f.Add(bytes.Clone(wire.Bytes()), security)
	}
	f.Fuzz(func(t *testing.T, data []byte, security byte) {
		q := vmessRequest{security: 3 + security%3, options: 29, command: 1}
		if q.security == 5 {
			q.options = 5
		}
		body := newVMessBody(bytes.NewBuffer(data), q.key, q.iv, q)
		_, _ = body.readChunk()
	})
}

func TestVMessUDPWriteState(t *testing.T) {
	q := vmessRequest{security: 3, options: 29, command: 2}
	var wire bytes.Buffer
	c := newVMessConn(memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}, q, true)
	if _, err := c.Write(make([]byte, 16384)); err != errVMessChunkTooLarge {
		t.Fatal(err)
	}
	if c.writeErr != nil || c.writer.counter != 0 || wire.Len() != 0 {
		t.Fatal("oversized UDP consumed connection state")
	}
	if _, err := c.Write([]byte("valid retry")); err != nil {
		t.Fatal(err)
	}
	body := newVMessBody(&wire, q.key, q.iv, q)
	if data, err := body.readChunk(); err != nil || string(data) != "valid retry" {
		t.Fatal("retry after size rejection", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	right.Close()
	broken := newVMessConn(left, q, true)
	_, first := broken.Write([]byte("first"))
	if first == nil {
		t.Fatal("closed writer accepted packet")
	}
	counter := broken.writer.counter
	if _, err := broken.Write([]byte("second")); err != first || broken.writer.counter != counter {
		t.Fatal("write failure did not remain sticky", err)
	}
}

func BenchmarkVMessAuthenticatedLength(b *testing.B) {
	for _, security := range []byte{3, 4} {
		b.Run(fmt.Sprint(security), func(b *testing.B) {
			q := vmessRequest{security: security, options: 29}
			writer := newVMessBody(struct {
				io.Reader
				io.Writer
			}{Writer: io.Discard}, q.key, q.iv, q)
			data := make([]byte, 8192)
			writer.writeChunk(data)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for i := range b.N {
				writer.counter = uint32(i % 65536)
				if err := writer.writeChunk(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
