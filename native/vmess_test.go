package native

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestVMessAuthenticationReplayAndTamper(t *testing.T) {
	in := testInbound(t, "vmess")
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	u, _ := newVMessUser(testUUID)
	q := vmessRequest{security: 3, options: 13, command: 1, address: "example.org:443"}
	_, _ = rand.Read(q.key[:])
	_, _ = rand.Read(q.iv[:])
	var wire bytes.Buffer
	if err := writeVMessRequest(&wire, u, q); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 17, 42, wire.Len() - 1} {
		bad := bytes.Clone(wire.Bytes())
		bad[offset] ^= 1
		if _, err := r.readVMessRequest(bytes.NewReader(bad), "server"); err == nil {
			t.Fatal("accepted modified authentication header", offset)
		}
	}
	if got, err := r.readVMessRequest(bytes.NewReader(wire.Bytes()), "server"); err != nil || got.address != q.address {
		t.Fatal("valid header after tampering", err)
	}
	if _, err := r.readVMessRequest(bytes.NewReader(wire.Bytes()), "server"); err == nil {
		t.Fatal("accepted replay")
	}
}

func TestVMessUDPSizeRejectionAndNonceLimit(t *testing.T) {
	for _, security := range []byte{3, 4, 5} {
		var wire bytes.Buffer
		q := vmessRequest{security: security, options: 13, command: 2}
		writer, reader := newVMessBody(&wire, q.key, q.iv, q), newVMessBody(&wire, q.key, q.iv, q)
		if err := writer.writeChunk(make([]byte, 16384)); err == nil || wire.Len() != 0 {
			t.Fatal("oversize was not rejected before writing")
		}
		if err := writer.writeChunk([]byte("valid")); err != nil {
			t.Fatal(err)
		}
		if got, err := reader.readChunk(); err != nil || string(got) != "valid" {
			t.Fatalf("rejected datagram desynchronized body: %q %v", got, err)
		}
		writer.counter = 65535
		if _, err := writer.nonce(); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.nonce(); err == nil {
			t.Fatal("VMess nonce repeated")
		}
	}
}

func TestVMessIndependentTCPUDP(t *testing.T) {
	for _, security := range []string{"auto", "aes-128-gcm", "none", "zero", "chacha20-poly1305"} {
		t.Run(security, func(t *testing.T) {
			in := Inbound{Type: "vmess", Tag: "server", Listen: "127.0.0.1", Users: []User{{UUID: testUUID}}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Security = security
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096})
		})
	}
}

func TestVMessReferenceInterop(t *testing.T) {
	for _, security := range []string{"aes-128-gcm", "none", "zero", "chacha20-poly1305"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(security+"/"+direction, func(t *testing.T) {
				in := Inbound{Type: "vmess", Tag: "server", Listen: "127.0.0.1", Users: []User{{UUID: testUUID}}}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.Security = security
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address("server"))
					out.Username, out.Password = "", ""
					out.Security = security
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
					front := testOutbound(t, local, portAddress(local.Listen, local.ListenPort))
					front.Username, front.Password, front.UUID = "", "", ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}
