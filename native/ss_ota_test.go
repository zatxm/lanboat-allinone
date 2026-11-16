package native

import (
	"bytes"
	"io"
	"testing"
)

func TestSSOTAEndToEnd(t *testing.T) {
	for _, method := range ShadowsocksMethods() {
		if validateSSOTA("shadowsocks", method) != nil {
			continue
		}
		t.Run(method, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Method, in.OTA = method, true
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.OTA = true
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096})
		})
	}
}

func TestAddedSSRCiphers(t *testing.T) {
	for _, method := range addedSSMethods {
		t.Run(method, func(t *testing.T) {
			in := testInbound(t, "shadowsocksr")
			in.Method, in.Protocol, in.Password = method, "auth_sha1_v4", "private"
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Protocol = in.Protocol
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDP(t, client)
		})
	}
}

func TestSSOTAOptionValidation(t *testing.T) {
	for _, method := range []string{"none", "table", "rc4", "rc4-md5-6", "aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		if err := validateSSOTA("shadowsocks", method); err == nil {
			t.Fatal("OTA accepted method without a random stream IV", method)
		}
	}
	if err := validateSSOTA("http", "aes-256-cfb"); err == nil {
		t.Fatal("OTA accepted for another protocol")
	}
	for _, config := range []string{
		`{"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":1234,"method":"none","password":"private","ota":true}]}`,
		`{"outbounds":[{"type":"shadowsocks","tag":"proxy","server":"127.0.0.1","server_port":1234,"method":"aes-128-gcm","password":"private","ota":true}]}`,
		`{"outbounds":[{"type":"direct","tag":"direct","ota":true}]}`,
	} {
		if _, err := Parse([]byte(config)); err == nil {
			t.Fatal("accepted invalid ota configuration", config)
		}
	}
}

func TestSSOTAIntegrity(t *testing.T) {
	for _, method := range append([]string{"aes-256-cfb"}, addedSSMethods...) {
		t.Run(method, func(t *testing.T) {
			key, err := newSSKey(method, "private")
			if err != nil {
				t.Fatal(err)
			}
			address, _ := encodeAddress("example.com:443")
			payload := bytes.Repeat([]byte("OTA payload"), 9000)
			var wire bytes.Buffer
			client, err := ssrClient(memoryNetConn{bytes.NewReader(nil), &wire}, Outbound{Protocol: "verify_sha1"}, key)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeAll(client, address); err != nil {
				t.Fatal(err)
			}
			if err := writeAll(client, payload); err != nil {
				t.Fatal(err)
			}
			server, err := ssrAccept(readerConn(wire.Bytes()), Inbound{Protocol: "verify_sha1"}, key, &replayWindow{})
			if err != nil {
				t.Fatal(err)
			}
			if got, err := readSSRAddress(server); err != nil || got != "example.com:443" {
				t.Fatal(got, err)
			}
			got, err := io.ReadAll(server)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("multi-frame integrity", err)
			}
			_, ivSize, _ := ssStreamParameters(method)
			for _, offset := range []int{ivSize, ivSize + len(address) + 3, wire.Len() - 1} {
				corrupt := append([]byte{}, wire.Bytes()...)
				corrupt[offset] ^= 1
				server, err := ssrAccept(readerConn(corrupt), Inbound{Protocol: "verify_sha1"}, key, &replayWindow{})
				if err == nil {
					_, err = readSSRAddress(server)
				}
				if err == nil {
					_, err = io.ReadAll(server)
				}
				if err == nil {
					t.Fatal("OTA accepted modified TCP data", offset)
				}
			}
			codec, _ := newSSRDatagrams(key, "verify_sha1", "")
			body := append(address, []byte("UDP authenticated payload")...)
			packet, err := codec.seal(append([]byte{}, body...), false)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := codec.open(packet, true); err != nil || !bytes.Equal(got, body) {
				t.Fatal("UDP integrity", err)
			}
			packet[len(packet)-1] ^= 1
			if _, err := codec.open(packet, true); err == nil {
				t.Fatal("OTA accepted modified UDP data")
			}
		})
	}
}

func FuzzLegacyCipherBlocks(f *testing.F) {
	f.Add([]byte("independent cipher input"), byte(0))
	f.Add(make([]byte, 64), byte(4))
	f.Fuzz(func(t *testing.T, data []byte, which byte) {
		method := addedSSMethods[int(which)%len(addedSSMethods)]
		size, _, _ := ssStreamParameters(method)
		key := make([]byte, size)
		copy(key, data)
		block, err := newSSStreamBlock(method, key)
		if err != nil {
			t.Fatal(err)
		}
		plain := make([]byte, block.BlockSize())
		if len(data) > size {
			copy(plain, data[size:])
		}
		buf := append([]byte{}, plain...)
		block.Encrypt(buf, buf)
		block.Decrypt(buf, buf)
		if !bytes.Equal(buf, plain) {
			t.Fatal("block inverse mismatch")
		}
		stream := &ssKey{method: method, master: key, streamBlock: block}
		packet, err := stream.sealStreamPacket(data)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := stream.openStreamPacket(packet)
		if err != nil || !bytes.Equal(decoded, data) {
			t.Fatal("packet inverse mismatch", err)
		}
	})
}
