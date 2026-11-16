package native

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

func TestSSRRandomHeadAmbiguousCRC(t *testing.T) {
	// This locally generated header has the CRC residue at both bytes 35 and 36.
	head, _ := hex.DecodeString("488046ca0a9ef7f25c1a5d5c91a2137fa471623f76ebe10973b8e59124c2ac518b389600")
	if ssrRandomHeadEnd(head) != 35 {
		t.Fatal("regression fixture lost its ambiguous residue")
	}
	key, _ := newSSKey("aes-256-cfb", "private")
	var wire bytes.Buffer
	client, _ := ssrClient(memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}, Outbound{Protocol: "auth_sha1_v4"}, key)
	address, _ := encodeAddress("127.0.0.1:443")
	client.Write(address)
	input := io.MultiReader(bytes.NewReader(head), bytes.NewReader(wire.Bytes()))
	server, e := ssrAccept(memoryNetConn{Reader: input, Writer: io.Discard}, Inbound{Protocol: "auth_sha1_v4", Obfs: "random_head"}, key, &replayWindow{})
	if e != nil {
		t.Fatal(e)
	}
	if a, e := readAddress(server); e != nil || a != "127.0.0.1:443" {
		t.Fatal(a, e)
	}
	for range 4096 {
		b := ssrRandomHead()
		if ssrRandomHeadEnd(b) != len(b) {
			t.Fatal("generated ambiguous random head")
		}
	}
}

func TestSSRRandomHeadFirstFrame(t *testing.T) {
	key, _ := newSSKey("aes-256-cfb", "private")
	address, _ := encodeAddress("127.0.0.1:443")
	for i := 0; i < 4096; i++ {
		var wire bytes.Buffer
		client, e := ssrClient(memoryNetConn{Reader: bytes.NewReader(make([]byte, 36)), Writer: &wire}, Outbound{Protocol: "auth_sha1_v4", Obfs: "random_head"}, key)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = client.Write(address); e != nil {
			t.Fatal(e)
		}
		input := io.MultiReader(bytes.NewReader(wire.Bytes()[:36]), bytes.NewReader(wire.Bytes()[36:]))
		server, e := ssrAccept(memoryNetConn{Reader: input, Writer: io.Discard}, Inbound{Protocol: "auth_sha1_v4", Obfs: "random_head"}, key, &replayWindow{})
		if e != nil {
			t.Fatalf("iteration=%d wire=%x error=%v", i, wire.Bytes(), e)
		}
		if a, e := readAddress(server); e != nil || a != "127.0.0.1:443" {
			t.Fatalf("address=%s error=%v", a, e)
		}
	}
}
