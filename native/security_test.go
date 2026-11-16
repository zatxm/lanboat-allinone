package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestConfigRejectsInvalidAndUnimplementedFields(t *testing.T) {
	for _, raw := range []string{
		`{"route":{"rules":[{"response_rcode":"NXDOMAIN","outbound":"direct"}]}}`,
		`{"route":{"rules":[{"type":"logical","mode":"and","ip_version":6,"rules":[{}],"outbound":"direct"}]}}`,
		`null`, `{}`, // empty object is valid; handled separately below
		`{} {}`, `{"outbounds":[{"type":"direct","tag":"same"},{"type":"direct","tag":"same"}]}`,
		`{"outbounds":[{"type":"socks","tag":"a","server":"127.0.0.1","server_port":1,"detour":"a"}]}`,
		`{"inbounds":[{"type":"trojan","users":[{"password":"p"}]}]}`,
		`{"inbounds":[{"type":"vless","users":[{"uuid":"invalid"}]}]}`,
		`{"outbounds":[{"type":"shadowsocks","tag":"s","server":"s","server_port":1,"method":"aes-256-gcm"}]}`,
		`{"outbounds":[{"type":"socks","tag":"s","server":"s","server_port":65536}]}`,
		`{"route":{"final":"missing"}}`, `{"route":{"rules":[{"outbound":"missing"}]}}`,
		`{"inbounds":[{"type":"tun","stack":"gvisor"}]}`, `{"outbounds":[{"type":"hysteria2","tag":"hy2"}]}`,
		`{"experimental":{"unknown":true}}`, `{"outbounds":[{"type":"direct","tag":"d","transport":{"type":"ws"}}]}`,
	} {
		if raw == `{}` {
			if _, err := Parse([]byte(raw)); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if _, err := Parse([]byte(raw)); err == nil {
			t.Errorf("invalid or unimplemented configuration accepted: %s", raw)
		}
	}
}

func TestAddressRoundTrip(t *testing.T) {
	for _, address := range []string{"four:443", "sixteenlettersxx:53", "example.com:65535", "127.0.0.1:80", "[2001:db8::42]:443"} {
		encoded, err := encodeAddress(address)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := readAddress(bytes.NewReader(encoded))
		if err != nil || decoded != address {
			t.Fatalf("address roundtrip %q -> %q: %v", address, decoded, err)
		}
		vless, err := vlessAddress(address)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err = readVLESSAddress(bytes.NewReader(vless))
		if err != nil || decoded != address {
			t.Fatalf("VLESS address roundtrip: %q %v", decoded, err)
		}
	}
}

func TestRejectsHTTPAuthorityInjection(t *testing.T) {
	for _, address := range []string{"evil\r\nX-Injected: yes:80", "evil\r\n:80", "bad host:80", "user@host:443", "host/extra:443", "[bad:ipv6]:443", "host\x01:80"} {
		if _, err := encodeAddress(address); err == nil {
			t.Errorf("invalid proxy authority accepted: %q", address)
		}
	}
}

func TestShadowsocksReplayAndTamper(t *testing.T) {
	key, err := newSSKey("aes-256-gcm", "private")
	if err != nil {
		t.Fatal(err)
	}
	var sender, receiver replayWindow
	packet, err := key.sealPacket([]byte("authenticated data"), &sender)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(packet)
	bad[len(bad)-1] ^= 1
	if _, err := key.openPacket(bad, &receiver); err == nil {
		t.Fatal("tampered UDP data accepted")
	}
	if _, err := key.openPacket(packet, &receiver); err != nil {
		t.Fatal("tampering poisoned valid salt", err)
	}
	if _, err := key.openPacket(packet, &receiver); err == nil {
		t.Fatal("replayed UDP data accepted")
	}
	if _, err := key.openPacket(packet, &sender); err == nil {
		t.Fatal("reflected client packet accepted")
	}
}

func TestStartFailureReleasesPreviouslyBoundPorts(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	first := unusedPort(t)
	raw, _ := json.Marshal(Config{Inbounds: []Inbound{{Type: "mixed", Tag: "first", Listen: "127.0.0.1", ListenPort: first}, {Type: "mixed", Tag: "busy", Listen: "127.0.0.1", ListenPort: uint16(busy.Addr().(*net.TCPAddr).Port)}}})
	r, err := New(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.Start(); err == nil {
		t.Fatal("occupied inbound port accepted")
	}
	reopened, err := net.Listen("tcp", portAddress("127.0.0.1", first))
	if err != nil {
		t.Fatal("failed Start leaked prior listener", err)
	}
	reopened.Close()
}

func TestHTTPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, _ := io.ReadAll(c)
		_ = writeAll(c, append([]byte("response:"), data...))
	}()
	in := testInbound(t, "http")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	c, err := client.Dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if err := writeAll(c, []byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "response:request" {
		t.Fatalf("half close discarded response: %q %v", b, err)
	}
}

func TestContextCancellationInterruptsHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(io.Discard, c)
	}()
	out := testOutbound(t, Inbound{Type: "socks"}, listener.Addr().String())
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	before := time.Now()
	c, err := client.Dial(ctx, "tcp", "example.com:443")
	if c != nil {
		c.Close()
	}
	if err == nil || time.Since(before) > time.Second {
		t.Fatal("handshake ignored context cancellation", err)
	}
}

func TestParentCancellationWhileConstructing(t *testing.T) {
	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		go cancel()
		r, err := New(ctx, []byte(`{}`), zap.NewNop())
		if err == nil {
			_ = r.Close()
		}
	}
}

func FuzzShadowsocksPacket(f *testing.F) {
	key, _ := newSSKey("aes-256-gcm", "packet-fuzz-password")
	var sent replayWindow
	valid, _ := key.sealPacket([]byte("test"), &sent)
	f.Add(valid)
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, packet []byte) { var received replayWindow; _, _ = key.openPacket(packet, &received) })
}

func TestLogicalRouteAndDomainBoundaries(t *testing.T) {
	config := Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct", Rules: []Rule{{Type: "logical", Mode: "and", Action: "reject", Rules: []Rule{{DomainSuffix: []string{"example.com"}}, {Port: []uint16{443}}}}}}}
	r := newTestRuntime(t, config)
	_, err := r.Dial(context.Background(), "tcp", "sub.example.com:443")
	if !errors.Is(err, ErrRejected) {
		t.Fatal("logical route not enforced", err)
	}
	rules, _ := compileRoute(config.Route, map[string]Outbound{"direct": {Type: "direct"}})
	if rules[0].matches(request{network: "tcp", address: "notexample.com:443"}) {
		t.Fatal("domain suffix matched across label boundary")
	}
	if rules[0].matches(request{network: "tcp", address: "sub.example.com:80"}) {
		t.Fatal("logical AND ignored port condition")
	}
}

func FuzzAddressDecoder(f *testing.F) {
	for _, value := range []string{"example.com:443", "127.0.0.1:80", "[::1]:53"} {
		b, _ := encodeAddress(value)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = readAddress(bytes.NewReader(b))
		_, _ = readVLESSAddress(bytes.NewReader(b))
	})
}

func TestHeaderLimit(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", 65537) + "\r\n\r\n"))
	if _, err := readHTTPHeader(reader); err == nil {
		t.Fatal("unbounded HTTP headers accepted")
	}
}
