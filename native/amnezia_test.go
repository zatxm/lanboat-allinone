package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func awgTestOptions(version string) *AmneziaWGOptions {
	o := &AmneziaWGOptions{Jc: 3, JMin: 16, JMax: 48}
	if version == "plain" {
		return o
	}
	o.S1, o.S2 = 31, 17
	o.H1, o.H2, o.H3, o.H4 = "1010", "2030", "3050", "4070"
	if version == "v2" || strings.HasPrefix(version, "v3") {
		o.S3, o.S4 = 9, 13
		o.H1, o.H2, o.H3, o.H4 = "1010-1020", "2030-2040", "3050-3060", "4070-4080"
		o.I1 = "<b 0xf0010203><r 7><t><rc 8><rd 3>"
		o.I3 = "<b 0xff1122>"
	}
	if version == "v3-header" || version == "v3" {
		o.HeaderProtectionKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x47}, 32))
		o.S3, o.S4 = 19, 23
	}
	if version == "v3-padding" || version == "v3" {
		o.ContentPaddingAddition = "32-96"
	}
	if version == "v3-trailers" || version == "v3" {
		o.RandomTrailers = true
	}
	if version == "v3-timers" || version == "v3" {
		o.RekeyAfterTime, o.RekeyTimeout, o.RejectAfterTime = "1-2", "1-2", "10-12"
		o.KeepaliveTimeout, o.MaxHandshakeAttempts, o.PersistentKeepalive = "1-2", "3-4", "1-2"
	}
	return o
}

func TestAmneziaWGIndependent(t *testing.T) {
	for _, version := range []string{"plain", "v1", "v2", "v3-header", "v3-padding", "v3-trailers", "v3-timers", "v3"} {
		t.Run(version, func(t *testing.T) {
			serverKey, serverPub := wgTestKey(t)
			clientKey, clientPub := wgTestKey(t)
			psk, _ := wgTestKey(t)
			in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Amnezia: awgTestOptions(version), Peers: []WireGuardPeer{{PublicKey: clientPub, PreSharedKey: psk, AllowedIPs: []string{"10.54.0.2/32"}}}}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Password, out.Username, out.UUID = "", "", ""
			out.PrivateKey = []string{clientKey}
			out.WireGuardOptions = WireGuardOptions{PublicKey: serverPub, PreSharedKey: psk, LocalAddress: []string{"10.54.0.2/32"}, Amnezia: awgTestOptions(version)}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
		})
	}
}

func TestAmneziaWGIPv6(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Amnezia: awgTestOptions("v2"), Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"fd54::2/128"}}}}}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Password, out.Username, out.UUID = "", "", ""
	out.PrivateKey = []string{clientKey}
	out.WireGuardOptions = WireGuardOptions{PublicKey: serverPub, LocalAddress: []string{"fd54::2/128"}, Amnezia: awgTestOptions("v2")}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	tcp, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		c, err := tcp.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(c, c)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "tcp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	want := bytes.Repeat([]byte("IPv6 AWG"), 10000)
	done := make(chan error, 1)
	go func() { done <- writeAll(c, want) }()
	got := make([]byte, len(want))
	if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(want, got) {
		t.Fatal("IPv6 TCP", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	u, err := client.Dial(ctx, "udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(4 * time.Second))
	want = bytes.Repeat([]byte{0x54}, 60000)
	if _, err = u.Write(want); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, 65535)
	n, err := u.Read(got)
	if err != nil || !bytes.Equal(want, got[:n]) {
		t.Fatal("IPv6 UDP", n, err)
	}
}

func TestAmneziaWGConfiguration(t *testing.T) {
	for _, mtu := range []int{65473, 65507} {
		if _, err := newWGObfuscation(nil, nil, mtu); err == nil {
			t.Fatal("accepted oversized encrypted WireGuard packet", mtu)
		}
	}
	if _, err := newWGObfuscation(nil, nil, 65472); err != nil {
		t.Fatal("rejected maximum WireGuard MTU", err)
	}
	for _, raw := range []string{`1010`, `"1010"`, `"1010-1030"`, `4294967295`, `"0-4294967295"`} {
		var value WGHeaderRange
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			t.Fatal(raw, err)
		}
		if _, err := parseWGMagic(value, 1); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{`-1`, `4294967296`, `true`, `null`, `{}`, `"3-2"`, `"1-2-3"`, `"foo"`} {
		var value WGHeaderRange
		err := json.Unmarshal([]byte(raw), &value)
		if err == nil {
			_, err = parseWGMagic(value, 1)
		}
		if err == nil {
			t.Fatal("accepted invalid header", raw)
		}
	}
	for _, opts := range []*AmneziaWGOptions{
		{H1: "1-4"}, {H1: "5-8", H2: "8-10"}, {S1: 65535}, {S2: 65535}, {S3: 65535}, {S4: 65535},
		{Jc: 1}, {JMin: 100, JMax: 99}, {Jc: 65535, JMax: 65000}, {I1: "<unknown>"},
	} {
		if _, err := newWGObfuscation(opts, nil, 1420); err == nil {
			t.Fatal("accepted invalid AmneziaWG options", opts)
		}
	}
	key, pub := wgTestKey(t)
	for _, side := range []string{"inbound", "outbound"} {
		cfg := Config{}
		if side == "inbound" {
			cfg.Inbounds = []Inbound{{Type: "wireguard", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{key}}, WireGuardOptions: WireGuardOptions{Amnezia: awgTestOptions("v2"), Peers: []WireGuardPeer{{PublicKey: pub, AllowedIPs: []string{"10.54.0.2/32"}}}}}}
		} else {
			cfg.Outbounds = []Outbound{{Type: "wireguard", Tag: "proxy", Server: "127.0.0.1", ServerPort: 5555, SSHOptions: SSHOptions{PrivateKey: []string{key}}, WireGuardOptions: WireGuardOptions{Amnezia: awgTestOptions("v2"), PublicKey: pub, LocalAddress: []string{"10.54.0.2/32"}}}}
		}
		data, _ := json.Marshal(cfg)
		if _, err := Parse(data); err != nil {
			t.Fatal(side, err)
		}
	}
	if _, err := Parse([]byte(`{"outbounds":[{"type":"direct","tag":"d","amnezia":{}}]}`)); err == nil {
		t.Fatal("ignored AmneziaWG on another protocol")
	}
}

func TestAmneziaWGCPS(t *testing.T) {
	for _, raw := range []string{"x", "<b>", "<b 0x>", "<b 0xz1>", "<r -1>", "<r 1001>", "<rc 1001>", "<rd 1001>", "<t><t>", "<t 1>", "<r>", "<r 1>", strings.Repeat("<r 1>", 257)} {
		if raw == "<r 1>" {
			raw = "<r 1"
		}
		if _, err := parseWGSignature(raw); err == nil {
			t.Fatal("accepted invalid signature", raw)
		}
	}
	s, err := parseWGSignature(" <b 0xaabbcc> <r 7><t><rc 25><rd 35>")
	if err != nil {
		t.Fatal(err)
	}
	first, second := s.packet(), s.packet()
	if len(first) != 74 || !bytes.Equal(first[:3], []byte{0xaa, 0xbb, 0xcc}) || bytes.Equal(first[3:10], second[3:10]) {
		t.Fatal("invalid CPS bytes")
	}
	stamp := int64(binary.BigEndian.Uint32(first[10:]))
	if delta := time.Now().Unix() - stamp; delta < 0 || delta > 1 {
		t.Fatal("invalid CPS timestamp", stamp)
	}
	for _, b := range first[14:39] {
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z') {
			t.Fatal("non-ASCII CPS character")
		}
	}
	for _, b := range first[39:] {
		if b < '0' || b > '9' {
			t.Fatal("non-digit CPS byte")
		}
	}
	o, _ := newWGObfuscation(awgTestOptions("v2"), nil, 1420)
	var packets [][]byte
	if err := o.decoys(context.Background(), func(b []byte) error { packets = append(packets, b); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(packets) != 5 || !bytes.HasPrefix(packets[0], []byte{0xf0, 1, 2, 3}) || !bytes.Equal(packets[1], []byte{0xff, 0x11, 0x22}) {
		t.Fatal("CPS ordering or missing index handling")
	}
	for _, p := range packets[2:] {
		if len(p) < 16 || len(p) > 48 {
			t.Fatal("junk length")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.decoys(ctx, func([]byte) error { t.Fatal("sent cancelled junk"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	want := errors.New("send failed")
	if err := o.decoys(context.Background(), func([]byte) error { return want }); err != want {
		t.Fatal("discarded send error", err)
	}
}

func TestAmneziaWGAuthenticatedWire(t *testing.T) {
	a, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b, _ := ecdh.X25519().GenerateKey(rand.Reader)
	o, err := newWGObfuscation(awgTestOptions("v2"), nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	s, err := wgInitiateKind(a, b.PublicKey().Bytes(), make([]byte, 32), o.header(1))
	if err != nil {
		t.Fatal(err)
	}
	init, kind := o.decode(o.wrap(1, s.message))
	if kind != 1 {
		t.Fatal("init padding")
	}
	pub, stamp, ck, h, err := wgReadInitiationKind(b, init, binary.LittleEndian.Uint32(init))
	if err != nil || len(stamp) != 12 {
		t.Fatal(err)
	}
	if _, _, _, _, err := wgReadInitiation(b, init); err == nil {
		t.Fatal("standard WG accepted custom type")
	}
	corrupt := append([]byte{}, init...)
	corrupt[0] ^= 1
	if _, _, _, _, err := wgReadInitiationKind(b, corrupt, binary.LittleEndian.Uint32(corrupt)); err == nil {
		t.Fatal("MAC1 did not authenticate magic header")
	}
	reply, server, err := wgRespondKind(b, pub, make([]byte, 32), ck, h, init, o.header(2))
	if err != nil {
		t.Fatal(err)
	}
	reply, kind = o.decode(o.wrap(2, reply))
	if kind != 2 {
		t.Fatal("response padding")
	}
	client, err := s.responseKind(reply, binary.LittleEndian.Uint32(reply))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := client.sealPrefixed(nil, o.header(4), o.prefix(4), 0)
	if err != nil {
		t.Fatal(err)
	}
	packet, kind = o.decode(packet)
	if kind != 4 {
		t.Fatal("transport padding")
	}
	if _, err := server.openKind(packet, binary.LittleEndian.Uint32(packet)); err != nil {
		t.Fatal(err)
	}
	if _, err := server.openKind(packet, binary.LittleEndian.Uint32(packet)); err == nil {
		t.Fatal("custom-header transport replay accepted")
	}
	// Cookie AAD is the MAC1 of the actual custom-header initiation, not a normalized packet.
	cookie := bytes.Repeat([]byte{0x54}, 16)
	key := blake2s(append([]byte("cookie--"), s.remote...), nil, 32)
	aead, _ := newChaChaAEAD(key, true)
	nonce := bytes.Repeat([]byte{0x23}, 24)
	response := binary.LittleEndian.AppendUint32(nil, o.header(3))
	response = binary.LittleEndian.AppendUint32(response, s.index)
	response = append(response, nonce...)
	response = aead.Seal(response, nonce, cookie, s.message[116:132])
	response, kind = o.decode(o.wrap(3, response))
	if kind != 3 {
		t.Fatal("cookie padding")
	}
	if err := s.cookieKind(response, binary.LittleEndian.Uint32(response)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s.message[132:], blake2s(s.message[:132], cookie, 16)) {
		t.Fatal("cookie MAC2 did not use the wire header")
	}
	response[len(response)-1] ^= 1
	if err := s.cookieKind(response, binary.LittleEndian.Uint32(response)); err == nil {
		t.Fatal("tampered cookie accepted")
	}
	for _, raw := range [][]byte{nil, {1}, make([]byte, 100), o.wrap(1, make([]byte, 147))} {
		if _, kind := o.decode(raw); kind != 0 {
			t.Fatal("malformed packet classified", len(raw), kind)
		}
	}
}

func FuzzAmneziaWG(f *testing.F) {
	f.Add([]byte("<b 0x01><r 10><t>"), byte(0))
	f.Add(make([]byte, 180), byte(1))
	f.Fuzz(func(t *testing.T, data []byte, which byte) {
		if which&1 == 0 {
			_, _ = parseWGSignature(string(data))
			return
		}
		version := "v2"
		if which&2 != 0 {
			version = "v3"
		}
		o, _ := newWGObfuscation(awgTestOptions(version), nil, 1420)
		body, kind := o.decode(data)
		if kind != 0 && len(body) < 4 {
			t.Fatal("short decoded packet")
		}
	})
}
