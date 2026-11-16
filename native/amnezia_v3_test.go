package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAmneziaWG3Frames(t *testing.T) {
	for _, version := range []string{"v3-header", "v3-trailers", "v3"} {
		t.Run(version, func(t *testing.T) {
			o, e := newWGObfuscation(awgTestOptions(version), nil, 1420)
			if e != nil {
				t.Fatal(e)
			}
			for i, size := range []int{148, 92, 64, 96} {
				body := make([]byte, size)
				rand.Read(body)
				binary.LittleEndian.PutUint32(body, o.header(uint32(i+1)))
				for range 16 {
					wire := o.wrap(uint32(i+1), body)
					if o.v3.key != nil && bytes.Equal(wire[o.padding[i]:o.padding[i]+4], body[:4]) {
						t.Fatal("unprotected header")
					}
					if i == 3 && !bytes.Equal(wire[o.padding[i]+16:o.padding[i]+size], body[16:]) {
						t.Fatal("header protection changed payload ciphertext")
					}
					got, kind := o.decode(wire)
					if kind != uint32(i+1) || !bytes.Equal(got, body) {
						t.Fatal("wire mismatch", i, kind, len(got))
					}
				}
			}
		})
	}
}

func TestAmneziaWG3Config(t *testing.T) {
	for _, raw := range []string{
		`{"header_protection_key":"invalid"}`, `{"header_protection_key":"` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + `","s1":12,"s2":12,"s3":11,"s4":12}`,
		`{"content_padding_addition":"0-2"}`, `{"content_padding_addition":"65508"}`, `{"content_padding_addition":"2-1"}`,
		`{"rekey_timeout":"86401"}`, `{"reject_after_time":"-1"}`, `{"keepalive_timeout":null}`, `{"max_handshake_attempts":"1025"}`,
		`{"persistent_keepalive_interval":"65536"}`, `{"rekey_after_time":"3-5","reject_after_time":"4-6"}`, `{"reject_after_time":10}`,
	} {
		var o AmneziaWGOptions
		err := json.Unmarshal([]byte(raw), &o)
		if err == nil {
			_, err = newWGObfuscation(&o, nil, 1420)
		}
		if err == nil {
			t.Fatal("invalid config accepted", raw)
		}
	}
	for _, raw := range []WGHeaderRange{"", "0", "(off)", "1", "1-86400"} {
		_, err := newWGObfuscation(&AmneziaWGOptions{RekeyTimeout: raw}, nil, 1420)
		if err != nil {
			t.Fatal(raw, err)
		}
	}
	var v wgV3
	if err := v.configure(awgTestOptions("v3"), [4]int{31, 17, 19, 23}, 1420); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if n := v.retry.pick(10); n < 1 || n > 2 {
			t.Fatal(n)
		}
	}
	if _, err := newWGObfuscation(&AmneziaWGOptions{ContentPaddingAddition: "100"}, nil, 65400); err == nil {
		t.Fatal("oversized UDP padding accepted")
	}
}

func TestAmneziaWG3PaddedKeepaliveAndExpiry(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	sender := &wgTransport{send: key, remote: 17, at: time.Now(), confirmed: true, rejectAfter: 3 * time.Second}
	receiver := &wgTransport{receive: key, local: 17, at: time.Now(), rejectAfter: 3 * time.Second}
	wire, err := sender.sealPadded(nil, 4, 0, 0, 78)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := receiver.open(wire); err != nil || len(got) != 0 {
		t.Fatal("padded keepalive", err)
	}
	if _, err := receiver.open(wire); err == nil {
		t.Fatal("keepalive replay accepted")
	}
	sender.at = time.Now().Add(-4 * time.Second)
	if _, err := sender.seal(nil); err == nil {
		t.Fatal("custom expiration ignored on send")
	}
	receiver.at = time.Now().Add(-4 * time.Second)
	if _, err := receiver.open(wire); err == nil {
		t.Fatal("custom expiration ignored on receive")
	}
	p := &wgPeer{obfs: &wgObfuscation{v3: wgV3{addition: wgMagic{32, 96}}}}
	if n := p.contentPadding(490); n != 10 {
		t.Fatal("padding exceeded UDP window", n)
	}
	if n := p.contentPadding(65507); n != 0 {
		t.Fatal("padding exceeded UDP maximum", n)
	}
}

func TestAmneziaWG3LiveRekey(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Amnezia: awgTestOptions("v3"), Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.54.0.2/32"}}}}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	o.Username, o.Password, o.UUID = "", "", ""
	o.PrivateKey = []string{clientKey}
	o.WireGuardOptions = WireGuardOptions{PublicKey: serverPub, LocalAddress: []string{"10.54.0.2/32"}, Amnezia: awgTestOptions("v3")}
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	origin := echoUDP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "udp", origin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(12 * time.Second))
	p := c.wgClients["proxy"].peer
	p.mu.Lock()
	initial := p.current.local
	p.mu.Unlock()
	for i := range 24 {
		want := []byte(strings.Repeat("active-key-rotation", 30) + string(rune(i)))
		if _, err := conn.Write(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 2048)
		n, err := conn.Read(got)
		if err != nil || !bytes.Equal(got[:n], want) {
			t.Fatal("live flow failed", i, err)
		}
		time.Sleep(125 * time.Millisecond)
	}
	p.mu.Lock()
	changed := p.current.local != initial
	p.mu.Unlock()
	if !changed {
		t.Fatal("active flow never rekeyed")
	}
}

func TestAmneziaWG3Cookies(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "enabled", true: "disabled"}[disabled], func(t *testing.T) {
			priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
			client, _ := ecdh.X25519().GenerateKey(rand.Reader)
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			remote, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			options := awgTestOptions("v3")
			options.DisableCookies = disabled
			obfs, err := newWGObfuscation(options, nil, 1420)
			if err != nil {
				t.Fatal(err)
			}
			l := &wgListener{private: priv, packet: packet, obfs: obfs, until: time.Now().Add(time.Minute), cookieTokens: 20}
			h, err := wgInitiateKind(client, priv.PublicKey().Bytes(), make([]byte, 32), obfs.header(1))
			if err != nil {
				t.Fatal(err)
			}
			if l.allowInitiation(h.message, remote.LocalAddr()) {
				t.Fatal("unchallenged overloaded initiation")
			}
			remote.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 65535)
			n, _, err := remote.ReadFrom(buf)
			if disabled {
				if err == nil {
					t.Fatal("disabled cookie emitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			body, kind := obfs.decode(buf[:n])
			if kind != 3 {
				t.Fatal("cookie framing", kind)
			}
			if err := h.cookieKind(body, binary.LittleEndian.Uint32(body)); err != nil {
				t.Fatal(err)
			}
			if !l.allowInitiation(h.message, remote.LocalAddr()) {
				t.Fatal("valid source cookie rejected")
			}
			changed := remote.LocalAddr().(*net.UDPAddr)
			other := *changed
			other.Port++
			if l.allowInitiation(h.message, &other) {
				t.Fatal("cookie accepted for different endpoint")
			}
		})
	}
}

func TestAmneziaWG3HeaderTamper(t *testing.T) {
	o, _ := newWGObfuscation(awgTestOptions("v3"), nil, 1420)
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client, _ := ecdh.X25519().GenerateKey(rand.Reader)
	h, _ := wgInitiateKind(client, priv.PublicKey().Bytes(), make([]byte, 32), o.header(1))
	wire := o.wrap(1, h.message)
	wire[o.prefix(1)+50] ^= 1
	body, kind := o.decode(wire)
	if kind == 1 {
		if _, _, _, _, err := wgReadInitiationKind(priv, body, binary.LittleEndian.Uint32(body)); err == nil {
			t.Fatal("tampered handshake accepted")
		}
	}
}

func TestAmneziaWG3HandshakeBudget(t *testing.T) {
	r := newTestRuntime(t, Config{})
	client, _ := wgTestKey(t)
	_, server := wgTestKey(t)
	p, err := newWGPeer(r, []string{client}, server, "", []string{"10.54.0.2/32"}, nil, "", 1420, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer p.close()
	options := &AmneziaWGOptions{RekeyTimeout: "1", MaxHandshakeAttempts: "2"}
	p.obfs, err = newWGObfuscation(options, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	p.remote = streamAddr("dropped-handshakes")
	sent := 0
	p.sender = func(b []byte, _ net.Addr) error {
		if binary.LittleEndian.Uint32(b) == 1 {
			sent++
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	err = p.ensure(ctx)
	if err == nil || sent != 2 || time.Since(start) < 2*time.Second {
		t.Fatal("retry timer/budget not applied", sent, err, time.Since(start))
	}
}
