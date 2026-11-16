package native

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestWireGuardRekeyAndLostHandshake(t *testing.T) {
	a, _ := wgTestKey(t)
	b, pub := wgTestKey(t)
	_, clientPub := func() (string, string) {
		key, _ := wgKey(a)
		p, _ := ecdh.X25519().NewPrivateKey(key)
		return a, base64.StdEncoding.EncodeToString(p.PublicKey().Bytes())
	}()
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "wg", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{b}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.21.0.2/32"}}}}}}})
	o := testOutbound(t, Inbound{Type: "wireguard"}, server.Address("wg"))
	o.Username, o.Password, o.UUID = "", "", ""
	o.PrivateKey = []string{a}
	o.WireGuardOptions = WireGuardOptions{PublicKey: pub, LocalAddress: []string{"10.21.0.2/32"}}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	peer, e := client.wgClients["proxy"].session(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Lose the first valid response: initiation retry must recover without creating a new session for a replay.
	sp := server.wgListeners["wg"].peers[0]
	sp.mu.Lock()
	original := sp.sender
	var dropped atomic.Bool
	sp.sender = func(b []byte, a net.Addr) error {
		if len(b) == 92 && dropped.CompareAndSwap(false, true) {
			return nil
		}
		return original(b, a)
	}
	sp.mu.Unlock()
	if e = peer.ensure(ctx); e != nil {
		t.Fatal(e)
	}
	assertUDPSizes(t, client, []int{511, 4096})
	peer.mu.Lock()
	old := peer.current
	old.at = time.Now().Add(-121 * time.Second)
	peer.mu.Unlock()
	if e = peer.ensure(ctx); e != nil {
		t.Fatal(e)
	}
	peer.mu.Lock()
	changed := peer.current != old
	peer.mu.Unlock()
	if !changed {
		t.Fatal("old transport key reused")
	}
	assertTCP(t, client)
}
func TestWireGuardTCPRetransmission(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "s", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.25.0.2/32"}}}}}}})
	o := testOutbound(t, Inbound{Type: "wireguard"}, server.Address("s"))
	o.PrivateKey = []string{clientKey}
	o.WireGuardOptions = WireGuardOptions{PublicKey: serverPub, LocalAddress: []string{"10.25.0.2/32"}}
	o.Username, o.Password, o.UUID = "", "", ""
	client := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, e := client.wgClients["proxy"].session(ctx)
	if e != nil {
		t.Fatal(e)
	}
	original := p.sender
	var n atomic.Int64
	p.sender = func(b []byte, a net.Addr) error {
		if len(b) > 32 && binary.LittleEndian.Uint32(b) == 4 && n.Add(1)%11 == 0 {
			return nil
		}
		return original(b, a)
	}
	assertTCP(t, client)
}
func TestLegacyDatagramLimits(t *testing.T) {
	s := newQUICProxySession(nil, "tuic")
	s.version = 4
	if e := s.sendTUIC4Packet(1, "example.com:53", make([]byte, 2000), false); e == nil {
		t.Fatal("oversized native TUIC4 packet accepted")
	}
	for _, kind := range []string{"hysteria", "hysteria2", "tuic"} {
		s.kind = kind
		for n := 0; n < 16; n++ {
			s.decodePacket(make([]byte, n))
		}
	}
}
func TestQUICRateLimiter(t *testing.T) {
	c := &quicConn{}
	c.sendRate.Store(125000)
	c.rateAt = time.Now()
	c.rateTokens = 0
	c.spaces[2].queue = []quicFrame{{data: []byte{1}, level: 2}}
	c.spaces[2].write = &quicKey{}
	c.spaces[2].ack = false
	if e := c.flush(time.Now()); e != nil {
		t.Fatal(e)
	}
	if c.rateNext.IsZero() || len(c.spaces[2].queue) != 1 {
		t.Fatal("rate pacing failed")
	}
}
func TestSSHWireAuthentication(t *testing.T) {
	key, pub := sshTestKey(t)
	private, e := sshPrivate([]string{key}, "")
	if e != nil {
		t.Fatal(e)
	}
	blob, e := sshPubKey(private.Public())
	if e != nil {
		t.Fatal(e)
	}
	if !sshPinned(blob, []string{pub}) {
		t.Fatal("pin mismatch")
	}
	message := []byte("SSH handshake message")
	signature, e := sshSign(private, "ssh-ed25519", message)
	if e != nil || sshVerify(blob, "ssh-ed25519", message, signature) != nil {
		t.Fatal(e)
	}
	signature[len(signature)-1] ^= 1
	if sshVerify(blob, "ssh-ed25519", message, signature) == nil {
		t.Fatal("modified signature accepted")
	}
	if sshVerify(blob, "rsa-sha2-256", message, signature) == nil {
		t.Fatal("signature type mismatch accepted")
	}
}
func FuzzLegacyNetworkDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{4, 2, 0, 0, 0, 1, 0, 0, 1, 127, 0, 0, 1, 0, 53})
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	init, _ := wgInitiate(key, key.PublicKey().Bytes(), make([]byte, 32))
	f.Add(init.message)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		decodeHY1Packet(b)
		decodeTUIC4Packet(b)
		sshAlgorithms(b)
		sshParsePub(b)
		sshOpenSSHPrivate(b)
		wgReadInitiation(key, b)
		if packet, e := parseTunPacket(b); e == nil {
			transportChecksum(packet, packet.data[packet.header:])
		}
	})
}

func TestWireGuardFINRetransmission(t *testing.T) {
	a, pub := wgTestKey(t)
	b, other := wgTestKey(t)
	r := newTestRuntime(t, Config{})
	p, e := newWGPeer(r, []string{a}, other, "", []string{"10.26.0.1/32"}, nil, "", 1420, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer p.close()
	priv, _ := wgKey(b)
	remote, _ := ecdh.X25519().NewPrivateKey(priv)
	init, _ := wgInitiate(p.private, remote.PublicKey().Bytes(), make([]byte, 32))
	src, stamp, ck, h, e := wgReadInitiation(remote, init.message)
	if e != nil {
		t.Fatal(e)
	}
	_ = stamp
	reply, server, e := wgRespond(remote, src, make([]byte, 32), ck, h, init.message)
	if e != nil {
		t.Fatal(e)
	}
	p.current, e = init.response(reply)
	if e != nil {
		t.Fatal(e)
	}
	p.remote = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	var count int
	p.sender = func(b []byte, _ net.Addr) error {
		if _, e := server.open(b); e != nil {
			return e
		}
		count++
		return nil
	}
	key := tunFlowKey{source: netip.MustParseAddr("10.26.0.1"), destination: netip.MustParseAddr("10.26.0.2"), sport: 30000, dport: 80}
	c := newWGTCP(p.stack, key, false)
	c.ready = true
	c.receive = 100
	p.stack.tcp[key] = c
	if e = c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	p.stack.expire(time.Now().Add(2 * time.Second))
	if count != 2 {
		t.Fatal("FIN was not retransmitted", count, pub)
	}
}
