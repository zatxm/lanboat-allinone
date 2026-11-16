package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func testICMPSegment(source, dest netip.Addr, kind byte, quote []byte) []byte {
	segment := make([]byte, 8+len(quote))
	segment[0] = kind
	copy(segment[8:], quote)
	protocol := byte(1)
	if source.Is6() {
		protocol = 58
	}
	packet := makeWGIP(source, dest, protocol, segment)
	p, _ := parseTunPacket(packet)
	sum := checksum(segment, 0)
	if protocol == 58 {
		sum = transportChecksum(p, segment)
	}
	binary.BigEndian.PutUint16(packet[p.header+2:], sum)
	return packet
}
func TestTUNICMPQuotationAndErrors(t *testing.T) {
	for _, family := range []bool{false, true} {
		source, dest, router := netip.MustParseAddr("172.19.0.1"), netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("192.0.2.1")
		protocol, kind := byte(1), byte(11)
		if family {
			source, dest, router = netip.MustParseAddr("fd00::1"), netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:1::1")
			protocol, kind = 58, 3
		}
		original := makeWGIP(source, dest, protocol, []byte{8, 0, 0, 0, 0, 7, 0, 3, 9})
		p, _ := parseTunPacket(original)
		quote := append([]byte{}, original[:p.header+8]...)
		// The quoted total length can be larger than the quoted bytes.
		response := testICMPSegment(router, source, kind, quote)
		rp, _ := parseTunPacket(response)
		segment := response[rp.header:]
		if !matchICMPResponse(segment, router, dest, 7, 3) || matchICMPResponse(segment, router, dest, 8, 3) {
			t.Fatal("ICMP quotation correlation")
		}
		var relayed []byte
		s := &wgIPStack{peer: &ipEndpoint{sendIP: func(b []byte) error { relayed = b; return nil }}}
		s.relayICMPError(p, icmpResponse{source: router, data: segment})
		out, e := parseTunPacket(relayed)
		if e != nil || out.source != router || out.destination != source || !bytes.Equal(out.data[out.header+8:], quote) {
			t.Fatal(out, e)
		}
		if protocol == 1 && checksum(out.data[out.header:], 0) != 0 || protocol == 58 && transportChecksum(out, out.data[out.header:]) != 0 {
			t.Fatal("ICMP checksum")
		}
	}
	for n := 0; n < 48; n++ {
		if _, e := parseICMPQuote(make([]byte, n)); e == nil {
			t.Fatal("invalid quotation accepted", n)
		}
	}
}
func TestWireGuardICMPTunnel(t *testing.T) {
	for _, family := range []bool{false, true} {
		serverKey, serverPub := wgTestKey(t)
		clientKey, clientPub := wgTestKey(t)
		serverLocal, clientLocal := "10.88.0.1/32", "10.88.0.2/32"
		kind, replyKind := byte(8), byte(0)
		if family {
			serverLocal, clientLocal = "fd88::1/128", "fd88::2/128"
			kind, replyKind = 128, 129
		}
		in := Inbound{Type: "wireguard", Tag: "wg", Listen: "127.0.0.1", Address: []string{serverLocal}, SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{LocalAddress: []string{serverLocal}, Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{clientLocal}}}}}
		// A rule-reply target provides deterministic remote Echo without raw privileges.
		server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Route: Route{Rules: []Rule{{Network: []string{"icmp"}, Action: "reject", Method: "default"}}}})
		out := testOutbound(t, Inbound{Type: "wireguard"}, server.Address("wg"))
		out.PrivateKey = []string{clientKey}
		out.PublicKey = serverPub
		out.LocalAddress = []string{clientLocal}
		client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		peer, e := client.wgClients["proxy"].session(ctx)
		if e != nil {
			t.Fatal(e)
		}
		destination := netip.MustParsePrefix(serverLocal).Addr()
		segment := []byte{kind, 0, 0, 0, 0, 7, 0, 3, 9}
		response, e := peer.stack.exchangeICMP(ctx, destination, segment, 63)
		if e != nil || len(response.data) != len(segment) || response.data[0] != replyKind || binary.BigEndian.Uint16(response.data[4:]) != 7 {
			t.Fatal("WireGuard ICMP", family, response, e)
		}
		unreachable := netip.MustParseAddr("203.0.113.19")
		if family {
			unreachable = netip.MustParseAddr("2001:db8::19")
		}
		response, e = peer.stack.exchangeICMP(ctx, unreachable, segment, 63)
		if e != nil || !icmpError(response.data[0], family) {
			t.Fatal("WireGuard ICMP error", family, response, e)
		}
	}
}

func TestTUNWireGuardUDPErrorRelay(t *testing.T) {
	testTUNWireGuardUDPErrorRelay(t, false)
}

func TestMasqueNATErrorRelay(t *testing.T) {
	testTUNWireGuardUDPErrorRelay(t, true)
}

func testTUNWireGuardUDPErrorRelay(t *testing.T, nat bool) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "wg", Listen: "127.0.0.1", Address: []string{"10.88.0.1/32"}, SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.88.0.2/32"}}}}}}, Route: Route{Rules: []Rule{{Network: []string{"udp"}, Action: "reject"}}}})
	out := testOutbound(t, Inbound{Type: "wireguard"}, server.Address("wg"))
	out.PrivateKey = []string{clientKey}
	out.PublicKey = serverPub
	out.LocalAddress = []string{"10.88.0.2/32"}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithCancel(client.ctx)
	replies := make(chan []byte, 1)
	endpoint := &ipEndpoint{runtime: client, inbound: "tun", done: ctx.Done(), sendIP: func(b []byte) error {
		select {
		case replies <- b:
		default:
		}
		return nil
	}}
	if nat {
		settings, _ := (masqueNATOptions{}).settings()
		endpoint.nat = newMasqueNAT(client, settings)
	}
	stack := newIPStack(endpoint)
	defer func() { cancel(); stack.close() }()
	original := makeUDPPacket(netip.MustParseAddr("172.19.0.5"), netip.MustParseAddr("203.0.113.25"), 30000, 9000, []byte("ICMP UDP relay"))
	p, _ := parseTunPacket(original)
	stack.input(p)
	select {
	case b := <-replies:
		reply, e := parseTunPacket(b)
		if e != nil || reply.source != p.destination || reply.destination != p.source || b[reply.header] != 3 || b[reply.header+1] != 3 || checksum(b[reply.header:], 0) != 0 || !bytes.Equal(b[reply.header+8:], original[:28]) {
			t.Fatal("translated UDP ICMP error", b, e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WireGuard ICMP error was lost by UDP forwarding")
	}
}
