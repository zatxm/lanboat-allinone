package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"tailscale.com/disco"
	"tailscale.com/net/packet"
	"tailscale.com/types/key"
)

// This is an external wire oracle. No upstream code is linked into the product.
func relayOracle() {
	keys := [2]key.DiscoPrivate{key.NewDisco(), key.NewDisco()}
	enc, dec := json.NewEncoder(os.Stdout), json.NewDecoder(os.Stdin)
	enc.Encode(map[string]any{"keys": []key.DiscoPublic{keys[0].Public(), keys[1].Public()}})
	var endpoint struct {
		Server      key.DiscoPublic
		VNI         uint32
		Address     netip.AddrPort
		Description []byte
	}
	must(dec.Decode(&endpoint))
	if len(endpoint.Description) > 0 {
		wire := append([]byte{9, 0, 0, 0, 0, 1}, endpoint.Description...)
		decoded, e := disco.Parse(wire)
		must(e)
		reply, ok := decoded.(*disco.AllocateUDPRelayEndpointResponse)
		if !ok || reply.ServerDisco != endpoint.Server || reply.VNI != endpoint.VNI || reply.ClientDisco[0] != keys[0].Public() || reply.ClientDisco[1] != keys[1].Public() {
			panic("invalid allocation wire format")
		}
	}
	var sockets [2]*net.UDPConn
	frame := func(control bool, body []byte) []byte {
		b := make([]byte, 8)
		header := packet.GeneveHeader{Control: control, Protocol: packet.GeneveProtocolWireGuard}
		if control {
			header.Protocol = packet.GeneveProtocolDisco
		}
		header.VNI.Set(endpoint.VNI)
		must(header.Encode(b))
		return append(b, body...)
	}
	for i := range sockets {
		socket, e := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
		must(e)
		defer socket.Close()
		sockets[i] = socket
		socket.SetDeadline(time.Now().Add(3 * time.Second))
		msg := disco.BindUDPRelayEndpointCommon{VNI: endpoint.VNI, Generation: uint32(i + 1), RemoteKey: keys[1-i].Public()}
		sealed := keys[i].Shared(endpoint.Server).Seal((&disco.BindUDPRelayEndpoint{BindUDPRelayEndpointCommon: msg}).AppendMarshal(nil))
		wire := append([]byte(disco.Magic), keys[i].Public().AppendTo(nil)...)
		wire = append(wire, sealed...)
		_, e = socket.WriteToUDPAddrPort(frame(true, wire), endpoint.Address)
		must(e)
		b := make([]byte, 4096)
		n, _, e := socket.ReadFromUDPAddrPort(b)
		must(e)
		var header packet.GeneveHeader
		must(header.Decode(b[:n]))
		if !header.Control || header.VNI.Get() != endpoint.VNI {
			panic("bad relay header")
		}
		plain, ok := keys[i].Shared(endpoint.Server).Open(b[8+38 : n])
		if !ok {
			panic("bad challenge encryption")
		}
		decoded, e := disco.Parse(plain)
		must(e)
		challenge, ok := decoded.(*disco.BindUDPRelayEndpointChallenge)
		if !ok || challenge.Generation != msg.Generation || challenge.VNI != msg.VNI || challenge.RemoteKey != msg.RemoteKey {
			panic("bad relay challenge")
		}
		answer := &disco.BindUDPRelayEndpointAnswer{BindUDPRelayEndpointCommon: challenge.BindUDPRelayEndpointCommon}
		wire = append([]byte(disco.Magic), keys[i].Public().AppendTo(nil)...)
		wire = append(wire, keys[i].Shared(endpoint.Server).Seal(answer.AppendMarshal(nil))...)
		_, e = socket.WriteToUDPAddrPort(frame(true, wire), endpoint.Address)
		must(e)
	}
	for i := range sockets {
		b := make([]byte, 128)
		binary.LittleEndian.PutUint32(b, 4)
		copy(b[4:], fmt.Sprintf("official-wire-%d", i))
		wire := frame(false, b)
		// The second answer and first data packet use different UDP sockets; retry until both bindings exist.
		var received []byte
		for j := 0; j < 4; j++ {
			_, e := sockets[i].WriteToUDPAddrPort(wire, endpoint.Address)
			must(e)
			sockets[1-i].SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			out := make([]byte, 4096)
			n, _, err := sockets[1-i].ReadFromUDPAddrPort(out)
			if err == nil {
				received = out[:n]
				break
			}
		}
		if !bytes.Equal(wire, received) {
			panic("relay data mismatch")
		}
	}
	enc.Encode(map[string]bool{"ok": true})
	// Stay alive until the test has checked revocation.
	_, _ = io.Copy(io.Discard, os.Stdin)
}
