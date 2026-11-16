package native

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"runtime"
	"testing"
)

func TestFakeTCPWire(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.1:12345", "198.51.100.1:443"}, {"[2001:db8::1]:12345", "[2001:db8::2]:443"}} {
		source, destination := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
		for _, size := range []int{0, 1, 1200, 65495} {
			payload := bytes.Repeat([]byte{0x5a}, size)
			packet, err := encodeFakeTCP(nil, source, destination, ^uint32(0), 0x12345678, 0xffff, payload)
			if err != nil {
				t.Fatal(err)
			}
			segment, ok := parseFakeTCP(packet)
			if !ok || segment.source != 12345 || segment.destination != 443 || segment.sequence != ^uint32(0) || segment.ack != 0x12345678 || segment.flags != 0x18 || !bytes.Equal(segment.payload, payload) {
				t.Fatal("wire", segment, ok)
			}
			if transportChecksum(tunPacket{source: source.Addr(), destination: destination.Addr(), protocol: 6}, packet) != 0 {
				t.Fatal("TCP checksum")
			}
		}
		if _, err := encodeFakeTCP(nil, source, destination, 0, 0, 0xffff, make([]byte, 65496)); err == nil {
			t.Fatal("accepted oversize payload")
		}
	}
	for _, b := range [][]byte{nil, make([]byte, 19), make([]byte, 20), append(make([]byte, 12), 0xf0, 0, 0, 0, 0, 0, 0, 0)} {
		if _, ok := parseFakeTCP(b); ok {
			t.Fatal("accepted invalid data offset")
		}
	}
	packet := make([]byte, 29)
	packet[12] = 7 << 4
	packet[28] = 7
	if got, ok := parseFakeTCP(packet); !ok || !bytes.Equal(got.payload, []byte{7}) {
		t.Fatal("TCP options")
	}
}

func TestFakeTCPConfig(t *testing.T) {
	out := Outbound{Type: "hysteria", Tag: "proxy", Server: "127.0.0.1", ServerPort: 443, Password: "private", Protocol: "faketcp", TLS: TLSOptions{Enabled: true}}
	in := Inbound{Type: "hysteria", Tag: "server", Listen: "127.0.0.1", Protocol: "faketcp", TLS: certificate(t), Users: []User{{Password: "private"}}}
	b, _ := json.Marshal(Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{out}})
	_, err := Parse(b)
	if (err == nil) != (runtime.GOOS == "linux") {
		t.Fatal("platform validation", err)
	}
	if runtime.GOOS != "linux" {
		return
	}
	for _, mode := range []string{"detour", "hop", "protocol"} {
		bad := out
		switch mode {
		case "detour":
			bad.Detour = "direct"
		case "hop":
			bad.ServerPort = 0
			bad.ServerPorts = []string{"443:444"}
		case "protocol":
			bad.Protocol = "fake-tcp"
		}
		b, _ = json.Marshal(Config{Outbounds: []Outbound{bad, {Type: "direct", Tag: "direct"}}})
		if _, err = Parse(b); err == nil {
			t.Fatal("accepted invalid mode", mode)
		}
	}
}

func TestFakeTCPQUICMTU(t *testing.T) {
	cid := []byte("12345678")
	for _, mtu := range []int{1200, 1472} {
		params, err := parseQUICParameters(quicParameters(cid, nil, nil, false, mtu), cid, nil, nil, true)
		if err != nil || params.maxUDPPayload != uint64(mtu) || params.maxDatagram > uint64(mtu-64) {
			t.Fatal("DATAGRAM does not fit negotiated MTU", params, err)
		}
		if mtu == 1200 && params.maxDatagram != 1136 || mtu == 1472 && params.maxDatagram != 1400 {
			t.Fatal("unexpected limit", params.maxDatagram)
		}
	}
}

func FuzzFakeTCP(f *testing.F) {
	for _, seed := range [][]byte{nil, make([]byte, 19), make([]byte, 20), bytes.Repeat([]byte{255}, 1400)} {
		f.Add(seed)
	}
	packet, _ := encodeFakeTCP(nil, netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("192.0.2.2:443"), 0, 0, 0xffff, []byte("payload"))
	f.Add(packet)
	f.Fuzz(func(t *testing.T, b []byte) {
		segment, ok := parseFakeTCP(b)
		if !ok {
			return
		}
		if len(segment.payload) != len(b)-int(b[12]>>4)*4 || segment.source != binary.BigEndian.Uint16(b) {
			t.Fatal("invalid parse bounds")
		}
	})
}
