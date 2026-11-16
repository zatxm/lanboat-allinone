package native

import (
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
)

type packetDevice struct{ packets [][]byte }

func (p *packetDevice) Read([]byte) (int, error) { return 0, io.EOF }
func (p *packetDevice) Write(b []byte) (int, error) {
	p.packets = append(p.packets, append([]byte{}, b...))
	return len(b), nil
}
func (p *packetDevice) Close() error { return nil }

func TestTUNPacketFragmentRoundTripAndOverlap(t *testing.T) {
	for _, family := range []string{"4", "6", "6-extension"} {
		t.Run(family, func(t *testing.T) {
			source, destination := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
			if family != "4" {
				source = netip.MustParseAddr("2001:db8::1")
				destination = netip.MustParseAddr("2001:db8::2")
			}
			packet := makeUDPPacket(source, destination, 10000, 443, bytes.Repeat([]byte{7}, 60000))
			if family == "6-extension" {
				packet = append(append(append([]byte{}, packet[:40]...), []byte{17, 0, 0, 0, 0, 0, 0, 0}...), packet[40:]...)
				packet[6] = 60
				binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
			}
			device := &packetDevice{}
			tun := &tunTunnel{device: device, in: Inbound{MTU: 1280}}
			if err := tun.writePacket(packet); err != nil {
				t.Fatal(err)
			}
			fragments := tunFragments{}
			var assembled []byte
			for i := len(device.packets) - 1; i >= 0; i-- {
				part, err := parseTunPacket(device.packets[i])
				if err != nil {
					t.Fatal(err)
				}
				out, err := fragments.assemble(part)
				if err != nil {
					t.Fatal(err)
				}
				if out != nil {
					assembled = out
				}
			}
			if family == "4" && len(assembled) == len(packet) {
				if checksum(assembled[:20], 0) != 0 {
					t.Fatal("IPv4 checksum mismatch")
				}
				copy(packet[4:6], assembled[4:6])
				copy(packet[10:12], assembled[10:12])
			}
			if !bytes.Equal(assembled, packet) {
				t.Fatal("fragment reassembly mismatch", len(assembled), len(packet))
			}
			p, err := parseTunPacket(assembled)
			if err != nil {
				t.Fatal(err)
			}
			if transportChecksum(p, assembled[p.header:]) != 0 {
				t.Fatal("UDP checksum mismatch")
			}
			first, _ := parseTunPacket(device.packets[0])
			fragments = tunFragments{}
			if _, err := fragments.assemble(first); err != nil {
				t.Fatal(err)
			}
			if _, err := fragments.assemble(first); err == nil {
				t.Fatal("overlapping fragment accepted")
			}
		})
	}
}
func FuzzTUNPacket(f *testing.F) {
	f.Add(makeUDPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1"), 100, 200, []byte("test")))
	f.Add([]byte{0x60})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := parseTunPacket(data)
		if err == nil {
			fragments := tunFragments{}
			fragments.assemble(p)
		}
	})
}
