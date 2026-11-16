package native

import (
	"net"
	"testing"
)

func TestTCPUDPEphemeralCollision(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		address := portAddress("127.0.0.1", unusedPort(t))
		occupied, err := net.ListenPacket("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { occupied.Close() })
		first, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		listener, packet, err := bindPairedUDP(first, automatic)
		if !automatic {
			if err == nil || listener != nil || packet != nil {
				t.Fatal("fixed port silently changed", listener, packet, err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			if listener.Addr().String() == address || listener.Addr().String() != packet.LocalAddr().String() {
				t.Fatal("TCP/UDP pair not reserved together", listener.Addr(), packet.LocalAddr())
			}
			listener.Close()
			packet.Close()
		}
		if extra, err := net.Listen("tcp", address); err != nil {
			t.Fatal("failed TCP listener leaked", err)
		} else {
			extra.Close()
		}
	}
}
