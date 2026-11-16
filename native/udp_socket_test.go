package native

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestUDPLargeDatagrams(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		for _, path := range []string{"dial", "resolver", "packet"} {
			t.Run(network+"/"+path, func(t *testing.T) {
				local := "127.0.0.1:0"
				if network == "udp6" {
					local = "[::1]:0"
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				server, err := (ListenOptions{}).listenPacket(ctx, network, local)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				r := &Runtime{}
				var client net.PacketConn
				var connected net.Conn
				switch path {
				case "dial":
					connected, err = r.dialSocket(ctx, DialOptions{}, network, server.LocalAddr().String())
				case "resolver":
					dialer := net.Dialer{Control: r.socketControl}
					connected, err = dialer.DialContext(ctx, network, server.LocalAddr().String())
				case "packet":
					client, err = r.listenPacketWithOptions(ctx, DialOptions{}, network, local, server.LocalAddr().String())
				}
				if err != nil {
					t.Fatal(err)
				}
				if connected != nil {
					client = connected.(*net.UDPConn)
				}
				defer client.Close()
				deadline, _ := ctx.Deadline()
				server.SetDeadline(deadline)
				client.SetDeadline(deadline)
				buffer := make([]byte, 65535)
				for _, size := range []int{0, 9217, 60000} {
					want := bytes.Repeat([]byte{byte(size)}, size)
					if connected != nil {
						_, err = connected.Write(want)
					} else {
						_, err = client.WriteTo(want, server.LocalAddr())
					}
					if err != nil {
						t.Fatalf("send %d bytes: %v", size, err)
					}
					n, peer, err := server.ReadFrom(buffer)
					if err != nil || !bytes.Equal(buffer[:n], want) {
						t.Fatalf("receive %d bytes: got %d, %v", size, n, err)
					}
					if _, err = server.WriteTo(buffer[:n], peer); err != nil {
						t.Fatalf("reply %d bytes: %v", size, err)
					}
					n, _, err = client.ReadFrom(buffer)
					if err != nil || !bytes.Equal(buffer[:n], want) {
						t.Fatalf("echo %d bytes: got %d, %v", size, n, err)
					}
				}
			})
		}
	}
}
