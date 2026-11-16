package native

import (
	"io"
	"net"
	"testing"
	"time"
)

func socksEchoProxy(t *testing.T) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				var greeting [3]byte
				if _, err := io.ReadFull(c, greeting[:]); err != nil {
					return
				}
				if greeting != [3]byte{5, 1, 0} {
					return
				}
				writeAll(c, []byte{5, 0})
				var header [3]byte
				if _, err := io.ReadFull(c, header[:]); err != nil {
					return
				}
				if _, err := readAddress(c); err != nil {
					return
				}
				if header[1] == 1 {
					writeAll(c, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
					_, _ = io.Copy(c, c)
					return
				}
				if header[1] != 3 {
					return
				}
				packets, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					return
				}
				defer packets.Close()
				address, _ := encodeAddress(packets.LocalAddr().String())
				writeAll(c, append([]byte{5, 0, 0}, address...))
				done := make(chan struct{})
				go func() { io.Copy(io.Discard, c); packets.Close(); close(done) }()
				defer func() { c.Close(); <-done }()
				buffer := make([]byte, 65535)
				for {
					n, from, err := packets.ReadFrom(buffer)
					if err != nil {
						return
					}
					_, _ = packets.WriteTo(buffer[:n], from)
				}
			}()
		}
	}()
	return listener.Addr().String()
}
