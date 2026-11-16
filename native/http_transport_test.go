package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestHTTP2MultiplexDeadlinesAndShutdown(t *testing.T) {
	for _, transport := range []string{"http", "grpc"} {
		t.Run(transport, func(t *testing.T) {
			in := testInbound(t, "vless")
			in.TLS = certificate(t)
			in.Transport = Transport{Type: transport, IdleTimeout: "40ms", PingTimeout: "1s"}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Transport = in.Transport
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				for {
					c, err := listener.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			var group sync.WaitGroup
			for i := range 24 {
				group.Add(1)
				go func() {
					defer group.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					c, err := client.Dial(ctx, "tcp", listener.Addr().String())
					if err != nil {
						t.Error(err)
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					payload := bytes.Repeat([]byte{byte(i)}, 70000)
					if err := writeAll(c, payload); err != nil {
						t.Error(err)
						return
					}
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
						t.Errorf("concurrent data: %v", err)
					}
				}()
			}
			group.Wait()
			c, err := client.Dial(context.Background(), "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			var b [1]byte
			if _, err := c.Read(b[:]); err == nil {
				t.Fatal("stream deadline ignored")
			} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatal("deadline error does not implement timeout", err)
			}
			active, err := client.Dial(context.Background(), "tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer active.Close()
			_ = active.SetReadDeadline(time.Now().Add(3 * time.Second))
			if err := writeAll(active, []byte("warm")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(active, make([]byte, 4)); err != nil {
				t.Fatal(err)
			}
			closed := make(chan struct{})
			go func() { client.Close(); server.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("HTTP/2 sessions blocked shutdown")
			}
			if _, err := active.Read(b[:]); err == nil {
				t.Fatal("closed runtime retained an HTTP/2 stream")
			}
		})
	}
}

func TestGRPCRejectsMalformedEnvelopes(t *testing.T) {
	for _, wire := range [][]byte{{1, 0, 0, 0, 0}, {0, 0, 0x10, 0, 1}, {0, 0, 0, 0, 2, 10, 5}, {0, 0, 0, 0, 1, 15}} {
		left, right := net.Pipe()
		_ = left.SetReadDeadline(time.Now().Add(time.Second))
		go func() { _, _ = right.Write(wire); right.Close() }()
		c := &grpcConn{Conn: left}
		if _, err := c.Read(make([]byte, 8)); err == nil {
			t.Fatal("invalid RPC accepted")
		}
		left.Close()
	}
}

func FuzzVMessInstruction(f *testing.F) {
	q := vmessRequest{security: 3, options: 13, command: 1, address: "example.org:443"}
	raw, _ := q.plaintext()
	f.Add(raw)
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, raw []byte) { _, _ = parseVMessPlaintext(raw) })
}

func FuzzTransportConfig(f *testing.F) {
	f.Add([]byte(`{"type":"ws","path":"/proxy"}`))
	f.Add([]byte(`{"type":"grpc","service_name":"lanboat"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var transport Transport
		if json.Unmarshal(raw, &transport) == nil {
			_ = transport.validate()
		}
	})
}
