package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func trustPair(t *testing.T, version int) (*Runtime, *Runtime) {
	t.Helper()
	return trustPairWithRoute(t, version, Route{})
}
func trustPairWithRoute(t *testing.T, version int, route Route) (*Runtime, *Runtime) {
	t.Helper()
	f := newMutualTLSFixture(t)
	in := Inbound{Type: "trusttunnel", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, TLS: f.server(), Users: []User{{Username: "client", Password: "private"}}}
	// Only server authentication is required by TrustTunnel.
	in.TLS.ClientAuthentication = ""
	in.TLS.ClientCertificate = nil
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Route: route})
	out := testOutbound(t, in, server.Address(in.Tag))
	out.TLS = f.client()
	out.HTTPVersion = version
	return server, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}
func TestTrustTunnelIndependent(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			_, client := trustPair(t, v)
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000, 65507})
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			check, e := client.trustClients["proxy"].connect(ctx, "_check")
			if e != nil {
				t.Fatal(e)
			}
			check.Close()
		})
	}
}
func TestTrustTunnelUDPIsolation(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			_, client := trustPair(t, v)
			address := echoUDP(t)
			var workers sync.WaitGroup
			for i := range 12 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					c, e := client.Dial(context.Background(), "udp", address)
					if e != nil {
						t.Error(e)
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(5 * time.Second))
					for range 8 {
						b := bytes.Repeat([]byte{byte(i)}, 4096)
						if _, e = c.Write(b); e != nil {
							t.Error(e)
							return
						}
						got := make([]byte, 8192)
						n, e := c.Read(got)
						if e != nil || !bytes.Equal(b, got[:n]) {
							t.Error("crossed UDP flow", i, n, e)
							return
						}
					}
				}()
			}
			workers.Wait()
			// An individual read timeout does not tear down the shared stream.
			c, e := client.Dial(context.Background(), "udp", address)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			if _, e = c.Read(make([]byte, 1)); !os.IsTimeout(e) {
				t.Fatal("deadline", e)
			}
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte{3})
			b := make([]byte, 1)
			if _, e = c.Read(b); e != nil || b[0] != 3 {
				t.Fatal(e, b)
			}
			client.resetNetworkTransports()
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{511})
		})
	}
}
func TestTrustTunnelBadAuthentication(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			server, client := trustPair(t, v)
			o := client.config.Outbounds[0]
			o.Password = "wrong"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			for _, network := range []string{"tcp", "udp"} {
				c, e := bad.Dial(context.Background(), network, server.Address("server"))
				if e == nil {
					c.Close()
					t.Fatal("bad password accepted", network)
				}
			}
		})
	}
}
func TestTrustTunnelPacketWire(t *testing.T) {
	for _, request := range []bool{false, true} {
		for _, address := range []string{"127.0.0.1:53", "[::1]:53", "[2001:db8::5]:53"} {
			src := netip.MustParseAddrPort("192.0.2.1:15200")
			dst := netip.MustParseAddrPort(address)
			var b bytes.Buffer
			want := bytes.Repeat([]byte{7}, 65507)
			if e := trustWritePacket(&b, src, dst, want, request); e != nil {
				t.Fatal(e)
			}
			a, d, p, e := trustReadPacket(&b, make([]byte, 66000), request)
			if e != nil || a != src || d != dst || !bytes.Equal(p, want) {
				t.Fatal(a, d, len(p), e)
			}
		}
	}
	for _, n := range []uint32{0, 1, 35, 36, 66000, ^uint32(0)} {
		b := binary.BigEndian.AppendUint32(nil, n)
		if _, _, _, e := trustReadPacket(bytes.NewReader(b), make([]byte, 66000), true); e == nil {
			t.Fatal("invalid packet", n)
		}
	}
}
func TestTrustTunnelHalfClose(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			_, client := trustPair(t, v)
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				c, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(3 * time.Second))
				b, e := io.ReadAll(c)
				if e == nil {
					_, e = c.Write(append(b, '!'))
				}
				done <- e
			}()
			c, e := client.Dial(context.Background(), "tcp", listener.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = c.Write([]byte("hello")); e != nil {
				t.Fatal(e)
			}
			if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(c)
			if e != nil || string(b) != "hello!" {
				t.Fatal(string(b), e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func FuzzTrustTunnelPacket(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0}, true)
	f.Add(make([]byte, 41), false)
	f.Fuzz(func(t *testing.T, b []byte, request bool) {
		_, _, _, _ = trustReadPacket(bytes.NewReader(b), make([]byte, 66000), request)
	})
}

func TestHTTP3UnknownUniStream(t *testing.T) {
	listener := testQUICListener(t)
	client := testQUICDial(t, listener.packet.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server, e := listener.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	send, e := server.OpenStream(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeAll(send, quicVar(nil, 0x21)); e != nil {
		t.Fatal(e)
	}
	send.CloseWrite()
	recv, e := client.AcceptStream(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer recv.Close()
	if e = h3Uni(recv); e != nil {
		t.Fatal("unknown HTTP3 stream is not critical", e)
	}
}

func TestTrustTunnelPacketValidationAndLimits(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			_, client := trustPair(t, v)
			address := echoUDP(t)
			var packets []net.Conn
			for range 256 {
				c, e := client.Dial(context.Background(), "udp", address)
				if e != nil {
					t.Fatal(e)
				}
				packets = append(packets, c)
			}
			if c, e := client.Dial(context.Background(), "udp", address); e == nil {
				c.Close()
				t.Fatal("unbounded UDP associations")
			}
			c := packets[0]
			if _, e := c.Write(make([]byte, 65508)); e == nil {
				t.Fatal("oversized UDP accepted")
			}
			c.SetDeadline(time.Now().Add(time.Second))
			if _, e := c.Write([]byte{7}); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 1)
			if _, e := c.Read(b); e != nil || b[0] != 7 {
				t.Fatal("local validation killed healthy associations", e, b)
			}
			for _, c := range packets {
				c.Close()
			}
			// Cross the original16-bit label boundary without reusing an old tuple.
			m := client.trustClients["proxy"].udp
			m.mu.Lock()
			m.next = 65535
			m.mu.Unlock()
			assertUDPSizes(t, client, []int{511})
		})
	}
}
func TestTrustTunnelPacketRejectsForeignReply(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	label := netip.MustParseAddrPort("198.18.0.0:1")
	target := netip.MustParseAddrPort("192.0.2.1:80")
	m := &trustUDPMux{conn: a, done: make(chan struct{}), packets: map[netip.AddrPort]*trustPacket{}}
	p := &trustPacket{mux: m, id: label, destination: target, incoming: make(chan []byte, 1), done: make(chan struct{}), wake: make(chan struct{})}
	m.packets[label] = p
	defer m.close()
	go m.receive()
	if e := trustWritePacket(b, netip.MustParseAddrPort("192.0.2.2:80"), label, []byte("wrong"), false); e != nil {
		t.Fatal(e)
	}
	if e := trustWritePacket(b, target, netip.MustParseAddrPort("198.18.0.0:2"), []byte("wrong"), false); e != nil {
		t.Fatal(e)
	}
	if e := trustWritePacket(b, target, label, []byte("right"), false); e != nil {
		t.Fatal(e)
	}
	p.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 16)
	n, e := p.Read(got)
	if e != nil || string(got[:n]) != "right" {
		t.Fatal(string(got[:n]), e)
	}
}
func TestTrustTunnelCloseInterrupts(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			_, client := trustPair(t, v)
			c, e := client.Dial(context.Background(), "udp", echoUDP(t))
			if e != nil {
				t.Fatal(e)
			}
			done := make(chan error, 1)
			go func() { _, e := c.Read(make([]byte, 1)); done <- e }()
			client.Close()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("closed UDP returned success")
				}
			case <-time.After(time.Second):
				t.Fatal("read not interrupted")
			}
		})
	}
}

func TestTrustTunnelICMPPolicy(t *testing.T) {
	for _, v := range []int{2, 3} {
		for _, method := range []string{"reply", "default", "drop"} {
			t.Run(fmt.Sprintf("%d/%s", v, method), func(t *testing.T) {
				_, client := trustPairWithRoute(t, v, Route{Rules: []Rule{{Network: []string{"icmp"}, AuthUser: []string{"client"}, Action: "reject", Method: method}}})
				for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
					destination := netip.MustParseAddr(address)
					kind := byte(8)
					if destination.Is6() {
						kind = 128
					}
					request := []byte{kind, 0, 0, 0, 0, 7, 0, 19, 1, 2, 3}
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					response, e := client.trustClients["proxy"].exchangeICMP(ctx, destination, request, 63)
					cancel()
					if method == "drop" {
						if e == nil {
							t.Fatal("drop replied")
						}
						continue
					}
					if e != nil {
						t.Fatal(e)
					}
					if method == "reply" {
						want := byte(0)
						if destination.Is6() {
							want = 129
						}
						if response.data[0] != want || !bytes.Equal(response.data[4:], request[4:]) {
							t.Fatal("Echo reply", response)
						}
					} else {
						if !icmpError(response.data[0], destination.Is6()) || len(response.data) != 8 || binary.BigEndian.Uint32(response.data[4:]) != 0 {
							t.Fatal("bad unreachable header", response)
						}
					}
				}
			})
		}
	}
}
