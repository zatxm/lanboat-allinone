package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestGenericMuxIndependent(t *testing.T) {
	for _, kind := range []string{"shadowsocks", "shadowsocksr", "vmess", "vless", "trojan", "socks", "http", "relay"} {
		for _, protocol := range []string{"h2mux", "smux", "yamux"} {
			for _, padding := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/padding=%v", kind, protocol, padding), func(t *testing.T) {
					in := testInbound(t, kind)
					if kind == "shadowsocksr" {
						in.Method = "aes-256-cfb"
						in.Password = "private"
						in.Protocol = "auth_sha1_v4"
					}

					in.Multiplex = MultiplexOptions{Enabled: true, Padding: padding}
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address("server"))
					out.Protocol = in.Protocol

					out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, Padding: padding, MaxConnections: 1}
					client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000})
					assertTCP(t, client)
					pool := client.genericMuxClients[out.Tag]
					if len(pool.entries) != 1 {
						t.Fatal("session was not reused")
					}
					old := pool.entries[0]
					client.resetNetworkTransports()
					assertTCP(t, client)
					if pool.entries[0] == old {
						t.Fatal("network reset retained session")
					}
				})
			}
		}
	}
}
func TestGenericMuxLimitsAndConcurrency(t *testing.T) {
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Multiplex.Enabled = true
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, MaxStreams: 2}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			target := relayEchoTCP(t)
			var all []net.Conn
			for range 5 {
				c, err := client.Dial(context.Background(), "tcp", target)
				if err != nil {
					t.Fatal(err)
				}
				all = append(all, c)
			}
			if len(client.genericMuxClients[out.Tag].entries) != 3 {
				t.Fatal("max_streams not applied")
			}
			var wg sync.WaitGroup
			for i, c := range all {
				wg.Go(func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(10 * time.Second))
					want := bytes.Repeat([]byte{byte(i)}, 1<<20)
					go func() {
						if err := writeAll(c, want); err != nil {
							t.Error(err)
						}
					}()
					got := make([]byte, len(want))
					if _, err := io.ReadFull(c, got); err != nil {
						t.Error(err)
					} else if !bytes.Equal(got, want) {
						t.Error("concurrent data corrupted")
					}
				})
			}
			wg.Wait()
			pool := client.genericMuxClients[out.Tag]
			pool.mu.Lock()
			for _, e := range pool.entries {
				if e.active != 0 {
					t.Error("stream release leaked")
				}
			}
			pool.mu.Unlock()
		})
	}
}
func TestGenericMuxRejectAndDeadline(t *testing.T) {
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Multiplex.Enabled = true
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "block"}}, Route: Route{Rules: []Rule{{Port: []uint16{1}, Outbound: "block"}}, Final: "direct"}})
			out := testOutbound(t, in, server.Address("server"))
			out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, MaxConnections: 1}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			bad, err := client.Dial(context.Background(), "tcp", "127.0.0.1:1")
			if err == nil {
				bad.SetDeadline(time.Now().Add(time.Second))
				_, err = bad.Read(make([]byte, 1))
				bad.Close()
			}
			if err == nil {
				t.Fatal("rejected stream succeeded")
			}
			c, err := client.Dial(context.Background(), "tcp", relayEchoTCP(t))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			_, err = c.Read(make([]byte, 1))
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read deadline: %v", err)
			}
			assertTCP(t, client)
		})
	}
}
func TestGenericMuxConfig(t *testing.T) {
	for _, o := range []MultiplexOptions{{Enabled: true, Protocol: "invalid"}, {Enabled: true, MaxStreams: 1, MinStreams: 1}, {Enabled: true, MaxStreams: 1, MaxConnections: 1}, {Enabled: true, MaxConnections: -1}, {Enabled: true, MaxStreams: 129}, {Enabled: true, Brutal: BrutalOptions{Enabled: true}}, {Enabled: true, Protocol: "mux.cool", Padding: true}} {
		if err := o.validate("vmess", false); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	if err := (MultiplexOptions{Enabled: true}).validate("hysteria2", false); err == nil {
		t.Fatal("accepted QUIC multiplex carrier")
	}
}
func TestGenericMuxPadding(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	left, right := &genericPaddingConn{Conn: a}, &genericPaddingConn{Conn: b}
	done := make(chan error, 1)
	want := bytes.Repeat([]byte("large padded data"), 10000)
	go func() {
		for range 20 {
			if err := writeAll(left, want); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for range 20 {
		got := make([]byte, len(want))
		if _, err := io.ReadFull(right, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("padding corrupted data")
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func TestGenericMuxPacketAddr(t *testing.T) {
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Multiplex.Enabled = true
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address("server"))
			o.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			p := client.genericMuxClients[o.Tag]
			e, err := p.acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer p.release(e)
			stream, err := e.session.open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			stream.SetDeadline(time.Now().Add(5 * time.Second))
			address, _ := encodeAddress(genericMuxAddress)
			if err = writeAll(stream, append([]byte{0, 3}, address...)); err != nil {
				t.Fatal(err)
			}
			packet := &genericPacketConn{Conn: &genericResponseConn{Conn: stream}, addresses: true}
			for _, target := range []string{echoUDP(t), echoUDP(t)} {
				want := []byte(target)
				if _, err = packet.writeTarget(want, target); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 1024)
				n, from, err := packet.readTarget(got)
				if err != nil || from != target || !bytes.Equal(got[:n], want) {
					t.Fatalf("packet reply %q %v", from, err)
				}
			}
		})
	}
}
func TestGenericMuxBrutalUnavailable(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_BRUTAL_KERNEL") == "1" {
		t.Skip("positive kernel test used in guest")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if setTCPBrutal(a, 125000) == nil {
		t.Fatal("accepted logical stream as TCP carrier")
	}
	in := testInbound(t, "shadowsocks")
	in.Multiplex.Enabled = true
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	o.Multiplex = MultiplexOptions{Enabled: true, Protocol: "smux", Brutal: BrutalOptions{Enabled: true, UpMbps: 10, DownMbps: 10}}
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := c.Dial(ctx, "tcp", relayEchoTCP(t))
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("server without Brutal accepted exchange")
	}
}
func FuzzGenericMuxPadding(f *testing.F) {
	f.Add([]byte{0, 1, 0, 0, 42})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		c := &genericPaddingConn{Conn: readerConn(data)}
		io.Copy(io.Discard, c)
	})
}
func FuzzYAMUXFrames(f *testing.F) {
	f.Add([]byte{0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := newMuxConfigured(ctx, readerConn(data), false, muxYAMUX, 1, 0, false)
		defer s.close(net.ErrClosed)
		select {
		case <-s.done:
		case <-time.After(100 * time.Millisecond):
			t.Fatal("parser stalled")
		}
	})
}

func TestGenericMuxReference(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if binary == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required for external multiplex interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", binary)
	for _, kind := range []string{"shadowsocks", "vmess", "vless", "trojan"} {
		for _, protocol := range []string{"h2mux", "smux", "yamux"} {
			for _, padding := range []bool{false, true} {
				for _, side := range []string{"client", "server"} {
					t.Run(fmt.Sprintf("%s/%s/padding=%v/%s", kind, protocol, padding, side), func(t *testing.T) {
						in := testInbound(t, kind)
						in.Multiplex = MultiplexOptions{Enabled: true, Padding: padding}
						in.ListenPort = unusedPort(t)
						var client *Runtime
						if side == "client" {
							referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
							out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
							out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, Padding: padding, MaxConnections: 1}
							client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						} else {
							in.ListenPort = 0
							server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
							out := testOutbound(t, in, server.Address("server"))
							out.Username = ""
							out.UUID = ""
							out.Method = ""
							switch kind {
							case "shadowsocks":
								out.Method = in.Method
							case "vmess", "vless":
								out.UUID = testUUID
								out.Password = ""
							}

							out.Multiplex = MultiplexOptions{Enabled: true, Protocol: protocol, Padding: padding, MaxConnections: 1}
							front := Inbound{Type: "socks", Tag: "front", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
							referenceRuntime(t, Config{Inbounds: []Inbound{front}, Outbounds: []Outbound{out}})
							client = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: front.ListenPort}}})
						}
						assertTCP(t, client)
						assertUDPSizes(t, client, []int{1, 511, 4096, 14000})
						assertTCP(t, client)
					})
				}
			}
		}
	}
}

func TestGenericMuxCarriers(t *testing.T) {
	for _, transport := range []string{"ws", "httpupgrade", "http", "grpc", "quic"} {
		t.Run(transport, func(t *testing.T) {
			in := testInbound(t, "vmess")
			in.Multiplex.Enabled = true
			in.Transport = Transport{Type: transport}
			if transport == "http" || transport == "grpc" || transport == "quic" {
				in.TLS = certificate(t)
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Transport = in.Transport
			out.Multiplex = MultiplexOptions{Enabled: true, Padding: true}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 4096})
		})
	}
	for _, method := range ss2022Methods {
		t.Run(method, func(t *testing.T) {
			in := ss2022Inbound(method, false)
			in.Multiplex.Enabled = true
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := ss2022Outbound(t, in, server.Address("server"))
			out.Multiplex = MultiplexOptions{Enabled: true, Protocol: "yamux", Padding: true}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 60000})
		})
	}
}
func TestGenericMuxNegotiation(t *testing.T) {
	for _, test := range []struct {
		name           string
		server, client MultiplexOptions
	}{
		{"disabled", MultiplexOptions{}, MultiplexOptions{Enabled: true, Protocol: "smux"}},
		{"requires-padding", MultiplexOptions{Enabled: true, Padding: true}, MultiplexOptions{Enabled: true, Protocol: "smux"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			in := testInbound(t, "shadowsocks")
			in.Multiplex = test.server
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Multiplex = test.client
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := client.Dial(ctx, "tcp", relayEchoTCP(t))
			if err == nil {
				c.SetDeadline(time.Now().Add(time.Second))
				_, err = c.Read(make([]byte, 1))
				c.Close()
			}
			if err == nil {
				t.Fatal("unnegotiated multiplex was accepted")
			}
		})
	}
}

func TestGenericMuxHardConnectionLimit(t *testing.T) {
	in := testInbound(t, "shadowsocks")
	in.Multiplex.Enabled = true
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Multiplex = MultiplexOptions{Enabled: true, Protocol: "smux", MaxConnections: 1}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	target := relayEchoTCP(t)
	all := make([]net.Conn, 0, 128)
	defer func() {
		for _, c := range all {
			c.Close()
		}
	}()
	for range 128 {
		c, err := client.Dial(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, c)
	}
	c, err := client.Dial(context.Background(), "tcp", target)
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("max_connections was exceeded when all streams were busy")
	}
	if len(client.genericMuxClients[out.Tag].entries) != 1 {
		t.Fatal("created extra physical connection")
	}
}
