package native

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func TestQUICTransportIndependent(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan", "shadowsocks", "relay"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = certificate(t)
			in.Transport = Transport{Type: "quic"}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address("server"))
			out.Transport = in.Transport
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			if kind == "shadowsocks" {
				if conn, err := c.Dial(context.Background(), "udp", echoUDP(t)); err == nil {
					conn.Close()
					t.Fatal("QUIC SS has no raw UDP channel")
				}
			} else if kind == "vmess" {
				assertUDPSizes(t, c, []int{1, 4096})
			} else {
				assertUDPSizes(t, c, []int{1, 4096, 60000})
			}
			c.resetNetworkTransports()
			assertTCP(t, c)
		})
	}
}

func TestQUICTransportReference(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		for _, side := range []string{"client", "server"} {
			t.Run(kind+"/"+side, func(t *testing.T) {
				in := testInbound(t, kind)
				in.TLS = certificate(t)
				in.Transport = Transport{Type: "quic"}
				var c *Runtime
				if side == "client" {
					in.ListenPort = unusedPort(t)
					ready := Inbound{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{ready, in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.Transport = in.Transport
					c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, s.Address("server"))
					out.Transport = in.Transport
					out.Username = ""
					if kind == "trojan" {
						out.UUID = ""
					} else {
						out.Password = ""
					}
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
					front := testOutbound(t, local, portAddress(local.Listen, local.ListenPort))
					front.Username, front.Password, front.UUID = "", "", ""
					c = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, c)
				if kind != "shadowsocks" {
					assertUDPSizes(t, c, []int{1, 4096})
				}
			})
		}
	}
}

func TestQUICTransportConcurrentCancelShutdown(t *testing.T) {
	in := testInbound(t, "vless")
	in.TLS = certificate(t)
	in.Transport = Transport{Type: "quic"}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.Transport = in.Transport
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	target := relayEchoTCP(t)
	var workers sync.WaitGroup
	for i := range 24 {
		workers.Go(func() {
			conn, err := c.Dial(context.Background(), "tcp", target)
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(8 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 70000)
			written := make(chan error, 1)
			go func() { written <- writeAll(conn, want) }()
			got := make([]byte, len(want))
			_, err = io.ReadFull(conn, got)
			if err != nil || !bytes.Equal(want, got) {
				t.Error("crossed QUIC transport streams", err)
			}
			if err := <-written; err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if conn, err := c.Dial(ctx, "tcp", target); err == nil {
		conn.Close()
		t.Fatal("canceled dial succeeded")
	}
	conn, err := c.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeAll(conn, []byte("warm")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { c.Close(); s.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("QUIC transport retained workers")
	}
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("closed runtime retained active stream")
	}
}

func TestQUICTransportValidationAndDetour(t *testing.T) {
	for _, transport := range []Transport{{Type: "quic", Path: "/"}, {Type: "quic", Host: "example.com"}, {Type: "quic", IdleTimeout: "1s"}, {Type: "quic", MaxEarlyData: 1}} {
		if transport.validate() == nil {
			t.Fatal("QUIC accepted HTTP/WS-only options", transport)
		}
	}
	if validateQUICTransport(Transport{Type: "quic"}, TLSOptions{}) == nil || validateQUICTransport(Transport{Type: "quic"}, TLSOptions{Enabled: true, MaxVersion: "1.2"}) == nil {
		t.Fatal("QUIC accepted missing TLS or old version")
	}
	out := Outbound{Type: "vless", Tag: "proxy", Server: "127.0.0.1", ServerPort: 1, UUID: testUUID, TLS: TLSOptions{Enabled: true, Insecure: true}, Transport: Transport{Type: "quic"}, Detour: "blocked"}
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out, {Type: "block", Tag: "blocked"}}})
	if conn, err := c.Dial(context.Background(), "tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("QUIC transport bypassed rejected detour")
	}
}

func TestQUICTransportGOSTReference(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			var c *Runtime
			if side == "client" {
				public := portAddress("127.0.0.1", unusedPort(t))
				ready := portAddress("127.0.0.1", unusedPort(t))
				startGOST(t, "-L", "socks5://"+ready, "-L", "relay+quic://client:private@"+public)
				waitPort(t, ready)
				out := testOutbound(t, Inbound{Type: "relay"}, public)
				out.TLS = TLSOptions{Enabled: true, Insecure: true, ALPN: []string{"h3", "quic", "gost"}}
				out.Transport = Transport{Type: "quic"}
				c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			} else {
				in := testInbound(t, "relay")
				in.TLS = certificate(t)
				in.TLS.ALPN = []string{"h3", "quic", "gost"}
				in.Transport = Transport{Type: "quic"}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				local := portAddress("127.0.0.1", unusedPort(t))
				startGOST(t, "-L", "socks5://"+local+"?udp=true", "-F", "relay+quic://client:private@"+s.Address("server")+"?secure=false")
				waitPort(t, local)
				out := testOutbound(t, Inbound{Type: "socks"}, local)
				out.Username, out.Password = "", ""
				c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			}
			assertTCP(t, c)
			if side == "client" {
				assertUDPSizes(t, c, []int{1, 4096})
			}
		})
	}
}
