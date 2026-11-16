package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func masqueHTTPPair(t *testing.T, version int, mode string) (*Runtime, *Runtime) {
	t.Helper()
	in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	host, port, _ := net.SplitHostPort(server.Address("server"))
	p, _ := shadowPort(port)
	out := Outbound{Type: "masque", Tag: "proxy", Server: host, ServerPort: p, Username: "client", Password: "private", HTTPVersion: version, TLS: TLSOptions{Enabled: true, Insecure: true}, MasqueOptions: MasqueOptions{Mode: mode}}
	return server, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}
func TestMasqueHTTPIndependent(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mode := range []string{"ip", "udp"} {
			t.Run(fmt.Sprintf("http%d/%s", version, mode), func(t *testing.T) {
				_, c := masqueHTTPPair(t, version, mode)
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				c.resetNetworkTransports()
				assertTCP(t, c)
				assertUDPAddress(t, c, []int{1, 60000}, masqueEcho(t, "udp", "[::1]:0"))
			})
		}
	}
}
func TestMasqueHTTPConcurrent(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mode := range []string{"ip", "udp"} {
			t.Run(fmt.Sprintf("http%d/%s", version, mode), func(t *testing.T) {
				_, c := masqueHTTPPair(t, version, mode)
				address := echoUDP(t)
				var wait sync.WaitGroup
				for i := range 16 {
					wait.Go(func() {
						conn, e := c.Dial(context.Background(), "udp", address)
						if e != nil {
							t.Error(e)
							return
						}
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(4 * time.Second))
						for range 4 {
							want := bytes.Repeat([]byte{byte(i)}, 8192)
							if _, e = conn.Write(want); e != nil {
								t.Error(e)
								return
							}
							got := make([]byte, 8192)
							n, e := conn.Read(got)
							if e != nil || !bytes.Equal(want, got[:n]) {
								t.Error("crossed MASQUE flows", n, e)
								return
							}
						}
					})
				}
				wait.Wait()
				conn, e := c.Dial(context.Background(), "udp", address)
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
				if _, e = conn.Read(make([]byte, 1)); !os.IsTimeout(e) {
					t.Fatal("read timeout", e)
				}
				conn.SetDeadline(time.Now().Add(time.Second))
				if _, e = conn.Write([]byte{42}); e != nil {
					t.Fatal(e)
				}
				b := make([]byte, 1)
				if _, e = conn.Read(b); e != nil || b[0] != 42 {
					t.Fatal(e, b)
				}
			})
		}
	}
}
func TestMasqueHTTPTCPHalfClose(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, cleartext := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/cleartext=%t", version, cleartext), func(t *testing.T) {
				var c *Runtime
				if cleartext {
					_, c = masqueCleartextPair(t, version, "udp")
				} else {
					_, c = masqueHTTPPair(t, version, "udp")
				}
				listener, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer listener.Close()
				done := make(chan error, 1)
				go func() {
					conn, e := listener.Accept()
					if e != nil {
						done <- e
						return
					}
					defer conn.Close()
					b, e := io.ReadAll(conn)
					if e == nil {
						e = writeAll(conn, append([]byte("trailing:"), b...))
					}
					done <- e
				}()
				conn, e := c.Dial(context.Background(), "tcp", listener.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				writeAll(conn, []byte("body"))
				if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
					t.Fatal(e)
				}
				got, e := io.ReadAll(conn)
				if e != nil || string(got) != "trailing:body" {
					t.Fatal(string(got), e)
				}
				if e = <-done; e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}

func TestMasqueHTTPAuthentication(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mode := range []string{"ip", "udp"} {
			t.Run(fmt.Sprintf("%d/%s", version, mode), func(t *testing.T) {
				f := newMutualTLSFixture(t)
				in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, TLS: f.server()}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "blocked"}}, Route: Route{Final: "blocked", Rules: []Rule{{AuthUser: []string{"example.com"}, Outbound: "direct"}}}})
				host, p, _ := net.SplitHostPort(s.Address("server"))
				port, _ := shadowPort(p)
				out := Outbound{Type: "masque", Tag: "proxy", Server: host, ServerPort: port, HTTPVersion: version, TLS: f.client(), MasqueOptions: MasqueOptions{Mode: mode}}
				c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 4096})
				for _, failure := range []string{"missing-identity", "hostname", "untrusted"} {
					t.Run(failure, func(t *testing.T) {
						bad := out
						bad.TLS = out.TLS
						switch failure {
						case "missing-identity":
							bad.TLS.ClientCertificate = nil
							bad.TLS.ClientKey = nil
						case "hostname":
							bad.TLS.ServerName = "invalid.example"
						case "untrusted":
							bad.TLS.Certificate = []string{newMutualTLSFixture(t).ca}
						}
						denied := newTestRuntime(t, Config{Outbounds: []Outbound{bad}})
						ctx, cancel := context.WithTimeout(context.Background(), time.Second)
						defer cancel()
						conn, e := denied.Dial(ctx, "tcp", s.Address("server"))
						if e == nil {
							conn.Close()
							t.Fatal("TLS failure accepted")
						}
					})
				}
				passwordServer, passwordClient := masqueHTTPPair(t, version, mode)
				wrong := passwordClient.config.Outbounds[0]
				wrong.Password = "bad"
				bad := newTestRuntime(t, Config{Outbounds: []Outbound{wrong}})
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if conn, e := bad.Dial(ctx, "tcp", passwordServer.Address("server")); e == nil {
					conn.Close()
					t.Fatal("wrong password accepted")
				}
				assertTCP(t, passwordClient)
			})
		}
	}
}
func TestMasqueHTTPLifecycle(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, mode := range []string{"ip", "udp"} {
			t.Run(fmt.Sprintf("%d/%s", version, mode), func(t *testing.T) {
				s, c := masqueHTTPPair(t, version, mode)
				conn, e := c.Dial(context.Background(), "udp", echoUDP(t))
				if e != nil {
					t.Fatal(e)
				}
				if _, e = conn.Write([]byte("active")); e != nil {
					t.Fatal(e)
				}
				if _, e = conn.Read(make([]byte, 32)); e != nil {
					t.Fatal(e)
				}
				blocked := make(chan error, 1)
				go func() { _, e := conn.Read(make([]byte, 32)); blocked <- e }()
				stopped := make(chan struct{})
				go func() { c.Close(); s.Close(); close(stopped) }()
				select {
				case <-stopped:
				case <-time.After(2 * time.Second):
					t.Fatal("runtime close stalled")
				}
				select {
				case e := <-blocked:
					if e == nil {
						t.Fatal("read survived close")
					}
				case <-time.After(time.Second):
					t.Fatal("reader leaked")
				}
			})
		}
	}
}
func TestMasqueHTTPConfiguration(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3, 4, -1} {
		o := MasqueOptions{}
		e := o.validate("masque", TLSOptions{Enabled: true}, version, 0, nil, false)
		if (e == nil) != (version >= 0 && version <= 3) {
			t.Fatal(version, e)
		}
	}
	for _, version := range []int{1, 2} {
		o := MasqueOptions{}
		for _, tls := range []TLSOptions{{Enabled: true, ALPN: []string{"h3"}}, {Enabled: true, MaxVersion: "1.1"}} {
			if e := o.validate("masque", tls, version, 0, nil, false); e == nil {
				t.Fatal("invalid HTTP TLS", version, tls)
			}
		}
	}
}
