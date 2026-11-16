package native

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func masquePair(t *testing.T, mode string) (*Runtime, *Runtime) {
	t.Helper()
	in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	host, port, _ := net.SplitHostPort(server.Address("server"))
	var n uint16
	fmt.Sscan(port, &n)
	out := Outbound{Type: "masque", Tag: "proxy", Server: host, ServerPort: n, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}, MasqueOptions: MasqueOptions{Mode: mode}}
	return server, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}
func TestMasqueIndependent(t *testing.T) {
	for _, mode := range []string{"ip", "udp"} {
		t.Run(mode, func(t *testing.T) {
			_, c := masquePair(t, mode)
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
			c.resetNetworkTransports()
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{511})
		})
	}
}
func TestMasqueConcurrentFlows(t *testing.T) {
	for _, mode := range []string{"ip", "udp"} {
		t.Run(mode, func(t *testing.T) {
			_, c := masquePair(t, mode)
			address := echoUDP(t)
			var workers sync.WaitGroup
			for i := range 16 {
				workers.Go(func() {
					conn, e := c.Dial(context.Background(), "udp", address)
					if e != nil {
						t.Error(e)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					for range 4 {
						data := bytes.Repeat([]byte{byte(i)}, 4096)
						if _, e = conn.Write(data); e != nil {
							t.Error(e)
							return
						}
						got := make([]byte, 8192)
						n, e := conn.Read(got)
						if e != nil || !bytes.Equal(data, got[:n]) {
							t.Error("crossed MASQUE flows", i, n, e)
							return
						}
					}
				})
			}
			workers.Wait()
			conn, e := c.Dial(context.Background(), "udp", address)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
			if _, e = conn.Read(make([]byte, 1)); !os.IsTimeout(e) {
				t.Fatal(e)
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
func TestMasqueAuthenticationAndRoutes(t *testing.T) {
	server, c := masquePair(t, "ip")
	out := c.config.Outbounds[0]
	out.Password = "bad"
	bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	conn, e := bad.Dial(context.Background(), "tcp", server.Address("server"))
	if e == nil {
		conn.Close()
		t.Fatal("wrong password accepted")
	}
	assertTCP(t, c)
	p := c.masqueClients["proxy"].ip.Load()
	if p.allowed(netip.MustParseAddr("192.0.2.123")) {
		t.Fatal("unassigned source accepted")
	}
	if e = p.control(3, nil); e != nil {
		t.Fatal(e)
	}
	packet := makeUDPPacket(p.addresses()[0], netip.MustParseAddr("127.0.0.1"), 1234, 53, []byte{1})
	if e = p.writePacket(packet); e != ErrRejected {
		t.Fatal("withdrawn route allowed", e)
	}
}
func TestMasqueCapsules(t *testing.T) {
	for _, b := range [][]byte{{0, 5}, {0, 4, 10, 1, 1, 1, 24}, {1, 4, 0, 0, 0, 0, 33}} {
		if _, e := masqueAddresses(b, false); e == nil {
			t.Fatal("invalid address accepted", b)
		}
	}
	if _, e := masqueAddresses(nil, true); e == nil {
		t.Fatal("empty request accepted")
	}
	for _, path := range []string{"/.well-known/masque/udp/host/0/", "/.well-known/masque/udp/host/65536/", "/.well-known/masque/udp/%2f/53/", "/wrong"} {
		if _, e := masqueUDPTarget(path); e == nil {
			t.Fatal(path)
		}
	}
	for _, host := range []string{"example.com", "127.0.0.1", "2001%3Adb8%3A%3A1"} {
		if _, e := masqueUDPTarget("/.well-known/masque/udp/" + host + "/53/"); e != nil {
			t.Fatal(host, e)
		}
	}
}
func FuzzMasqueCapsules(f *testing.F) {
	f.Add([]byte{0, 4, 10, 0, 0, 2, 32})
	f.Add([]byte{4, 0, 0, 0, 0, 255, 255, 255, 255, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = masqueAddresses(b, false)
		_, _ = masqueAddresses(b, true)
		if routes, err := masqueRoutes(b); err == nil {
			for _, route := range routes {
				masqueRouteWidth(route)
			}
		}
		_, _ = masqueUDPTarget(string(b))
	})
}

func TestMasqueParallelTCP(t *testing.T) {
	for _, mode := range []string{"ip", "udp"} {
		t.Run(mode, func(t *testing.T) {
			_, r := masquePair(t, mode)
			target := relayEchoTCP(t)
			var workers sync.WaitGroup
			for i := range 8 {
				workers.Go(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					c, e := r.Dial(ctx, "tcp", target)
					if e != nil {
						t.Error(e)
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(10 * time.Second))
					data := bytes.Repeat([]byte{byte(i)}, 300000)
					done := make(chan error, 1)
					go func() { done <- writeAll(c, data) }()
					got := make([]byte, len(data))
					_, e = io.ReadFull(c, got)
					if e != nil || !bytes.Equal(data, got) {
						t.Error("concurrent TCP tunnel", e)
					}
					if e = <-done; e != nil {
						t.Error(e)
					}
				})
			}
			workers.Wait()
		})
	}
}
func TestMasqueICMP(t *testing.T) {
	var c *Runtime
	// Route a synthetic Echo in the independent stack without raw-socket privileges.
	in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t)}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Route: Route{Rules: []Rule{{Network: []string{"icmp"}, Action: "reject", Method: "reply"}}}})
	out := testOutbound(t, in, server.Address("server"))
	c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	p, e := c.masqueClients["proxy"].ipSession(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, address := range []string{"127.0.0.1", "::1"} {
		ip := netip.MustParseAddr(address)
		echo := []byte{8, 0, 0, 0, 0, 1, 0, 7, 9, 8, 7}
		want := byte(0)
		if ip.Is6() {
			echo[0] = 128
			want = 129
		}
		reply, e := p.stack.exchangeICMP(ctx, ip, echo, 64)
		if e != nil || len(reply.data) < 8 || reply.data[0] != want {
			t.Fatal(address, reply, e)
		}
	}
}
func TestMasqueHeaderOrder(t *testing.T) {
	if _, e := h3Decode(h3Encode([][2]string{{"host", "proxy"}, {":method", "CONNECT"}})); e == nil {
		t.Fatal("pseudo-header after ordinary header accepted")
	}
}

func TestMasqueRawIdentity(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(pub)
	in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t)}
	in.TLS.ClientAuthentication = "require-and-verify"
	in.TLS.ClientCertificatePublicKeySHA256 = []string{base64.StdEncoding.EncodeToString(sum[:])}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	identity, e := tls.X509KeyPair([]byte(strings.Join(in.TLS.Certificate, "\n")), []byte(strings.Join(in.TLS.Key, "\n")))
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(identity.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	out := testOutbound(t, in, server.Address("server"))
	out.Username, out.Password = "", ""
	out.PrivateKey = []string{base64.StdEncoding.EncodeToString(der)}
	out.MasquePublicKey = base64.StdEncoding.EncodeToString(leaf.RawSubjectPublicKeyInfo)
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, client)
	assertUDPSizes(t, client, []int{1, 511})
	raw, e := json.Marshal(client.config)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Parse(raw); e != nil {
		t.Fatal("normalized identity cannot be reloaded", e)
	}
	out.MasquePublicKey = base64.StdEncoding.EncodeToString(pub)
	bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	if c, e := bad.Dial(context.Background(), "tcp", "127.0.0.1:80"); e == nil {
		c.Close()
		t.Fatal("wrong server key accepted")
	}
}
func TestMasqueBufferBounds(t *testing.T) {
	m := &masqueSession{q: &quicConn{done: make(chan struct{})}, space: make(chan struct{}, 1)}
	a := &masqueFlow{session: m, incoming: make(chan masqueDatagram, 256), done: make(chan struct{})}
	b := &masqueFlow{session: m, incoming: make(chan masqueDatagram, 256), done: make(chan struct{})}
	payload := make([]byte, 60001)
	for range 128 {
		if e := a.deliver(payload, false); e != nil {
			t.Fatal(e)
		}
	}
	if m.buffered.Load() > 4<<20 {
		t.Fatal("session queue exceeded budget")
	}
	before := m.buffered.Load()
	if e := b.deliver(payload, false); e != nil {
		t.Fatal(e)
	}
	if m.buffered.Load() != before {
		t.Fatal("streams did not share queue budget")
	}
}

func TestMasqueDatagramConsumerRace(t *testing.T) {
	// All datagrams fit both budgets even without a consumer. Concurrent reads
	// must not make a failed shared-budget CAS look like a full queue.
	const count = 16384
	m := newMasqueHTTPSession(context.Background())
	defer m.close()
	f := &masqueFlow{session: m, incoming: make(chan masqueDatagram, count), done: make(chan struct{}), notify: make(chan struct{}, 1)}
	f.SetReadDeadline(time.Now().Add(3 * time.Second))
	read := make(chan int, 1)
	go func() {
		b := make([]byte, 16)
		for i := range count {
			if _, err := f.Read(b); err != nil {
				read <- i
				return
			}
		}
		read <- count
	}()
	for range count {
		if err := f.deliver(make([]byte, 17), false); err != nil {
			t.Fatal(err)
		}
	}
	if got := <-read; got != count || m.buffered.Load() != 0 {
		t.Fatalf("non-full datagram queue lost packets:received %d/%d,budget %d", got, count, m.buffered.Load())
	}
}

func masqueEcho(t *testing.T, network, address string) string {
	t.Helper()
	if network == "tcp" {
		l, e := net.Listen("tcp", address)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
			}
		}()
		return l.Addr().String()
	}
	p, e := net.ListenPacket("udp", address)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { p.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, e := p.ReadFrom(b)
			if e != nil {
				return
			}
			p.WriteTo(b[:n], from)
		}
	}()
	return p.LocalAddr().String()
}
