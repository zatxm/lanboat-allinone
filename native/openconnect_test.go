package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func ocPair(t *testing.T, ciphers ...string) (*Runtime, *Runtime) {
	t.Helper()
	return ocOptionsPair(t, OpenConnectOptions{Group: "staff", DTLSCipherSuites: ciphers})
}

func ocOptionsPair(t *testing.T, options OpenConnectOptions) (*Runtime, *Runtime) {
	t.Helper()
	in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "p<&\"密码"}}, TLS: certificate(t), OpenConnectOptions: options}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	host, port, _ := net.SplitHostPort(s.Address("server"))
	var n uint16
	fmt.Sscan(port, &n)
	o := Outbound{Type: "openconnect", Tag: "proxy", Server: host, ServerPort: n, Username: "client", Password: in.Users[0].Password, TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: in.OpenConnectOptions}
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{o}})
}
func TestOpenConnectIndependent(t *testing.T) {
	server, c := ocPair(t)
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
	old := c.ocClients["proxy"].tunnel.Load()
	c.resetNetworkTransports()
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{511})
	if c.ocClients["proxy"].tunnel.Load() == old {
		t.Fatal("network reset retained tunnel")
	}
	c.resetNetworkTransports()
	c.ocClients["proxy"].cookie = server.ocServers["server"].cookie("client", time.Now().Add(-2*time.Hour))
	assertTCP(t, c)
}
func TestOpenConnectConcurrentFlows(t *testing.T) {
	_, c := ocPair(t)
	tunnel, err := c.ocClients["proxy"].session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ocWaitDTLS(t, tunnel)
	address := echoUDP(t)
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			conn, e := c.Dial(context.Background(), "udp", address)
			if e != nil {
				t.Error(e)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			for range 4 {
				b := bytes.Repeat([]byte{byte(i)}, 4096)
				if _, e = conn.Write(b); e != nil {
					t.Error(e)
					return
				}
				out := make([]byte, 8192)
				n, e := conn.Read(out)
				if e != nil || !bytes.Equal(b, out[:n]) {
					t.Error(n, e)
					return
				}
			}
		})
	}
	wg.Wait()
}
func TestOpenConnectCookie(t *testing.T) {
	s := newOCServer()
	now := time.Unix(1000000, 0)
	cookie := s.cookie("u<&用户", now)
	if s.user(cookie, now) != "u<&用户" || s.user(cookie, now.Add(time.Hour)) != "" || newOCServer().user(cookie, now) != "" {
		t.Fatal("session validation")
	}
	b, _ := base64.RawURLEncoding.DecodeString(cookie)
	for i := range b {
		bad := bytes.Clone(b)
		bad[i] ^= 1
		if s.user(base64.RawURLEncoding.EncodeToString(bad), now) != "" {
			t.Fatal("accepted changed session", i)
		}
	}
	for _, bad := range []string{"", "%%%", cookie + "A", string(bytes.Repeat([]byte{'A'}, 1025))} {
		if s.user(bad, now) != "" {
			t.Fatal("invalid cookie accepted")
		}
	}
}
func TestOpenConnectAuthentication(t *testing.T) {
	_, client := ocPair(t)
	o := client.config.Outbounds[0]
	for _, field := range []string{"user", "password", "group"} {
		t.Run(field, func(t *testing.T) {
			bad := o
			switch field {
			case "user":
				bad.Username = "other"
			case "password":
				bad.Password = "bad"
			case "group":
				bad.Group = "bad"
			}
			r := newTestRuntime(t, Config{Outbounds: []Outbound{bad}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, e := r.Dial(ctx, "tcp", "127.0.0.1:9"); e == nil {
				conn.Close()
				t.Fatal("accepted invalid credentials")
			}
		})
	}
	if !ocValidCookie("valid-_01") {
		t.Fatal("valid cookie rejected")
	}
	for _, s := range []string{"", "a\rb", "a;b", "a b", "a\\b"} {
		if ocValidCookie(s) {
			t.Fatal("invalid cookie", s)
		}
	}
}
func TestOpenConnectSameOrigin(t *testing.T) {
	u, _ := url.Parse("https://vpn.example:443/auth")
	for _, v := range []string{"http://vpn.example:443/", "https://evil.example/", "//evil.example/a", "https://u@vpn.example:443/", "/auth#fragment"} {
		if _, e := ocSameOrigin(u, u, v); e == nil {
			t.Fatal("accepted action", v)
		}
	}
	for _, v := range []string{"/auth", "next", "?a=1", "https://vpn.example:443/"} {
		if _, e := ocSameOrigin(u, u, v); e != nil {
			t.Fatal(v, e)
		}
	}
}
func TestOpenConnectAddresses(t *testing.T) {
	valid := http.Header{}
	valid.Set("X-CSTP-Address", "10.44.0.2")
	valid.Set("X-CSTP-Address-IP6", "fd44::2/64")
	a, e := ocAddresses(valid)
	if e != nil || len(a) != 2 {
		t.Fatal(a, e)
	}
	for _, value := range []string{"0.0.0.0", "224.0.0.1", "::ffff:10.0.0.1", "fe80::1%eth0", "invalid"} {
		h := http.Header{}
		h.Set("X-CSTP-Address", value)
		if _, e := ocAddresses(h); e == nil {
			t.Fatal("accepted", value)
		}
	}
	valid.Add("X-CSTP-Address", "10.44.0.3")
	if _, e := ocAddresses(valid); e == nil {
		t.Fatal("duplicate family")
	}
}
func TestOpenConnectConfig(t *testing.T) {
	_, c := ocPair(t)
	base := c.config
	for _, change := range []func(*Outbound){func(o *Outbound) { o.TLS.Enabled = false }, func(o *Outbound) { o.TLS.ALPN = []string{"h2"} }, func(o *Outbound) { o.MTU = 1279 }, func(o *Outbound) { o.LocalAddress = []string{"0.0.0.0/32"} }, func(o *Outbound) { o.Group = "a\r\nb" }, func(o *Outbound) { o.Transport.Type = "ws" }, func(o *Outbound) { o.Password = strings.Repeat("p", 256) }} {
		copy := base
		copy.Outbounds = append([]Outbound{}, base.Outbounds...)
		change(&copy.Outbounds[0])
		raw, _ := json.Marshal(copy)
		if _, e := Parse(raw); e == nil {
			t.Fatal("accepted invalid OpenConnect config", string(raw))
		}
	}
	value := ocXML{Client: "vpn", Type: "auth-reply", Auth: &ocAuth{Fields: []ocField{{XMLName: xml.Name{Local: "password"}, Value: "<secret>&密码"}}}}
	b, e := ocMarshal(value)
	if e != nil {
		t.Fatal(e)
	}
	var got ocXML
	if e = xml.Unmarshal(b, &got); e != nil || got.Auth.Fields[0].Value != "<secret>&密码" {
		t.Fatal(e, string(b))
	}
}
func TestOpenConnectBufferedResponse(t *testing.T) {
	packet := []byte("HTTP/1.1 200 CONNECTED\r\nX-CSTP-MTU: 1280\r\n\r\nSTF\x01\x00\x01\x04\x00X")
	response, reader, e := ocResponse(bufio.NewReader(bytes.NewReader(packet)), &http.Request{Method: "CONNECT"})
	if e != nil || response.StatusCode != 200 {
		t.Fatal(e)
	}
	k, b, e := ocReadFrame(reader, make([]byte, 65535))
	if e != nil || k != 4 || string(b) != "X" {
		t.Fatal(k, b, e)
	}
}
func TestOpenConnectDPD(t *testing.T) {
	_, r := ocPair(t)
	left, right := net.Pipe()
	defer right.Close()
	tunnel := newOCTunnel(r, left, "", []netip.Addr{netip.MustParseAddr("10.44.0.2")}, 1280, "", time.Hour)
	tunnel.start()
	defer func() { tunnel.close(); <-tunnel.finished }()
	frame := []byte{'S', 'T', 'F', 1, 0, 3, 3, 0, 1, 2, 3}
	right.SetDeadline(time.Now().Add(time.Second))
	if e := writeAll(right, frame); e != nil {
		t.Fatal(e)
	}
	kind, b, e := ocReadFrame(right, make([]byte, 65535))
	if e != nil || kind != 4 || !bytes.Equal(b, []byte{1, 2, 3}) {
		t.Fatal(kind, b, e)
	}
	frame[7] = 1
	if e = writeAll(right, frame[:8]); e != nil {
		t.Fatal(e)
	}
	select {
	case <-tunnel.finished:
	case <-time.After(time.Second):
		t.Fatal("invalid frame retained tunnel")
	}
}

func TestOpenConnectSourceIsolation(t *testing.T) {
	r := newTestRuntime(t, Config{})
	left, right := net.Pipe()
	defer right.Close()
	tunnel := newOCTunnel(r, left, "server", []netip.Addr{netip.MustParseAddr("10.44.0.2")}, 1280, "client", time.Hour)
	tunnel.start()
	defer func() { tunnel.close(); <-tunnel.finished }()
	destination := netip.MustParseAddr("127.0.0.1")
	payload := makeUDPPacket(netip.MustParseAddr("10.44.0.99"), destination, 10000, 53, []byte("spoof"))
	frame := append([]byte("STF\x01\x00\x00\x00\x00"), payload...)
	binary.BigEndian.PutUint16(frame[4:6], uint16(len(payload)))
	right.SetDeadline(time.Now().Add(time.Second))
	if e := writeAll(right, frame); e != nil {
		t.Fatal(e)
	}
	// A subsequent DPD reply is an ordered receive-loop barrier.
	if e := writeAll(right, []byte("STF\x01\x00\x00\x03\x00")); e != nil {
		t.Fatal(e)
	}
	if kind, _, e := ocReadFrame(right, make([]byte, 65535)); e != nil || kind != 4 {
		t.Fatal(kind, e)
	}
	tunnel.stack.mu.Lock()
	defer tunnel.stack.mu.Unlock()
	if len(tunnel.stack.tcp)+len(tunnel.stack.udp) != 0 || len(tunnel.stack.udpJobs) != 0 {
		t.Fatal("source spoof reached IP stack")
	}
}
func TestOpenConnectCancellationAndDeadlines(t *testing.T) {
	_, r := ocPair(t)
	address := echoUDP(t)
	c, e := r.Dial(context.Background(), "udp", address)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, e = c.Read(make([]byte, 1)); !os.IsTimeout(e) {
		t.Fatal("UDP read deadline", e)
	}
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte{42})
	var b [1]byte
	if _, e = c.Read(b[:]); e != nil || b[0] != 42 {
		t.Fatal(e, b)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Read(b[:]); e == nil {
		t.Fatal("closed runtime retained flow")
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		conn, e := l.Accept()
		if e == nil {
			defer conn.Close()
			var b [4096]byte
			for {
				if _, e = conn.Read(b[:]); e != nil {
					return
				}
			}
		}
	}()
	host, port, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.Atoi(port)
	slow := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "proxy", Server: host, ServerPort: uint16(n), Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}}}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if conn, e := slow.Dial(ctx, "tcp", "127.0.0.1:9"); e == nil {
		conn.Close()
		t.Fatal("accepted stalled handshake")
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancellation was delayed")
	}
}
func TestOpenConnectSessionIsolation(t *testing.T) {
	_, first := ocPair(t)
	second := newTestRuntime(t, first.config)
	var wg sync.WaitGroup
	for _, c := range []*Runtime{first, second} {
		wg.Go(func() { assertTCP(t, c); assertUDPSizes(t, c, []int{511, 60000}) })
	}
	wg.Wait()
}

func BenchmarkOpenConnectFrame(b *testing.B) {
	frame := append([]byte("STF\x01\x05\x00\x00\x00"), make([]byte, 1280)...)
	buffer := make([]byte, 65535)
	reader := bytes.NewReader(frame)
	b.ReportAllocs()
	b.SetBytes(1280)
	for b.Loop() {
		reader.Reset(frame)
		if _, _, e := ocReadFrame(reader, buffer); e != nil {
			b.Fatal(e)
		}
	}
}
func FuzzOpenConnectFrame(f *testing.F) {
	f.Add([]byte("STF\x01\x00\x01\x04\x00X"))
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, p, e := ocReadFrame(bytes.NewReader(b), make([]byte, 65535))
		if e == nil {
			if len(b) < 8 || len(p) != int(binary.BigEndian.Uint16(b[4:6])) || k != b[6] {
				t.Fatal("invalid parsed frame")
			}
		}
	})
}
