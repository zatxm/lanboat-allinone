package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func realityFixture(t *testing.T) (TLSOptions, TLSOptions) {
	t.Helper()
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("reality-cover")) }))
	cover.EnableHTTP2 = true
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}}
	cover.StartTLS()
	t.Cleanup(cover.Close)
	host, port, _ := net.SplitHostPort(cover.Listener.Addr().String())
	n, _ := shadowPort(port)
	private, public, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := TLSOptions{Enabled: true, ServerName: "localhost", Reality: &RealityOptions{Enabled: true, PrivateKey: private, ShortID: []string{"0123456789abcdef", ""}, Handshake: &ShadowTLSHandshake{Server: host, ServerPort: n}, MaxTimeDifference: "1m"}}
	client := TLSOptions{Enabled: true, ServerName: "localhost", Reality: &RealityOptions{Enabled: true, PublicKey: public, ShortID: []string{"0123456789abcdef"}}}
	return server, client
}

func realityPair(t *testing.T, kind string, vision bool, transport Transport) (*Runtime, *Runtime) {
	t.Helper()
	server, client := realityFixture(t)
	in := testInbound(t, kind)
	in.TLS = server
	in.Transport = transport
	if vision {
		in.Users[0].Flow = visionFlow
	}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.TLS = client
	out.Transport = transport
	if vision {
		out.Flow = visionFlow
	}
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}

func TestRealityIndependent(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan", "anytls", "relay", "socks", "shadowsocks"} {
		t.Run(kind, func(t *testing.T) {
			_, c := realityPair(t, kind, false, Transport{})
			assertTCP(t, c)
			sizes := []int{1, 4096}
			if kind != "vmess" {
				sizes = append(sizes, 60000)
			}
			assertUDPSizes(t, c, sizes)
		})
	}
	for _, kind := range []string{"ws", "httpupgrade", "http", "grpc", "xhttp"} {
		t.Run(kind, func(t *testing.T) {
			tr := Transport{Type: kind, Path: "/reality"}
			if kind == "grpc" {
				tr.Path = ""
				tr.ServiceName = "reality"
			}
			_, c := realityPair(t, "vless", false, tr)
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
	for _, version := range []string{"http/1.1", "h2"} {
		t.Run("xhttp-"+version, func(t *testing.T) {
			server, client := realityFixture(t)
			server.ALPN, client.ALPN = []string{version}, []string{version}
			in := testInbound(t, "vless")
			in.TLS = server
			in.Transport = Transport{Type: "xhttp", Path: "/reality", XHTTPOptions: XHTTPOptions{Mode: "stream-one"}}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address("server"))
			o.TLS = client
			o.Transport = in.Transport
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
	t.Run("vision", func(t *testing.T) {
		_, c := realityPair(t, "vless", true, Transport{})
		assertTCP(t, c)
		visionHTTPS(t, c, tls.VersionTLS13, true)
		visionHTTPS(t, c, tls.VersionTLS12, true)
		assertUDPSizes(t, c, []int{1, 4096, 60000})
	})
	t.Run("vision-fragment", func(t *testing.T) {
		_, original := realityPair(t, "vless", true, Transport{})
		o := original.config.Outbounds[0]
		o.TLS.Fragment, o.TLS.RecordFragment = true, true
		o.TLS.FragmentFallbackDelay = "1ms"
		c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
		visionHTTPS(t, c, tls.VersionTLS13, true)
	})
}

func TestRealityAuthentication(t *testing.T) {
	server, client := realityFixture(t)
	cfg, err := client.config(false, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	h, err := newSTHello(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hello, err := h.marshal("", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	hello, err = client.Reality.clientHello(h, hello)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.Reality.authenticate(hello, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err = server.Reality.authenticate(hello, time.Now().Add(2*time.Minute)); err == nil {
		t.Fatal("expired authentication accepted")
	}
	for _, index := range []int{6, 20, 39, 50, 70, len(hello) - 1} {
		bad := bytes.Clone(hello)
		bad[index] ^= 1
		if _, err = server.Reality.authenticate(bad, time.Now()); err == nil {
			t.Fatal("tampered authentication", index)
		}
	}
	server.Reality.ShortID = []string{"0000000000000000"}
	if _, err = server.Reality.authenticate(hello, time.Now()); err == nil {
		t.Fatal("wrong short ID accepted")
	}
	private, _, _ := GenerateRealityKeyPair()
	server.Reality.PrivateKey = private
	if _, err = server.Reality.authenticate(hello, time.Now()); err == nil {
		t.Fatal("wrong server key accepted")
	}
}

func TestRealityFallback(t *testing.T) {
	s, c := realityPair(t, "vless", false, Transport{})
	for _, wrong := range []string{"public-key", "short-id", "server-name"} {
		t.Run(wrong, func(t *testing.T) {
			o := c.config.Outbounds[0]
			x := *o.TLS.Reality
			o.TLS.Reality = &x
			switch wrong {
			case "public-key":
				_, x.PublicKey, _ = GenerateRealityKeyPair()
			case "short-id":
				x.ShortID = []string{"ffffffffffffffff"}
			case "server-name":
				o.TLS.ServerName = "other.local"
			}
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if conn, err := bad.Dial(ctx, "tcp", "127.0.0.1:1"); err == nil {
				conn.Close()
				t.Fatal("invalid Reality authenticated")
			}
		})
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "localhost", MinVersion: tls.VersionTLS13}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get("https://" + s.Address("server"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil || string(b) != "reality-cover" {
		t.Fatal(string(b), err)
	}
}

func TestRealityHybrid(t *testing.T) {
	server, client := realityFixture(t)
	_ = server
	cfg, _ := client.config(false, "localhost")
	h, err := newSTHello(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if h.kem == nil {
		t.Fatal("hybrid key share missing")
	}
	wire, err := h.marshal("", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	_, pub, err := realityHelloData(wire)
	if err != nil || !bytes.Equal(pub, h.key.PublicKey().Bytes()) {
		t.Fatal("hybrid ECDH field mismatch", err)
	}
	for _, group := range []tls.CurveID{tls.X25519, tls.X25519MLKEM768} {
		t.Run(fmt.Sprint(group), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			options := certificate(t)
			scfg, err := options.config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			scfg.MinVersion = tls.VersionTLS13
			scfg.CurvePreferences = []tls.CurveID{group}
			done := make(chan error, 1)
			go func() {
				raw, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer raw.Close()
				c := tls.Server(raw, scfg)
				if e = c.Handshake(); e == nil {
					_, e = io.Copy(c, c)
				}
				done <- e
			}()
			raw, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}
			secure, err := shadowTLS13(context.Background(), raw, cfg, TLSOptions{}, "password")
			if err != nil {
				t.Fatal(err)
			}
			conn := &realityConn{Conn: secure.conn, tls: secure}
			defer conn.Close()
			want := bytes.Repeat([]byte("hybrid"), 10000)
			go conn.Write(want)
			got := make([]byte, len(want))
			if _, err = io.ReadFull(conn, got); err != nil || !bytes.Equal(got, want) {
				t.Fatal("hybrid data", err)
			}
			conn.Close()
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRealityConfig(t *testing.T) {
	server, client := realityFixture(t)
	cases := []struct {
		name   string
		server bool
		change func(*TLSOptions)
	}{
		{"disabled-tls", false, func(o *TLSOptions) { o.Enabled = false }},
		{"insecure", false, func(o *TLSOptions) { o.Insecure = true }},
		{"sni", false, func(o *TLSOptions) { o.DisableSNI = true }},
		{"version", false, func(o *TLSOptions) { o.MinVersion = "1.2" }},
		{"cipher", false, func(o *TLSOptions) { o.CipherSuites = []string{"TLS_AES_128_GCM_SHA256"} }},
		{"curves", false, func(o *TLSOptions) { o.CurvePreferences = []string{"X25519"} }},
		{"engine", false, func(o *TLSOptions) { o.Engine = "openssl" }},
		{"alpn", false, func(o *TLSOptions) { o.ALPN = []string{""} }},
		{"key", false, func(o *TLSOptions) { o.Reality.PublicKey = "bad" }},
		{"id", false, func(o *TLSOptions) { o.Reality.ShortID = []string{"xyz"} }},
		{"ids", false, func(o *TLSOptions) { o.Reality.ShortID = []string{"", "12"} }},
		{"cert", false, func(o *TLSOptions) { o.CertificatePath = "missing.pem" }},
		{"ech", false, func(o *TLSOptions) { o.ECH = &ECHOptions{} }},
		{"private-client", false, func(o *TLSOptions) { o.Reality.PrivateKey = server.Reality.PrivateKey }},
		{"handshake-client", false, func(o *TLSOptions) { o.Reality.Handshake = server.Reality.Handshake }},
		{"timestamp-client", false, func(o *TLSOptions) { o.Reality.MaxTimeDifference = "1m" }},
		{"duplicate", true, func(o *TLSOptions) { o.Reality.ShortID = []string{"12", "1200"} }},
		{"server-key", true, func(o *TLSOptions) { o.Reality.PrivateKey = "bad" }},
		{"missing-target", true, func(o *TLSOptions) { o.Reality.Handshake = nil }},
		{"fragment-inbound", true, func(o *TLSOptions) { o.Fragment = true }},
		{"disabled-reality", true, func(o *TLSOptions) { o.Reality.Enabled = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := client
			if tc.server {
				o = server
			}
			x := *o.Reality
			o.Reality = &x
			tc.change(&o)
			if _, err := o.config(tc.server, "localhost"); err == nil {
				t.Fatal("invalid Reality accepted")
			}
		})
	}
	for _, tr := range []Transport{{Type: "quic"}, {Type: "mkcp"}, {Type: "xhttp"}} {
		o := client
		if tr.Type == "xhttp" {
			o.ALPN = []string{"h3"}
		}
		if err := validateRealityTransport("vless", o, tr); err == nil {
			t.Fatal("non-TCP Reality accepted", tr.Type)
		}
	}
	if err := validateRealityTransport("hysteria2", client, Transport{}); err == nil {
		t.Fatal("QUIC proxy Reality accepted")
	}
	for _, o := range []TLSOptions{server, client} {
		cfg := Config{}
		if o.Reality.PrivateKey != "" {
			in := testInbound(t, "vless")
			in.TLS = o
			cfg.Inbounds = []Inbound{in}
		} else {
			cfg.Outbounds = []Outbound{{Type: "vless", Tag: "proxy", Server: "127.0.0.1", ServerPort: 443, UUID: testUUID, TLS: o}}
		}
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Parse(data); err != nil {
			t.Fatal("configuration round trip", err)
		}
	}
}

type realityFinishedTamper struct {
	net.Conn
	tampered bool
}

func (c *realityFinishedTamper) Write(b []byte) (int, error) {
	if !c.tampered && len(b) > 5 && b[0] == 23 {
		b = bytes.Clone(b)
		b[len(b)-1] ^= 1
		c.tampered = true
	}
	return c.Conn.Write(b)
}
func TestRealityFinished(t *testing.T) {
	server, client := realityFixture(t)
	s := newTestRuntime(t, Config{})
	in := testInbound(t, "vless")
	in.TLS = server
	scfg, err := server.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := s.realityAccept(in, b, scfg); b.Close(); done <- err }()
	cfg, _ := client.config(false, "localhost")
	tamper := &realityFinishedTamper{Conn: a}
	conn, err := dialReality(context.Background(), tamper, cfg, client)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = <-done; err == nil {
		t.Fatal("corrupted Finished accepted")
	}
	if !tamper.tampered {
		t.Fatal("Finished not tampered")
	}
}

func FuzzRealityHello(f *testing.F) {
	private, public, err := GenerateRealityKeyPair()
	if err != nil {
		f.Fatal(err)
	}
	client := RealityOptions{Enabled: true, PublicKey: public, ShortID: []string{""}}
	server := RealityOptions{Enabled: true, PrivateKey: private, ShortID: []string{""}}
	h, err := newSTHello(&tls.Config{ServerName: "public.test", CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}})
	if err != nil {
		f.Fatal(err)
	}
	hello, _ := h.marshal("", nil, false)
	hello, err = client.clientHello(h, hello)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(hello)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		realityHelloData(data)
		server.authenticate(data, time.Now())
	})
}

func TestRealityCancellation(t *testing.T) {
	_, client := realityFixture(t)
	cfg, err := client.config(false, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"hello-write", "server-read"} {
		t.Run(phase, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			if phase == "server-read" {
				go func() { shadowHello(b) }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := dialReality(ctx, a, cfg, client); done <- err }()
			select {
			case err := <-done:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Reality handshake ignored context cancellation")
			}
		})
	}
}

func TestRealityDefaults(t *testing.T) {
	server, client := realityFixture(t)
	server.ServerName = ""
	server.Reality.ShortID = nil
	server.Reality.MaxTimeDifference = "0s"
	client.Reality.ShortID = nil
	in := testInbound(t, "vless")
	in.TLS = server
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.TLS = client
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 4096})
	cfg, _ := client.config(false, "localhost")
	h, _ := newSTHello(cfg)
	hello, _ := h.marshal("", nil, false)
	hello, _ = client.Reality.clientHello(h, hello)
	if _, err := server.Reality.authenticate(hello, time.Now().Add(time.Hour)); err != nil {
		t.Fatal("zero duration did not disable clock window", err)
	}
	for _, value := range []string{"-1s", "bad"} {
		o := server
		x := *server.Reality
		o.Reality = &x
		x.MaxTimeDifference = value
		if _, err := o.config(true, ""); err == nil {
			t.Fatal("invalid duration accepted", value)
		}
	}
}
