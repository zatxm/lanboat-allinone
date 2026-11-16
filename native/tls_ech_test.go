package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testECHPair(t testing.TB) (string, string) {
	t.Helper()
	config, key, err := GenerateECHKeyPair("public.test")
	if err != nil {
		t.Fatal(err)
	}
	return string(config), string(key)
}

func testECHServer(t *testing.T, f mutualTLSFixture, key string) TLSOptions {
	o := f.server()
	o.ClientAuthentication, o.ClientCertificate = "", nil
	o.ECH = &ECHOptions{Enabled: true, Key: []string{key}}
	return o
}

func testECHClient(f mutualTLSFixture, config string) TLSOptions {
	o := f.client()
	o.ClientCertificate, o.ClientKey = nil, nil
	o.ECH = &ECHOptions{Enabled: true, Config: []string{config}}
	return o
}

func requireECH(state tls.ConnectionState) error {
	if !state.ECHAccepted {
		return errors.New("ECH was not negotiated")
	}
	return nil
}

func newECHRuntime(t *testing.T, cfg Config, tag string) *Runtime {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), data, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	r.serverTLS[tag].VerifyConnection = requireECH
	if err = r.Start(); err != nil {
		t.Fatal(err)
	}
	return r
}

type echCaptureConn struct {
	net.Conn
	mu sync.Mutex
	b  bytes.Buffer
}

func (c *echCaptureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.b.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func TestECHHandshakePrivacy(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	s, err := testECHServer(t, f, key).config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := testECHClient(f, config).config(false, "")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	right, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	left, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	left.SetDeadline(time.Now().Add(2 * time.Second))
	right.SetDeadline(time.Now().Add(2 * time.Second))
	type result struct {
		state tls.ConnectionState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		server := tls.Server(left, s)
		err := server.Handshake()
		if err == nil {
			var b [1]byte
			_, err = io.ReadFull(server, b[:])
		}
		done <- result{server.ConnectionState(), err}
	}()
	capture := &echCaptureConn{Conn: right}
	client := tls.Client(capture, c)
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	server := <-done
	if server.err != nil || !server.state.ECHAccepted || !client.ConnectionState().ECHAccepted || server.state.ServerName != "example.com" {
		t.Fatalf("ECH was not accepted: %+v, %v", server.state, server.err)
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if bytes.Contains(capture.b.Bytes(), []byte("example.com")) || !bytes.Contains(capture.b.Bytes(), []byte("public.test")) {
		t.Fatal("inner server name exposed or outer server name missing")
	}
}

func TestECHProtocols(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	for _, kind := range []string{"socks", "http", "trojan", "anytls", "relay", "vless", "vmess", "hysteria2", "tuic", "brook", "trusttunnel"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = testECHServer(t, f, key)
			if isQUICProxy(kind) {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			if kind == "trusttunnel" {
				in.Users = []User{{Username: "client", Password: "private"}}
			}
			if kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/ech"}
			}
			if kind == "vmess" {
				in.Transport = Transport{Type: "grpc", ServiceName: "ech"}
			}
			if kind == "brook" {
				in.Transport = Transport{Type: "ws", Path: "/ech"}
			}
			s := newECHRuntime(t, Config{Inbounds: []Inbound{in}}, in.Tag)
			out := testOutbound(t, in, s.Address(in.Tag))
			out.TLS, out.Transport = testECHClient(f, config), in.Transport
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			if kind != "http" {
				assertUDPSizes(t, c, []int{1, 511})
			}
		})
	}
}

func TestECHRejectDoesNotDowngrade(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, _ := testECHPair(t)
	_, different := testECHPair(t)
	for _, kind := range []string{"trojan", "vless", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = testECHServer(t, f, different)
			if kind == "hysteria2" {
				in.Users = []User{{Password: "private"}}
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address(in.Tag))
			out.TLS = testECHClient(f, config)
			out.TLS.Insecure = true
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			var hits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			defer origin.Close()
			u := strings.TrimPrefix(origin.URL, "http://")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := c.Dial(ctx, "tcp", u)
			if conn != nil {
				conn.Close()
			}
			if err == nil || hits.Load() != 0 {
				t.Fatal("ECH rejection reached origin")
			}
		})
	}
}

func TestECHMutualTLSAndPins(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	for _, source := range []string{"pem", "pkcs12", "pins"} {
		t.Run(source, func(t *testing.T) {
			so, co := f.server(), f.client()
			so.ECH = &ECHOptions{Enabled: true, Key: []string{key}}
			co.ECH = &ECHOptions{Enabled: true, Config: []string{config}}
			if source == "pkcs12" {
				so.Certificate, so.Key = nil, nil
				co.ClientCertificate, co.ClientKey = nil, nil
				so.PKCS12 = base64.StdEncoding.EncodeToString(exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, "private"))
				so.PKCS12Password = "private"
				co.PKCS12 = base64.StdEncoding.EncodeToString(exportTestPKCS12(t, f.clientCert, f.clientKey, f.ca, "private"))
				co.PKCS12Password = "private"
			}
			if source == "pins" {
				so.ClientCertificate = nil
				so.ClientCertificateSHA256 = []string{tlsPinFor(t, f.clientCert, false)}
				co.Certificate = nil
				co.CertificateSHA256 = []string{tlsPinFor(t, f.serverCert, false)}
			}
			s, err := so.config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			c, err := co.config(false, "")
			if err != nil {
				t.Fatal(err)
			}
			ss, cs, err := exchangeTLSPair(s, c)
			if err != nil || !ss.ECHAccepted || !cs.ECHAccepted || len(ss.PeerCertificates) == 0 {
				t.Fatalf("ECH mTLS: %v", err)
			}
		})
	}
}

func TestECHOfficialReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 is required for ECH interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	data, err := exec.Command(ref, "generate", "ech-keypair", "public.test").Output()
	if err != nil {
		t.Fatal(err)
	}
	var refConfig, refKey string
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			t.Fatal("reference returned invalid ECH PEM")
		}
		if block.Type == "ECH CONFIGS" {
			refConfig = string(pem.EncodeToMemory(block))
		} else if block.Type == "ECH KEYS" {
			refKey = string(pem.EncodeToMemory(block))
		}
		data = rest
	}
	if refConfig == "" || refKey == "" {
		t.Fatal("reference ECH generation omitted data")
	}
	f := newMutualTLSFixture(t)
	ownConfig, ownKey := testECHPair(t)
	for _, kind := range []string{"trojan", "hysteria2"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(kind+"/"+direction, func(t *testing.T) {
				in := testInbound(t, kind)
				in.TLS = testECHServer(t, f, refKey)
				if kind == "hysteria2" {
					in.Users = []User{{Password: "private"}}
					in.TLS.ALPN = quicALPN(kind)
				}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					ins := []Inbound{in}
					if kind == "hysteria2" {
						ins = append([]Inbound{{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t)}}, in)
					}
					referenceRuntime(t, Config{Inbounds: ins, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = testECHClient(f, refConfig)
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					in.TLS.ECH.Key = []string{ownKey}
					s := newECHRuntime(t, Config{Inbounds: []Inbound{in}}, in.Tag)
					out := testOutbound(t, in, s.Address(in.Tag))
					out.TLS, out.Username, out.UUID = testECHClient(f, ownConfig), "", ""
					if kind == "hysteria2" {
						out.TLS.ALPN = quicALPN(kind)
					}
					local := Inbound{Type: "mixed", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: out.Tag}})
					front := testOutbound(t, Inbound{Type: "socks"}, portAddress(local.Listen, local.ListenPort))
					front.Username, front.Password = "", ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func TestECHFilesAndValidation(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "config.pem"), filepath.Join(dir, "key.pem")
	write := func(path, value string) {
		t.Helper()
		if err := os.WriteFile(path+".new", []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".new", path); err != nil {
			t.Fatal(err)
		}
	}
	write(cp, config)
	write(kp, key)
	so, co := testECHServer(t, f, key), testECHClient(f, config)
	so.ECH.Key, so.ECH.KeyPath = nil, kp
	co.ECH.Config, co.ECH.ConfigPath = nil, cp
	s, err := so.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := co.config(false, "")
	if err != nil {
		t.Fatal(err)
	}
	check := func(ok bool) {
		t.Helper()
		cfg, err := prepareClientTLS(context.Background(), c, co, nil)
		if err == nil {
			var ss, cs tls.ConnectionState
			ss, cs, err = exchangeTLSPair(s, cfg)
			if err == nil && (!ss.ECHAccepted || !cs.ECHAccepted) {
				t.Fatal("ECH silently disabled")
			}
		}
		if (err == nil) != ok {
			t.Fatalf("success=%v, want%v: %v", err == nil, ok, err)
		}
	}
	check(true)
	newConfig, newKey := testECHPair(t)
	write(kp, newKey)
	check(false)
	write(cp, newConfig)
	check(true)
	for _, path := range []string{cp, kp} {
		write(path, "broken")
		check(false)
		if path == cp {
			write(path, newConfig)
		} else {
			write(path, newKey)
		}
		check(true)
	}
	for _, tc := range []struct {
		name   string
		server bool
		change func(*TLSOptions)
	}{
		{"client-key", false, func(o *TLSOptions) { o.ECH.Key = []string{key} }},
		{"server-config", true, func(o *TLSOptions) { o.ECH.Config = []string{config} }},
		{"no-sni", false, func(o *TLSOptions) { o.DisableSNI = true }},
		{"tls12-min", false, func(o *TLSOptions) { o.MinVersion = "1.2" }},
		{"tls12-max", true, func(o *TLSOptions) { o.MaxVersion = "1.2" }},
		{"bad-query", false, func(o *TLSOptions) { o.ECH.QueryServerName = "bad/name" }},
		{"bad-pem", false, func(o *TLSOptions) { o.ECH.Config = []string{"broken"} }},
		{"two-sources", false, func(o *TLSOptions) { o.ECH.ConfigPath = cp }},
		{"key-mismatch", true, func(o *TLSOptions) {
			block, _ := pem.Decode([]byte(key))
			block.Bytes[10] ^= 1
			o.ECH.Key = []string{string(pem.EncodeToMemory(block))}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := testECHClient(f, config)
			if tc.server {
				o = testECHServer(t, f, key)
			}
			tc.change(&o)
			if _, err := o.config(tc.server, ""); err == nil {
				t.Fatal("invalid ECH options accepted")
			}
		})
	}
	for _, field := range []string{"pq_signature_schemes_enabled", "dynamic_record_sizing_disabled"} {
		raw := `{"outbounds":[{"type":"trojan","server":"example.com","server_port":443,"password":"p","tls":{"enabled":true,"ech":{"enabled":true,"` + field + `":false}}}]}`
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("deprecated ECH field accepted")
		}
	}
}

func echDNSConfig(config string, names ...string) DNSConfig {
	block, _ := pem.Decode([]byte(config))
	var answers []string
	for _, name := range names {
		answers = append(answers, name+". 60 IN HTTPS 1 . ech="+base64.StdEncoding.EncodeToString(block.Bytes))
	}
	return DNSConfig{Rules: []DNSRule{{Rule: Rule{Domain: names, Action: "predefined"}, Answer: answers}}}
}

func TestECHDNSDiscoveryProtocols(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	for _, kind := range []string{"socks", "trojan", "anytls", "vless", "hysteria2", "trusttunnel"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = testECHServer(t, f, key)
			if kind == "hysteria2" {
				in.Users = []User{{Password: "private"}}
			}
			if kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/ech"}
			}
			if kind == "trusttunnel" {
				in.HTTPVersion = 3
				in.Users = []User{{Username: "client", Password: "private"}}
			}
			s := newECHRuntime(t, Config{Inbounds: []Inbound{in}}, in.Tag)
			out := testOutbound(t, in, s.Address(in.Tag))
			out.TLS, out.Transport, out.HTTPVersion = testECHClient(f, config), in.Transport, in.HTTPVersion
			out.TLS.ECH.Config = nil
			out.TLS.ECH.QueryServerName = "ech.test"
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}, DNS: echDNSConfig(config, "ech.test")})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 511})
		})
	}
}

func TestECHDNSDiscoveryAndAliases(t *testing.T) {
	config, _ := testECHPair(t)
	block, _ := pem.Decode([]byte(config))
	encoded := base64.StdEncoding.EncodeToString(block.Bytes)
	for _, tc := range []struct {
		name   string
		answer []string
		ok     bool
	}{
		{"direct", []string{"ech.test. HTTPS 1 . ech=" + encoded}, true},
		{"cname-in-packet", []string{"ech.test. CNAME target.test.", "target.test. HTTPS 1 . ech=" + encoded}, true},
		{"https-alias-in-packet", []string{"ech.test. HTTPS 0 target.test.", "target.test. HTTPS 1 . ech=" + encoded}, true},
		{"mandatory", []string{"ech.test. HTTPS 1 . mandatory=alpn,ech alpn=h2 ech=" + encoded}, true},
		{"unknown-mandatory", []string{"ech.test. HTTPS 1 . mandatory=key123 key123=foo ech=" + encoded}, false},
		{"missing-ech", []string{"ech.test. HTTPS 1 . alpn=h2"}, false},
		{"alias-cycle", []string{"ech.test. HTTPS 0 target.test.", "target.test. HTTPS 0 ech.test."}, false},
		{"unrelated-owner", []string{"unrelated.test. HTTPS 1 . ech=" + encoded}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, Config{DNS: DNSConfig{Rules: []DNSRule{{Rule: Rule{Domain: []string{"ech.test", "target.test"}, Action: "predefined"}, Answer: tc.answer}}}})
			list, err := r.resolver.lookupECH(context.Background(), "ech.test")
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v,want%v: %v", err == nil, tc.ok, err)
			}
			if tc.ok && !bytes.Equal(list, block.Bytes) {
				t.Fatal("wrong ECH configuration")
			}
		})
	}
	r := newTestRuntime(t, Config{DNS: echDNSConfig(config, "ech.test")})
	ctx := context.WithValue(context.Background(), echLookupKey{}, &echLookupTrail{name: "ech.test"})
	if _, err := r.resolver.lookupECH(ctx, "ech.test"); err == nil {
		t.Fatal("DNS discovery cycle accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.resolver.lookupECH(ctx, "ech.test"); err == nil {
		t.Fatal("canceled ECH lookup succeeded")
	}
}

func TestECHEncryptedDNS(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	boot := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "bootstrap", Listen: "127.0.0.1"}}, DNS: echDNSConfig(config, "ech.test")})
	bh, bp, _ := net.SplitHostPort(boot.Address("bootstrap"))
	bn, _ := net.LookupPort("tcp", bp)
	for _, kind := range []string{"tls", "https", "quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			so := testECHServer(t, f, key)
			var address string
			if kind == "https" {
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(dnsAnswer(b))
				}))
				var err error
				s.TLS, err = so.config(true, "")
				if err != nil {
					t.Fatal(err)
				}
				s.TLS.VerifyConnection = requireECH
				s.EnableHTTP2 = true
				s.StartTLS()
				defer s.Close()
				address = s.Listener.Addr().String()
			} else {
				in := Inbound{Type: "dns-" + kind, Tag: "dns", Listen: "127.0.0.1", TLS: so}
				if kind == "tls" {
					in.Type = "dns"
				}
				s := newECHRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42"}}}}}}, in.Tag)
				address = s.Address("dns")
			}
			h, p, _ := net.SplitHostPort(address)
			n, _ := net.LookupPort("tcp", p)
			co := testECHClient(f, config)
			co.ECH.Config = nil
			co.ECH.QueryServerName = "ech.test"
			c := newTestRuntime(t, Config{DNS: DNSConfig{DisableCache: true, Timeout: "1s", Final: "secure", Servers: []DNSServer{{Type: "udp", Tag: "bootstrap", Server: bh, ServerPort: uint16(bn)}, {Type: kind, Tag: "secure", Server: h, ServerPort: uint16(n), DomainResolver: "bootstrap", TLS: co}}}})
			for range 2 {
				if ips, err := c.LookupIP(context.Background(), "example.test"); err != nil || len(ips) == 0 {
					t.Fatalf("ECH DNS: %v,%v", ips, err)
				}
			}
		})
	}
}

func TestECHRuleDownloader(t *testing.T) {
	f := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ECH download") }))
	var err error
	s.TLS, err = testECHServer(t, f, key).config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	s.TLS.VerifyConnection = requireECH
	s.StartTLS()
	defer s.Close()
	o := testECHClient(f, config)
	o.ECH.Config = nil
	o.ECH.QueryServerName = "ech.test"
	r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{{Tag: "ech", TLS: o}}, DNS: echDNSConfig(config, "ech.test")})
	c, tr, err := r.ruleHTTPClient(RuleSet{HTTPClient: "ech", URL: s.URL})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.CloseIdleConnections()
	response, err := c.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	b, err := io.ReadAll(response.Body)
	if err != nil || string(b) != "ECH download" {
		t.Fatalf("body=%q,%v", b, err)
	}
}

func FuzzECH(f *testing.F) {
	config, key := testECHPair(f)
	for _, value := range []string{config, key} {
		b, _ := pem.Decode([]byte(value))
		f.Add(b.Bytes)
	}
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		_ = validateECHList(b)
		_, _ = parseECHKeys(b)
		_, _ = parseSVCB(b)
	})
}
