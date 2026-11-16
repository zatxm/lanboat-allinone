package native

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tlsPinFor(t *testing.T, cert string, publicKey bool) string {
	t.Helper()
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		t.Fatal("missing certificate")
	}
	b := block.Bytes
	if publicKey {
		c, e := x509.ParseCertificate(b)
		if e != nil {
			t.Fatal(e)
		}
		b = c.RawSubjectPublicKeyInfo
	}
	sum := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func exchangeTLSPair(server, client *tls.Config) (tls.ConnectionState, tls.ConnectionState, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, err
	}
	defer listener.Close()
	right, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		return tls.ConnectionState{}, tls.ConnectionState{}, err
	}
	left, err := listener.Accept()
	if err != nil {
		right.Close()
		return tls.ConnectionState{}, tls.ConnectionState{}, err
	}
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(2 * time.Second))
	_ = right.SetDeadline(time.Now().Add(2 * time.Second))
	type result struct {
		state tls.ConnectionState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		defer left.Close()
		s := tls.Server(left, server)
		err := s.Handshake()
		var b [1]byte
		if err == nil {
			_, err = io.ReadFull(s, b[:])
		}
		if err == nil {
			_, err = s.Write(b[:])
		}
		done <- result{s.ConnectionState(), err}
	}()
	c := tls.Client(right, client)
	err = c.Handshake()
	if err == nil {
		_, err = c.Write([]byte{1})
	}
	var b [1]byte
	if err == nil {
		_, err = io.ReadFull(c, b[:])
	}
	right.Close()
	r := <-done
	if err == nil {
		err = r.err
	}
	return c.ConnectionState(), r.state, err
}

func TestTLSPinVerification(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	cert, key, bad := tlsPinFor(t, f.serverCert, false), tlsPinFor(t, f.serverCert, true), tlsPinFor(t, g.serverCert, false)
	serverOptions := TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}}
	server, err := serverOptions.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name              string
		cert, key         []string
		insecure, allowed bool
	}{
		{"certificate", []string{cert}, nil, false, true}, {"public-key", nil, []string{key}, false, true},
		{"cert-or-key", []string{cert}, []string{bad}, false, true}, {"key-or-cert", []string{bad}, []string{key}, false, true},
		{"rotation", []string{bad, cert}, nil, false, true}, {"wrong", []string{bad}, nil, false, false}, {"insecure-wrong", []string{bad}, nil, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := TLSOptions{Enabled: true, ServerName: "wrong.example", CertificateSHA256: test.cert, CertificatePublicKeySHA256: test.key, Insecure: test.insecure}
			client, err := o.config(false, "")
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = exchangeTLSPair(server, client)
			if (err == nil) != test.allowed {
				t.Fatal("pin decision", test.allowed, err)
			}
		})
	}
	// An unrelated pinned certificate appended after an attacker's leaf must not authenticate it.
	malicious, err := (TLSOptions{Enabled: true, Certificate: []string{g.serverCert, f.serverCert}, Key: []string{g.serverKey}}).config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	client, _ := (TLSOptions{Enabled: true, CertificateSHA256: []string{cert}}).config(false, "")
	if _, _, err = exchangeTLSPair(malicious, client); err == nil {
		t.Fatal("appended certificate bypassed leaf pin")
	}
}

func TestTLSClientCertificatePins(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	for _, publicKey := range []bool{false, true} {
		for _, required := range []bool{false, true} {
			for _, identity := range []string{"valid", "missing", "wrong"} {
				t.Run(fmt.Sprint(publicKey, "/", required, "/", identity), func(t *testing.T) {
					o := f.server()
					o.ClientCertificate = nil
					o.ClientAuthentication = "verify-if-given"
					if required {
						o.ClientAuthentication = "require-and-verify"
					}
					pin := tlsPinFor(t, f.clientCert, publicKey)
					if publicKey {
						o.ClientCertificatePublicKeySHA256 = []string{pin}
					} else {
						o.ClientCertificateSHA256 = []string{pin}
					}
					server, err := o.config(true, "")
					if err != nil {
						t.Fatal(err)
					}
					c := f.client()
					if identity == "missing" {
						c.ClientCertificate, c.ClientKey = nil, nil
					}
					if identity == "wrong" {
						c.ClientCertificate, c.ClientKey = []string{g.clientCert}, []string{g.clientKey}
					}
					client, err := c.config(false, "")
					if err != nil {
						t.Fatal(err)
					}
					_, _, err = exchangeTLSPair(server, client)
					allowed := identity == "valid" || !required && identity == "missing"
					if (err == nil) != allowed {
						t.Fatal("client pin decision", allowed, err)
					}
				})
			}
		}
	}
}

func TestTLSNegotiationAndNoSNI(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, version := range []string{"1.2", "1.3"} {
		for _, noSNI := range []bool{false, true} {
			t.Run(version+fmt.Sprint(noSNI), func(t *testing.T) {
				s := f.server()
				s.ClientAuthentication = "no"
				s.MinVersion, s.MaxVersion = version, version
				s.CurvePreferences = []string{"P256"}
				s.CipherSuites = []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}
				server, err := s.config(true, "")
				if err != nil {
					t.Fatal(err)
				}
				o := f.client()
				o.MinVersion, o.MaxVersion = version, version
				o.CurvePreferences = []string{"P256"}
				o.DisableSNI = noSNI
				client, err := o.config(false, "")
				if err != nil {
					t.Fatal(err)
				}
				state, peer, err := exchangeTLSPair(server, client)
				if err != nil {
					t.Fatal(err)
				}
				want := uint16(tls.VersionTLS12)
				if version == "1.3" {
					want = tls.VersionTLS13
				}
				if state.Version != want {
					t.Fatal(state.Version)
				}
				if noSNI && peer.ServerName != "" || !noSNI && peer.ServerName != "example.com" {
					t.Fatal("SNI", peer.ServerName)
				}
				o.ServerName = "wrong.example"
				client, _ = o.config(false, "")
				if _, _, err = exchangeTLSPair(server, client); err == nil {
					t.Fatal("hostname verification lost when disabling SNI")
				}
			})
		}
	}
	s := f.server()
	s.MinVersion, s.MaxVersion = "1.2", "1.2"
	server, _ := s.config(true, "")
	c := f.client()
	c.MinVersion = "1.3"
	client, _ := c.config(false, "")
	if _, _, err := exchangeTLSPair(server, client); err == nil {
		t.Fatal("TLS version mismatch accepted")
	}
}

func TestTLSInvalidOptions(t *testing.T) {
	f := newMutualTLSFixture(t)
	pin := tlsPinFor(t, f.serverCert, false)
	for _, test := range []struct {
		name   string
		server bool
		change func(*TLSOptions)
	}{
		{"version", false, func(o *TLSOptions) { o.MinVersion = "1.4" }}, {"range", false, func(o *TLSOptions) { o.MinVersion = "1.3"; o.MaxVersion = "1.2" }},
		{"cipher", false, func(o *TLSOptions) { o.CipherSuites = []string{"bad"} }}, {"curve", false, func(o *TLSOptions) { o.CurvePreferences = []string{"bad"} }},
		{"engine", false, func(o *TLSOptions) { o.Engine = "openssl" }}, {"server-engine", true, func(o *TLSOptions) { o.Engine = "go" }}, {"server-sni", true, func(o *TLSOptions) { o.DisableSNI = true }},
		{"pin-ca", false, func(o *TLSOptions) { o.CertificateSHA256 = []string{pin} }}, {"server-pin-role", true, func(o *TLSOptions) { o.CertificateSHA256 = []string{pin} }},
		{"client-pin-role", false, func(o *TLSOptions) { o.ClientCertificateSHA256 = []string{pin} }}, {"client-pin-ca", true, func(o *TLSOptions) { o.ClientCertificateSHA256 = []string{pin} }},
		{"bad-base64", false, func(o *TLSOptions) { o.Certificate = nil; o.CertificateSHA256 = []string{strings.Repeat("!", 44)} }},
		{"digest-size", false, func(o *TLSOptions) {
			o.Certificate = nil
			o.CertificateSHA256 = []string{base64.StdEncoding.EncodeToString(make([]byte, 31))}
		}},
		{"bad-alpn", false, func(o *TLSOptions) { o.ALPN = []string{strings.Repeat("x", 256)} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := f.client()
			if test.server {
				o = f.server()
			}
			test.change(&o)
			if _, err := o.config(test.server, "example.com"); err == nil {
				t.Fatal("invalid TLS options accepted")
			}
		})
	}
	raw := fmt.Sprintf(`{"outbounds":[{"type":"trojan","server":"example.com","server_port":443,"password":"p","tls":{"enabled":true,"certificate_sha256":%q,"curve_preferences":"P256","min_version":"1.3","engine":"go"}}]}`, pin)
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatal("scalar TLS options", err)
	}
}

func TestTLSPinsRejectBeforeProxyTraffic(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	for _, kind := range []string{"trojan", "vless", "hysteria2", "juicity"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			if isQUICProxy(kind) {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			in.TLS = f.server()
			if kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/pins"}
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address(in.Tag))
			out.TLS = f.client()
			out.TLS.Certificate = nil
			out.TLS.CertificateSHA256 = []string{tlsPinFor(t, f.serverCert, false)}
			out.Transport = in.Transport
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511})
			out.TLS.Insecure = true
			out.TLS.CertificateSHA256 = []string{tlsPinFor(t, g.serverCert, false)}
			if kind == "juicity" {
				out.PinnedCertchainSHA256 = tlsPinFor(t, f.serverCert, false)
			} // Both configured pin policies must hold.
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			var hits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = w.Write([]byte("bad")) }))
			defer origin.Close()
			tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return bad.Dial(ctx, n, a) }}
			defer tr.CloseIdleConnections()
			response, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get(origin.URL)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || hits.Load() != 0 {
				t.Fatal("pin failure reached origin", hits.Load(), err)
			}
		})
	}
}

func writeTLSFiles(t *testing.T, dir string, f mutualTLSFixture) {
	t.Helper()
	for name, data := range map[string]string{"server.crt": f.serverCert, "server.key": f.serverKey, "ca.crt": f.ca, "client.crt": f.clientCert, "client.key": f.clientKey} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p+".new", []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(p+".new", p); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTLSFilesReloadProtocols(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	for _, kind := range []string{"trojan", "vless", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			writeTLSFiles(t, dir, f)
			in := testInbound(t, kind)
			if isQUICProxy(kind) {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			in.TLS = TLSOptions{Enabled: true, CertificatePath: filepath.Join(dir, "server.crt"), KeyPath: filepath.Join(dir, "server.key"), ClientAuthentication: "require-and-verify", ClientCertificatePath: []string{filepath.Join(dir, "ca.crt")}}
			if kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/reload"}
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address(in.Tag))
			out.Transport = in.Transport
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", CertificatePath: filepath.Join(dir, "ca.crt"), ClientCertificatePath: []string{filepath.Join(dir, "client.crt")}, ClientKeyPath: filepath.Join(dir, "client.key")}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511})
			writeTLSFiles(t, dir, g)
			client.resetNetworkTransports()
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511})
		})
	}
}

func TestTLSFilesInvalidUpdateAndRecovery(t *testing.T) {
	f := newMutualTLSFixture(t)
	dir := t.TempDir()
	writeTLSFiles(t, dir, f)
	so := f.server()
	so.Certificate, so.Key, so.ClientCertificate = nil, nil, nil
	so.CertificatePath, so.KeyPath = filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	so.ClientCertificatePath = []string{filepath.Join(dir, "ca.crt")}
	co := f.client()
	co.Certificate, co.ClientCertificate, co.ClientKey = nil, nil, nil
	co.CertificatePath = filepath.Join(dir, "ca.crt")
	co.ClientCertificatePath = []string{filepath.Join(dir, "client.crt")}
	co.ClientKeyPath = filepath.Join(dir, "client.key")
	server, err := so.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	client, err := co.config(false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"server.crt", "server.key", "ca.crt", "client.crt", "client.key"} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := exchangeTLSPair(server, client); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := exchangeTLSPair(server, client); err == nil {
				t.Fatal("invalid changed credentials used an old snapshot")
			}
			writeTLSFiles(t, dir, f)
			if _, _, err := exchangeTLSPair(server, client); err != nil {
				t.Fatal("recovery", err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, _, err := exchangeTLSPair(server, client); err == nil {
				t.Fatal("removed credentials accepted")
			}
			writeTLSFiles(t, dir, f)
		})
	}
}

func TestTLSPinResumptionVerification(t *testing.T) {
	f := newMutualTLSFixture(t)
	so := TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}}
	server, _ := so.config(true, "")
	co := TLSOptions{Enabled: true, ServerName: "example.com", CertificateSHA256: []string{tlsPinFor(t, f.serverCert, false)}}
	client, _ := co.config(false, "")
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	for i := range 2 {
		state, _, err := exchangeTLSPair(server, client)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && !state.DidResume {
			t.Fatal("test did not resume a TLS session")
		}
	}
	client.VerifyConnection = func(tls.ConnectionState) error { return errors.New("policy changed") }
	if _, _, err := exchangeTLSPair(server, client); err == nil {
		t.Fatal("resumption bypassed certificate policy")
	}
}

func TestTLSPinsOfficialReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required for TLS pin interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	for _, policy := range []string{"certificate", "public-key", "either", "client-certificate", "client-public-key"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(policy+"/"+direction, func(t *testing.T) {
				in := testInbound(t, "trojan")
				in.TLS = f.server()
				in.ListenPort = unusedPort(t)
				clientTLS := f.client()
				clientTLS.Certificate = nil
				clientTLS.ServerName = "unrelated.example"
				switch policy {
				case "certificate":
					clientTLS.CertificateSHA256 = []string{tlsPinFor(t, f.serverCert, false)}
				case "public-key":
					clientTLS.CertificatePublicKeySHA256 = []string{tlsPinFor(t, f.serverCert, true)}
				case "either":
					clientTLS.CertificateSHA256 = []string{tlsPinFor(t, g.serverCert, false)}
					clientTLS.CertificatePublicKeySHA256 = []string{tlsPinFor(t, f.serverCert, true)}
				default:
					clientTLS.CertificateSHA256 = []string{tlsPinFor(t, f.serverCert, false)}
					in.TLS.ClientCertificate = nil
					if policy == "client-certificate" {
						in.TLS.ClientCertificateSHA256 = []string{tlsPinFor(t, f.clientCert, false)}
					} else {
						in.TLS.ClientCertificatePublicKeySHA256 = []string{tlsPinFor(t, f.clientCert, true)}
					}
				}
				var client *Runtime
				if direction == "client" {
					referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = clientTLS
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address(in.Tag))
					out.TLS = clientTLS
					out.Username, out.UUID = "", ""
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

func TestTLSReloadRevokesResumedClient(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	dir := t.TempDir()
	writeTLSFiles(t, dir, f)
	options := f.server()
	options.ClientCertificate = nil
	options.ClientCertificatePath = []string{filepath.Join(dir, "ca.crt")}
	server, err := options.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	var ticket [32]byte
	ticket[0] = 7
	server.SetSessionTicketKeys([][32]byte{ticket})
	server = cloneTLSConfig(server)
	// Supply a fixed ticket key on credential snapshots so rotation cannot hide a
	// policy bypass by simply forcing a full handshake with a new ticket key.
	load := server.GetConfigForClient
	server.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		c, e := load(h)
		if e == nil {
			c = c.Clone()
			c.SetSessionTicketKeys([][32]byte{ticket})
		}
		return c, e
	}
	client, _ := f.client().config(false, "")
	client.ClientSessionCache = tls.NewLRUClientSessionCache(4)
	for i := range 2 {
		state, _, err := exchangeTLSPair(server, client)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && !state.DidResume {
			t.Fatal("test did not resume mTLS")
		}
	}
	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, []byte(g.ca), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err = exchangeTLSPair(server, client)
	if err == nil {
		t.Fatal("resumed client survived CA revocation")
	}
	snapshot, err := server.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(f.clientCert))
	old, _ := x509.ParseCertificate(block.Bytes)
	if snapshot.VerifyConnection == nil || snapshot.VerifyConnection(tls.ConnectionState{DidResume: true, PeerCertificates: []*x509.Certificate{old}}) == nil {
		t.Fatal("resumed client verification did not use the updated CA")
	}
}

func TestTLSQUICVersionValidation(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2", "tuic", "juicity", "dns-quic", "dns-h3"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = certificate(t)
			in.TLS.MaxVersion = "1.2"
			if isQUICProxy(kind) {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			raw, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
			if _, err := Parse(raw); err == nil {
				t.Fatal("QUIC listener accepted TLS1.2 maximum")
			}
		})
	}
	for _, kind := range []string{"quic", "h3"} {
		c := Config{DNS: DNSConfig{Servers: []DNSServer{{Type: kind, Tag: "dns", Server: "127.0.0.1", TLS: TLSOptions{MaxVersion: "1.2"}}}}}
		raw, _ := json.Marshal(c)
		if _, err := Parse(raw); err == nil {
			t.Fatal("QUIC resolver accepted TLS1.2 maximum")
		}
	}
}

func FuzzTLSOptions(f *testing.F) {
	f.Add([]byte(`{"enabled":true,"min_version":"1.3","curve_preferences":"P256"}`))
	f.Add([]byte(`{"enabled":true,"certificate_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var o TLSOptions
		if decodeOptions(b, &o) != nil {
			return
		}
		o.CertificatePath, o.KeyPath, o.ClientKeyPath = "", "", ""
		o.ClientCertificatePath = nil
		o.PKCS12Path = ""
		if o.ECH != nil {
			o.ECH.KeyPath, o.ECH.ConfigPath = "", ""
		}
		_, _ = o.staticConfig(false, "example.com")
		_, _ = o.staticConfig(true, "")
	})
}

func TestTLSRuleDownloaderHostnameAndNoSNI(t *testing.T) {
	f := newMutualTLSFixture(t)
	dir := t.TempDir()
	writeTLSFiles(t, dir, f)
	var seen atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("secure rules")) }))
	server.TLS, _ = (TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}}).config(true, "")
	server.TLS.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) { seen.Store(h.ServerName); return nil, nil }
	server.StartTLS()
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	for _, noSNI := range []bool{false, true} {
		t.Run(fmt.Sprint(noSNI), func(t *testing.T) {
			r := newTestRuntime(t, Config{HTTPClients: []HTTPClientOptions{{Tag: "download", TLS: TLSOptions{CertificatePath: filepath.Join(dir, "ca.crt"), DisableSNI: noSNI}}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.com": {"127.0.0.1"}, "wrong.example": {"127.0.0.1"}}}}}})
			client, transport, err := r.ruleHTTPClient(RuleSet{HTTPClient: "download"})
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			for _, host := range []string{"example.com", "wrong.example"} {
				resp, err := client.Get("https://" + net.JoinHostPort(host, port) + "/")
				if resp != nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
				if (err == nil) != (host == "example.com") {
					t.Fatal("HTTPS downloader hostname verification", host, err)
				}
				want := host
				if noSNI {
					want = ""
				}
				if seen.Load() != want {
					t.Fatal("HTTPS downloader SNI", seen.Load(), want)
				}
			}
		})
	}
}

func TestTLSPinsDNS(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	for _, kind := range []string{"tls", "https", "quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			var address string
			if kind == "https" {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(dnsAnswer(b))
				}))
				server.TLS, _ = (TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}}).config(true, "")
				server.StartTLS()
				defer server.Close()
				address = server.Listener.Addr().String()
			} else {
				in := Inbound{Type: "dns-" + kind, Tag: "dns", Listen: "127.0.0.1", TLS: TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}}}
				if kind == "tls" {
					in.Type = "dns"
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42"}}}}}})
				address = server.Address("dns")
			}
			host, port, _ := net.SplitHostPort(address)
			number, _ := net.LookupPort("tcp", port)
			options := DNSServer{Type: kind, Tag: "secure", Server: host, ServerPort: uint16(number), TLS: TLSOptions{CertificatePublicKeySHA256: []string{tlsPinFor(t, f.serverCert, true)}}}
			client := newTestRuntime(t, Config{DNS: DNSConfig{Timeout: "500ms", DisableCache: true, Servers: []DNSServer{options}}})
			if ips, err := client.LookupIP(context.Background(), "example.test"); err != nil || len(ips) == 0 {
				t.Fatal("pinned DNS", ips, err)
			}
			options.TLS.Insecure = true
			options.TLS.CertificatePublicKeySHA256 = []string{tlsPinFor(t, g.serverCert, true)}
			bad := newTestRuntime(t, Config{DNS: DNSConfig{Timeout: "500ms", DisableCache: true, Servers: []DNSServer{options}}})
			if _, err := bad.LookupIP(context.Background(), "example.test"); err == nil {
				t.Fatal("DNS accepted mismatched pin")
			}
		})
	}
}
