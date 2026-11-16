package native

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func exportTestPKCS12(t testing.TB, cert, key, ca, password string, options ...string) []byte {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{"cert.pem": cert, "key.pem": key, "ca.pem": ca} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"pkcs12", "-export", "-in", filepath.Join(dir, "cert.pem"), "-inkey", filepath.Join(dir, "key.pem"), "-passout", "env:LANBOAT_P12_TEST_PASSWORD", "-iter", "32", "-name", "Lanboat test identity"}
	if ca != "" {
		args = append(args, "-certfile", filepath.Join(dir, "ca.pem"))
	}
	cmd := exec.Command("openssl", append(args, options...)...)
	cmd.Env = append(os.Environ(), "LANBOAT_P12_TEST_PASSWORD="+password)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl pkcs12: %v: %s", err, stderr.String())
	}
	return data
}

func TestPKCS12OpenSSL(t *testing.T) {
	f := newMutualTLSFixture(t)
	tests := []struct {
		name, password string
		args           []string
	}{
		{"default-aes256", "private", nil},
		{"aes128", "private", []string{"-keypbe", "AES-128-CBC", "-certpbe", "AES-128-CBC"}},
		{"aes192", "private", []string{"-keypbe", "AES-192-CBC", "-certpbe", "AES-192-CBC"}},
		{"unencrypted", "private", []string{"-keypbe", "NONE", "-certpbe", "NONE"}},
		{"empty", "", nil},
		{"unicode", "岚舟🔑", nil},
		{"legacy", "private", []string{"-legacy"}},
		{"legacy-empty", "", []string{"-legacy"}},
		{"legacy-unicode", "岚舟🔑", []string{"-legacy"}},
		{"legacy-rc4-128", "private", []string{"-legacy", "-keypbe", "PBE-SHA1-RC4-128", "-certpbe", "PBE-SHA1-RC4-128"}},
		{"legacy-rc4-40", "private", []string{"-legacy", "-keypbe", "PBE-SHA1-RC4-40", "-certpbe", "PBE-SHA1-RC4-40"}},
		{"legacy-3des", "private", []string{"-legacy", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES"}},
		{"legacy-2des", "private", []string{"-legacy", "-keypbe", "PBE-SHA1-2DES", "-certpbe", "PBE-SHA1-2DES"}},
		{"legacy-rc2-128", "private", []string{"-legacy", "-keypbe", "PBE-SHA1-RC2-128", "-certpbe", "PBE-SHA1-RC2-128"}},
		{"legacy-rc2-40", "private", []string{"-legacy", "-keypbe", "PBE-SHA1-RC2-40", "-certpbe", "PBE-SHA1-RC2-40"}},
		{"mac-sha1", "private", []string{"-macalg", "sha1"}},
		{"mac-sha224", "private", []string{"-macalg", "sha224"}},
		{"mac-sha384", "private", []string{"-macalg", "sha384"}},
		{"mac-sha512", "private", []string{"-macalg", "sha512"}},
		{"mac-sha512-224", "private", []string{"-macalg", "sha512-224"}},
		{"mac-sha512-256", "private", []string{"-macalg", "sha512-256"}},
	}
	leaf, _ := pem.Decode([]byte(f.serverCert))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, test.password, test.args...)
			original := bytes.Clone(data)
			pair, err := decodePKCS12(data, test.password)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original, data) || len(pair.Certificate) != 2 || !bytes.Equal(pair.Certificate[0], leaf.Bytes) || pair.Leaf == nil {
				t.Fatal("wrong certificate chain or modified input")
			}
			client, err := (TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{f.ca}}).config(false, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = exchangeTLSPair(&tls.Config{Certificates: []tls.Certificate{pair}}, client); err != nil {
				t.Fatal(err)
			}
			if _, err = decodePKCS12(data, "wrong-password"); err == nil {
				t.Fatal("wrong password accepted")
			}
			var pfx struct {
				Version int
				Safe    p12Content
				MAC     p12MAC
			}
			if err := p12ASN1(data, &pfx); err != nil {
				t.Fatal(err)
			}
			var safe []byte
			if err := p12ASN1(pfx.Safe.Data.Bytes, &safe); err != nil {
				t.Fatal(err)
			}
			data[bytes.Index(data, safe)+len(safe)/2] ^= 1
			if _, err = decodePKCS12(data, test.password); err == nil {
				t.Fatal("tampered PKCS12 accepted")
			}
		})
	}
}

func TestPKCS12PBMAC1Fixtures(t *testing.T) {
	var manifest struct {
		Files []struct{ File, Password, SHA256 string }
	}
	b, err := os.ReadFile("testdata/pkcs12/provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 4 {
		t.Fatal("missing PBMAC1 fixtures")
	}
	for _, fixture := range manifest.Files {
		t.Run(fixture.File, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata/pkcs12", fixture.File))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			if hex.EncodeToString(sum[:]) != fixture.SHA256 {
				t.Fatal("fixture digest mismatch")
			}
			pair, err := decodePKCS12(data, fixture.Password)
			if err != nil {
				t.Fatal(err)
			}
			client := &tls.Config{ServerName: "example.com", RootCAs: x509.NewCertPool(), Time: func() time.Time { return pair.Leaf.NotBefore.Add(time.Minute) }}
			client.RootCAs.AddCert(pair.Leaf)
			if _, _, err = exchangeTLSPair(&tls.Config{Certificates: []tls.Certificate{pair}}, client); err != nil {
				t.Fatal(err)
			}
			if _, err = decodePKCS12(data, "wrong-password"); err == nil {
				t.Fatal("PBMAC1 accepted wrong password")
			}
			data[len(data)/2] ^= 1
			if _, err = decodePKCS12(data, fixture.Password); err == nil {
				t.Fatal("PBMAC1 accepted modified authenticated content")
			}
		})
	}
}

func TestPKCS12PrivateKeyTypes(t *testing.T) {
	for _, kind := range []string{"rsa", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			var public, key any
			if kind == "rsa" {
				k, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				public, key = &k.PublicKey, k
			} else {
				var err error
				public, key, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, key)
			if err != nil {
				t.Fatal(err)
			}
			private, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			data := exportTestPKCS12(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), "", "private")
			pair, err := decodePKCS12(data, "private")
			if err != nil {
				t.Fatal(err)
			}
			client := &tls.Config{ServerName: "example.com", RootCAs: x509.NewCertPool()}
			client.RootCAs.AddCert(pair.Leaf)
			if _, _, err = exchangeTLSPair(&tls.Config{Certificates: []tls.Certificate{pair}}, client); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPKCS12MutualTLSProtocols(t *testing.T) {
	f := newMutualTLSFixture(t)
	server := exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, "private")
	client := exportTestPKCS12(t, f.clientCert, f.clientKey, f.ca, "private", "-legacy")
	for _, kind := range []string{"socks", "trojan", "anytls", "relay", "vless", "vmess", "hysteria2", "tuic", "brook"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = f.server()
			in.TLS.Certificate, in.TLS.Key = nil, nil
			in.TLS.PKCS12, in.TLS.PKCS12Password = base64.StdEncoding.EncodeToString(server), "private"
			if kind == "hysteria2" || kind == "tuic" {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			if kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/mtls"}
			}
			if kind == "brook" {
				in.Transport = Transport{Type: "ws", Path: "/brook"}
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address(in.Tag))
			out.Transport, out.TLS = in.Transport, f.client()
			out.TLS.ClientCertificate, out.TLS.ClientKey = nil, nil
			out.TLS.PKCS12, out.TLS.PKCS12Password = base64.StdEncoding.EncodeToString(client), "private"
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 511})
		})
	}
}

func TestPKCS12OfficialReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 is required for PKCS12 TLS interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	f := newMutualTLSFixture(t)
	serverP12 := base64.StdEncoding.EncodeToString(exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, "private"))
	clientP12 := base64.StdEncoding.EncodeToString(exportTestPKCS12(t, f.clientCert, f.clientKey, f.ca, "private", "-legacy"))
	for _, kind := range []string{"trojan", "hysteria2"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(kind+"/"+direction, func(t *testing.T) {
				in := testInbound(t, kind)
				in.TLS = f.server()
				if kind == "hysteria2" {
					in.Users = []User{{Password: "private"}}
					in.TLS.ALPN = quicALPN(kind)
				}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					inbounds := []Inbound{in}
					if kind == "hysteria2" {
						inbounds = append([]Inbound{{Type: "mixed", Listen: "127.0.0.1", ListenPort: unusedPort(t)}}, in)
					}
					referenceRuntime(t, Config{Inbounds: inbounds, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = f.client()
					out.TLS.Engine = "go"
					if kind == "hysteria2" {
						out.TLS.ALPN = quicALPN(kind)
					}
					out.TLS.ClientCertificate, out.TLS.ClientKey = nil, nil
					out.TLS.PKCS12, out.TLS.PKCS12Password = clientP12, "private"
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					in.TLS.Certificate, in.TLS.Key = nil, nil
					in.TLS.PKCS12, in.TLS.PKCS12Password = serverP12, "private"
					if kind == "hysteria2" {
						// The reference ChromeParrot client rejects its own identity callbacks.
						// Verify PKCS12 server authentication here; independent endpoints test mTLS.
						in.TLS.ClientAuthentication, in.TLS.ClientCertificate = "", nil
					}
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address(in.Tag))
					out.TLS, out.Username, out.UUID = f.client(), "", ""
					out.TLS.Engine = "go"
					if kind == "hysteria2" {
						out.TLS.ALPN = quicALPN(kind)
						out.TLS.ClientCertificate, out.TLS.ClientKey = nil, nil
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

func TestPKCS12DNS(t *testing.T) {
	f := newMutualTLSFixture(t)
	serverP12 := base64.StdEncoding.EncodeToString(exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, "private"))
	clientP12 := base64.StdEncoding.EncodeToString(exportTestPKCS12(t, f.clientCert, f.clientKey, f.ca, "private"))
	for _, kind := range []string{"tls", "https", "quic", "h3"} {
		t.Run(kind, func(t *testing.T) {
			so, co := f.server(), f.client()
			so.Certificate, so.Key, co.ClientCertificate, co.ClientKey = nil, nil, nil, nil
			so.PKCS12, so.PKCS12Password, co.PKCS12, co.PKCS12Password = serverP12, "private", clientP12, "private"
			var address string
			if kind == "https" {
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					b, _ := io.ReadAll(r.Body)
					w.Header().Set("Content-Type", "application/dns-message")
					_, _ = w.Write(dnsAnswer(b))
				}))
				var err error
				server.TLS, err = so.config(true, "")
				if err != nil {
					t.Fatal(err)
				}
				server.StartTLS()
				defer server.Close()
				address = server.Listener.Addr().String()
			} else {
				in := Inbound{Type: "dns-" + kind, Tag: "dns", Listen: "127.0.0.1", TLS: so}
				if kind == "tls" {
					in.Type = "dns"
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"example.test": {"192.0.2.42"}}}}}})
				address = server.Address("dns")
			}
			host, port, _ := net.SplitHostPort(address)
			number, _ := net.LookupPort("tcp", port)
			client := newTestRuntime(t, Config{DNS: DNSConfig{Timeout: "1s", DisableCache: true, Servers: []DNSServer{{Type: kind, Tag: "secure", Server: host, ServerPort: uint16(number), TLS: co}}}})
			for range 2 {
				ips, err := client.LookupIP(context.Background(), "example.test")
				if err != nil || len(ips) == 0 {
					t.Fatalf("PKCS12 DNS: %v, %v", ips, err)
				}
			}
		})
	}
}

func TestPKCS12FileReload(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	serverPath, clientPath := filepath.Join(t.TempDir(), "server.p12"), filepath.Join(t.TempDir(), "client.p12")
	serverData := exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, "private")
	clientData := exportTestPKCS12(t, f.clientCert, f.clientKey, f.ca, "private")
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path+".tmp", data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			t.Fatal(err)
		}
	}
	write(serverPath, serverData)
	write(clientPath, clientData)
	so, co := f.server(), f.client()
	so.Certificate, so.Key, co.ClientCertificate, co.ClientKey = nil, nil, nil, nil
	so.PKCS12Path, so.PKCS12Password = serverPath, "private"
	co.PKCS12Path, co.PKCS12Password = clientPath, "private"
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
		_, _, err := exchangeTLSPair(s, c)
		if (err == nil) != ok {
			t.Fatalf("handshake success=%v, want%v: %v", err == nil, ok, err)
		}
	}
	check(true)
	for _, path := range []string{serverPath, clientPath} {
		write(path, []byte("broken"))
		check(false)
		if path == serverPath {
			write(path, serverData)
		} else {
			write(path, clientData)
		}
		check(true)
	}
	write(clientPath, exportTestPKCS12(t, g.clientCert, g.clientKey, g.ca, "private"))
	check(false)
	write(clientPath, clientData)
	check(true)
	write(serverPath, exportTestPKCS12(t, g.serverCert, g.serverKey, g.ca, "private"))
	check(false)
	write(serverPath, serverData)
	check(true)
}

func TestPKCS12Validation(t *testing.T) {
	f := newMutualTLSFixture(t)
	valid := exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, "private")
	encoded := base64.StdEncoding.EncodeToString(valid)
	for _, tc := range []struct {
		name   string
		server bool
		o      TLSOptions
	}{
		{"bad-base64", false, TLSOptions{PKCS12: "!?"}},
		{"bad-data", false, TLSOptions{PKCS12: "YWJj"}},
		{"password-only", false, TLSOptions{PKCS12Password: "private"}},
		{"missing-file", false, TLSOptions{PKCS12Path: filepath.Join(t.TempDir(), "missing")}},
		{"two-sources", false, TLSOptions{PKCS12: encoded, PKCS12Path: "unused"}},
		{"wrong-password", false, TLSOptions{PKCS12: encoded, PKCS12Password: "wrong"}},
		{"pem-client", false, TLSOptions{PKCS12: encoded, ClientKey: []string{f.clientKey}}},
		{"pem-server", true, TLSOptions{PKCS12: encoded, Certificate: []string{f.serverCert}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.o.Enabled = true
			if _, err := tc.o.config(tc.server, "example.com"); err == nil {
				t.Fatal("invalid PKCS12 config accepted")
			}
		})
	}
	noMAC := exportTestPKCS12(t, f.serverCert, f.serverKey, f.ca, "private", "-nomac")
	if _, err := decodePKCS12(noMAC, "private"); err == nil || !strings.Contains(err.Error(), "MAC") {
		t.Fatalf("missing MAC accepted: %v", err)
	}
	if _, err := decodePKCS12(append(bytes.Clone(valid), 0), "private"); err == nil {
		t.Fatal("trailing DER accepted")
	}
	for _, password := range []string{strings.Repeat("x", 4097), "\xff"} {
		if _, err := decodePKCS12(valid, password); err == nil {
			t.Fatal("invalid password encoding accepted")
		}
	}
	for _, salt := range [][]byte{nil, make([]byte, 1025)} {
		if err := new(p12Decoder).charge(salt, 1, 1); err == nil {
			t.Fatal("invalid KDF salt accepted")
		}
	}
	for _, iterations := range []int{-1, 0, 1000001} {
		if err := new(p12Decoder).charge([]byte{1}, iterations, 1); err == nil {
			t.Fatal("unbounded KDF accepted")
		}
	}
	if err := (&p12Decoder{work: 10000000}).charge([]byte{1}, 1, 1); err == nil {
		t.Fatal("KDF budget ignored")
	}
}

func TestPKCS12RC2Vectors(t *testing.T) {
	for _, v := range []struct {
		key, plain, encrypted string
		bits                  int
	}{
		{"0000000000000000", "0000000000000000", "ebb773f993278eff", 63},
		{"ffffffffffffffff", "ffffffffffffffff", "278b27e42e2f0d49", 64},
		{"3000000000000000", "1000000000000001", "30649edf9be7d2c2", 64},
		{"88", "0000000000000000", "61a8a244adacccf0", 64},
		{"88bca90e90875a", "0000000000000000", "6ccf4308974c267f", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "1a807d272bbe5db1", 64},
		{"88bca90e90875a7f0f79c384627bafb2", "0000000000000000", "2269552ab0f85ca6", 128},
		{"88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", "0000000000000000", "5b78d3a43dfff1f1", 129},
	} {
		key, _ := hex.DecodeString(v.key)
		plain, _ := hex.DecodeString(v.plain)
		encrypted, _ := hex.DecodeString(v.encrypted)
		c := newRC2(key, v.bits)
		b := make([]byte, 8)
		c.Encrypt(b, plain)
		if !bytes.Equal(b, encrypted) {
			t.Fatalf("RC2 vector mismatch: %x", b)
		}
		c.Decrypt(b, b)
		if !bytes.Equal(b, plain) {
			t.Fatal("RC2 inverse mismatch")
		}
	}
}

func testP12DER(t testing.TB, value any) []byte {
	t.Helper()
	b, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testP12Explicit(b []byte) asn1.RawValue {
	return asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: b}
}

func testP12Bags(t testing.TB, bags []p12Bag) []byte {
	t.Helper()
	contents := []p12Content{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}, Data: testP12Explicit(testP12DER(t, testP12DER(t, bags)))}}
	safe := testP12DER(t, contents)
	mac := p12MAC{Salt: []byte("test-salt"), Iterations: 2}
	mac.Digest.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	d := p12Decoder{unicode: []byte{0, 0}}
	key, err := d.derive(sha256.New, mac.Salt, mac.Iterations, 3, 32)
	if err != nil {
		t.Fatal(err)
	}
	h := hmac.New(sha256.New, key)
	h.Write(safe)
	mac.Digest.Value = h.Sum(nil)
	return testP12DER(t, struct {
		Version int
		Safe    p12Content
		MAC     p12MAC
	}{3, p12Content{Type: contents[0].Type, Data: testP12Explicit(testP12DER(t, safe))}, mac})
}

func TestPKCS12AuthenticatedStructures(t *testing.T) {
	f, g := newMutualTLSFixture(t), newMutualTLSFixture(t)
	key, _ := pem.Decode([]byte(f.clientKey))
	keyBag := p12Bag{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}, Value: testP12Explicit(key.Bytes)}
	certBag := func(value string) p12Bag {
		cert, _ := pem.Decode([]byte(value))
		return p12Bag{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}, Value: testP12Explicit(testP12DER(t, struct {
			Type asn1.ObjectIdentifier
			DER  []byte `asn1:"explicit,tag:0"`
		}{asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}, cert.Bytes}))}
	}
	cert, ca := certBag(f.clientCert), certBag(f.ca)
	valid := []p12Bag{keyBag, ca, cert, cert}
	nested := valid
	for range 10 {
		nested = []p12Bag{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}, Value: testP12Explicit(testP12DER(t, nested))}}
	}
	for _, tc := range []struct {
		name string
		bags []p12Bag
		ok   bool
	}{
		{"reordered-chain-duplicate-leaf", valid, true},
		{"nested", []p12Bag{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}, Value: testP12Explicit(testP12DER(t, valid))}}, true},
		{"no-key", []p12Bag{cert}, false},
		{"no-cert", []p12Bag{keyBag}, false},
		{"wrong-cert", []p12Bag{keyBag, certBag(g.clientCert)}, false},
		{"multiple-keys", []p12Bag{keyBag, keyBag, cert}, false},
		{"unknown-bag", []p12Bag{{Type: asn1.ObjectIdentifier{1, 2, 3}, Value: testP12Explicit([]byte{5, 0})}}, false},
		{"deep-nesting", nested, false},
		{"too-many-certs", append(repeatP12Bag(65, ca), keyBag, cert), false},
		{"too-many-bags", repeatP12Bag(257, ca), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair, err := decodePKCS12(testP12Bags(t, tc.bags), "")
			if (err == nil) != tc.ok {
				t.Fatalf("accepted=%v, want%v: %v", err == nil, tc.ok, err)
			}
			if tc.ok && len(pair.Certificate) != 2 {
				t.Fatal("wrong assembled chain")
			}
		})
	}
}

func repeatP12Bag(n int, bag p12Bag) []p12Bag {
	bags := make([]p12Bag, n)
	for i := range bags {
		bags[i] = bag
	}
	return bags
}

func FuzzPKCS12(f *testing.F) {
	f.Add([]byte{0x30, 0}, "private")
	f.Add([]byte{0x30, 3, 2, 1, 3}, "")
	f.Add(testP12Bags(f, nil), "")
	f.Add(testP12Bags(f, []p12Bag{{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}, Value: testP12Explicit([]byte{0x30, 0})}}), "")
	for _, name := range []string{"pbmac1-sha256", "pbmac1-sha512", "pbmac1-mixed", "pbmac1-unicode"} {
		data, err := os.ReadFile("testdata/pkcs12/" + name + ".p12")
		if err != nil {
			f.Fatal(err)
		}
		password := "private"
		if name == "pbmac1-unicode" {
			password = "岚舟🔑"
		}
		f.Add(data, password)
	}
	f.Fuzz(func(t *testing.T, data []byte, password string) {
		if len(data) > 65536 || len(password) > 64 {
			return
		}
		_, _ = decodePKCS12(data, password)
		var a pkix.AlgorithmIdentifier
		if p12ASN1(data, &a) == nil {
			_, _ = (&p12Decoder{password: password}).decrypt(a, []byte{1, 2, 3, 4})
		}
	})
}

func BenchmarkPKCS12FileSnapshot(b *testing.B) {
	data, err := os.ReadFile("testdata/pkcs12/pbmac1-sha256.p12")
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "identity.p12")
	if err = os.WriteFile(path, data, 0600); err != nil {
		b.Fatal(err)
	}
	c := tlsFileCache{options: TLSOptions{Enabled: true, PKCS12Path: path, PKCS12Password: "private"}, server: true, paths: []string{path}}
	first, err := c.current()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		current, err := c.current()
		if err != nil || current != first {
			b.Fatal("unchanged identity was reloaded", err)
		}
	}
}
