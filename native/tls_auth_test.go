package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type mutualTLSFixture struct {
	ca, serverCert, serverKey, clientCert, clientKey string
}

func newMutualTLSFixture(t *testing.T) mutualTLSFixture {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	caKey := key()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Lanboat test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	makeLeaf := func(client bool) (string, string) {
		k := key()
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if client {
			leaf.SerialNumber, leaf.ExtKeyUsage = big.NewInt(3), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		b, err := x509.CreateCertificate(rand.Reader, leaf, ca, &k.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	}
	f := mutualTLSFixture{ca: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
	f.serverCert, f.serverKey = makeLeaf(false)
	f.clientCert, f.clientKey = makeLeaf(true)
	return f
}

func (f mutualTLSFixture) server() TLSOptions {
	return TLSOptions{Enabled: true, Certificate: []string{f.serverCert}, Key: []string{f.serverKey}, ClientAuthentication: "require-and-verify", ClientCertificate: []string{f.ca}}
}

func (f mutualTLSFixture) client() TLSOptions {
	return TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{f.ca}, ClientCertificate: []string{f.clientCert}, ClientKey: []string{f.clientKey}}
}

func TestMutualTLSProtocols(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, kind := range []string{"socks", "trojan", "anytls", "relay", "vless", "vmess", "hysteria2", "tuic", "brook"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.TLS = f.server()
			if kind == "hysteria2" || kind == "tuic" {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			if kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/mtls"}
			}
			if kind == "brook" {
				in.Transport = Transport{Type: "ws", Path: "/brook"}
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address(in.Tag))
			out.TLS, out.Transport = f.client(), in.Transport
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511})
		})
	}
}

func TestMutualTLSAuthenticationModes(t *testing.T) {
	f, untrusted := newMutualTLSFixture(t), newMutualTLSFixture(t)
	for _, mode := range []string{"no", "request", "require-any", "verify-if-given", "require-and-verify"} {
		for _, identity := range []string{"valid", "missing", "untrusted", "wrong-purpose"} {
			t.Run(mode+"/"+identity, func(t *testing.T) {
				in := testInbound(t, "trojan")
				in.TLS = f.server()
				in.TLS.ClientAuthentication = mode
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address(in.Tag))
				out.TLS = f.client()
				if identity == "missing" {
					out.TLS.ClientCertificate, out.TLS.ClientKey = nil, nil
				} else if identity == "untrusted" {
					out.TLS.ClientCertificate, out.TLS.ClientKey = untrusted.client().ClientCertificate, untrusted.client().ClientKey
				} else if identity == "wrong-purpose" {
					out.TLS.ClientCertificate, out.TLS.ClientKey = []string{f.serverCert}, []string{f.serverKey}
				}
				// Always send the selected identity so verify-if-given also tests
				// an untrusted certificate instead of silently omitting it.
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				if identity != "missing" {
					cfg := client.clientTLS[out.Tag]
					cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cfg.Certificates[0], nil }
				}
				var hits atomic.Int32
				origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = w.Write([]byte("accepted")) }))
				defer origin.Close()
				transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return client.Dial(ctx, network, address)
				}}
				defer transport.CloseIdleConnections()
				response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(origin.URL)
				allowed := mode == "no" || mode == "request" || mode == "require-any" && identity != "missing" || mode == "verify-if-given" && (identity == "valid" || identity == "missing") || mode == "require-and-verify" && identity == "valid"
				if response != nil {
					response.Body.Close()
				}
				if (err == nil) != allowed || (hits.Load() != 0) != allowed {
					t.Fatal("mTLS decision", allowed, hits.Load(), err)
				}
			})
		}
	}
}

func TestMutualTLSOfficialReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 is required for modern mTLS interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	f := newMutualTLSFixture(t)
	for _, direction := range []string{"client", "server"} {
		t.Run(direction, func(t *testing.T) {
			in := testInbound(t, "trojan")
			in.TLS = f.server()
			var client *Runtime
			if direction == "client" {
				in.ListenPort = unusedPort(t)
				referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
				out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
				out.TLS = f.client()
				client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			} else {
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address(in.Tag))
				out.TLS, out.Username, out.UUID = f.client(), "", ""
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

func TestMutualTLSFilesAndInvalidOptions(t *testing.T) {
	f := newMutualTLSFixture(t)
	dir := t.TempDir()
	paths := map[string]string{"ca.pem": f.ca, "client.pem": f.clientCert, "key.pem": f.clientKey}
	for name, data := range paths {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	o := f.client()
	o.ClientCertificate, o.ClientKey = nil, nil
	o.ClientCertificatePath, o.ClientKeyPath = []string{filepath.Join(dir, "client.pem")}, filepath.Join(dir, "key.pem")
	if c, err := o.config(false, "example.com"); err != nil || len(c.Certificates) != 1 {
		t.Fatal("client certificate files", err)
	}
	s := f.server()
	s.ClientCertificate, s.ClientCertificatePath = nil, []string{filepath.Join(dir, "ca.pem")}
	if c, err := s.config(true, ""); err != nil || c.ClientCAs == nil {
		t.Fatal("client CA files", err)
	}
	for _, test := range []struct {
		server bool
		change func(*TLSOptions)
	}{
		{true, func(o *TLSOptions) { o.ClientAuthentication = "unknown" }},
		{true, func(o *TLSOptions) { o.ClientCertificate = nil }},
		{true, func(o *TLSOptions) { o.ClientCertificate = []string{"invalid PEM"} }},
		{true, func(o *TLSOptions) { o.ClientKey = []string{f.clientKey} }},
		{false, func(o *TLSOptions) { o.ClientAuthentication = "request" }},
		{false, func(o *TLSOptions) { o.ClientKey = nil }},
		{false, func(o *TLSOptions) { o.ClientCertificate = nil }},
		{false, func(o *TLSOptions) { o.ClientKey = []string{f.serverKey} }},
		{false, func(o *TLSOptions) { o.ClientCertificatePath = []string{filepath.Join(dir, "missing")} }},
	} {
		o := f.client()
		if test.server {
			o = f.server()
		}
		test.change(&o)
		if _, err := o.config(test.server, "example.com"); err == nil {
			t.Fatalf("invalid mTLS options accepted: %+v", test.server)
		}
	}
	// client_certificate_path is a list for servers and a scalar for clients;
	// both compatible JSON spellings must load without losing the identity.
	raw := fmt.Sprintf(`{"outbounds":[{"type":"trojan","server":"example.com","server_port":443,"password":"x","tls":{"enabled":true,"client_certificate_path":%q,"client_key_path":%q}}]}`, filepath.Join(dir, "client.pem"), filepath.Join(dir, "key.pem"))
	if _, err := Parse([]byte(raw)); err != nil {
		t.Fatal(err)
	}
}
