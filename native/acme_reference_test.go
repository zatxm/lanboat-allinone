package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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
)

// Pebble performs its normal validation. No always-valid validation bypass is
// enabled: its independent validator must reach our HTTP/TLS/TXT proofs.
type acmeFixture struct {
	provider, ca, apiCA string
	apiPair             tls.Certificate
	client              HTTPClientOptions
	httpPort, tlsPort   uint16
	dns                 net.PacketConn
	mu                  sync.Mutex
	txt                 map[string][]string
	aliases             map[string]string
	queries             atomic.Int32
	txtQueries          atomic.Int32
	stop                func()
}

func newACMEFixture(t *testing.T, eab bool) *acmeFixture {
	t.Helper()
	binaryPath := os.Getenv("LANBOAT_TEST_PEBBLE")
	if binaryPath == "" {
		t.Skip("LANBOAT_TEST_PEBBLE must identify the pinned external ACME reference")
	}
	f := &acmeFixture{httpPort: unusedPort(t), txt: map[string][]string{}, aliases: map[string]string{}}
	f.tlsPort = unusedPort(t, f.httpPort)
	var err error
	f.dns, err = net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); f.serveDNS() }()
	t.Cleanup(func() { f.dns.Close(); <-done })
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACME reference API"}, DNSNames: []string{"api.cloudflare.com", "alidns.aliyuncs.com", "api.zerossl.com", "auth.example.org"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private, _ := x509.MarshalPKCS8PrivateKey(key)
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	f.apiPair, err = tls.X509KeyPair(cert, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "api.pem"), filepath.Join(dir, "api-key.pem")
	if err = os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, privatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	apiPort, managementPort := unusedPort(t, f.httpPort, f.tlsPort), unusedPort(t, f.httpPort, f.tlsPort)
	for managementPort == apiPort {
		managementPort = unusedPort(t, f.httpPort, f.tlsPort, apiPort)
	}
	address := fmt.Sprintf("127.0.0.1:%d", apiPort)
	management := fmt.Sprintf("127.0.0.1:%d", managementPort)
	config := map[string]any{"pebble": map[string]any{"listenAddress": address, "managementListenAddress": management, "certificate": certPath, "privateKey": keyPath, "httpPort": f.httpPort, "tlsPort": f.tlsPort, "externalAccountBindingRequired": eab, "externalAccountMACKeys": map[string]string{"test-kid": "dGVzdC1lYWItc2VjcmV0LXdpdGgtYXQtbGVhc3QtMzItYnl0ZXM"}, "retryAfter": map[string]int{"authz": 0, "order": 0}, "profiles": map[string]any{"default": map[string]any{"description": "test", "validityPeriod": 7776000}, "shortlived": map[string]any{"description": "IP test", "validityPeriod": 518400}, "minute": map[string]any{"description": "short TTL test", "validityPeriod": 60}}}}
	data, _ := json.Marshal(config)
	path := filepath.Join(dir, "pebble.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	logs, err := os.Create(filepath.Join(dir, "pebble.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binaryPath, "-config", path, "-dnsserver", f.dns.LocalAddr().String())
	cmd.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_VA_ALWAYS_VALID=0", "PEBBLE_AUTHZREUSE=0", "PEBBLE_WFE_NONCEREJECT=0")
	cmd.Stdout, cmd.Stderr = logs, logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var stopped sync.Once
	f.stop = func() { stopped.Do(func() { cmd.Process.Kill(); cmd.Wait() }) }
	t.Cleanup(func() {
		f.stop()
		logs.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logs.Name())
			t.Log(string(b))
		}
	})
	waitPort(t, address, 30*time.Second)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cert)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	resp, err := client.Get("https://" + management + "/roots/0")
	if err != nil {
		t.Fatal(err)
	}
	root, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode, err)
	}
	f.ca, f.apiCA, f.provider = string(root), string(cert), "https://"+address+"/dir"
	f.client = HTTPClientOptions{Tag: "acme-api", TLS: TLSOptions{Certificate: []string{string(cert)}}}
	return f
}

func (f *acmeFixture) serveDNS() {
	buffer := make([]byte, 4096)
	for {
		n, from, e := f.dns.ReadFrom(buffer)
		if e != nil {
			return
		}
		q := buffer[:n]
		name, end, typ, e := dnsQuestion(q)
		if e != nil {
			continue
		}
		f.queries.Add(1)
		f.mu.Lock()
		alias := f.aliases[name]
		values := append([]string(nil), f.txt[name]...)
		if alias != "" {
			values = append(values, f.txt[alias]...)
		}
		f.mu.Unlock()
		answer := append([]byte(nil), q[:end]...)
		binary.BigEndian.PutUint16(answer[2:4], 0x8180)
		binary.BigEndian.PutUint16(answer[6:8], 0)
		binary.BigEndian.PutUint16(answer[8:10], 0)
		binary.BigEndian.PutUint16(answer[10:12], 0)
		add := func(kind uint16, data []byte) {
			owner := name
			if alias != "" && kind != 5 {
				owner = alias
			}
			answer, _ = dnsAppendName(answer, owner)
			answer = append(answer, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 1, byte(len(data)>>8), byte(len(data)))
			answer = append(answer, data...)
			binary.BigEndian.PutUint16(answer[6:8], binary.BigEndian.Uint16(answer[6:8])+1)
		}
		if alias != "" {
			data, _ := dnsAppendName(nil, alias)
			add(5, data)
		}
		switch typ {
		case 1:
			add(1, []byte{127, 0, 0, 1})
		case 16:
			f.txtQueries.Add(1)
			for _, s := range values {
				add(16, append([]byte{byte(len(s))}, []byte(s)...))
			}
		case 5:
		}
		f.dns.WriteTo(answer, from)
	}
}

func (f *acmeFixture) options(t *testing.T) CertificateProviderOptions {
	return CertificateProviderOptions{Type: "acme", Tag: "acme", Domain: []string{"example.org"}, DataDirectory: t.TempDir(), HTTPClient: clientReference(f.client.Tag), ACMEOptions: ACMEOptions{Provider: f.provider, Profile: "default", AlternativeHTTPPort: f.httpPort, AlternativeTLSPort: f.tlsPort, Email: "test@example.org"}}
}
func (f *acmeFixture) core(t *testing.T, o CertificateProviderOptions) (*Runtime, *managedCertificate) {
	t.Helper()
	r := newTestRuntime(t, Config{CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{f.client}})
	return r, r.certificateProviders[o.Tag]
}
func (f *acmeFixture) current(t *testing.T, p *managedCertificate, name string) *tls.Certificate {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cert, e := p.current(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(f.ca))
	inter := x509.NewCertPool()
	for _, der := range cert.Certificate[1:] {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			t.Fatal(e)
		}
		inter.AddCert(c)
	}
	if _, e = cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, DNSName: name}); e != nil {
		t.Fatal(e)
	}
	return cert
}
func acmePortClosed(t *testing.T, port uint16) {
	t.Helper()
	l, e := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if e != nil {
		t.Fatal("challenge port leaked", e)
	}
	l.Close()
}

func TestACMEReferenceChallenges(t *testing.T) {
	f := newACMEFixture(t, false)
	for _, kind := range []string{"http-01", "tls-alpn-01", "ip-http", "ip-tls", "ipv6-http", "ipv6-tls"} {
		t.Run(kind, func(t *testing.T) {
			o := f.options(t)
			o.DisableHTTPChallenge = strings.Contains(kind, "tls")
			o.DisableTLSALPNChallenge = !o.DisableHTTPChallenge
			name := "example.org"
			if strings.HasPrefix(kind, "ip") {
				name = "127.0.0.1"
				if strings.HasPrefix(kind, "ipv6") {
					name = "::1"
				}
				o.Domain = []string{name}
				o.Profile = "shortlived"
			}
			_, p := f.core(t, o)
			cert := f.current(t, p, name)
			if cert.Leaf.NotAfter.Before(time.Now()) {
				t.Fatal("expired")
			}
			acmePortClosed(t, f.httpPort)
			acmePortClosed(t, f.tlsPort)
			for _, kind := range []string{"account", "certificate"} {
				path, e := p.acmePath(kind)
				if e != nil {
					t.Fatal(e)
				}
				st, e := os.Stat(path)
				if e != nil || st.Mode().Perm() != 0600 {
					t.Fatal("state permissions", st, e)
				}
			}
			_, cached := f.core(t, o)
			again := f.current(t, cached, name)
			if !cert.Leaf.Equal(again.Leaf) {
				t.Fatal("cache was not reused")
			}
		})
	}
}

func TestACMEReferenceChallengeFallback(t *testing.T) {
	f := newACMEFixture(t, false)
	busy, e := net.Listen("tcp", fmt.Sprintf(":%d", f.httpPort))
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	_, p := f.core(t, f.options(t))
	f.current(t, p, "example.org")
	acmePortClosed(t, f.tlsPort)
}

func TestACMEReferenceKeyTypesAndEAB(t *testing.T) {
	f := newACMEFixture(t, true)
	for _, kind := range []string{"p256", "p384", "rsa2048", "rsa4096"} {
		t.Run(kind, func(t *testing.T) {
			o := f.options(t)
			o.KeyType = kind
			accountKey, e := acmeGenerateKey(kind)
			if e != nil {
				t.Fatal(e)
			}
			der, e := x509.MarshalPKCS8PrivateKey(accountKey)
			if e != nil {
				t.Fatal(e)
			}
			o.AccountKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			o.ExternalAccount = &ACMEExternalAccount{"test-kid", "dGVzdC1lYWItc2VjcmV0LXdpdGgtYXQtbGVhc3QtMzItYnl0ZXM"}
			o.DisableTLSALPNChallenge = true
			_, p := f.core(t, o)
			f.current(t, p, "example.org")
		})
	}
}

func TestACMEReferenceSharedPorts(t *testing.T) {
	f := newACMEFixture(t, false)
	for _, challenge := range []string{"http", "tls", "tls-h2"} {
		t.Run(challenge, func(t *testing.T) {
			o := f.options(t)
			o.DisableHTTPChallenge = challenge != "http"
			o.DisableTLSALPNChallenge = challenge == "http"
			in := testInbound(t, "trojan")
			if challenge == "tls-h2" {
				in = testInbound(t, "vless")
				in.Transport = Transport{Type: "http", Path: "/acme"}
			}
			in.TLS = TLSOptions{Enabled: true, CertificateProvider: "acme"}
			inputs := []Inbound{in}
			if challenge != "http" {
				inputs[0].ListenPort = f.tlsPort
			} else {
				plain := testInbound(t, "mixed")
				plain.Tag = "challenge-http"
				plain.ListenPort = f.httpPort
				inputs = append(inputs, plain)
			}
			server := newTestRuntime(t, Config{Inbounds: inputs, CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{f.client}})
			out := testOutbound(t, in, server.Address(in.Tag))
			out.Transport = in.Transport
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.org", Certificate: []string{f.ca}}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCPTimeout(t, client, 30*time.Second)
			assertUDPSizes(t, client, []int{1, 511})
			// Proof cleanup must keep the application listener alive.
			assertTCPTimeout(t, client, 30*time.Second)
			server.Close()
			acmePortClosed(t, f.httpPort)
			acmePortClosed(t, f.tlsPort)
		})
	}
}

// Use a local HTTPS DNS API fixture but real Pebble DNS validation. This fixture
// is not used for ACME signing, challenge validation or certificate issuance.
func (f *acmeFixture) dnsAPI(t *testing.T, handler http.HandlerFunc) (HTTPClientOptions, Outbound) {
	t.Helper()
	api := httptest.NewUnstartedServer(handler)
	api.TLS = &tls.Config{Certificates: []tls.Certificate{f.apiPair}, MinVersion: tls.VersionTLS12}
	api.StartTLS()
	t.Cleanup(api.Close)
	host, port := splitTestAddress(t, api.Listener.Addr().String())
	in := testInbound(t, "socks")
	gateway := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Route: Route{Rules: []Rule{{Domain: []string{"api.cloudflare.com", "alidns.aliyuncs.com", "auth.example.org"}, Action: "route-options", OverrideAddress: host, OverridePort: port}}}})
	out := testOutbound(t, in, gateway.Address(in.Tag))
	out.Tag = "dns-api-proxy"
	client := f.client
	client.Detour = out.Tag
	return client, out
}
