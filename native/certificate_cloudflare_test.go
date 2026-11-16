package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

type originCAFixture struct {
	key      *ecdsa.PrivateKey
	root     *x509.Certificate
	ca       string
	client   HTTPClientOptions
	outbound Outbound
	requests atomic.Int32
	mode     atomic.Int32
	clock    atomic.Int64
	lifetime atomic.Int64
	block    chan struct{}
}

func newOriginCAFixture(t *testing.T) *originCAFixture {
	t.Helper()
	f := &originCAFixture{block: make(chan struct{})}
	f.clock.Store(time.Now().Unix())
	f.lifetime.Store(int64(90 * 24 * time.Hour))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Origin CA fixture"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: f.now().Add(-24 * time.Hour), NotAfter: f.now().Add(20 * 365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.root, _ = x509.ParseCertificate(der)
	f.ca = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := f.sign([]string{"api.cloudflare.com"}, &serverKey.PublicKey, 2)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	pair, err := tls.X509KeyPair([]byte(leaf), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := f.requests.Add(1)
		if req.Method != "POST" || req.URL.Path != "/client/v4/certificates" || req.Host != "api.cloudflare.com" || req.Header.Get("Content-Type") != "application/json" || req.Header.Get("X-Fixture") != "checked" {
			t.Error("invalid Origin CA API request", req.Method, req.URL.Path, req.Host)
			w.WriteHeader(400)
			return
		}
		token, caKey := req.Header.Get("Authorization"), req.Header.Get("X-Auth-User-Service-Key")
		if !(token == "Bearer test-token" && caKey == "" || token == "" && caKey == "test-ca-key") {
			t.Error("invalid Origin CA API authentication headers")
			w.WriteHeader(401)
			return
		}
		switch f.mode.Load() {
		case 1:
			w.WriteHeader(403)
			io.WriteString(w, `{"errors":[{"message":"test-token test-ca-key"}]}`)
			return
		case 2:
			w.Header().Set("Location", "/redirected")
			w.WriteHeader(307)
			return
		case 3:
			io.WriteString(w, strings.Repeat("x", originCAMaxResponse+1))
			return
		case 4:
			io.WriteString(w, `{"success":false,"errors":[{"message":"test-token"}]}`)
			return
		case 5:
			io.WriteString(w, "not JSON test-token")
			return
		case 6:
			select {
			case <-req.Context().Done():
				return
			case <-f.block:
			}
		}
		var body struct {
			CSR      string   `json:"csr"`
			Hosts    []string `json:"hostnames"`
			Type     string   `json:"request_type"`
			Validity int      `json:"requested_validity"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		block, _ := pem.Decode([]byte(body.CSR))
		if block == nil {
			t.Error("missing CSR")
			w.WriteHeader(400)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil || !slices.Equal(csr.DNSNames, body.Hosts) || body.Validity == 0 || body.Type != "origin-ecc" && body.Type != "origin-rsa" {
			t.Error("invalid signed CSR or API request")
			w.WriteHeader(400)
			return
		}
		names := body.Hosts
		public := csr.PublicKey
		if f.mode.Load() == 7 {
			names = []string{"wrong.test"}
		}
		if f.mode.Load() == 8 {
			public = &f.key.PublicKey
		}
		cert, err := f.sign(names, public, int64(n)+10)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": fmt.Sprint(n), "certificate": cert, "hostnames": body.Hosts, "request_type": body.Type, "requested_validity": body.Validity, "expires_on": f.now().Add(time.Duration(f.lifetime.Load())).UTC().Format(time.RFC3339)}})
	}))
	api.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	api.StartTLS()
	t.Cleanup(api.Close)
	host, portText, _ := net.SplitHostPort(api.Listener.Addr().String())
	var port uint16
	fmt.Sscan(portText, &port)
	in := testInbound(t, "socks")
	gateway := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Route: Route{Rules: []Rule{{Domain: []string{"api.cloudflare.com"}, Action: "route-options", OverrideAddress: host, OverridePort: port}}}})
	f.outbound = testOutbound(t, in, gateway.Address(in.Tag))
	f.outbound.Tag = "api-proxy"
	f.client = HTTPClientOptions{Tag: "api", Detour: "api-proxy", TLS: TLSOptions{ServerName: "api.cloudflare.com", Certificate: []string{f.ca}}, Headers: map[string]headerValues{"X-Fixture": {"checked"}, "authorization": {"must-be-replaced"}}}
	return f
}

func (f *originCAFixture) now() time.Time { return time.Unix(f.clock.Load(), 0) }

func (f *originCAFixture) sign(names []string, public any, serial int64) (string, error) {
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: f.now().Add(-time.Minute), NotAfter: f.now().Add(time.Duration(f.lifetime.Load())), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, f.root, public, f.key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), err
}

func (f *originCAFixture) options(t *testing.T) CertificateProviderOptions {
	return CertificateProviderOptions{Type: "cloudflare-origin-ca", Tag: "origin", Domain: []string{"example.com", "*.example.com"}, DataDirectory: t.TempDir(), APIToken: "test-token", RequestType: "origin-ecc", RequestedValidity: 90, HTTPClient: "api"}
}

func (f *originCAFixture) core(t *testing.T, options CertificateProviderOptions) (*Runtime, *managedCertificate) {
	t.Helper()
	r := newTestRuntime(t, Config{CertificateProviders: []CertificateProviderOptions{options}, Outbounds: []Outbound{f.outbound}, HTTPClients: []HTTPClientOptions{f.client}})
	p := r.certificateProviders[options.Tag]
	p.now = f.now
	return r, p
}

func TestOriginCAProtocols(t *testing.T) {
	f := newOriginCAFixture(t)
	for _, test := range []struct {
		kind        string
		httpVersion int
	}{{"socks", 0}, {"http", 0}, {"trojan", 0}, {"anytls", 0}, {"vmess", 0}, {"vless", 0}, {"hysteria", 0}, {"hysteria2", 0}, {"tuic", 0}, {"juicity", 0}, {"relay", 0}, {"brook", 0}, {"naive", 2}, {"naive", 3}, {"trusttunnel", 2}, {"trusttunnel", 3}, {"masque", 1}, {"masque", 2}, {"masque", 3}} {
		t.Run(fmt.Sprintf("%s/%d", test.kind, test.httpVersion), func(t *testing.T) {
			kind := test.kind
			options := f.options(t)
			if kind == "http" {
				options.RequestType = "origin-rsa"
			}
			in := testInbound(t, kind)
			in.HTTPVersion = test.httpVersion
			if kind == "naive" {
				in.HTTPVersion = 0
			}
			in.TLS = TLSOptions{Enabled: true, CertificateProvider: "origin"}
			if kind == "socks" {
				in.TLS.MaxVersion = "1.2"
			}
			if isQUICProxy(kind) {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			if kind == "naive" || kind == "trusttunnel" || kind == "masque" {
				in.Users = []User{{Username: "client", Password: "private"}}
			}
			if kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/origin"}
			}
			if kind == "vmess" {
				in.Transport = Transport{Type: "grpc", ServiceName: "origin"}
			}
			if kind == "brook" {
				in.Transport = Transport{Type: "ws", Path: "/origin"}
			}
			if kind == "trojan" {
				inline := options
				inline.Tag = ""
				raw, _ := json.Marshal(inline)
				in.TLS.CertificateProvider = certificateReference(raw)
			}
			before := f.requests.Load()
			server := newTestRuntime(t, Config{CertificateProviders: []CertificateProviderOptions{options}, Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, f.outbound}, HTTPClients: []HTTPClientOptions{f.client}})
			if f.requests.Load() != before {
				t.Fatal("certificate was requested before a handshake")
			}
			out := testOutbound(t, in, server.Address(in.Tag))
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{f.ca}}
			out.Transport = in.Transport
			out.HTTPVersion = test.httpVersion
			if kind == "naive" {
				out.HTTPVersion = 0
				out.QUIC = test.httpVersion == 3
				out.UDPOverTCP = true
			}
			if kind == "masque" {
				out.MasqueOptions = MasqueOptions{Mode: "ip"}
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			if kind != "http" {
				assertUDPSizes(t, client, []int{1, 511})
			}
			if got := f.requests.Load() - before; got != 1 {
				t.Fatal("expected one certificate request", got)
			}
		})
	}
}

func TestOriginCAHotTrustAndRenewedHandshake(t *testing.T) {
	f := newOriginCAFixture(t)
	options := f.options(t)
	mutual := newMutualTLSFixture(t)
	caPath := filepath.Join(t.TempDir(), "client-ca.pem")
	if err := os.WriteFile(caPath, []byte(mutual.ca), 0600); err != nil {
		t.Fatal(err)
	}
	in := testInbound(t, "vless")
	in.TLS = TLSOptions{Enabled: true, CertificateProvider: "origin", ClientAuthentication: "require-and-verify", ClientCertificatePath: []string{caPath}}
	in.Transport = Transport{Type: "http", Path: "/origin"}
	server := newTestRuntime(t, Config{CertificateProviders: []CertificateProviderOptions{options}, Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, f.outbound}, HTTPClients: []HTTPClientOptions{f.client}})
	p := server.certificateProviders[options.Tag]
	p.now = f.now
	out := testOutbound(t, in, server.Address(in.Tag))
	out.Transport = in.Transport
	out.TLS = mutual.client()
	out.TLS.Certificate = []string{f.ca}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, client)
	first, _ := p.current(context.Background(), "example.com")
	// Trust files must still reload when a provider supplies the server identity.
	other := newMutualTLSFixture(t)
	if err := os.WriteFile(caPath, []byte(other.ca), 0600); err != nil {
		t.Fatal(err)
	}
	client.resetNetworkTransports()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, "tcp", "127.0.0.1:9")
	if err == nil {
		conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte("must fail"))
		if err == nil {
			_, err = conn.Read(make([]byte, 1))
		}
		conn.Close()
	}
	if err == nil {
		t.Fatal("changed client CA did not revoke authentication")
	}
	f.clock.Add(int64(65 * 24 * time.Hour / time.Second))
	p.current(context.Background(), "example.com")
	p.workers.Wait()
	current, err := p.current(context.Background(), "example.com")
	if err != nil || current == first {
		t.Fatal("renewal failed", err)
	}
	// Exercise the rotated certificate with a real TLS handshake at the provider clock.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(f.ca))
	base := server.serverTLS[in.Tag]
	unsecured := cloneTLSConfig(base)
	unsecured.ClientAuth = tls.NoClientCert
	unsecured.GetConfigForClient = nil
	listener, err := tls.Listen("tcp", "127.0.0.1:0", unsecured)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			e = c.(*tls.Conn).Handshake()
			c.Close()
		}
		done <- e
	}()
	c, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{RootCAs: roots, ServerName: "example.com", Time: f.now, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	if c.ConnectionState().PeerCertificates[0].SerialNumber.Cmp(current.Leaf.SerialNumber) != 0 {
		t.Fatal("TLS handshake served old certificate")
	}
	c.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOriginCAOfficial(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required for Origin CA interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	f := newOriginCAFixture(t)
	for _, side := range []string{"client", "server"} {
		for _, inline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/inline=%v", side, inline), func(t *testing.T) {
				options := f.options(t)
				if inline {
					options.APIToken = ""
					options.OriginCAKey = "test-ca-key"
				}
				in := testInbound(t, "trojan")
				in.TLS = TLSOptions{Enabled: true, CertificateProvider: "origin"}
				if inline {
					local := options
					local.Tag = ""
					raw, _ := json.Marshal(local)
					in.TLS.CertificateProvider = certificateReference(raw)
				}
				proxy := f.outbound
				proxy.UUID = ""
				httpClient := f.client
				httpClient.Headers = map[string]headerValues{"X-Fixture": {"checked"}}
				config := Config{CertificateProviders: []CertificateProviderOptions{options}, Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, proxy}, HTTPClients: []HTTPClientOptions{httpClient}}
				var client *Runtime
				if side == "client" {
					in.ListenPort = unusedPort(t)
					config.Inbounds[0] = in
					referenceRuntime(t, config)
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{f.ca}}
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, config)
					out := testOutbound(t, in, server.Address(in.Tag))
					out.Username = ""
					out.UUID = ""
					out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{f.ca}}
					local := Inbound{Type: "mixed", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}})
					front := testOutbound(t, Inbound{Type: "socks"}, portAddress(local.Listen, local.ListenPort))
					front.Username = ""
					front.Password = ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func BenchmarkOriginCACached(b *testing.B) {
	p := &managedCertificate{r: &Runtime{ctx: context.Background()}, options: CertificateProviderOptions{Domain: []string{"example.com", "*.example.com"}}, now: time.Now, loaded: true, cert: &tls.Certificate{Leaf: &x509.Certificate{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := p.current(context.Background(), "edge.example.com"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestOriginCAKeysCacheAndSNI(t *testing.T) {
	f := newOriginCAFixture(t)
	for _, kind := range []string{"origin-ecc", "origin-rsa"} {
		for _, auth := range []string{"token", "ca-key"} {
			t.Run(kind+"/"+auth, func(t *testing.T) {
				options := f.options(t)
				options.RequestType = kind
				if auth == "ca-key" {
					options.APIToken, options.OriginCAKey = "", "test-ca-key"
				}
				_, p := f.core(t, options)
				before := f.requests.Load()
				for _, name := range []string{"other.test", "a.b.example.com", ".example.com", "*.example.com"} {
					if _, err := p.current(context.Background(), name); err == nil {
						t.Fatal("unmanaged SNI accepted", name)
					}
				}
				if f.requests.Load() != before {
					t.Fatal("unmanaged SNI triggered issuance")
				}
				var workers sync.WaitGroup
				for range 24 {
					workers.Go(func() {
						if _, err := p.current(context.Background(), "edge.example.com"); err != nil {
							t.Error(err)
						}
					})
				}
				workers.Wait()
				if f.requests.Load()-before != 1 {
					t.Fatal("concurrent issuance was not coalesced")
				}
				path, _ := p.statePath()
				stat, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && stat.Mode().Perm() != 0600 {
					t.Fatal("private state is not0600", stat.Mode())
				}
				data, _ := os.ReadFile(path)
				if strings.Contains(string(data), "test-token") || strings.Contains(string(data), "test-ca-key") {
					t.Fatal("API credential leaked into certificate cache")
				}
				for _, name := range []string{"example.com", "edge.example.com", "EDGE.EXAMPLE.COM.", ""} {
					if _, err := p.current(context.Background(), name); err != nil {
						t.Fatal(name, err)
					}
				}
				for _, name := range []string{"other.test", "a.b.example.com", ".example.com"} {
					if _, err := p.current(context.Background(), name); err == nil {
						t.Fatal("unmanaged SNI accepted", name)
					}
				}
				_, restarted := f.core(t, options)
				if _, err := restarted.current(context.Background(), "example.com"); err != nil {
					t.Fatal(err)
				}
				if f.requests.Load()-before != 1 {
					t.Fatal("persisted certificate was not reused")
				}
			})
		}
	}
}

func TestOriginCARenewal(t *testing.T) {
	f := newOriginCAFixture(t)
	r, p := f.core(t, f.options(t))
	first, err := p.current(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Add(int64(65 * 24 * time.Hour / time.Second))
	f.mode.Store(1)
	before := f.requests.Load()
	cert, err := p.current(context.Background(), "example.com")
	if err != nil || cert != first {
		t.Fatal("valid certificate blocked by renewal", err)
	}
	p.workers.Wait()
	for range 24 {
		if _, err := p.current(context.Background(), "example.com"); err != nil {
			t.Fatal(err)
		}
	}
	if f.requests.Load()-before != 1 {
		t.Fatal("failed renewal not throttled")
	}
	f.clock.Add(61)
	f.mode.Store(0)
	if _, err := p.current(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	p.workers.Wait()
	cert, err = p.current(context.Background(), "example.com")
	if err != nil || cert == first || cert.Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Fatal("certificate not rotated", err)
	}
	f.clock.Add(int64(100 * 24 * time.Hour / time.Second))
	f.mode.Store(1)
	if _, err := p.current(context.Background(), "example.com"); err == nil {
		t.Fatal("expired certificate served after renewal failure")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.current(context.Background(), "example.com"); err == nil {
		t.Fatal("closed provider served a certificate")
	}
}

func TestOriginCAInvalidResponses(t *testing.T) {
	f := newOriginCAFixture(t)
	for mode := int32(1); mode <= 8; mode++ {
		if mode == 6 {
			continue
		}
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			f.mode.Store(mode)
			_, p := f.core(t, f.options(t))
			before := f.requests.Load()
			_, err := p.current(context.Background(), "example.com")
			if err == nil {
				t.Fatal("invalid API response accepted")
			}
			if strings.Contains(err.Error(), "test-token") || strings.Contains(err.Error(), "test-ca-key") {
				t.Fatal("credential exposed in error")
			}
			if f.requests.Load()-before != 1 {
				t.Fatal("API redirect followed or request repeated")
			}
			path, _ := p.statePath()
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("invalid certificate persisted", err)
			}
		})
	}
}

func TestOriginCACancelAndClose(t *testing.T) {
	f := newOriginCAFixture(t)
	f.mode.Store(6)
	r, p := f.core(t, f.options(t))
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, err := p.current(ctx, "example.com"); result <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for f.requests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.requests.Load() != 1 {
		t.Fatal("API request did not start")
	}
	cancel()
	select {
	case err := <-result:
		if err != context.Canceled {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handshake cancellation blocked")
	}
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime close did not cancel issuance")
	}
	close(f.block)
}

func TestOriginCACorruptCache(t *testing.T) {
	f := newOriginCAFixture(t)
	options := f.options(t)
	_, p := f.core(t, options)
	if _, err := p.current(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	path, _ := p.statePath()
	before := f.requests.Load()
	for _, data := range []string{"not JSON", `{"version":0}`, strings.Repeat("x", originCAMaxResponse+1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		_, reloaded := f.core(t, options)
		for range 2 {
			if _, err := reloaded.current(context.Background(), "example.com"); err == nil {
				t.Fatal("corrupt state was accepted")
			}
		}
		if f.requests.Load() != before {
			t.Fatal("corrupt state overwritten by new issuance")
		}
	}
}

func TestOriginCAPersistFailure(t *testing.T) {
	f := newOriginCAFixture(t)
	options := f.options(t)
	_, p := f.core(t, options)
	first, err := p.current(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	path, _ := p.statePath()
	before, _ := os.ReadFile(path)
	saved := options.DataDirectory + ".saved"
	if err := os.Rename(options.DataDirectory, saved); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(saved) })
	if err := os.WriteFile(options.DataDirectory, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(int64(65 * 24 * time.Hour / time.Second))
	if cert, err := p.current(context.Background(), "example.com"); err != nil || cert != first {
		t.Fatal("persistence failure blocked old certificate", err)
	}
	p.workers.Wait()
	p.mu.Lock()
	last, cert := p.err, p.cert
	p.mu.Unlock()
	if last == nil || cert != first {
		t.Fatal("unsaved certificate published", last)
	}
	after, err := os.ReadFile(filepath.Join(saved, filepath.Base(path)))
	if err != nil || string(before) != string(after) {
		t.Fatal("old cache changed", err)
	}
}

func FuzzCertificateProviderConfig(f *testing.F) {
	for _, seed := range []string{`"shared"`, `{"type":"cloudflare-origin-ca","domain":["example.com"],"api_token":"test"}`, `{"type":"cloudflare-origin-ca","domain":["*.example.com"],"origin_ca_key":"test","request_type":"origin-ecc"}`, `{"type":"acme","domain":["example.org"],"email":"test@example.org"}`, `{"type":"acme","domain":["*.example.org"],"dns01_challenge":{"provider":"cloudflare","api_token":"test"}}`, `{"type":"tailscale","endpoint":"ts"}`, `{"type":"tailscale"}`, `null`, `{`, `[]`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16384 {
			return
		}
		var ref certificateReference
		if json.Unmarshal(raw, &ref) != nil {
			return
		}
		encoded, err := json.Marshal(ref)
		if err != nil {
			t.Fatal(err)
		}
		var again certificateReference
		if err := json.Unmarshal(encoded, &again); err != nil {
			t.Fatal("certificate provider reference failed round trip", err)
		}
		canonical, err := json.Marshal(again)
		if err != nil || string(canonical) != string(encoded) {
			t.Fatal("certificate provider JSON failed canonical round trip", err)
		}
	})
}

func TestCertificateProviderValidation(t *testing.T) {
	base := `{"type":"cloudflare-origin-ca","tag":"origin","domain":["example.com"],"api_token":"private"}`
	valid := `{"certificate_providers":[` + base + `],"inbounds":[{"type":"trojan","users":[{"password":"private"}],"tls":{"enabled":true,"certificate_provider":"origin"}}]}`
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"unknown":        strings.Replace(valid, `"certificate_provider":"origin"`, `"certificate_provider":"missing"`, 1),
		"duplicate":      strings.Replace(valid, base, base+","+base, 1),
		"untagged":       strings.Replace(valid, `"tag":"origin",`, "", 1),
		"unsupported":    strings.Replace(valid, "cloudflare-origin-ca", "acme", 1),
		"bad-domain":     strings.Replace(valid, "example.com", "a.*.example.com", 1),
		"ip-domain":      strings.Replace(valid, "example.com", "127.0.0.1", 1),
		"bad-key-type":   strings.Replace(valid, `"domain":`, `"request_type":"ed25519","domain":`, 1),
		"bad-validity":   strings.Replace(valid, `"domain":`, `"requested_validity":4,"domain":`, 1),
		"two-auth":       strings.Replace(valid, `"api_token":`, `"origin_ca_key":"key","api_token":`, 1),
		"no-auth":        strings.Replace(valid, `,"api_token":"private"`, "", 1),
		"disabled":       strings.Replace(valid, `"enabled":true`, `"enabled":false`, 1),
		"static":         strings.Replace(valid, `"enabled":true`, `"certificate":["conflict"],"enabled":true`, 1),
		"outbound":       `{"outbounds":[{"type":"trojan","server":"example.com","server_port":443,"password":"x","tls":{"enabled":true,"certificate_provider":` + base + `}}]}`,
		"unknown-client": strings.Replace(valid, `"domain":`, `"http_client":"missing","domain":`, 1),
		"unknown-detour": strings.Replace(valid, `"domain":`, `"http_client":{"detour":"missing"},"domain":`, 1),
		"unknown-field":  strings.Replace(valid, `"domain":`, `"ignored":true,"domain":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("invalid provider accepted")
			}
		})
	}
	var o CertificateProviderOptions
	json.Unmarshal([]byte(base), &o)
	if err := o.normalize(); err != nil || o.RequestType != "origin-rsa" || o.RequestedValidity != 5475 {
		t.Fatal("provider defaults", o.RequestType, o.RequestedValidity, err)
	}
	o.Tag = ""
	raw, _ := json.Marshal(o)
	var ref certificateReference
	if err := json.Unmarshal(raw, &ref); err != nil {
		t.Fatal(err)
	}
	roundTrip, _ := json.Marshal(ref)
	if !json.Valid(roundTrip) || roundTrip[0] != '{' {
		t.Fatal("inline provider lost during JSON round trip")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &Runtime{ctx: ctx, logger: zap.NewNop()}
	p := &managedCertificate{r: r, options: o, now: time.Now}
	if _, err := p.current(ctx, "example.com"); err != context.Canceled {
		t.Fatal(err)
	}
	if path, err := p.statePath(); err != nil || filepath.Ext(path) != ".json" {
		t.Fatal(path, err)
	}
}
