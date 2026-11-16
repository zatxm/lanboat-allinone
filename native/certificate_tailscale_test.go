package native

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type tailscaleCertificateFixture struct {
	*acmeFixture
	control string
	decoder *json.Decoder
	input   io.Writer
	proofs  atomic.Int32
	mode    atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func newTailscaleCertificateFixture(t *testing.T) *tailscaleCertificateFixture {
	t.Helper()
	f := &tailscaleCertificateFixture{acmeFixture: newACMEFixture(t, false), entered: make(chan struct{}, 16), release: make(chan struct{})}
	t.Cleanup(func() { close(f.release) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var proof struct {
			Version int
			NodeKey string
			Name    string
			Type    string
			Value   string
		}
		if err := json.NewDecoder(io.LimitReader(req.Body, 4096)).Decode(&proof); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		_, keyErr := tsPublic(proof.NodeKey, "nodekey")
		value, err := base64.RawURLEncoding.Strict().DecodeString(proof.Value)
		if proof.Version != tailscaleCapability || keyErr != nil || proof.Type != "TXT" || !strings.HasPrefix(proof.Name, "_acme-challenge.") || err != nil || len(value) != 32 {
			t.Error("invalid authenticated SetDNS proof")
			w.WriteHeader(400)
			return
		}
		f.proofs.Add(1)
		switch f.mode.Load() {
		case 1:
			w.WriteHeader(503)
			return
		case 2:
			f.entered <- struct{}{}
			select {
			case <-f.release:
			case <-req.Context().Done():
				return
			}
		}
		f.mu.Lock()
		f.txt[canonicalDomain(proof.Name)] = []string{proof.Value}
		f.mu.Unlock()
		io.WriteString(w, "{}")
	}))
	t.Cleanup(api.Close)
	t.Setenv("LANBOAT_TS_CERTIFICATE", "1")
	t.Setenv("LANBOAT_TS_CERTIFICATE_DOMAINS", `["alias.test.ts.net"]`)
	t.Setenv("LANBOAT_TS_CERTIFICATE_CALLBACK", api.URL)
	f.control, f.decoder, f.input = startTSReference(t, false)
	return f
}

func (f *tailscaleCertificateFixture) config(t *testing.T) Config {
	t.Helper()
	return Config{
		Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{
			AuthKey: "test-only-auth", ControlURL: f.control, StateDirectory: t.TempDir(), Hostname: "native", ForceDERP: true, OnDemand: true,
		}}},
		CertificateProviders: []CertificateProviderOptions{{Type: "tailscale", Tag: "ts-cert", Endpoint: "ts"}},
		HTTPClients:          []HTTPClientOptions{f.client},
		Outbounds:            []Outbound{{Type: "direct", Tag: "direct"}},
		Route:                Route{Final: "direct"},
	}
}

// Only tests replace the public CA with a pinned external Pebble instance.
// Product configuration remains the official endpoint-only provider schema.
func (f *tailscaleCertificateFixture) prepare(t *testing.T, p *managedCertificate, name string) *managedCertificate {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child, err := p.tailscaleCertificate(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if child.options.Provider != "https://acme-v02.api.letsencrypt.org/directory" || child.options.KeyType != "p256" || !strings.HasSuffix(child.options.DataDirectory, string(filepath.Separator)+"certificates") {
		t.Fatal("invalid production CA/key/cache defaults")
	}
	child.options.Provider, child.options.HTTPClient, child.options.Profile = f.provider, clientReference(f.client.Tag), "default"
	return child
}

func TestTailscaleCertificateReference(t *testing.T) {
	f := newTailscaleCertificateFixture(t)
	cfg := f.config(t)
	cfg.CertificateProviders = append(cfg.CertificateProviders, CertificateProviderOptions{Type: "tailscale", Tag: "second", Endpoint: "ts"})
	in := testInbound(t, "trojan")
	in.TLS = TLSOptions{Enabled: true, CertificateProvider: certificateReference(`{"type":"tailscale","endpoint":"ts"}`)}
	cfg.Inbounds = []Inbound{in}
	r := newTestRuntime(t, cfg)
	p := r.certificateProviders["ts-cert"]
	if p != r.certificateProviders["second"] || p != r.certificateProviders[string(r.config.Inbounds[0].TLS.CertificateProvider)] {
		t.Fatal("shared and inline providers duplicate the endpoint issuer")
	}
	if _, err := os.Stat(cfg.Endpoints[0].StateDirectory + "/state.json"); !os.IsNotExist(err) {
		t.Fatal("on-demand endpoint started before use", err)
	}
	child := f.prepare(t, p, "")
	if child.options.Domain[0] != "native.test.ts.net" {
		t.Fatal("missing SNI did not use the endpoint DNS name")
	}
	first := f.current(t, p, "NATIVE.TEST.TS.NET.")
	// An actual ClientHello without SNI still receives the node's own identity.
	conn, err := tls.Dial("tcp", r.Address(in.Tag), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal("empty-SNI TLS handshake", err)
	}
	if !conn.ConnectionState().PeerCertificates[0].Equal(first.Leaf) {
		t.Fatal("empty-SNI handshake served the wrong identity")
	}
	conn.Close()
	if f.proofs.Load() != 1 || f.txtQueries.Load() == 0 {
		t.Fatal("CA did not independently validate the Tailscale TXT proof")
	}
	for _, name := range []string{"peer.test.ts.net", "unmanaged.example.org", "*.test.ts.net", "100.64.0.1", "bad\n.test.ts.net"} {
		if _, err := p.current(context.Background(), name); err == nil {
			t.Fatal("unmanaged SNI accepted", name)
		}
	}
	if f.proofs.Load() != 1 {
		t.Fatal("unmanaged SNI reached the certificate authority")
	}
	f.prepare(t, p, "alias.test.ts.net")
	alias := f.current(t, p, "alias.test.ts.net")
	if alias.Leaf.Equal(first.Leaf) || f.proofs.Load() != 2 {
		t.Fatal("different SNI did not receive an isolated identity")
	}
	path, err := child.statePath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("certificate state permissions", info, err)
	}
	account, _ := child.acmePath("account")
	var before acmeAccountState
	if err = readCertificateJSON(account, &before); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if _, err = p.current(context.Background(), "native.test.ts.net"); err == nil {
		t.Fatal("closed provider accepted a handshake")
	}
	f.stop()
	restored := newTestRuntime(t, cfg)
	q := restored.certificateProviders["ts-cert"]
	cached := f.prepare(t, q, "native.test.ts.net")
	got := f.current(t, q, "native.test.ts.net")
	if !got.Leaf.Equal(first.Leaf) || f.proofs.Load() != 2 {
		t.Fatal("restart did not use the persisted certificate")
	}
	var after acmeAccountState
	account, _ = cached.acmePath("account")
	if err = readCertificateJSON(account, &after); err != nil || before.Key != after.Key || before.URL != after.URL {
		t.Fatal("account identity changed on restart", err)
	}
	if err = restored.DisconnectTailscale("ts"); err != nil {
		t.Fatal(err)
	}
	if _, err = q.current(context.Background(), "native.test.ts.net"); err != nil || f.proofs.Load() != 2 {
		t.Fatal("on-demand reconnect lost the cached identity", err)
	}
}

func TestTailscaleCertificateRenewal(t *testing.T) {
	f := newTailscaleCertificateFixture(t)
	r := newTestRuntime(t, f.config(t))
	p := r.certificateProviders["ts-cert"]
	var clock atomic.Int64
	clock.Store(time.Now().Add(10 * time.Second).Unix())
	p.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	child := f.prepare(t, p, "native.test.ts.net")
	first := f.current(t, p, "native.test.ts.net")
	clock.Add(int64(61 * 24 * time.Hour / time.Second))
	old, err := p.current(context.Background(), "native.test.ts.net")
	if err != nil || old != first {
		t.Fatal("renewal interrupted the valid identity", err)
	}
	child.workers.Wait()
	if child.err != nil || child.cert.Leaf.Equal(first.Leaf) || f.proofs.Load() != 2 {
		t.Fatal("background renewal failed", child.err)
	}
	latest := child.cert
	// A CA may reuse a valid authorization and never call SetDNS again.
	// Stop the issuer so renewal must fail regardless of that decision.
	f.stop()
	clock.Add(int64(2 * time.Hour / time.Second))
	if got, err := p.current(context.Background(), "native.test.ts.net"); err != nil || got != latest {
		t.Fatal("failed renewal interrupted the valid identity", err)
	}
	child.workers.Wait()
	if child.err == nil || child.cert != latest || !child.next.After(p.now()) {
		t.Fatal("failed renewal lost its valid certificate or backoff")
	}
	// Revoke a cached name through the authenticated map stream.
	if err = json.NewEncoder(f.input).Encode(map[string]any{"op": "dns", "hostname": "native", "dns": tsDNSConfig{CertDomains: []string{"alias.test.ts.net"}}}); err != nil {
		t.Fatal(err)
	}
	var result struct{ OK bool }
	if err = f.decoder.Decode(&result); err != nil || !result.OK {
		t.Fatal("certificate domain update", result, err)
	}
	c := r.tailscaleClient("ts")
	until := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		revoked := !slices.Contains(c.dnsConfig.CertDomains, "native.test.ts.net")
		c.mu.Unlock()
		if revoked {
			break
		}
		if time.Now().After(until) {
			t.Fatal("certificate revocation map did not arrive")
		}
		time.Sleep(time.Millisecond)
	}
	count := f.proofs.Load()
	if _, err = p.current(context.Background(), "native.test.ts.net"); err == nil || f.proofs.Load() != count {
		t.Fatal("revoked cached name accepted", err)
	}
	f.prepare(t, p, "alias.test.ts.net")
	if len(p.children) != 1 || p.children["native.test.ts.net"] != nil {
		t.Fatal("retired domain cache was not released")
	}
}

func TestTailscaleCertificateDNSFailure(t *testing.T) {
	f := newTailscaleCertificateFixture(t)
	r := newTestRuntime(t, f.config(t))
	p := r.certificateProviders["ts-cert"]
	child := f.prepare(t, p, "native.test.ts.net")
	f.mode.Store(1)
	_, err := p.current(context.Background(), "native.test.ts.net")
	child.workers.Wait()
	if err == nil || child.cert != nil || f.proofs.Load() != 1 || !child.next.After(child.now()) {
		t.Fatal("SetDNS failure did not reject issuance and retain backoff", err)
	}
}

func TestTailscaleCertificateConcurrentCancel(t *testing.T) {
	f := newTailscaleCertificateFixture(t)
	r := newTestRuntime(t, f.config(t))
	p := r.certificateProviders["ts-cert"]
	child := f.prepare(t, p, "native.test.ts.net")
	f.mode.Store(2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := p.current(ctx, "native.test.ts.net"); done <- err }()
	select {
	case <-f.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("SetDNS did not start")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("waiter cancellation ignored", err)
	}
	var wg sync.WaitGroup
	results := make(chan *tls.Certificate, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			cert, err := p.current(context.Background(), "native.test.ts.net")
			results <- cert
			errs <- err
		})
	}
	f.release <- struct{}{}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	first := <-results
	for cert := range results {
		if cert != first {
			t.Fatal("concurrent issuance not coalesced")
		}
	}
	if f.proofs.Load() != 1 {
		t.Fatal("duplicate concurrent SetDNS publication")
	}
	// Cancel a pending renewal by closing the owning runtime.
	child.mu.Lock()
	child.cert, child.next = nil, time.Time{}
	child.mu.Unlock()
	go func() { _, err := p.current(context.Background(), "native.test.ts.net"); done <- err }()
	select {
	case <-f.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("renewal did not start")
	}
	closed := make(chan struct{})
	go func() { r.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not cancel certificate issuance")
	}
	if err := <-done; err == nil {
		t.Fatal("shutdown waiter returned success")
	}
	f.release <- struct{}{}
}

func TestTailscaleCertificateResumptionRevocation(t *testing.T) {
	f := newTailscaleCertificateFixture(t)
	cfg := f.config(t)
	in := testInbound(t, "trojan")
	in.TLS = TLSOptions{Enabled: true, CertificateProvider: "ts-cert"}
	cfg.Inbounds = []Inbound{in}
	r := newTestRuntime(t, cfg)
	p := r.certificateProviders["ts-cert"]
	f.prepare(t, p, "native.test.ts.net")
	f.current(t, p, "native.test.ts.net")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(f.ca))
	endpoint := r.tailscaleClient("ts")
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, sni := range []bool{true, false} {
			t.Run(fmt.Sprintf("TLS%x/SNI%v", version, sni), func(t *testing.T) {
				endpoint.mu.Lock()
				endpoint.dnsConfig.CertDomains = []string{"native.test.ts.net"}
				endpoint.mu.Unlock()
				listener, err := tls.Listen("tcp", "127.0.0.1:0", cloneTLSConfig(r.serverTLS[in.Tag]))
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				server := make(chan error, 3)
				go func() {
					for range 3 {
						conn, err := listener.Accept()
						if err != nil {
							server <- err
							return
						}
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						err = conn.(*tls.Conn).Handshake()
						if err == nil {
							_, err = conn.Write([]byte{1})
						}
						conn.Close()
						server <- err
					}
				}()
				client := &tls.Config{RootCAs: roots, ServerName: "native.test.ts.net", MinVersion: version, MaxVersion: version, ClientSessionCache: tls.NewLRUClientSessionCache(2)}
				if !sni {
					client.ServerName = ""
					client.InsecureSkipVerify = true
					client.VerifyConnection = func(cs tls.ConnectionState) error {
						intermediates := x509.NewCertPool()
						for _, cert := range cs.PeerCertificates[1:] {
							intermediates.AddCert(cert)
						}
						_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "native.test.ts.net"})
						return err
					}
				}
				for i := range 2 {
					conn, err := tls.Dial("tcp", listener.Addr().String(), client)
					if err != nil {
						t.Fatal(err)
					}
					var data [1]byte
					_, err = io.ReadFull(conn, data[:])
					resumed := conn.ConnectionState().DidResume
					conn.Close()
					if err != nil || resumed != (sni && i == 1) || data[0] != 1 {
						t.Fatal("TLS resumption", i, resumed, err)
					}
					if err = <-server; err != nil {
						t.Fatal(err)
					}
				}
				endpoint.mu.Lock()
				endpoint.dnsConfig.CertDomains = nil
				endpoint.mu.Unlock()
				conn, err := tls.Dial("tcp", listener.Addr().String(), client)
				if conn != nil {
					conn.Close()
				}
				if err == nil {
					t.Fatal("session ticket bypassed certificate domain revocation")
				}
				if err = <-server; err == nil {
					t.Fatal("server resumed a revoked certificate domain")
				}
			})
		}
	}
}

func TestTailscaleCertificateProtocols(t *testing.T) {
	f := newTailscaleCertificateFixture(t)
	state := t.TempDir()
	for _, test := range []struct {
		kind    string
		version int
	}{{"socks", 0}, {"http", 0}, {"trojan", 0}, {"anytls", 0}, {"vmess", 0}, {"vless", 0}, {"hysteria", 0}, {"hysteria2", 0}, {"tuic", 0}, {"juicity", 0}, {"relay", 0}, {"brook", 0}, {"naive", 2}, {"naive", 3}, {"trusttunnel", 2}, {"trusttunnel", 3}, {"masque", 1}, {"masque", 2}, {"masque", 3}} {
		t.Run(fmt.Sprintf("%s/%d", test.kind, test.version), func(t *testing.T) {
			cfg := f.config(t)
			cfg.Endpoints[0].StateDirectory = state
			in := testInbound(t, test.kind)
			in.HTTPVersion = test.version
			in.TLS = TLSOptions{Enabled: true, CertificateProvider: "ts-cert"}
			if isQUICProxy(test.kind) {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			if test.kind == "naive" || test.kind == "trusttunnel" || test.kind == "masque" {
				in.Users = []User{{Username: "client", Password: "private"}}
			}
			if test.kind == "naive" {
				in.HTTPVersion = 0
			}
			if test.kind == "vmess" {
				in.Transport = Transport{Type: "grpc", ServiceName: "certificate"}
			}
			if test.kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/certificate"}
			}
			if test.kind == "brook" {
				in.Transport = Transport{Type: "ws", Path: "/certificate"}
			}
			if test.kind == "trojan" {
				in.TLS.CertificateProvider = certificateReference(`{"type":"tailscale","endpoint":"ts"}`)
			}
			cfg.Inbounds = []Inbound{in}
			server := newTestRuntime(t, cfg)
			p := server.certificateProviders[string(server.config.Inbounds[0].TLS.CertificateProvider)]
			f.prepare(t, p, "native.test.ts.net")
			f.current(t, p, "native.test.ts.net")
			out := testOutbound(t, in, server.Address(in.Tag))
			out.TLS = TLSOptions{Enabled: true, ServerName: "native.test.ts.net", Certificate: []string{f.ca}}
			out.Transport, out.HTTPVersion = in.Transport, test.version
			if test.kind == "naive" {
				out.HTTPVersion, out.QUIC, out.UDPOverTCP = 0, test.version == 3, true
			}
			if test.kind == "masque" {
				out.MasqueOptions = MasqueOptions{Mode: "ip"}
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			if test.kind != "http" {
				assertUDPSizes(t, client, []int{1, 511})
			}
			server.Close()
		})
	}
}

func TestTailscaleCertificateConfig(t *testing.T) {
	valid := `{"endpoints":[{"type":"tailscale","tag":"ts"}],"certificate_providers":[{"type":"tailscale","tag":"cert","endpoint":"ts"}],"inbounds":[{"type":"trojan","tag":"in","listen":"127.0.0.1","listen_port":443,"users":[{"password":"test"}],"tls":{"enabled":true,"certificate_provider":"cert"}}]}`
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"domain":["example.org"]`, `"data_directory":"test"`, `"http_client":"http"`, `"provider":"letsencrypt"`, `"email":"test@example.org"`, `"api_token":"test"`, `"origin_ca_key":"test"`, `"key_type":"p256"`, `"request_type":"origin-rsa"`, `"requested_validity":7`} {
		t.Run(field, func(t *testing.T) {
			raw := strings.Replace(valid, `"endpoint":"ts"`, `"endpoint":"ts",`+field, 1)
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("conflicting provider options accepted")
			}
		})
	}
	for _, replacement := range []string{`"endpoint":"missing"`, `"endpoint":""`, `"endpoint":null`} {
		if _, err := Parse([]byte(strings.Replace(valid, `"endpoint":"ts"`, replacement, 1))); err == nil {
			t.Fatal("unknown endpoint accepted", replacement)
		}
	}
	if _, err := Parse([]byte(strings.Replace(valid, `"type":"tailscale","tag":"ts"`, `"type":"wireguard","tag":"ts"`, 1))); err == nil {
		t.Fatal("non-Tailscale endpoint accepted")
	}
	for _, names := range [][]string{{"*.test.ts.net"}, {"127.0.0.1"}, {"single"}, {"bad..ts.net"}, {"bad\n.ts.net"}, make([]string, 129)} {
		if err := (tsDNSConfig{CertDomains: names}).validate(); err == nil {
			t.Fatal("invalid certificate domain map accepted", names)
		}
	}
	for _, typ := range []string{"acme", "cloudflare-origin-ca"} {
		o := CertificateProviderOptions{Type: typ, Endpoint: "ts", Domain: []string{"example.org"}, APIToken: "test"}
		if err := o.normalize(); err == nil {
			t.Fatal("Tailscale field on another provider accepted")
		}
	}
}

func TestTailscaleCertificateSetDNSFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{{"denied", 403, "secret-proof"}, {"failed", 500, "secret-proof"}, {"redirect", 307, "secret-proof"}, {"empty", 200, ""}, {"null", 200, "null"}, {"array", 200, "[]"}, {"oversize", 200, strings.Repeat("x", (64<<10)+1)}} {
		t.Run(test.name, func(t *testing.T) {
			r, endpoint := tsDNSFixture(t, tsDNSConfig{CertDomains: []string{"native.test.ts.net"}})
			endpoint.nodeKey, _ = ecdh.X25519().GenerateKey(rand.Reader)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			defer api.Close()
			endpoint.control = &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(api.URL, "http://"))
			}}
			defer endpoint.control.CloseIdleConnections()
			client := &acmeClient{p: &managedCertificate{r: r, tailscaleEndpoint: "ts"}}
			if _, err := client.presentTailscaleDNS(context.Background(), "native.test.ts.net", "secret-proof"); err == nil || strings.Contains(err.Error(), "secret-proof") {
				t.Fatal("invalid response accepted or secret leaked", err)
			}
		})
	}
}

func TestTailscaleCertificateDisabledAndAmbiguous(t *testing.T) {
	r, c := tsDNSFixture(t, tsDNSConfig{})
	r.initACME()
	p := &managedCertificate{r: r, options: CertificateProviderOptions{Type: "tailscale", Endpoint: "ts"}, now: time.Now}
	defer p.close()
	for _, name := range []string{"", "native.test.ts.net"} {
		if _, err := p.current(context.Background(), name); err == nil || p.children != nil {
			t.Fatal("disabled HTTPS created a certificate manager")
		}
	}
	snapshot := c.dns.Load()
	tsDNSPublish(t, c, tsDNSConfig{CertDomains: []string{"one.test.ts.net", "two.test.ts.net"}})
	if c.dns.Load() != snapshot {
		t.Fatal("HTTPS permission change invalidated unrelated DNS sessions")
	}
	if _, err := p.current(context.Background(), ""); err == nil || p.children != nil {
		t.Fatal("ambiguous empty-SNI certificate accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.current(ctx, "one.test.ts.net"); !errors.Is(err, context.Canceled) || p.children != nil {
		t.Fatal("cancelled request created a certificate manager", err)
	}
}

func BenchmarkTailscaleCertificateCached(b *testing.B) {
	ctx := context.Background()
	r := &Runtime{ctx: ctx}
	c := &tailscaleClient{ctx: ctx, ready: make(chan struct{}), self: tsNode{Name: "native.test.ts.net", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}, dnsConfig: tsDNSConfig{CertDomains: []string{"native.test.ts.net"}}}
	c.once.Do(func() {})
	close(c.ready)
	r.tailscaleClients = map[string]*tailscaleClient{"ts": c}
	child := &managedCertificate{r: r, options: CertificateProviderOptions{Domain: []string{"native.test.ts.net"}}, now: time.Now, loaded: true, cert: &tls.Certificate{Leaf: &x509.Certificate{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour)}}}
	p := &managedCertificate{r: r, options: CertificateProviderOptions{Type: "tailscale", Endpoint: "ts"}, children: map[string]*managedCertificate{"native.test.ts.net": child}}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := p.current(ctx, "native.test.ts.net"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
