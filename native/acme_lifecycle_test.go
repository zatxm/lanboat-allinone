package native

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestACMEReferenceRenewal(t *testing.T) {
	f := newACMEFixture(t, false)
	o := f.options(t)
	r, p := f.core(t, o)
	var clock atomic.Int64
	clock.Store(time.Now().Add(10 * time.Second).Unix())
	p.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	first := f.current(t, p, "example.org")
	accountPath, _ := p.acmePath("account")
	var initial acmeAccountState
	if e := readCertificateJSON(accountPath, &initial); e != nil {
		t.Fatal(e)
	}
	clock.Add(int64(61 * 24 * time.Hour / time.Second))
	old, e := p.current(context.Background(), "example.org")
	if e != nil || !old.Leaf.Equal(first.Leaf) {
		t.Fatal("renewal blocked old certificate", e)
	}
	p.workers.Wait()
	if p.err != nil || p.cert.Leaf.Equal(first.Leaf) {
		t.Fatal("certificate not renewed", p.err)
	}
	var renewed acmeAccountState
	if e := readCertificateJSON(accountPath, &renewed); e != nil || renewed.Key != initial.Key || renewed.URL != initial.URL {
		t.Fatal("renewal changed account identity", e)
	}
	latest := p.cert
	// An actual post-renewal HTTP2 handshake must serve the replacement identity.
	in := testInbound(t, "vless")
	in.Transport = Transport{Type: "http", Path: "/renewed"}
	in.TLS = TLSOptions{Enabled: true, CertificateProvider: "acme"}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{f.client}})
	out := testOutbound(t, in, server.Address(in.Tag))
	out.TLS = TLSOptions{Enabled: true, ServerName: "example.org", Certificate: []string{f.ca}}
	out.Transport = in.Transport
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCPTimeout(t, client, 30*time.Second)
	f.stop()
	clock.Add(int64(2 * time.Hour / time.Second))
	old, e = p.current(context.Background(), "example.org")
	if e != nil || !old.Leaf.Equal(latest.Leaf) {
		t.Fatal("renewal failure interrupted old certificate", e)
	}
	p.workers.Wait()
	if p.err == nil || !p.cert.Leaf.Equal(latest.Leaf) || !p.next.After(p.now()) {
		t.Fatal("renewal failure lost valid identity/backoff", p.err)
	}
	_, cached := f.core(t, o)
	f.current(t, cached, "example.org")
	if _, e = p.current(context.Background(), "unmanaged.example.org"); e == nil {
		t.Fatal("unmanaged SNI accepted")
	}
	r.Close()
	if _, e = p.current(context.Background(), "example.org"); e == nil {
		t.Fatal("closed provider accepted")
	}
}

func TestACMEReferenceProtocols(t *testing.T) {
	f := newACMEFixture(t, false)
	for _, test := range []struct {
		kind    string
		version int
	}{{"socks", 0}, {"http", 0}, {"trojan", 0}, {"anytls", 0}, {"vmess", 0}, {"vless", 0}, {"hysteria", 0}, {"hysteria2", 0}, {"tuic", 0}, {"juicity", 0}, {"relay", 0}, {"brook", 0}, {"naive", 2}, {"naive", 3}, {"trusttunnel", 2}, {"trusttunnel", 3}, {"masque", 1}, {"masque", 2}, {"masque", 3}} {
		t.Run(fmt.Sprintf("%s/%d", test.kind, test.version), func(t *testing.T) {
			o := f.options(t)
			o.DisableHTTPChallenge = true
			in := testInbound(t, test.kind)
			in.HTTPVersion = test.version
			in.TLS = TLSOptions{Enabled: true, CertificateProvider: "acme"}
			if isQUICProxy(test.kind) {
				in.Users = []User{{UUID: testUUID, Password: "private"}}
			}
			if test.kind == "naive" || test.kind == "trusttunnel" || test.kind == "masque" {
				in.Users = []User{{Username: "client", Password: "private"}}
			}
			if test.kind == "vmess" {
				in.Transport = Transport{Type: "grpc", ServiceName: "acme"}
			}
			if test.kind == "vless" {
				in.Transport = Transport{Type: "http", Path: "/acme"}
			}
			if test.kind == "brook" {
				in.Transport = Transport{Type: "ws", Path: "/acme"}
			}
			if test.kind == "naive" {
				in.HTTPVersion = 0
			}
			if test.kind == "trojan" {
				inline := o
				inline.Tag = ""
				raw, _ := json.Marshal(inline)
				in.TLS.CertificateProvider = certificateReference(raw)
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{f.client}})
			out := testOutbound(t, in, server.Address(in.Tag))
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.org", Certificate: []string{f.ca}}
			out.Transport = in.Transport
			out.HTTPVersion = test.version
			if test.kind == "naive" {
				out.HTTPVersion = 0
				out.QUIC = test.version == 3
				out.UDPOverTCP = true
			}
			if test.kind == "masque" {
				out.MasqueOptions = MasqueOptions{Mode: "ip"}
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCPTimeout(t, client, 30*time.Second, f.httpPort, f.tlsPort)
			if test.kind != "http" {
				assertUDPSizes(t, client, []int{1, 511})
			}
			server.Close()
			acmePortClosed(t, f.tlsPort)
		})
	}
}

func TestACMEReferenceConcurrentAndCancel(t *testing.T) {
	f := newACMEFixture(t, false)
	o := f.options(t)
	_, p := f.core(t, o)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := p.current(ctx, "example.org"); e == nil {
		t.Fatal("cancel ignored")
	}
	var wg sync.WaitGroup
	results := make(chan *tls.Certificate, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Go(func() { cert, e := p.current(context.Background(), "example.org"); results <- cert; errs <- e })
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	first := <-results
	for cert := range results {
		if cert != first {
			t.Fatal("concurrent issuance not coalesced")
		}
	}
	acmePortClosed(t, f.httpPort)
	acmePortClosed(t, f.tlsPort)
	// A caller cancellation during a shared issuance must not cancel its peers.
	o.Domain = []string{"second.example.org"}
	o.DataDirectory = t.TempDir()
	_, p = f.core(t, o)
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, e := p.current(ctx, "second.example.org"); e == nil || !strings.Contains(e.Error(), "deadline") {
		t.Fatal("waiter deadline ignored", e)
	}
	f.current(t, p, "second.example.org")
}

func TestACMEOfficial(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 is required for ACME interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	f := newACMEFixture(t, false)
	for _, side := range []string{"client", "server"} {
		for _, inline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/inline=%v", side, inline), func(t *testing.T) {
				o := f.options(t)
				o.DisableHTTPChallenge = true
				in := testInbound(t, "trojan")
				in.TLS = TLSOptions{Enabled: true, CertificateProvider: "acme"}
				if inline {
					local := o
					local.Tag = ""
					raw, _ := json.Marshal(local)
					in.TLS.CertificateProvider = certificateReference(raw)
				}
				config := Config{CertificateProviders: []CertificateProviderOptions{o}, HTTPClients: []HTTPClientOptions{f.client}, Inbounds: []Inbound{in}}
				config.Log.Level = "debug"
				var client *Runtime
				if side == "client" {
					in.ListenPort = unusedPort(t, f.httpPort, f.tlsPort)
					config.Inbounds[0] = in
					referenceRuntime(t, config)
					// The official provider prefetches asynchronously; its listener
					// becomes ready before its first certificate. Await a verified
					// TLS identity before testing application traffic.
					roots := x509.NewCertPool()
					roots.AppendCertsFromPEM([]byte(f.ca))
					deadline := time.Now().Add(15 * time.Second)
					for {
						conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 500 * time.Millisecond}, "tcp", portAddress(in.Listen, in.ListenPort), &tls.Config{RootCAs: roots, ServerName: "example.org"})
						if e == nil {
							conn.Close()
							break
						}
						if time.Now().After(deadline) {
							t.Fatal("official ACME identity not ready", e)
						}
						time.Sleep(20 * time.Millisecond)
					}
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = TLSOptions{Enabled: true, ServerName: "example.org", Certificate: []string{f.ca}}
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, config)
					out := testOutbound(t, in, server.Address(in.Tag))
					out.Username = ""
					out.UUID = ""
					out.TLS = TLSOptions{Enabled: true, ServerName: "example.org", Certificate: []string{f.ca}}
					local := Inbound{Type: "mixed", Listen: "127.0.0.1", ListenPort: unusedPort(t, f.httpPort, f.tlsPort)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}})
					front := testOutbound(t, Inbound{Type: "socks"}, portAddress(local.Listen, local.ListenPort))
					front.Username = ""
					front.Password = ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCPTimeout(t, client, 30*time.Second)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func TestACMEReferenceShutdown(t *testing.T) {
	f := newACMEFixture(t, false)
	o := f.options(t)
	r, p := f.core(t, o)
	done := make(chan error, 1)
	go func() { _, e := p.current(context.Background(), "example.org"); done <- e }()
	deadline := time.After(3 * time.Second)
	for {
		r.acme.mu.Lock()
		active := len(r.acme.listeners) > 0
		r.acme.mu.Unlock()
		if active {
			break
		}
		select {
		case <-deadline:
			t.Fatal("challenge listener not started")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown stuck on ACME")
	}
	if e := <-done; e == nil {
		t.Fatal("shutdown waiter accepted")
	}
	acmePortClosed(t, f.httpPort)
	acmePortClosed(t, f.tlsPort)
}

func TestACMEReferenceAccountRecovery(t *testing.T) {
	f := newACMEFixture(t, true)
	o := f.options(t)
	o.ExternalAccount = &ACMEExternalAccount{"wrong-kid", "dGVzdC1lYWItc2VjcmV0LXdpdGgtYXQtbGVhc3QtMzItYnl0ZXM"}
	_, p := f.core(t, o)
	_, e := p.current(context.Background(), "example.org")
	if e == nil || strings.Contains(e.Error(), "wrong-kid") {
		t.Fatal("invalid EAB accepted/leaked", e)
	}
	path, _ := p.acmePath("account")
	var before acmeAccountState
	if e = readCertificateJSON(path, &before); e != nil || before.Key == "" {
		t.Fatal("failed registration lost its key", e)
	}
	o.ExternalAccount.KeyID = "test-kid"
	_, p = f.core(t, o)
	f.current(t, p, "example.org")
	var after acmeAccountState
	if e = readCertificateJSON(path, &after); e != nil || before.Key != after.Key || after.URL == "" {
		t.Fatal("account recovery changed identity", e)
	}
}

func TestACMEReferenceShortLifetime(t *testing.T) {
	f := newACMEFixture(t, false)
	o := f.options(t)
	o.Profile = "minute"
	_, p := f.core(t, o)
	var clock atomic.Int64
	clock.Store(time.Now().Add(10 * time.Second).Unix())
	p.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	first := f.current(t, p, "example.org")
	if !p.next.Before(first.Leaf.NotAfter) {
		t.Fatal("renewal cooldown exceeds certificate lifetime")
	}
	clock.Add(40)
	current, e := p.current(context.Background(), "example.org")
	if e != nil || current != first {
		t.Fatal("short-lived certificate interrupted", e)
	}
	p.workers.Wait()
	if p.err != nil || p.cert == first {
		t.Fatal("short-lived certificate was not renewed", p.err)
	}
}
