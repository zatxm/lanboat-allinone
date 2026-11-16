package native

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestACMEValidation(t *testing.T) {
	valid := func() CertificateProviderOptions {
		return CertificateProviderOptions{Type: "acme", Tag: "acme", Domain: []string{"Example.ORG.", "example.org"}}
	}
	for _, test := range []struct {
		name   string
		change func(*CertificateProviderOptions)
	}{
		{"wildcard-http", func(o *CertificateProviderOptions) { o.Domain = []string{"*.example.org"} }},
		{"no-challenge", func(o *CertificateProviderOptions) { o.DisableHTTPChallenge = true; o.DisableTLSALPNChallenge = true }},
		{"invalid-key", func(o *CertificateProviderOptions) { o.AccountKey = "private-key-secret" }},
		{"key-type", func(o *CertificateProviderOptions) { o.KeyType = "rsa1024" }},
		{"ip-zone", func(o *CertificateProviderOptions) { o.Domain = []string{"fe80::1%eth0"} }},
		{"email", func(o *CertificateProviderOptions) { o.Email = "User <test@example.org>" }},
		{"wrong-default", func(o *CertificateProviderOptions) { o.DefaultServerName = "not-managed.example.org" }},
		{"unsafe-url", func(o *CertificateProviderOptions) { o.Provider = "http://acme.example.org/dir" }},
		{"credentials-url", func(o *CertificateProviderOptions) { o.Provider = "https://user:secret@example.org/dir" }},
		{"mixed-provider", func(o *CertificateProviderOptions) { o.APIToken = "secret" }},
		{"eab-short", func(o *CertificateProviderOptions) { o.ExternalAccount = &ACMEExternalAccount{"kid", "c2hvcnQ"} }},
		{"eab-invalid", func(o *CertificateProviderOptions) { o.ExternalAccount = &ACMEExternalAccount{"kid", "!!"} }},
		{"zerossl", func(o *CertificateProviderOptions) { o.Provider = "zerossl" }},
		{"ip-dns", func(o *CertificateProviderOptions) {
			o.Domain = []string{"127.0.0.1"}
			o.DNS01Challenge = &ACMEDNSOptions{Provider: "cloudflare", APIToken: "token"}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			o := valid()
			test.change(&o)
			if e := o.normalize(); e == nil || strings.Contains(e.Error(), "private-key-secret") {
				t.Fatal("invalid config accepted or secret disclosed", e)
			}
		})
	}
	for _, test := range []struct {
		name    string
		options ACMEDNSOptions
	}{
		{"no-token", ACMEDNSOptions{Provider: "cloudflare"}},
		{"unknown", ACMEDNSOptions{Provider: "route53"}},
		{"conflict", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token", AccessKeyID: "id"}},
		{"no-secret", ACMEDNSOptions{Provider: "alidns", AccessKeyID: "id"}},
		{"no-server", ACMEDNSOptions{Provider: "acmedns", Username: "user", Password: "pass", Subdomain: "id"}},
		{"bad-resolver", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token", Resolvers: []string{"1.1.1.1:no"}}},
		{"zero-port", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token", Resolvers: []string{"1.1.1.1:0"}}},
		{"bad-timeout", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token", PropagationTimeout: "0s"}},
		{"bad-delay", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token", PropagationDelay: "-1s"}},
		{"bad-ttl", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token", TTL: "1ms"}},
		{"bad-record", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token", OverrideDomain: "127.0.0.1"}},
		{"header-injection", ACMEDNSOptions{Provider: "cloudflare", APIToken: "token\r\nsecret"}},
	} {
		t.Run("dns/"+test.name, func(t *testing.T) {
			if test.options.validate() == nil {
				t.Fatal("invalid DNS options accepted")
			}
		})
	}
	o := valid()
	o.Domain = append(o.Domain, "127.0.0.1")
	if e := o.normalize(); e != nil || len(o.Domain) != 2 || o.Profile != "shortlived" {
		t.Fatal(o, e)
	}
	before := o.Provider
	if e := o.normalize(); e != nil || o.Provider != before {
		t.Fatal("normalization not idempotent", e)
	}
}

func TestACMEJWSKeys(t *testing.T) {
	for _, kind := range []string{"p256", "p384", "rsa2048", "ed25519"} {
		t.Run(kind, func(t *testing.T) {
			key, e := acmeGenerateKey(kind)
			if e != nil {
				t.Fatal(e)
			}
			jwk, alg, hash, e := acmeJWK(key)
			if e != nil || !json.Valid(jwk) || alg == "" {
				t.Fatal(alg, e)
			}
			message := []byte("protected.payload")
			signature, e := acmeSignature(key, hash, message)
			if e != nil {
				t.Fatal(e)
			}
			var digest []byte
			switch hash {
			case crypto.SHA256:
				d := sha256.Sum256(message)
				digest = d[:]
			case crypto.SHA384:
				d := sha512.Sum384(message)
				digest = d[:]
			default:
				digest = message
			}
			switch pub := key.Public().(type) {
			case *ecdsa.PublicKey:
				n := len(signature) / 2
				if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(signature[:n]), new(big.Int).SetBytes(signature[n:])) {
					t.Fatal("invalid ECDSA signature")
				}
			case *rsa.PublicKey:
				if e = rsa.VerifyPKCS1v15(pub, hash, digest, signature); e != nil {
					t.Fatal(e)
				}
			case ed25519.PublicKey:
				if !ed25519.Verify(pub, message, signature) {
					t.Fatal("invalid Ed25519 signature")
				}
			}
			if kind == "ed25519" {
				// Pebble only issues RSA/ECDSA certificates; verify Ed25519 CSR,
				// identity matching and persistence without claiming CA acceptance.
				csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"example.org"}}, key)
				if e != nil {
					t.Fatal(e)
				}
				parsed, e := x509.ParseCertificateRequest(csr)
				if e != nil || parsed.CheckSignature() != nil {
					t.Fatal("invalid Ed25519 CSR", e)
				}
				leaf := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org"}, DNSNames: []string{"example.org"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
				der, e := x509.CreateCertificate(rand.Reader, leaf, leaf, key.Public(), key)
				if e != nil {
					t.Fatal(e)
				}
				private, _ := x509.MarshalPKCS8PrivateKey(key)
				o := CertificateProviderOptions{Type: "acme", Tag: "acme", Domain: []string{"example.org"}, DataDirectory: t.TempDir(), ACMEOptions: ACMEOptions{KeyType: kind}}
				if e = o.normalize(); e != nil {
					t.Fatal(e)
				}
				p := &managedCertificate{options: o}
				state := acmeCertificateState{1, o.Domain, o.Provider, o.KeyType, o.Profile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))}
				path, _ := p.acmePath("certificate")
				if e = saveCertificateJSON(path, state); e != nil {
					t.Fatal(e)
				}
				if e = p.loadACME(); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestACMEWireErrors(t *testing.T) {
	for _, mode := range []string{"badNonce", "no-nonce", "rate-limit", "redirect", "large", "cross-authority"} {
		t.Run(mode, func(t *testing.T) {
			var count atomic.Int32
			var target string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode != "no-nonce" {
					w.Header().Set("Replay-Nonce", fmt.Sprint(count.Load()+1))
				}
				if r.Method == "HEAD" {
					return
				}
				count.Add(1)
				if mode == "badNonce" && count.Load() == 1 {
					w.WriteHeader(400)
					io.WriteString(w, `{"type":"urn:ietf:params:acme:error:badNonce","detail":"secret"}`)
					return
				}
				if mode == "rate-limit" {
					w.Header().Set("Retry-After", "7200")
					w.WriteHeader(429)
					io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rateLimited","detail":"secret"}`)
					return
				}
				if mode == "redirect" {
					w.Header().Set("Location", target+"/redirect")
					w.WriteHeader(307)
					return
				}
				if mode == "large" {
					io.WriteString(w, strings.Repeat("x", originCAMaxResponse+1))
					return
				}
				var j acmeJWS
				if json.NewDecoder(r.Body).Decode(&j) != nil {
					t.Error("invalid JWS JSON")
				}
				protected, _ := base64.RawURLEncoding.DecodeString(j.Protected)
				var h map[string]any
				json.Unmarshal(protected, &h)
				if h["url"] != target+"/order" || h["jwk"] == nil || h["kid"] != nil || j.Payload != "" {
					t.Error("invalid POST-as-GET envelope", string(protected), j.Payload)
				}
				io.WriteString(w, `{"ok":true}`)
			}))
			defer server.Close()
			target = server.URL
			r := newTestRuntime(t, Config{})
			p := &managedCertificate{r: r, now: time.Now}
			base, _ := url.Parse(target)
			key, _ := acmeGenerateKey("p256")
			c := &acmeClient{p: p, base: base, key: key, http: &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
			c.jwk, c.alg, c.hash, _ = acmeJWK(key)
			c.directory.NewNonce = target + "/nonce"
			address := target + "/order"
			if mode == "cross-authority" {
				address = "http://127.0.0.1:1/order"
			}
			_, _, _, e := c.post(context.Background(), address, nil)
			if mode == "badNonce" {
				if e != nil || count.Load() != 2 {
					t.Fatal("bad nonce was not retried", e, count.Load())
				}
				return
			}
			if e == nil || strings.Contains(e.Error(), "secret") {
				t.Fatal("unsafe response accepted", e)
			}
			if mode == "rate-limit" {
				var problem *acmeError
				if !errors.As(e, &problem) || problem.retry.Before(time.Now().Add(119*time.Minute)) {
					t.Fatal("Retry-After lost", e)
				}
			}
		})
	}
}

func TestACMECacheCorruptionAndUnwritable(t *testing.T) {
	r := newTestRuntime(t, Config{})
	o := CertificateProviderOptions{Type: "acme", Tag: "acme", Domain: []string{"example.org"}, DataDirectory: t.TempDir()}
	if e := o.normalize(); e != nil {
		t.Fatal(e)
	}
	r.initACME()
	p := &managedCertificate{r: r, options: o, now: time.Now}
	path, _ := p.acmePath("certificate")
	os.WriteFile(path, []byte(`{"version":1,"private_key":"secret"}`), 0600)
	if _, e := p.current(context.Background(), "example.org"); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal("corrupt cache accepted/disclosed", e)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "secret") {
		t.Fatal("corrupt file overwritten")
	}
	o.DataDirectory = filepath.Join(t.TempDir(), "file")
	os.WriteFile(o.DataDirectory, []byte("keep"), 0600)
	p = &managedCertificate{r: r, options: o, now: time.Now}
	if _, e := p.issueACME(context.Background()); e == nil {
		t.Fatal("unwritable identity state accepted")
	}
}

type acmeTestRoundTrip func(*http.Request) (*http.Response, error)

func (f acmeTestRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestACMEZeroSSLBinding(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			p := &managedCertificate{options: CertificateProviderOptions{ACMEOptions: ACMEOptions{Email: "test@example.org"}}}
			c := &acmeClient{p: p, http: &http.Client{Transport: acmeTestRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != "https://api.zerossl.com/acme/eab-credentials-email" || r.Method != "POST" || r.ParseForm() != nil || r.Form.Get("email") != "test@example.org" {
					t.Error("invalid ZeroSSL EAB request")
				}
				body := `{"success":false,"error":"private-response"}`
				if valid {
					body = `{"success":true,"eab_kid":"kid","eab_hmac_key":"dGVzdC1lYWItc2VjcmV0LXdpdGgtYXQtbGVhc3QtMzItYnl0ZXM"}`
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			binding, e := c.zeroSSLBinding(context.Background())
			if valid && (e != nil || binding.KeyID != "kid") {
				t.Fatal(binding, e)
			}
			if !valid && (e == nil || strings.Contains(e.Error(), "private-response")) {
				t.Fatal("unsafe ZeroSSL response", e)
			}
		})
	}
}
