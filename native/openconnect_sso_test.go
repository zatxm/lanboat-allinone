package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ocSSOAuth(mode string) *ocAuth {
	return &ocAuth{ID: "sso", SSOLogin: "https://vpn.example/login", SSOFinal: "/success", SSOTokenCookie: "acSamlv2Token", SSOErrorCookie: "acSamlv2Error", SSOBrowser: mode, Form: &ocForm{Inputs: []ocInput{{Type: "sso", Name: "sso-token"}, {Type: "hidden", Name: "state", Value: "hidden"}}}}
}

func ocEncryptSSO(t testing.TB, public, token string) string {
	t.Helper()
	der, _ := base64.StdEncoding.DecodeString(public)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	aesKey, _ := hkdf.Key(sha256.New, shared, nil, "AC_ECIES", 32)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCMWithTagSize(block, 12)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	sealed := gcm.Seal(nil, nonce, []byte(token), nil)
	der, _ = x509.MarshalPKIXPublicKey(key.PublicKey())
	b := []byte{0, 1}
	for i, v := range [][]byte{der, sealed[len(sealed)-12:], sealed[:len(sealed)-12], nonce} {
		b = binary.BigEndian.AppendUint16(b, uint16(i+1))
		b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
		b = append(b, v...)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func ocSSOCallback(t *testing.T, encoded, address string) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(address + "/api/sso/" + url.PathEscape(encoded) + "?return=https%3A%2F%2Fevil.example%2F")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 || strings.Contains(resp.Header.Get("Location"), "evil.example") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal(resp.StatusCode, resp.Header)
	}
}

func TestOpenConnectSSOBrowserAndTunnel(t *testing.T) {
	if isolateOpenConnectSSO(t) {
		return
	}
	testOpenConnectSSOTunnel(t, "")
}

func TestBrowserOpenConnectSSO(t *testing.T) {
	if isolateOpenConnectSSO(t) {
		return
	}
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		t.Run(profile, func(t *testing.T) { testOpenConnectSSOTunnel(t, profile) })
	}
}

func testOpenConnectSSOTunnel(t *testing.T, profile string) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, mode := range []string{"embedded", "external"} {
			t.Run(strconv.Itoa(int(version))+"/"+mode, func(t *testing.T) {
				server, client := ocPair(t)
				in := server.config.Inbounds[0]
				var logins, connects, prompts atomic.Int32
				var signing, exchange atomic.Value
				var origin string
				gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					origin := "https://" + req.Host
					if req.Method == "CONNECT" {
						pub, _ := base64.StdEncoding.DecodeString(req.Header.Get("X-AnyConnect-STRAP-Pubkey"))
						key, err := x509.ParsePKIXPublicKey(pub)
						if err != nil {
							t.Error(err)
							w.WriteHeader(403)
							return
						}
						binding := req.TLS.TLSUnique
						if version == tls.VersionTLS13 {
							binding, err = req.TLS.ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
						}
						digest := sha256.Sum256(append(bytes.Clone(binding), pub...))
						sig, _ := base64.StdEncoding.DecodeString(req.Header.Get("X-AnyConnect-STRAP-Verify"))
						if err != nil || req.Header.Get("X-AnyConnect-STRAP-Pubkey") != signing.Load() || !ecdsa.VerifyASN1(key.(*ecdsa.PublicKey), digest[:], sig) {
							t.Error("invalid STRAP channel binding")
							w.WriteHeader(403)
							return
						}
						connects.Add(1)
						raw, rw, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						defer raw.Close()
						var b bytes.Buffer
						b.WriteString("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n")
						req.Header.Write(&b)
						b.WriteString("\r\n")
						err = server.serveOpenConnect(in, &bufferedConn{Conn: raw, reader: bufio.NewReader(io.MultiReader(&b, rw.Reader))})
						if err != nil {
							t.Error(err)
						}
						return
					}
					var message ocXML
					if err := xml.NewDecoder(req.Body).Decode(&message); err != nil {
						t.Error(err)
						return
					}
					if message.Aggregate != "2" || message.Agent == nil || message.Agent.Who != "vpn" || message.Agent.Value != Version || message.Version != "" {
						t.Error("invalid aggregate authentication version envelope")
						w.WriteHeader(400)
						return
					}
					if message.Type == "init" {
						logins.Add(1)
						if message.Capabilities == nil || !slices.Contains(message.Capabilities.Methods, "single-sign-on-v2") || !slices.Contains(message.Capabilities.Methods, "single-sign-on-external-browser") {
							t.Error("SSO capabilities missing")
						}
						signing.Store(req.Header.Get("X-AnyConnect-STRAP-Pubkey"))
						exchange.Store(req.Header.Get("X-AnyConnect-STRAP-DH-Pubkey"))
						auth := ocSSOAuth(mode)
						auth.SSOLogin = origin + "/saml/login"
						auth.SSOFinal = origin + "/success"
						ocAuthReply(t, w, ocXML{Type: "auth-request", Auth: auth, Opaque: &ocOpaque{Data: "<bound>request1</bound>"}})
						return
					}
					v := map[string]string{}
					for _, f := range message.Auth.Fields {
						v[f.XMLName.Local] = f.Value
					}
					if v["sso-token"] != "SAMLToken123" || v["state"] != "hidden" || v["password"] != "" || message.Opaque == nil || message.Opaque.Data != "<bound>request1</bound>" || req.Header.Get("X-AnyConnect-STRAP-DH-Pubkey") != exchange.Load() {
						t.Error("SSO state or token lost")
						w.WriteHeader(401)
						return
					}
					ocAuthReply(t, w, ocXML{Type: "complete", Token: server.ocServers[in.Tag].cookie("client", time.Now())})
				}))
				gateway.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
				gateway.StartTLS()
				defer gateway.Close()
				origin = gateway.URL
				u, _ := url.Parse(origin)
				port, _ := strconv.Atoi(u.Port())
				c := client.ocClients["proxy"]
				c.o.Server, c.o.ServerPort = u.Hostname(), uint16(port)
				if profile != "" {
					c.o.TLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				}
				client.SetOpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) {
					prompts.Add(1)
					b, _ := json.Marshal(form)
					if bytes.Contains(b, []byte(in.Users[0].Password)) || bytes.Contains(b, []byte("hidden")) || form.SSO == nil || form.SSO.FinalURL != origin+"/success" {
						t.Fatal("missing metadata or secret exposed")
					}
					if mode == "external" {
						cmd := exec.CommandContext(ctx, "python3", "../tests/openconnect-sso-reference.py", exchange.Load().(string), "SAMLToken123")
						b, err := cmd.Output()
						if err != nil {
							t.Fatal(err)
						}
						ocSSOCallback(t, strings.TrimSpace(string(b)), "http://127.0.0.1:29786")
						return nil, nil
					}
					token, done, err := form.SSO.Complete(form.SSO.FinalURL, []*http.Cookie{{Name: "acSamlv2Token", Value: "SAMLToken123"}})
					if err != nil || !done {
						t.Fatal(err)
					}
					return map[string]string{"sso-token": token}, nil
				})
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := client.AuthenticateOpenConnect(ctx, "proxy"); err != nil {
					t.Fatal(err)
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 4096, 60000})
				client.resetNetworkTransports()
				assertTCP(t, client)
				if logins.Load() != 1 || prompts.Load() != 1 || connects.Load() != 2 || c.strap.dh != nil {
					t.Fatal("SSO repeated or ephemeral key retained")
				}
				client.Close()
			})
		}
	}
}

func TestOpenConnectSSOValidation(t *testing.T) {
	u, _ := url.Parse("https://vpn.example/auth")
	for _, test := range []struct {
		name   string
		change func(*ocAuth)
	}{
		{"scheme", func(a *ocAuth) { a.SSOLogin = "file:///tmp/not-a-browser" }},
		{"credentials", func(a *ocAuth) { a.SSOLogin = "https://user:pass@vpn.example/login" }},
		{"final-origin", func(a *ocAuth) { a.SSOFinal = "https://evil.example/success" }},
		{"missing-final", func(a *ocAuth) { a.SSOFinal = "" }},
		{"missing-cookie", func(a *ocAuth) { a.SSOTokenCookie = "" }},
		{"cookie-injection", func(a *ocAuth) { a.SSOTokenCookie = "a;b" }},
		{"same-cookie", func(a *ocAuth) { a.SSOErrorCookie = a.SSOTokenCookie }},
		{"browser", func(a *ocAuth) { a.SSOBrowser = "shell" }},
		{"missing-field", func(a *ocAuth) { a.Form.Inputs = nil }},
		{"duplicate-field", func(a *ocAuth) { a.Form.Inputs = append(a.Form.Inputs, ocInput{Type: "sso", Name: "token2"}) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := ocSSOAuth("")
			test.change(a)
			if _, err := ocSSOForm(u, a); err == nil {
				t.Fatal("accepted invalid browser metadata")
			}
		})
	}
	s, err := ocSSOForm(u, ocSSOAuth(""))
	if err != nil {
		t.Fatal(err)
	}
	if _, done, err := s.Complete("https://idp.example/", nil); done || err != nil {
		t.Fatal("untrusted page completed")
	}
	for _, cookies := range [][]*http.Cookie{nil, {{Name: s.ErrorCookie, Value: "secret-error"}}, {{Name: s.TokenCookie, Value: "a;b"}}, {{Name: s.TokenCookie, Value: "one"}, {Name: s.TokenCookie, Value: "two"}}} {
		_, done, err := s.Complete(s.FinalURL, cookies)
		if !done || err == nil || strings.Contains(err.Error(), "secret-error") {
			t.Fatal("invalid token accepted or error leaked", err)
		}
	}
}

func TestOpenConnectSSORequiredAndDisabled(t *testing.T) {
	u, _ := url.Parse("https://vpn.example/auth")
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "vpn", Server: "vpn.example", ServerPort: 443, TLS: TLSOptions{Enabled: true}}}})
	c := r.ocClients["vpn"]
	_, err := c.answer(context.Background(), u, ocSSOAuth(""), map[string]bool{})
	var required *OpenConnectAuthRequiredError
	if !errors.As(err, &required) || required.Form.SSO == nil {
		t.Fatal(err)
	}
	c.o.DisableExternalAuth = true
	if _, err = c.answer(context.Background(), u, ocSSOAuth(""), map[string]bool{}); err == nil {
		t.Fatal("accepted disabled SSO")
	}
	r.SetOpenConnectAuthHandler(func(context.Context, OpenConnectAuthForm) (map[string]string, error) {
		t.Fatal("disabled SSO reached handler")
		return nil, nil
	})
	if err := (OpenConnectOptions{DisableExternalAuth: true}).validate("socks", TLSOptions{}, Transport{}, 0, nil); err == nil {
		t.Fatal("SSO option allowed on another protocol")
	}
	if _, err := Parse([]byte(`{"inbounds":[{"type":"openconnect","tag":"vpn","listen":"127.0.0.1","listen_port":443,"disable_external_auth":true,"tls":{"enabled":true}}]}`)); err == nil || !strings.Contains(err.Error(), "outbound options") {
		t.Fatal("client-only option accepted on server", err)
	}
	_, disabled := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		var message ocXML
		if err := xml.NewDecoder(req.Body).Decode(&message); err != nil {
			t.Error(err)
		}
		if message.Capabilities != nil || req.Header.Get("X-AnyConnect-STRAP-Pubkey") != "" || req.Header.Get("X-AnyConnect-STRAP-DH-Pubkey") != "" {
			t.Error("disabled browser capabilities advertised")
		}
		ocAuthReply(t, w, ocXML{Type: "complete", Token: "PasswordOnlyCookie"})
	})
	disabled.o.DisableExternalAuth = true
	if err := disabled.login(context.Background()); err != nil || disabled.strap != nil {
		t.Fatal("password-only login failed", err)
	}
}

func TestOpenConnectSSOListenerBoundary(t *testing.T) {
	if isolateOpenConnectSSO(t) {
		return
	}
	s, _ := newOCStrap()
	l, err := ocListenSSO(s, "https://vpn.example/success")
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	if other, err := ocListenSSO(s, "https://vpn.example/success"); err == nil {
		other.close()
		t.Fatal("shared callback port accepted")
	}
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, test := range []struct{ method, host, path string }{{"POST", "localhost:29786", "/api/sso/bad"}, {"GET", "evil.example", "/api/sso/bad"}, {"GET", "localhost:29786", "/favicon.ico"}, {"GET", "localhost:29786", "/api/sso/bad"}} {
		req, _ := http.NewRequest(test.method, "http://127.0.0.1:29786"+test.path, nil)
		req.Host = test.host
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Fatal(res.StatusCode)
		}
	}
	select {
	case <-l.token:
		t.Fatal("invalid request completed SSO")
	default:
	}
	address := "http://127.0.0.1:29786"
	for _, listener := range l.listeners {
		if strings.HasPrefix(listener.Addr().String(), "[") {
			address = "http://[::1]:29786"
		}
	}
	ocSSOCallback(t, ocEncryptSSO(t, s.dhPublic, "IPv6Token123"), address)
	if token := <-l.token; token != "IPv6Token123" {
		t.Fatal("wrong callback token")
	}
}

func TestOpenConnectSSOEncryptedToken(t *testing.T) {
	if isolateOpenConnectSSO(t) {
		return
	}
	s, err := newOCStrap()
	if err != nil {
		t.Fatal(err)
	}
	valid := ocEncryptSSO(t, s.dhPublic, "Token123")
	if v, err := s.decrypt(valid); err != nil || v != "Token123" {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(valid)
	for i := range raw {
		b := bytes.Clone(raw)
		b[i] ^= 1
		if _, err := s.decrypt(base64.StdEncoding.EncodeToString(b)); err == nil {
			t.Fatal("accepted changed token", i)
		}
	}
	for _, v := range []string{"", "%%%", strings.Repeat("A", 16385), ocEncryptSSO(t, s.dhPublic, "secret-unsafe"), valid + "A"} {
		if _, err := s.decrypt(v); err == nil {
			t.Fatal("accepted malformed encrypted token")
		}
	}
	other, _ := newOCStrap()
	if _, err := other.decrypt(valid); err == nil {
		t.Fatal("cross-session token accepted")
	}
	s.dh = nil
	if _, err := s.decrypt(valid); err == nil {
		t.Fatal("expired session key accepted")
	}
}

func TestOpenConnectSSOListenerCancellation(t *testing.T) {
	if isolateOpenConnectSSO(t) {
		return
	}
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "vpn", Server: "vpn.example", ServerPort: 443, TLS: TLSOptions{Enabled: true}}}})
	c := r.ocClients["vpn"]
	c.strap, _ = newOCStrap()
	form := OpenConnectAuthForm{SSO: &OpenConnectSSO{Mode: "external", FinalURL: "https://vpn.example/success"}, Fields: []OpenConnectAuthField{{Name: "sso-token", Type: "sso"}}}
	for _, mode := range []string{"cancel", "handler-error", "reject-plaintext", "bad-request"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			_, err := c.externalSSO(ctx, form, func(ctx context.Context, _ OpenConnectAuthForm) (map[string]string, error) {
				switch mode {
				case "handler-error":
					return nil, io.EOF
				case "reject-plaintext":
					return map[string]string{"sso-token": "unsafe"}, nil
				case "bad-request":
					resp, err := http.Get("http://127.0.0.1:29786/api/sso/not-a-token")
					if err != nil {
						t.Fatal(err)
					}
					resp.Body.Close()
					if resp.StatusCode != 404 {
						t.Fatal(resp.StatusCode)
					}
				}
				return nil, nil
			})
			if err == nil {
				t.Fatal("accepted incomplete callback")
			}
			l, err := net.Listen("tcp4", "127.0.0.1:29786")
			if err != nil {
				t.Fatal("listener leaked", err)
			}
			l.Close()
		})
	}
}

func FuzzOpenConnectSSOToken(f *testing.F) {
	s, _ := newOCStrap()
	f.Add("bad")
	f.Add(base64.StdEncoding.EncodeToString([]byte{0, 1, 0, 1, 0, 91}))
	f.Add(ocEncryptSSO(f, s.dhPublic, "FuzzToken123"))
	f.Fuzz(func(t *testing.T, encoded string) { s.decrypt(encoded) })
}

func BenchmarkOpenConnectSSO(b *testing.B) {
	b.Run("session-keys", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := newOCStrap(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("encrypted-token", func(b *testing.B) {
		s, err := newOCStrap()
		if err != nil {
			b.Fatal(err)
		}
		encoded := ocEncryptSSO(b, s.dhPublic, "BenchmarkToken123")
		b.ReportAllocs()
		for b.Loop() {
			if _, err := s.decrypt(encoded); err != nil {
				b.Fatal(err)
			}
		}
	})
}
