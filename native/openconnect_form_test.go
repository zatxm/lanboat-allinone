package native

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ocAuthFixture(t *testing.T, handler http.HandlerFunc) (*Runtime, *ocClient) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	u, _ := url.Parse(server.URL)
	p, _ := strconv.Atoi(u.Port())
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "openconnect", Tag: "vpn", Server: u.Hostname(), ServerPort: uint16(p), Username: "alice", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}}}})
	return r, r.ocClients["vpn"]
}
func ocAuthReply(t *testing.T, w http.ResponseWriter, v ocXML) {
	t.Helper()
	b, e := ocMarshal(v)
	if e != nil {
		t.Fatal(e)
	}
	w.Header().Set("Content-Type", "text/xml")
	w.Write(b)
}

func TestOpenConnectInteractiveForms(t *testing.T) {
	var round atomic.Int32
	var connection atomic.Value
	r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		b, e := ocBody(req.Body)
		if e != nil {
			t.Error(e)
			return
		}
		var msg ocXML
		if xml.Unmarshal(b, &msg) != nil {
			t.Error("bad XML")
			return
		}
		switch round.Add(1) {
		case 1:
			connection.Store(req.RemoteAddr)
			http.SetCookie(w, &http.Cookie{Name: "challenge", Value: "bound", Path: "/auth", Secure: true})
			ocAuthReply(t, w, ocXML{Type: "auth-request", Auth: &ocAuth{ID: "main", Form: &ocForm{Action: "/auth", Method: "post", Inputs: []ocInput{{Type: "text", Name: "username"}, {Type: "password", Name: "password"}}}}})
		case 2:
			if req.RemoteAddr != connection.Load() {
				t.Error("authentication TLS connection was not reused")
			}
			v := map[string]string{}
			for _, f := range msg.Auth.Fields {
				v[f.XMLName.Local] = f.Value
			}
			if v["username"] != "alice" || v["password"] != "private" {
				t.Error("automatic credentials missing")
			}
			ocAuthReply(t, w, ocXML{Type: "auth-request", Opaque: &ocOpaque{Attrs: []xml.Attr{{Name: xml.Name{Local: "is-for"}, Value: "sg"}}, Data: "<challenge>opaque-token&lt;x</challenge>"}, Auth: &ocAuth{ID: "second", Title: "Second factor", Message: "Enter code", Form: &ocForm{Action: "?step=2", Inputs: []ocInput{{Type: "hidden", Name: "state", Value: "opaque<&"}, {Type: "password", Name: "password"}}, Selects: []ocSelect{{Name: "factor", Options: []ocOption{{Value: "totp", Text: "Authenticator"}, {Value: "push", Text: "Push"}}}}}}})
		case 3:
			if req.RemoteAddr != connection.Load() || msg.Opaque == nil || msg.Opaque.Data != "<challenge>opaque-token&lt;x</challenge>" {
				t.Error("TLS or opaque state lost")
			}
			cookie, e := req.Cookie("challenge")
			if e != nil || cookie.Value != "bound" || req.URL.Query().Get("step") != "2" {
				t.Error("auth state lost")
			}
			v := map[string]string{}
			for _, f := range msg.Auth.Fields {
				v[f.XMLName.Local] = f.Value
			}
			if v["state"] != "opaque<&" || v["password"] != "654321" || v["factor"] != "totp" {
				t.Error("challenge response mismatch")
			}
			ocAuthReply(t, w, ocXML{Type: "complete", Token: "authenticated-cookie"})
		default:
			t.Error("unexpected retry")
			w.WriteHeader(401)
		}
	})
	var prompts int
	r.SetOpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) {
		prompts++
		if form.ID != "second" || form.Title != "Second factor" || form.Message != "Enter code" || len(form.Fields) != 2 {
			t.Fatal(form)
		}
		b, _ := json.Marshal(form)
		if strings.Contains(string(b), "private") || strings.Contains(string(b), "opaque") {
			t.Fatal("secrets exposed in prompt", string(b))
		}
		return map[string]string{"password": "654321", "factor": "totp"}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if e := c.login(ctx); e != nil {
		t.Fatal(e)
	}
	if c.cookie != "authenticated-cookie" || prompts != 1 || round.Load() != 3 {
		t.Fatal(c.cookie, prompts, round.Load())
	}
}

func TestOpenConnectAuthAnswers(t *testing.T) {
	r := newTestRuntime(t, Config{})
	c := &ocClient{r: r, o: Outbound{Tag: "vpn", Username: "alice", Password: "private"}}
	u, _ := url.Parse("https://vpn.test/auth")
	auth := &ocAuth{ID: "otp", Form: &ocForm{Inputs: []ocInput{{Name: "token", Type: "password"}, {Name: "opaque", Type: "hidden", Value: "csrf"}}}}
	_, err := c.answer(context.Background(), u, auth, map[string]bool{})
	var required *OpenConnectAuthRequiredError
	if !errors.As(err, &required) || len(required.Form.Fields) != 1 || strings.Contains(err.Error(), "csrf") {
		t.Fatal(err, required)
	}
	for _, answers := range []map[string]string{{"opaque": "changed", "token": "123"}, {"unknown": "x", "token": "123"}, {"token": ""}, {"token": strings.Repeat("x", 8193)}} {
		ctx := WithOpenConnectAuth(context.Background(), func(context.Context, OpenConnectAuthForm) (map[string]string, error) { return answers, nil })
		if _, err := c.answer(ctx, u, auth, map[string]bool{}); err == nil {
			t.Fatal("invalid answer accepted")
		}
	}
	c.o.AuthForm = map[string]map[string]string{"otp": {"token": "123456", "unrequested": "never-send"}}
	msg, e := c.answer(context.Background(), u, auth, map[string]bool{})
	if e != nil || len(msg.Auth.Fields) != 2 || msg.Auth.Fields[0].Value != "123456" {
		t.Fatal(msg, e)
	}
	for _, f := range msg.Auth.Fields {
		if f.XMLName.Local == "unrequested" {
			t.Fatal("unrequested credential sent")
		}
	}
	c.o.AuthForm = nil
	r.SetOpenConnectAuthHandler(func(context.Context, OpenConnectAuthForm) (map[string]string, error) {
		return nil, errors.New("wrong handler")
	})
	ctx := WithOpenConnectAuth(context.Background(), func(context.Context, OpenConnectAuthForm) (map[string]string, error) {
		return map[string]string{"token": "explicit"}, nil
	})
	if msg, e := c.answer(ctx, u, auth, map[string]bool{}); e != nil || msg.Auth.Fields[0].Value != "explicit" {
		t.Fatal(msg, e)
	}
	r.SetOpenConnectAuthHandler(nil)
	_, err = c.answer(context.Background(), u, &ocAuth{Form: &ocForm{Inputs: []ocInput{{Name: "password", Type: "text"}}}}, map[string]bool{})
	if !errors.As(err, &required) {
		t.Fatal("password filled into cleartext control", err)
	}
}

func TestOpenConnectAuthCancellation(t *testing.T) {
	r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		ocAuthReply(t, w, ocXML{Type: "auth-request", Auth: &ocAuth{ID: "otp", Form: &ocForm{Inputs: []ocInput{{Type: "password", Name: "token"}}}}})
	})
	entered := make(chan struct{})
	r.SetOpenConnectAuthHandler(func(ctx context.Context, _ OpenConnectAuthForm) (map[string]string, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.login(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("callback not reached")
	}
	cancel()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if c.cookie != "" {
		t.Fatal("cancelled login retained cookie")
	}
}

func TestOpenConnectAuthNetworkReset(t *testing.T) {
	r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		ocAuthReply(t, w, ocXML{Type: "auth-request", Auth: &ocAuth{Form: &ocForm{Inputs: []ocInput{{Type: "password", Name: "token"}}}}})
	})
	entered := make(chan struct{})
	r.SetOpenConnectAuthHandler(func(ctx context.Context, _ OpenConnectAuthForm) (map[string]string, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	done := make(chan error, 1)
	go func() { done <- r.AuthenticateOpenConnect(context.Background(), "vpn") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("callback not reached")
	}
	reset := make(chan struct{})
	go func() { c.reset(); close(reset) }()
	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("network reset blocked on authentication")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestOpenConnectAuthTimeout(t *testing.T) {
	r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		ocAuthReply(t, w, ocXML{Type: "auth-request", Auth: &ocAuth{Form: &ocForm{Inputs: []ocInput{{Type: "password", Name: "token"}}}}})
	})
	c.o.AuthTimeout = "1s"
	r.SetOpenConnectAuthHandler(func(ctx context.Context, _ OpenConnectAuthForm) (map[string]string, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	start := time.Now()
	if err := r.AuthenticateOpenConnect(context.Background(), "vpn"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("auth_timeout not applied")
	}
}

func TestOpenConnectAuthRepeatedPassword(t *testing.T) {
	r := newTestRuntime(t, Config{})
	c := &ocClient{r: r, o: Outbound{Password: "primary"}}
	u, _ := url.Parse("https://vpn.test/")
	sent := map[string]bool{}
	for i, id := range []string{"main", "second"} {
		a := &ocAuth{ID: id, Form: &ocForm{Inputs: []ocInput{{Type: "password", Name: "password"}}}}
		_, err := c.answer(context.Background(), u, a, sent)
		if i == 0 && err != nil || i == 1 && err == nil {
			t.Fatal(i, err)
		}
	}
}

func TestOpenConnectAuthValidation(t *testing.T) {
	var parsed ocXML
	if e := xml.Unmarshal([]byte(`<config-auth><auth><form><input name="username"/><select name="group_list"><option selected="true">staff</option><option value="">none</option></select></form></auth></config-auth>`), &parsed); e != nil {
		t.Fatal(e)
	}
	core := newTestRuntime(t, Config{})
	client := &ocClient{r: core, o: Outbound{Username: "alice"}}
	target, _ := url.Parse("https://vpn.test/")
	if msg, e := client.answer(context.Background(), target, parsed.Auth, map[string]bool{}); e != nil || msg.Group != "staff" {
		t.Fatal("XML default control or option text value", msg, e)
	}
	base := `{"outbounds":[{"type":"openconnect","tag":"vpn","server":"vpn.test","server_port":443,"tls":{"enabled":true},"auth_timeout":"2m","auth_form":{"main":{"username":"u","password":"p"}}}]}`
	if _, err := Parse([]byte(base)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(base, `"2m"`, `"0s"`, 1), strings.Replace(base, `"2m"`, `"31m"`, 1), strings.Replace(base, `"username":"u"`, `"bad:name":"u"`, 1), strings.Replace(base, `"type":"openconnect"`, `"type":"socks"`, 1)} {
		if _, e := Parse([]byte(bad)); e == nil {
			t.Fatal("invalid auth config accepted")
		}
	}
	u, _ := url.Parse("https://vpn.test:443/")
	if _, e := ocSameOrigin(u, u, "https://VPN.TEST/auth"); e != nil {
		t.Fatal(e)
	}
	r := newTestRuntime(t, Config{})
	c := &ocClient{r: r}
	for _, f := range []ocForm{{Inputs: []ocInput{{Type: "text", Name: "x"}, {Type: "hidden", Name: "x"}}}, {Inputs: []ocInput{{Type: "hidden", Name: "bad:name"}}}, {Selects: []ocSelect{{Name: "x"}}}, {Inputs: []ocInput{{Type: "file", Name: "x"}}}, {Inputs: make([]ocInput, 129)}} {
		if _, e := c.answer(context.Background(), u, &ocAuth{Form: &f}, map[string]bool{}); e == nil {
			t.Fatal("invalid form accepted")
		}
	}
}

func TestOpenConnectAuthRedirectSafety(t *testing.T) {
	for _, kind := range []string{"redirect", "form", "premature-cookie"} {
		t.Run(kind, func(t *testing.T) {
			var leaked atomic.Bool
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Store(true) }))
			defer other.Close()
			_, c := ocAuthFixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "redirect":
					w.Header().Set("Location", other.URL)
					w.WriteHeader(307)
				case "form":
					ocAuthReply(t, w, ocXML{Type: "auth-request", Auth: &ocAuth{Form: &ocForm{Action: other.URL, Inputs: []ocInput{{Type: "password", Name: "password"}}}}})
				default:
					http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: "not-authenticated", Path: "/", Secure: true})
					io.WriteString(w, `<config-auth type="auth-request"/>`)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := c.login(ctx); err == nil || leaked.Load() || c.cookie != "" {
				t.Fatal("unsafe authentication", err, leaked.Load(), c.cookie)
			}
		})
	}
}

func TestOpenConnectAuthFullTunnel(t *testing.T) {
	s, c := ocPair(t)
	out := c.config.Outbounds[0]
	out.Username = ""
	out.Password = ""
	r := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	r.SetOpenConnectAuthHandler(func(_ context.Context, f OpenConnectAuthForm) (map[string]string, error) {
		return map[string]string{"username": "client", "password": s.config.Inbounds[0].Users[0].Password}, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.AuthenticateOpenConnect(ctx, out.Tag); err != nil {
		t.Fatal(err)
	}
	assertTCP(t, r)
}

func FuzzOpenConnectAuthForm(f *testing.F) {
	f.Add(`<config-auth type="auth-request"><auth id="main"><form><input type="password" name="password"/></form></auth></config-auth>`)
	f.Fuzz(func(t *testing.T, text string) {
		if len(text) > 65536 {
			return
		}
		var v ocXML
		if xml.Unmarshal([]byte(text), &v) != nil || v.Auth == nil || v.Auth.Form == nil {
			return
		}
		r := &Runtime{}
		c := &ocClient{r: r, o: Outbound{Username: "u", Password: "p"}}
		u, _ := url.Parse("https://vpn.test/auth")
		_, _ = c.answer(context.Background(), u, v.Auth, map[string]bool{})
	})
}
