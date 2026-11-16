package native

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// OpenConnectSSO describes browser work for the caller; it contains no VPN credentials.
// In external mode the core receives the encrypted token on localhost:29786.
type OpenConnectSSO struct {
	Mode        string `json:"mode"`
	LoginURL    string `json:"login_url"`
	FinalURL    string `json:"final_url"`
	TokenCookie string `json:"token_cookie,omitempty"`
	ErrorCookie string `json:"error_cookie,omitempty"`
}

// Complete extracts a WebView token only at the gateway's final page.
// The caller must obtain cookies from that page's browser cookie store.
func (s *OpenConnectSSO) Complete(page string, cookies []*http.Cookie) (string, bool, error) {
	if s.Mode != "webview" || page != s.FinalURL {
		return "", false, nil
	}
	var token string
	for _, c := range cookies {
		if c == nil || c.Value == "" {
			continue
		}
		if s.ErrorCookie != "" && c.Name == s.ErrorCookie {
			return "", true, errors.New("OpenConnect browser authentication failed")
		}
		if c.Name == s.TokenCookie {
			if token != "" || !ocValidCookie(c.Value) {
				return "", true, errors.New("invalid OpenConnect browser token")
			}
			token = c.Value
		}
	}
	if token == "" {
		return "", true, errors.New("OpenConnect browser returned no authentication token")
	}
	return token, true, nil
}

func ocSSOForm(origin *url.URL, auth *ocAuth) (*OpenConnectSSO, error) {
	n := 0
	for _, f := range auth.Form.Inputs {
		if f.Type == "sso" {
			n++
		}
	}
	if n == 0 && auth.SSOLogin == "" && auth.SSOFinal == "" && auth.SSOBrowser == "" && auth.SSOTokenCookie == "" && auth.SSOErrorCookie == "" {
		return nil, nil
	}
	if n != 1 {
		return nil, errors.New("OpenConnect SSO requires one token field")
	}
	login, err := url.Parse(auth.SSOLogin)
	if err != nil || len(auth.SSOLogin) > 8192 || login.Scheme != "https" || login.Hostname() == "" || login.User != nil || login.Fragment != "" || strings.ContainsAny(auth.SSOLogin, "\x00\r\n") {
		return nil, errors.New("invalid OpenConnect browser login URL")
	}
	final, err := ocSameOrigin(origin, origin, auth.SSOFinal)
	if err != nil || auth.SSOFinal == "" || len(auth.SSOFinal) > 8192 {
		return nil, errors.New("invalid OpenConnect browser final URL")
	}
	s := &OpenConnectSSO{Mode: "webview", LoginURL: login.String(), FinalURL: final.String(), TokenCookie: auth.SSOTokenCookie, ErrorCookie: auth.SSOErrorCookie}
	switch auth.SSOBrowser {
	case "external":
		s.Mode = "external"
	case "", "embedded", "internal":
	default:
		return nil, errors.New("unsupported OpenConnect browser mode")
	}
	for _, name := range []string{s.TokenCookie, s.ErrorCookie} {
		if name != "" && (len(name) > 256 || (&http.Cookie{Name: name, Value: "valid"}).Valid() != nil) {
			return nil, errors.New("invalid OpenConnect SSO cookie name")
		}
	}
	if s.Mode == "webview" && s.TokenCookie == "" || s.TokenCookie != "" && s.TokenCookie == s.ErrorCookie {
		return nil, errors.New("invalid OpenConnect SSO cookie names")
	}
	return s, nil
}

type ocStrap struct {
	sign             *ecdsa.PrivateKey
	dh               *ecdh.PrivateKey
	public, dhPublic string
}

func newOCStrap() (*ocStrap, error) {
	sign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dh, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub, err := x509.MarshalPKIXPublicKey(&sign.PublicKey)
	if err != nil {
		return nil, err
	}
	dhPub, err := x509.MarshalPKIXPublicKey(dh.PublicKey())
	if err != nil {
		return nil, err
	}
	return &ocStrap{sign: sign, dh: dh, public: base64.StdEncoding.EncodeToString(pub), dhPublic: base64.StdEncoding.EncodeToString(dhPub)}, nil
}

func (s *ocStrap) headers(h http.Header) {
	// Gateways use these header names case-sensitively.
	h["X-AnyConnect-STRAP-Pubkey"] = []string{s.public}
	h["X-AnyConnect-STRAP-DH-Pubkey"] = []string{s.dhPublic}
}

func (s *ocStrap) verify(raw net.Conn, h http.Header) error {
	c, ok := raw.(interface{ ConnectionState() tls.ConnectionState })
	if !ok {
		return errors.New("OpenConnect STRAP requires TLS channel binding")
	}
	state := c.ConnectionState()
	binding := state.TLSUnique
	if state.Version >= tls.VersionTLS13 {
		var err error
		binding, err = tlsExport(raw, "EXPORTER-Channel-Binding", nil, 32)
		if err != nil {
			return err
		}
	}
	if len(binding) == 0 {
		return errors.New("OpenConnect STRAP channel binding is unavailable")
	}
	pub, _ := base64.StdEncoding.DecodeString(s.public)
	digest := sha256.Sum256(append(append([]byte(nil), binding...), pub...))
	sig, err := ecdsa.SignASN1(rand.Reader, s.sign, digest[:])
	if err != nil {
		return err
	}
	h["X-AnyConnect-STRAP-Pubkey"] = []string{s.public}
	h["X-AnyConnect-STRAP-Verify"] = []string{base64.StdEncoding.EncodeToString(sig)}
	return nil
}

func (s *ocStrap) decrypt(encoded string) (string, error) {
	bad := errors.New("invalid OpenConnect encrypted SSO token")
	if s == nil || s.dh == nil || len(encoded) > 16384 {
		return "", bad
	}
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(b) < 2 || binary.BigEndian.Uint16(b) != 1 {
		return "", bad
	}
	parts := [5][]byte{}
	for b = b[2:]; len(b) != 0; {
		if len(b) < 4 {
			return "", bad
		}
		tag, n := int(binary.BigEndian.Uint16(b)), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if tag < 1 || tag > 4 || n == 0 || n > len(b) || parts[tag] != nil {
			return "", bad
		}
		parts[tag], b = b[:n], b[n:]
	}
	if len(parts[1]) != 91 || len(parts[2]) != 12 || len(parts[3]) == 0 || len(parts[3]) > 8192 || len(parts[4]) != 12 {
		return "", bad
	}
	pub, err := x509.ParsePKIXPublicKey(parts[1])
	if err != nil {
		return "", bad
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return "", bad
	}
	peer, err := key.ECDH()
	if err != nil {
		return "", bad
	}
	secret, err := s.dh.ECDH(peer)
	if err != nil {
		return "", bad
	}
	defer clear(secret)
	aesKey, err := hkdf.Key(sha256.New, secret, nil, "AC_ECIES", 32)
	if err != nil {
		return "", bad
	}
	defer clear(aesKey)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCMWithTagSize(block, 12)
	token, err := gcm.Open(nil, parts[4], append(append([]byte(nil), parts[3]...), parts[2]...), nil)
	if err != nil {
		return "", bad
	}
	defer clear(token)
	for _, b := range token {
		if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z') {
			return "", bad
		}
	}
	return string(token), nil
}

func (c *ocClient) externalSSO(ctx context.Context, form OpenConnectAuthForm, handler OpenConnectAuthHandler) (map[string]string, error) {
	if c.strap == nil {
		return nil, errors.New("OpenConnect external SSO has no session key")
	}
	loop, err := ocListenSSO(c.strap, form.SSO.FinalURL)
	if err != nil {
		return nil, err
	}
	defer loop.close()
	stop := context.AfterFunc(ctx, loop.close)
	defer stop()
	answers, err := handler(ctx, form)
	if err != nil {
		return nil, err
	}
	for _, f := range form.Fields {
		if f.Type == "sso" && answers[f.Name] != "" {
			return nil, errors.New("external OpenConnect SSO token must arrive through the encrypted callback")
		}
	}
	select {
	case token := <-loop.token:
		if answers == nil {
			answers = map[string]string{}
		}
		for _, f := range form.Fields {
			if f.Type == "sso" {
				answers[f.Name] = token
			}
		}
		return answers, nil
	case err := <-loop.err:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type ocSSOListener struct {
	server      *http.Server
	listeners   []net.Listener
	token       chan string
	err         chan error
	once        sync.Once
	workers     sync.WaitGroup
	connections sync.WaitGroup
	active      atomic.Int32
}

func ocListenSSO(strap *ocStrap, final string) (*ocSSOListener, error) {
	l := &ocSSOListener{token: make(chan string, 1), err: make(chan error, 2)}
	l.server = &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 16384}
	l.server.SetKeepAlivesEnabled(false)
	l.server.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			l.connections.Add(1)
			if l.active.Add(1) > 8 {
				conn.Close()
			}
		}
		if state == http.StateClosed {
			l.active.Add(-1)
			l.connections.Done()
		}
	}
	l.server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		if req.Method != "GET" || req.Host != "localhost:29786" && req.Host != "127.0.0.1:29786" && req.Host != "[::1]:29786" || !strings.HasPrefix(req.URL.Path, "/api/sso/") || req.URL.IsAbs() || req.ContentLength > 0 || len(req.TransferEncoding) != 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		token, err := strap.decrypt(strings.TrimPrefix(req.URL.Path, "/api/sso/"))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Never redirect to a URL supplied by the callback request.
		w.Header().Set("Location", final)
		w.WriteHeader(http.StatusFound)
		select {
		case l.token <- token:
		default:
		}
	})
	for _, address := range []string{"127.0.0.1:29786", "[::1]:29786"} {
		network := "tcp4"
		if strings.HasPrefix(address, "[") {
			network = "tcp6"
		}
		listener, err := net.Listen(network, address)
		if err != nil {
			if network == "tcp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EPROTONOSUPPORT)) {
				continue
			}
			l.close()
			return nil, errors.New("OpenConnect SSO cannot bind loopback port29786")
		}
		l.listeners = append(l.listeners, listener)
	}
	for _, listener := range l.listeners {
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			if err := l.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				l.err <- errors.New("OpenConnect SSO callback listener failed")
			}
		}()
	}
	return l, nil
}

func (l *ocSSOListener) close() {
	l.once.Do(func() {
		l.server.Close()
		for _, listener := range l.listeners {
			listener.Close()
		}
		l.workers.Wait()
		l.connections.Wait()
	})
}
