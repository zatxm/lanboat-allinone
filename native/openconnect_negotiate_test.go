package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type ocTestNegotiate struct {
	next  func(context.Context, []byte) ([]byte, bool, error)
	close atomic.Int32
}

func (s *ocTestNegotiate) Next(ctx context.Context, b []byte) ([]byte, bool, error) {
	return s.next(ctx, b)
}
func (s *ocTestNegotiate) Close() error { s.close.Add(1); return nil }

func TestOpenConnectNegotiate(t *testing.T) {
	for _, mode := range []string{"mutual", "client-complete", "missing-final", "bad-final", "bad-base64", "loop", "fallback", "deny-downgrade"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			var provider atomic.Int32
			r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
				n := requests.Add(1)
				if req.Header.Get("X-Support-HTTP-Auth") == "" {
					if mode != "fallback" {
						t.Error("authentication unexpectedly downgraded")
					}
					ocAuthReply(t, w, ocXML{Type: "complete", Token: "fallback-cookie"})
					return
				}
				if n == 1 || mode == "loop" {
					value := "Negotiate"
					if mode == "bad-base64" {
						value += " invalid!"
					}
					w.Header().Set("WWW-Authenticate", "Basic realm=\"vpn\", "+value)
					w.WriteHeader(401)
					return
				}
				if req.Header.Get("Authorization") != "Negotiate "+base64.StdEncoding.EncodeToString([]byte("client-token")) {
					t.Error("client token lost")
				}
				if mode == "fallback" || mode == "deny-downgrade" {
					if mode == "fallback" {
						w.Header().Set("X-Support-HTTP-Auth", "fallback")
					}
					w.WriteHeader(401)
					return
				}
				if mode != "missing-final" && mode != "client-complete" {
					token := "server-token"
					if mode == "bad-final" {
						token = "forged-token"
					}
					w.Header().Set("WWW-Authenticate", "nEgOtIaTe "+base64.StdEncoding.EncodeToString([]byte(token)))
				}
				ocAuthReply(t, w, ocXML{Type: "complete", Token: "negotiate-cookie"})
			})
			steps := 0
			session := &ocTestNegotiate{next: func(_ context.Context, b []byte) ([]byte, bool, error) {
				steps++
				if len(b) == 0 {
					return []byte("client-token"), mode == "client-complete", nil
				}
				if string(b) != "server-token" {
					return nil, false, errors.New("mutual authentication rejected")
				}
				return nil, true, nil
			}}
			r.SetOpenConnectNegotiateHandler(func(_ context.Context, info OpenConnectNegotiateRequest) (OpenConnectNegotiateSession, error) {
				provider.Add(1)
				if info.Endpoint != "vpn" || info.Service != "HTTP/127.0.0.1" || len(info.ChannelBinding) != 32 || !strings.HasPrefix(info.URL, "https://127.0.0.1:") {
					t.Error("GSS target or TLS binding missing")
				}
				return session, nil
			})
			err := c.login(context.Background())
			success := mode == "mutual" || mode == "client-complete" || mode == "fallback"
			if (err == nil) != success {
				t.Fatal(mode, err)
			}
			if !success && c.cookie != "" {
				t.Fatal("unverified context accepted cookie")
			}
			if requests.Load() > 17 {
				t.Fatal("unbounded Negotiate retries")
			}
			if mode == "bad-base64" {
				if provider.Load() != 0 {
					t.Fatal("invalid token reached provider")
				}
			} else if provider.Load() != 1 || session.close.Load() != 1 {
				t.Fatal("GSS context not closed exactly once")
			}
			if mode == "mutual" && steps != 2 {
				t.Fatal("mutual authentication not completed")
			}
		})
	}
}

func TestOpenConnectNegotiateCancellation(t *testing.T) {
	r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(401)
	})
	entered := make(chan struct{})
	session := &ocTestNegotiate{next: func(ctx context.Context, _ []byte) ([]byte, bool, error) {
		close(entered)
		<-ctx.Done()
		return nil, false, ctx.Err()
	}}
	r.SetOpenConnectNegotiateHandler(func(context.Context, OpenConnectNegotiateRequest) (OpenConnectNegotiateSession, error) {
		return session, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.AuthenticateOpenConnect(ctx, "vpn") }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("provider not reached")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) || session.close.Load() != 1 || c.cookie != "" {
		t.Fatal("cancelled context retained", err)
	}
}

func TestOpenConnectNegotiateContextIsolation(t *testing.T) {
	r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", "Negotiate")
			w.WriteHeader(401)
			return
		}
		ocAuthReply(t, w, ocXML{Type: "complete", Token: "bound-cookie"})
	})
	r.SetOpenConnectNegotiateHandler(func(context.Context, OpenConnectNegotiateRequest) (OpenConnectNegotiateSession, error) {
		t.Error("default provider used despite context override")
		return nil, errors.New("wrong provider")
	})
	s := &ocTestNegotiate{next: func(context.Context, []byte) ([]byte, bool, error) { return []byte("bound-token"), true, nil }}
	ctx := WithOpenConnectNegotiate(context.Background(), func(context.Context, OpenConnectNegotiateRequest) (OpenConnectNegotiateSession, error) { return s, nil })
	if err := c.login(ctx); err != nil || s.close.Load() != 1 {
		t.Fatal(err)
	}
	c.cookie = ""
	if err := c.login(WithOpenConnectNegotiate(context.Background(), nil)); err == nil {
		t.Fatal("explicitly disabled provider still active")
	}
}

func TestOpenConnectNegotiateBindingChange(t *testing.T) {
	_, c := ocAuthFixture(t, func(http.ResponseWriter, *http.Request) {})
	session := &ocTestNegotiate{next: func(context.Context, []byte) ([]byte, bool, error) { return []byte("client-token"), true, nil }}
	n := &ocNegotiate{handler: func(context.Context, OpenConnectNegotiateRequest) (OpenConnectNegotiateSession, error) {
		return session, nil
	}}
	defer n.close()
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("first-certificate")}}}
	h := http.Header{"Www-Authenticate": {"Negotiate"}}
	if err := n.challenge(context.Background(), c, "https://gateway.invalid/", h, state); err != nil {
		t.Fatal(err)
	}
	state.PeerCertificates[0] = &x509.Certificate{Raw: []byte("other-certificate")}
	if err := n.challenge(context.Background(), c, "https://gateway.invalid/", h, state); err == nil {
		t.Fatal("continued GSS context over a different TLS binding")
	}
	if err := n.finish(context.Background(), http.Header{}, state); err == nil {
		t.Fatal("accepted cookie over a different TLS binding")
	}
}

func FuzzOpenConnectNegotiateToken(f *testing.F) {
	for _, value := range []string{"Negotiate", "Negotiate AA==", "Basic realm=\"vpn\", Negotiate YWJj", "Negotiate !!!!", "Negotiate AA==, Negotiate AA=="} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 65536 {
			return
		}
		b, found, err := ocNegotiateToken(http.Header{"Www-Authenticate": {value}})
		if err == nil && found {
			if len(b) > 32768 {
				t.Fatal("oversized token")
			}
			encoded := "Negotiate"
			if len(b) != 0 {
				encoded += " " + base64.StdEncoding.EncodeToString(b)
			}
			got, ok, err := ocNegotiateToken(http.Header{"Www-Authenticate": {encoded}})
			if err != nil || !ok || !bytes.Equal(got, b) {
				t.Fatal("token changed")
			}
		}
	})
}
