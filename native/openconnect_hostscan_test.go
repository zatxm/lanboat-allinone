package native

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenConnectHostScan(t *testing.T) {
	for _, name := range []string{"hostscan", "legacy-root", "legacy-auth"} {
		legacy := name != "hostscan"
		t.Run(name, func(t *testing.T) {
			var scanned atomic.Bool
			var waits atomic.Int32
			var prompts int
			var capability *OpenConnectHostScan
			r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
				switch req.URL.Path {
				case "/":
					form := ocXML{Type: "auth-request", HostScan: &ocHostScan{Ticket: "private-ticket", Token: "private-token", BaseURI: "/scan", WaitURI: "/wait"}}
					if legacy {
						form.HostScan, form.CSD = nil, &ocCSD{Ticket: "private-ticket", Token: "private-token"}
						p := &ocCSDPlatform{Start: "/scan", Wait: "/wait", Stub: "/stub"}
						switch runtime.GOOS {
						case "darwin":
							form.CSDMac = p
						case "windows":
							form.CSDWindows = p
						default:
							form.CSDLinux = p
						}
					}
					if name == "legacy-auth" {
						form.Auth = &ocAuth{CSD: form.CSD, CSDLinux: form.CSDLinux, CSDMac: form.CSDMac, CSDWindows: form.CSDWindows}
						form.CSD, form.CSDLinux, form.CSDMac, form.CSDWindows = nil, nil, nil, nil
					}
					ocAuthReply(t, w, form)
				case "/scan/manifest":
					cookie, err := req.Cookie("sdesktop")
					if err != nil || cookie.Value != "private-token" || req.Method != "GET" {
						t.Error("scanner did not share login cookie")
					}
					io.WriteString(w, "<manifest/>")
				case "/scan/report":
					b, _ := io.ReadAll(req.Body)
					if req.Method != "POST" || string(b) != "<hostscan><status>local-result</status></hostscan>" {
						t.Error("report not provided by trusted callback")
					}
					scanned.Store(true)
					w.WriteHeader(204)
				case "/wait":
					if !scanned.Load() || req.Method != "GET" {
						t.Error("wait page reached before scan completed")
					}
					waits.Add(1)
					io.WriteString(w, `<META CONTENT='0; URL=/ready?stage=1&amp;x=2' HTTP-EQUIV="Refresh">`)
				case "/ready":
					if req.URL.Query().Get("x") != "2" {
						t.Error("refresh entity not decoded")
					}
					w.Header().Set("Location", "/auth")
					w.WriteHeader(302)
				case "/auth":
					if req.Method == "GET" {
						ocAuthReply(t, w, ocXML{Type: "auth-request", Auth: &ocAuth{ID: "main", Form: &ocForm{Action: "/auth", Inputs: []ocInput{{Type: "text", Name: "username"}, {Type: "password", Name: "password"}}}}})
						return
					}
					var reply ocXML
					if err := xml.NewDecoder(req.Body).Decode(&reply); err != nil || reply.Auth == nil || len(reply.Auth.Fields) != 2 || reply.Auth.Fields[1].Value != "private" {
						t.Error("credentials did not follow completed scan")
					}
					ocAuthReply(t, w, ocXML{Type: "complete", Token: "checked-cookie"})
				default:
					t.Error("unexpected request", req.URL.Path)
					w.WriteHeader(404)
				}
			})
			r.SetOpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) {
				prompts++
				s := form.HostScan
				if s == nil || s.Ticket != "private-ticket" || s.Token != "private-token" {
					t.Fatal("scan challenge missing")
				}
				capability = s
				result, err := s.Request(ctx, "GET", s.BaseURL+"/manifest", "", nil)
				if err != nil || result.Status != 200 || string(result.Body) != "<manifest/>" {
					t.Fatal(result, err)
				}
				if _, err = s.Request(ctx, "POST", s.BaseURL+"/report", "text/xml", []byte("<hostscan><status>local-result</status></hostscan>")); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Request(ctx, "GET", "https://other.invalid/steal", "", nil); err == nil {
					t.Fatal("scanner credentials sent cross-origin")
				}
				if _, err := s.Request(ctx, "POST", s.BaseURL, "text/xml", make([]byte, 65537)); err == nil {
					t.Fatal("unbounded report accepted")
				}
				// Presentation data cannot rewrite the core's validated wait location.
				s.WaitURL = "https://other.invalid/steal"
				return nil, nil
			})
			if err := c.login(context.Background()); err != nil || c.cookie != "checked-cookie" || prompts != 1 || waits.Load() != 1 {
				t.Fatal("scan/login failed", err, prompts, waits.Load())
			}
			if _, err := capability.Request(context.Background(), "GET", "/scan/manifest", "", nil); !errors.Is(err, context.Canceled) {
				t.Fatal("scanner retained login capability", err)
			}
		})
	}
}

func TestOpenConnectHostScanBoundary(t *testing.T) {
	for _, mode := range []string{"no-handler", "cross-origin", "invalid-token", "cancel", "oversized-response", "cross-refresh"} {
		t.Run(mode, func(t *testing.T) {
			var called bool
			r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/large" {
					io.CopyN(w, strings.NewReader(strings.Repeat("x", 1<<20+1)), 1<<20+1)
					return
				}
				if req.URL.Path == "/wait" {
					w.Header().Set("Refresh", "0; url=https://other.invalid/")
					return
				}
				h := &ocHostScan{Ticket: "ticket", Token: "token", BaseURI: "/scan", WaitURI: "/wait"}
				if mode == "cross-origin" {
					h.BaseURI = "https://other.invalid/"
				}
				if mode == "invalid-token" {
					h.Token = "invalid;cookie"
				}
				ocAuthReply(t, w, ocXML{Type: "auth-request", HostScan: h})
			})
			if mode != "no-handler" {
				r.SetOpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) {
					called = true
					if mode == "cancel" {
						return nil, context.Canceled
					}
					if mode == "oversized-response" {
						_, err := form.HostScan.Request(ctx, "GET", "/large", "", nil)
						return nil, err
					}
					return nil, nil
				})
			}
			err := c.login(context.Background())
			if err == nil || c.cookie != "" {
				t.Fatal("invalid scanner path accepted")
			}
			if (mode == "cross-origin" || mode == "invalid-token") && called {
				t.Fatal("invalid challenge reached callback")
			}
			if mode == "no-handler" {
				var required *OpenConnectAuthRequiredError
				if !errors.As(err, &required) || required.Form.HostScan == nil {
					t.Fatal("scan not exposed to caller", err)
				}
			}
		})
	}
}

func TestOpenConnectHostScanRequestCancellation(t *testing.T) {
	entered := make(chan struct{})
	r, c := ocAuthFixture(t, func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/scan" {
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			close(entered)
			<-req.Context().Done()
			return
		}
		ocAuthReply(t, w, ocXML{Type: "auth-request", HostScan: &ocHostScan{Ticket: "ticket", Token: "token", BaseURI: "/scan", WaitURI: "/wait"}})
	})
	r.SetOpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) {
		_, err := form.HostScan.Request(ctx, "GET", form.HostScan.BaseURL, "", nil)
		return nil, err
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.login(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("scanner request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || c.cookie != "" {
			t.Fatal("scanner cancellation did not close login", err)
		}
	case <-time.After(time.Second):
		t.Fatal("scanner HTTP read survived cancellation")
	}
}

func FuzzOpenConnectHostScan(f *testing.F) {
	f.Add(`<config-auth><host-scan><host-scan-ticket>t</host-scan-ticket><host-scan-token>x</host-scan-token><host-scan-base-uri>/scan</host-scan-base-uri><host-scan-wait-uri>/wait</host-scan-wait-uri></host-scan></config-auth>`, `0; url=/wait`)
	f.Add(`<config-auth/>`, `NaN`)
	f.Fuzz(func(t *testing.T, text, refresh string) {
		if len(text)+len(refresh) > 65536 {
			return
		}
		u, _ := url.Parse("https://gateway.invalid/auth")
		var form ocXML
		if xml.Unmarshal([]byte(text), &form) == nil {
			s, err := ocHostScanForm(u, u, form)
			if err == nil && s != nil {
				for _, raw := range []string{s.BaseURL, s.WaitURL, s.StubURL} {
					if raw != "" {
						p, _ := url.Parse(raw)
						if p.Scheme != u.Scheme || p.Host != u.Host {
							t.Fatal("origin escaped")
						}
					}
				}
			}
		}
		_, delay, ok, err := ocHostScanRefresh(http.Header{"Refresh": {refresh}}, []byte(text))
		if ok && err == nil && (delay < 0 || delay > 30*time.Second) {
			t.Fatal("unbounded wait")
		}
	})
}
