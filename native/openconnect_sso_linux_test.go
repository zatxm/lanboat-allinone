//go:build linux

package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenConnectSSOOfficialReference(t *testing.T) {
	if os.Getenv("LANBOAT_OC_SSO_CHILD") != "1" {
		cmd := exec.Command("unshare", "--user", "--map-auto", "--map-root-user", "--setgroups", "allow", "--net", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), "LANBOAT_OC_SSO_CHILD=1")
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated OpenConnect SSO reference: %v\n%s", err, b)
		}
		return
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureLink(lo.Index, 65536); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../.cache/openconnect-reference/root")
	if err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs("../tests/openconnect-sso-reference.py")
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	browser := filepath.Join(dir, "browser")
	// Test-controlled absolute paths, never gateway data, form the executable arguments.
	if err = os.WriteFile(browser, []byte(fmt.Sprintf("#!/bin/sh\nexec '%s' '%s' --browser \"$1\"\n", python, script)), 0700); err != nil {
		t.Fatal(err)
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(fmt.Sprintf("TLS%x", version), func(t *testing.T) {
			var public atomic.Value
			var replies atomic.Int32
			gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				origin := "https://" + req.Host
				if req.Method == "GET" {
					if req.URL.Path == "/success" {
						w.Write([]byte("authenticated"))
						return
					}
					if req.URL.Path != "/login" {
						w.WriteHeader(404)
						return
					}
					cmd := exec.Command(python, script, public.Load().(string), "SSOReferenceToken123")
					b, err := cmd.Output()
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					target := "http://[::1]:29786/api/sso/" + url.QueryEscape(strings.TrimSpace(string(b))) + "?return=" + url.QueryEscape(origin+"/success")
					http.Redirect(w, req, target, http.StatusFound)
					return
				}
				var message ocXML
				if err := xml.NewDecoder(req.Body).Decode(&message); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if message.Aggregate != "2" || message.Agent == nil || message.Agent.Who != "vpn" || message.Agent.Value == "" {
					t.Error("official client XML envelope mismatch")
					w.WriteHeader(400)
					return
				}
				if message.Type == "init" {
					public.Store(req.Header.Get("X-AnyConnect-STRAP-DH-Pubkey"))
					if public.Load().(string) == "" {
						t.Error("official client did not advertise ECIES key")
						w.WriteHeader(400)
						return
					}
					a := ocSSOAuth("external")
					a.ID = "main"
					a.SSOLogin = origin + "/login"
					a.SSOFinal = origin + "/success"
					ocAuthReply(t, w, ocXML{Client: "vpn", Type: "auth-request", Auth: a, Opaque: &ocOpaque{Data: "<auth-method>single-sign-on-external-browser</auth-method>"}})
					return
				}
				values := map[string]string{}
				if message.Auth != nil {
					for _, f := range message.Auth.Fields {
						values[f.XMLName.Local] = f.Value
					}
				}
				if values["sso-token"] != "SSOReferenceToken123" || values["state"] != "hidden" {
					t.Error("official client rejected wire fixture")
					w.WriteHeader(403)
					return
				}
				replies.Add(1)
				http.SetCookie(w, &http.Cookie{Name: "webvpn", Value: "SSOReferenceCookie123", Path: "/", Secure: true})
				ocAuthReply(t, w, ocXML{Client: "vpn", Type: "complete", Token: "SSOReferenceCookie123", Auth: &ocAuth{ID: "success"}})
			}))
			gateway.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
			gateway.StartTLS()
			defer gateway.Close()
			origin := gateway.URL
			pin := sha256.Sum256(gateway.Certificate().RawSubjectPublicKeyInfo)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, filepath.Join(root, "usr/sbin/openconnect"), "--authenticate", "--non-inter", "--external-browser", browser, "--servercert", "pin-sha256:"+base64.StdEncoding.EncodeToString(pin[:]), origin)
			cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+filepath.Join(root, "usr/lib/x86_64-linux-gnu"))
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err = cmd.Run()
			if err != nil {
				t.Fatalf("official SSO authentication: %v;stderr=%s", err, stderr.String())
			}
			if replies.Load() != 1 || !bytes.Contains(stdout.Bytes(), []byte("SSOReferenceCookie123")) {
				t.Fatal("official client did not obtain VPN cookie")
			}
		})
	}
}
