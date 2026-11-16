package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestShadowTLSBrowserHello(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		t.Run(profile, func(t *testing.T) {
			h, err := newSTHello(&tls.Config{ServerName: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if err := h.initBrowser(profile); err != nil {
				t.Fatal(err)
			}
			ordinary, err := h.marshal("", nil, true)
			if err != nil {
				t.Fatal(err)
			}
			unsigned := bytes.Clone(ordinary)
			clear(unsigned[67:71])
			mac := hmac.New(sha1.New, []byte("private"))
			mac.Write(unsigned)
			want := mac.Sum(nil)[:4]
			signed, err := h.marshal("private", nil, true)
			if err != nil || !bytes.Equal(signed[67:71], want) || !bytes.Equal(signed[:67], ordinary[:67]) || !bytes.Equal(signed[71:], ordinary[71:]) {
				t.Fatal("browser ClientHello changed outside authentication suffix", err)
			}
			if !shadowHelloAuth(signed, "private") || shadowHelloAuth(signed, "wrong") {
				t.Fatal("browser ClientHello authentication failed")
			}
			for _, position := range []int{6, 39, 67, len(signed) - 1} {
				bad := bytes.Clone(signed)
				bad[position] ^= 1
				if shadowHelloAuth(bad, "private") {
					t.Fatal("tampered ClientHello authenticated")
				}
			}
			retry, err := h.marshal("private", []byte{0, 1, 9}, false)
			if err != nil || !bytes.Equal(retry[39:71], signed[39:71]) {
				t.Fatal("retry changed authenticated session ID", err)
			}
		})
	}
}

func TestShadowTLSBrowserPaths(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		for _, v := range []int{1, 2, 3} {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				if v == 1 && version != tls.VersionTLS12 {
					continue
				}
				for _, plugins := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
					t.Run(fmt.Sprintf("%s/v%d/TLS%x/plugins%t-%t", profile, v, version, plugins[0], plugins[1]), func(t *testing.T) {
						_, c := shadowPair(t, v, version, plugins[0], plugins[1], "shadowsocks", profile)
						assertTCP(t, c)
						assertTCP(t, c)
						if plugins[0] && plugins[1] {
							assertUDPSizes(t, c, []int{0, 1, 4096, 60000})
						}
					})
				}
				t.Run(fmt.Sprintf("%s/v%d/TLS%x/vless", profile, v, version), func(t *testing.T) {
					_, c := shadowPair(t, v, version, false, false, "vless", profile)
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{0, 1, 4096, 60000})
				})
			}
		}
	}
}

func TestShadowTLSBrowserOfficial(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		for _, v := range []int{1, 2, 3} {
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				if v == 1 && version != tls.VersionTLS12 {
					continue
				}
				for _, kind := range []string{"detour", "plugin", "vless"} {
					t.Run(fmt.Sprintf("%s/v%d/TLS%x/%s", profile, v, version, kind), func(t *testing.T) {
						inner := "shadowsocks"
						if kind == "vless" {
							inner = kind
						}
						c := shadowReferencePair(t, v, version, "client", kind == "plugin", inner, profile)
						assertTCP(t, c)
						assertTCP(t, c)
						if inner == "vless" {
							assertUDPSizes(t, c, []int{1, 511, 4096})
						}
					})
				}
			}
		}
	}
}

func TestShadowTLSBrowserFallback(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		for _, strict := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/strict=%t", profile, strict), func(t *testing.T) {
				h, security := shadowCover(t, tls.VersionTLS12)
				security.MaxVersion = ""
				security.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				inner := testInbound(t, "vless")
				inner.Tag = "inner"
				in := Inbound{Type: "shadowtls", Tag: "st", Version: "3", Detour: "inner", Users: []User{{Password: "private"}}, ShadowTLSOptions: ShadowTLSOptions{Handshake: &h, StrictMode: strict}}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in, inner}})
				o := testOutbound(t, in, s.Address("st"))
				o.Version, o.Password, o.TLS = "3", "private", security
				proxy := testOutbound(t, inner, s.Address("st"))
				proxy.TLS = TLSOptions{}
				o.Tag, proxy.Detour = "outer", "outer"
				c := newTestRuntime(t, Config{Outbounds: []Outbound{proxy, o}})
				if strict {
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					conn, err := c.Dial(ctx, "tcp", masqueEcho(t, "tcp", "127.0.0.1:0"))
					if err == nil {
						conn.SetDeadline(time.Now().Add(3 * time.Second))
						err = writeAll(conn, []byte("probe"))
						if err == nil {
							_, err = io.ReadFull(conn, make([]byte, 5))
						}
						conn.Close()
					}
					if err == nil {
						t.Fatal("strict ShadowTLS3 forwarded TLS1.2 traffic")
					}
					return
				}
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 4096, 60000})
			})
		}
	}
}

func TestShadowTLSBrowserMuddle(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		for _, protocol := range []string{"http/1.1", "h2"} {
			t.Run(profile+"/"+protocol, func(t *testing.T) {
				f := newMutualTLSFixture(t)
				server := f.server()
				server.ClientAuthentication, server.ClientCertificate = "no", nil
				cfg, err := server.config(true, "")
				if err != nil {
					t.Fatal(err)
				}
				cfg.MinVersion = tls.VersionTLS13
				cfg.NextProtos = []string{protocol}
				var requests atomic.Int32
				cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if (r.ProtoMajor == 2) != (protocol == "h2") {
						t.Error("muddle negotiated wrong HTTP version")
					}
					requests.Add(1)
					fmt.Fprint(w, "ordinary-cover")
				}))
				cover.TLS, cover.EnableHTTP2 = cfg, true
				cover.StartTLS()
				defer cover.Close()
				host, port, err := net.SplitHostPort(cover.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				p, err := shadowPort(port)
				if err != nil {
					t.Fatal(err)
				}
				h, security := ShadowTLSHandshake{Server: host, ServerPort: p}, f.client()
				security.ALPN = []string{protocol}
				security.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				o := Outbound{Type: "shadowtls", Tag: "outer", Server: h.Server, ServerPort: h.ServerPort, Version: "3", Password: "private", TLS: security}
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				conn, err := c.Dial(ctx, "tcp", "example.com:80")
				if conn != nil {
					conn.Close()
				}
				if err == nil {
					t.Fatal("unauthenticated plain TLS endpoint accepted")
				}
				if requests.Load() != 1 {
					t.Fatal("missing HTTP cover request", requests.Load())
				}
			})
		}
	}
}
