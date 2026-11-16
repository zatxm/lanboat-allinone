package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func shadowCover(t *testing.T, version uint16) (ShadowTLSHandshake, TLSOptions) {
	t.Helper()
	fixture := newMutualTLSFixture(t)
	serverOptions := fixture.server()
	serverOptions.ClientAuthentication = "no"
	serverOptions.ClientCertificate = nil
	serverTLS, e := serverOptions.config(true, "")
	if e != nil {
		t.Fatal(e)
	}
	serverTLS.MinVersion, serverTLS.MaxVersion = version, version
	serverTLS.SessionTicketsDisabled = true
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "cover-http-reached") }))
	s.TLS = serverTLS
	s.StartTLS()
	t.Cleanup(s.Close)
	host, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	p, _ := shadowPort(port)
	options := TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{fixture.ca}, MinVersion: "1.2", MaxVersion: "1.3"}
	if version == tls.VersionTLS12 {
		options.MaxVersion = "1.2"
	}
	return ShadowTLSHandshake{Server: host, ServerPort: p}, options
}
func shadowPair(t *testing.T, version int, tlsVersion uint16, clientPlugin, serverPlugin bool, kind string, profiles ...string) (*Runtime, *Runtime) {
	t.Helper()
	h, security := shadowCover(t, tlsVersion)
	if len(profiles) != 0 {
		security.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profiles[0]}
	}
	inner := testInbound(t, kind)
	inner.TLS = TLSOptions{}
	inner.Tag = "inner"
	st := Inbound{Type: "shadowtls", Tag: "shadow", Version: strconv.Itoa(version), Detour: "inner", ShadowTLSOptions: ShadowTLSOptions{Handshake: &h, StrictMode: version == 3 && tlsVersion == tls.VersionTLS13}}
	if version == 2 {
		st.Password = "outer-secret"
	}
	if version == 3 {
		st.Users = []User{{Name: "user", Password: "outer-secret"}}
	}
	var s *Runtime
	password := ""
	if version > 1 {
		password = ";password=outer-secret"
	}
	if serverPlugin {
		inner.Plugin = "shadow-tls"
		inner.PluginOpts = fmt.Sprintf("version=%d%s;handshake=%s", version, password, portAddress(h.Server, h.ServerPort))
		s = newTestRuntime(t, Config{Inbounds: []Inbound{inner}})
	} else {
		s = newTestRuntime(t, Config{Inbounds: []Inbound{st, inner}})
	}
	address := s.Address("shadow")
	if serverPlugin {
		address = s.Address("inner")
	}
	o := testOutbound(t, inner, address)
	o.TLS = security
	if clientPlugin {
		o.Plugin = "shadow-tls"
		o.PluginOpts = fmt.Sprintf("version=%d%s;host=example.com", version, password)
		return s, newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	}
	stOut := Outbound{Type: "shadowtls", Tag: "outer", Server: o.Server, ServerPort: o.ServerPort, Version: strconv.Itoa(version), TLS: security}
	if version > 1 {
		stOut.Password = "outer-secret"
	}
	o.TLS = TLSOptions{}
	o.Detour = "outer"
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{o, stOut}})
}
func TestShadowTLSIndependent(t *testing.T) {
	for _, v := range []int{1, 2, 3} {
		for _, tlsVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			if v == 1 && tlsVersion == tls.VersionTLS13 {
				continue
			}
			for _, clientPlugin := range []bool{false, true} {
				for _, serverPlugin := range []bool{false, true} {
					t.Run(fmt.Sprintf("v%d/tls%d/clientPlugin%v/serverPlugin%v", v, tlsVersion, clientPlugin, serverPlugin), func(t *testing.T) {
						_, c := shadowPair(t, v, tlsVersion, clientPlugin, serverPlugin, "shadowsocks")
						assertTCP(t, c)
						assertTCP(t, c)
						if clientPlugin && serverPlugin {
							assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
						}
					})
				}
			}
		}
	}
}
func TestShadowTLSInnerProtocols(t *testing.T) {
	for _, v := range []int{1, 2, 3} {
		for _, kind := range []string{"vless", "vmess", "relay"} {
			t.Run(fmt.Sprintf("v%d/%s", v, kind), func(t *testing.T) {
				tlsVersion := uint16(tls.VersionTLS13)
				if v == 1 {
					tlsVersion = tls.VersionTLS12
				}
				_, c := shadowPair(t, v, tlsVersion, false, false, kind)
				assertTCP(t, c)
				sizes := []int{0, 1, 511, 4096, 16000, 60000}
				if kind == "vmess" {
					sizes = sizes[1 : len(sizes)-1]
				}
				assertUDPSizes(t, c, sizes)
			})
		}
	}
}
func TestShadowTLSSignedHello(t *testing.T) {
	for _, curve := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		t.Run(fmt.Sprint(curve), func(t *testing.T) {
			for range 10 {
				h, e := newSTHello(&tls.Config{ServerName: "example.com", CurvePreferences: []tls.CurveID{curve}})
				if e != nil {
					t.Fatal(e)
				}
				hello, e := h.marshal("private", nil, true)
				if e != nil {
					t.Fatal(e)
				}
				if !shadowHelloAuth(hello, "private") || shadowHelloAuth(hello, "bad") {
					t.Fatal("invalid ClientHello signature")
				}
			}
		})
	}
}
func TestShadowTLSConfig(t *testing.T) {
	valid := `{"inbounds":[{"type":"shadowtls","tag":"st","version":3,"detour":"inner","users":[{"name":"a","password":"private"}],"handshake":{"server":"example.com","server_port":443}},{"type":"shadowsocks","tag":"inner","listen_port":0,"method":"aes-128-gcm","password":"inner-secret"}]}`
	c, e := Parse([]byte(valid))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(c)
	if _, e = Parse(b); e != nil {
		t.Fatal("reload", e)
	}
	for _, bad := range []string{strings.Replace(valid, `"version":3`, `"version":4`, 1), strings.Replace(valid, `"detour":"inner"`, `"detour":"missing"`, 1), strings.Replace(valid, `"detour":"inner"`, `"detour":"st"`, 1), strings.Replace(valid, `"server_port":443`, `"server_port":0`, 1), strings.Replace(valid, `"users":[{"name":"a","password":"private"}]`, `"users":[]`, 1)} {
		if _, e = Parse([]byte(bad)); e == nil {
			t.Fatal("accepted invalid ShadowTLS", bad)
		}
	}
}
func TestShadowTLSDataIntegrity(t *testing.T) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			a, b := net.Pipe()
			t.Cleanup(func() { a.Close(); b.Close() })
			seed := []byte("public-server-challenge")
			writer := &shadowStream{Conn: a, version: v, writeMAC: shadowMAC("private", seed)}
			reader := &shadowStream{Conn: b, version: v, readMAC: shadowMAC("private", seed)}
			payload := bytes.Repeat([]byte("independent"), 8000)
			done := make(chan error, 1)
			go func() {
				_, e := writer.Write(payload)
				if e == nil {
					e = writer.CloseWrite()
				}
				done <- e
			}()
			got, e := io.ReadAll(reader)
			if e != nil || !bytes.Equal(got, payload) {
				t.Fatal(len(got), e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestShadowTLSWrongPasswordAndFallback(t *testing.T) {
	testShadowTLSWrongPassword(t, "")
}

func TestShadowTLSBrowserWrongPassword(t *testing.T) {
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		t.Run(profile, func(t *testing.T) { testShadowTLSWrongPassword(t, profile) })
	}
}

func testShadowTLSWrongPassword(t *testing.T, profile string) {
	for _, v := range []int{2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			h, security := shadowCover(t, tls.VersionTLS13)
			if profile != "" {
				security.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
			}
			in := Inbound{Type: "shadowtls", Tag: "st", Version: strconv.Itoa(v), Password: "private", Detour: "inner", ShadowTLSOptions: ShadowTLSOptions{Handshake: &h}}
			if v == 3 {
				in.Password = ""
				in.Users = []User{{Password: "private"}}
			}
			inner := testInbound(t, "shadowsocks")
			inner.Tag = "inner"
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in, inner}})
			host, port, _ := net.SplitHostPort(s.Address("st"))
			p, _ := shadowPort(port)
			out := Outbound{Type: "shadowtls", Tag: "outer", Server: host, ServerPort: p, TLS: security, Version: strconv.Itoa(v), Password: "wrong"}
			proxy := testOutbound(t, inner, "127.0.0.1:1")
			proxy.Detour = "outer"
			c := newTestRuntime(t, Config{Outbounds: []Outbound{proxy, out}})
			var reached atomic.Bool
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Store(true)
				fmt.Fprint(w, "should-never-reach-origin")
			}))
			defer origin.Close()
			probeTransport := &http.Transport{DialContext: c.Dial}
			defer probeTransport.CloseIdleConnections()
			resp, e := (&http.Client{Transport: probeTransport, Timeout: time.Second}).Get(origin.URL)
			if resp != nil {
				resp.Body.Close()
			}
			if e == nil || reached.Load() {
				t.Fatal("wrong ShadowTLS password reached the proxy target", e)
			}

			transport := &http.Transport{TLSClientConfig: &tls.Config{ServerName: "example.com", InsecureSkipVerify: true}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "tcp", s.Address("st"))
			}}
			defer transport.CloseIdleConnections()
			resp, e = (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get("https://example.com/")
			if e != nil {
				t.Fatal(e)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if string(body) != "cover-http-reached" {
				t.Fatal(string(body))
			}
		})
	}
}
