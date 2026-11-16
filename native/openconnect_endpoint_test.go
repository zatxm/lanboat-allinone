package native

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func ocEndpointRuntime(t *testing.T, ep ocEndpointOptions, cfg Config) *Runtime {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(data, &doc)
	ep.Type = "openconnect"
	doc["endpoints"], _ = json.Marshal([]ocEndpointOptions{ep})
	raw, _ := json.Marshal(doc)
	r, err := New(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOpenConnectEndpointTraffic(t *testing.T) {
	for _, cstp := range []bool{false, true} {
		t.Run(fmt.Sprint("cstp", cstp), func(t *testing.T) {
			cert := certificate(t)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: cert, OpenConnectOptions: OpenConnectOptions{Group: "staff", DisableDTLS: cstp, DNS: []string{"10.44.0.1", "fd44::1"}, SearchDomains: []string{"corp.test"}}}}})
			ep := ocEndpointOptions{Tag: "proxy", Server: "https://" + server.Address("server") + "/auth", Username: "client", Password: "private", AuthGroup: "staff", NoUDP: cstp, OnDemand: true, MTU: 1400, DPDInterval: "1s", TLS: ocEndpointTLS{CertificateAuthority: cert.Certificate, SystemTrustDisabled: true, TLSOptions: TLSOptions{ServerName: "example.com"}}}
			ep.TLS.SystemTrustDisabled = cstp
			if cstp {
				ep.TLS.CertificateAuthority = nil
				ep.TLS.CertificateAuthorityPath = filepath.Join(t.TempDir(), "ca.pem")
				if err := os.WriteFile(ep.TLS.CertificateAuthorityPath, []byte(strings.Join(cert.Certificate, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
			}
			client := ocEndpointRuntime(t, ep, Config{})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000})
			c := client.ocClients["proxy"]
			first := c.tunnel.Load()
			if first.dpd != 2*time.Second || first.stack.peer.inbound != "proxy" || first.stack.nat == nil {
				t.Fatal("endpoint settings did not reach the tunnel")
			}
			if !cstp {
				ocWaitDTLS(t, first)
			} else if first.dtls != nil {
				t.Fatal("no_udp negotiated DTLS")
			}
			if err := client.DisconnectOpenConnect("proxy"); err != nil || c.tunnel.Load() != nil {
				t.Fatal("disconnect", err)
			}
			assertTCP(t, client)
			if c.tunnel.Load() == first {
				t.Fatal("disconnected tunnel reused")
			}
			client.resetNetworkTransports()
			assertUDP(t, client)
			if cstp {
				client.DisconnectOpenConnect("proxy")
				if err := os.WriteFile(ep.TLS.CertificateAuthorityPath, []byte("invalid CA"), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				conn, err := client.Dial(ctx, "tcp", "127.0.0.1:80")
				cancel()
				if conn != nil {
					conn.Close()
				}
				if err == nil {
					t.Fatal("invalid replacement CA was accepted")
				}
				if err := os.WriteFile(ep.TLS.CertificateAuthorityPath, []byte(strings.Join(cert.Certificate, "\n")), 0600); err != nil {
					t.Fatal(err)
				}
				assertTCP(t, client)
			}
		})
	}
}

func TestOpenConnectEndpointCookieAndEager(t *testing.T) {
	server, _ := ocPair(t)
	ep := ocEndpointOptions{Tag: "proxy", Server: server.Address("server"), Cookie: server.ocServers["server"].cookie("client", time.Now()), NoUDP: true, TLS: ocEndpointTLS{TLSOptions: TLSOptions{Insecure: true}}}
	client := ocEndpointRuntime(t, ep, Config{})
	c := client.ocClients["proxy"]
	deadline := time.Now().Add(3 * time.Second)
	for c.tunnel.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("non-on-demand endpoint did not establish at Start")
		}
		time.Sleep(time.Millisecond)
	}
	assertTCP(t, client)
	if err := client.DisconnectOpenConnect("proxy"); err == nil {
		t.Fatal("manual disconnect accepted an eager endpoint")
	}
	ep.Tag, ep.OnDemand, ep.IPv6Disabled = "lazy", true, true
	lazy := ocEndpointRuntime(t, ep, Config{Route: Route{Final: "lazy"}})
	if lazy.ocClients["lazy"].tunnel.Load() != nil {
		t.Fatal("on-demand endpoint connected at Start")
	}
	if err := lazy.AuthenticateOpenConnect(context.Background(), "lazy"); err != nil {
		t.Fatal(err)
	}
	tunnel := lazy.ocClients["lazy"].tunnel.Load()
	for _, addr := range tunnel.local {
		if addr.Is6() {
			t.Fatal("ipv6_disabled retained a tunnel address")
		}
	}
	lazy.Close()
	if lazy.DisconnectOpenConnect("lazy") == nil {
		t.Fatal("closed runtime reactivated")
	}
}

func TestOpenConnectEndpointDetourBootstrapDNS(t *testing.T) {
	for _, dtls := range []bool{false, true} {
		t.Run(fmt.Sprint("dtls", dtls), func(t *testing.T) {
			port, seen := ocDNSFixture(t)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "u", Password: "p"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DisableDTLS: !dtls, DNS: []string{"192.0.2.53"}, SplitDNS: []string{"private.test"}}}}, Route: Route{Rules: []Rule{{Port: []uint16{53}, OverrideAddress: "127.0.0.1", OverridePort: port, Outbound: "direct"}, {IPCIDR: []string{"192.0.2.42/32", "2001:db8::42/128"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			hop := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "socks", Tag: "hop", Listen: "127.0.0.1"}}})
			hopHost, hopPort, _ := net.SplitHostPort(hop.Address("hop"))
			pn, _ := strconv.Atoi(hopPort)
			_, gatewayPort, _ := net.SplitHostPort(server.Address("server"))
			client := ocEndpointRuntime(t, ocEndpointOptions{Tag: "proxy", Server: "https://gateway.test:" + gatewayPort, Username: "u", Password: "p", NoUDP: !dtls, OnDemand: true, DomainResolver: "bootstrap", Detour: "hop", TLS: ocEndpointTLS{TLSOptions: TLSOptions{Insecure: true}}}, Config{Outbounds: []Outbound{{Type: "socks", Tag: "hop", Server: hopHost, ServerPort: uint16(pn)}}, Route: Route{Final: "proxy"}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "bootstrap", Predefined: map[string][]string{"gateway.test": {"127.0.0.1"}}}, {Type: "openconnect", Tag: "private", Endpoint: "proxy"}}, Final: "private", Timeout: "2s"}})
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "endpoint-via-private-dns") }))
			defer origin.Close()
			transport := &http.Transport{DialContext: client.Dial}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			response, err := httpClient.Get(strings.Replace(origin.URL, "127.0.0.1", "origin.private.test", 1))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "endpoint-via-private-dns" {
				t.Fatal(string(body), err)
			}
			if !slices.Contains(seen(), "udp:origin.private.test") {
				t.Fatal("business DNS was replaced by the peer bootstrap resolver", seen())
			}
			if dtls {
				tunnel := client.ocClients["proxy"].tunnel.Load()
				ocWaitDTLS(t, tunnel)
				assertUDPSizes(t, client, []int{1, 4096, 60000})
				if !tunnel.dtlsPath.Load() {
					t.Fatal("DTLS detour did not carry packets")
				}
			}
			hop.mu.Lock()
			active := len(hop.connections)
			hop.mu.Unlock()
			if active == 0 {
				t.Fatal("VPN transport bypassed the SOCKS detour")
			}
		})
	}
}

func TestOpenConnectEndpointValidation(t *testing.T) {
	for name, change := range map[string]string{
		"http":             `"server":"http://vpn.test"`,
		"credentials":      `"server":"https://user:password@vpn.test"`,
		"query":            `"server":"vpn.test/?a=b"`,
		"empty-query":      `"server":"vpn.test/?"`,
		"fragment":         `"server":"vpn.test/#"`,
		"bad-port":         `"server":"vpn.test:65536"`,
		"zero-port":        `"server":"vpn.test:0"`,
		"empty-port":       `"server":"vpn.test:"`,
		"bad-host":         `"server":"bad:host:443"`,
		"flavor":           `"server":"vpn.test","flavor":"gp"`,
		"cookie":           `"server":"vpn.test","cookie":"bad;value"`,
		"agent-injection":  `"server":"vpn.test","user_agent":"x\r\nHost:bad"`,
		"group-conflict":   `"server":"vpn.test","group":"one","auth_group":"two"`,
		"empty-trust":      `"server":"vpn.test","tls":{"system_trust_disabled":true}`,
		"pins":             `"server":"vpn.test","tls":{"peer_fingerprint":"sha256:xx"}`,
		"pin-type":         `"server":"vpn.test","tls":{"peer_fingerprint":"sha512:1234"}`,
		"pin-padding":      `"server":"vpn.test","tls":{"peer_fingerprint":"pin-sha256:===="}`,
		"CA-conflict":      `"server":"vpn.test","tls":{"certificate_authority":["PEM"],"certificate_authority_path":"/no"}`,
		"empty-form":       `"server":"vpn.test","form_entries":[{"name":"password"}]`,
		"hidden-injection": `"server":"vpn.test","form_entries":[{"submission_key":"x:y","value":"p"}]`,
		"promote-value":    `"server":"vpn.test","form_entries":[{"submission_key":"password","promote":true,"value":"p"}]`,
		"DPD":              `"server":"vpn.test","dpd_interval":"-1s"`,
		"base-mtu":         `"server":"vpn.test","base_mtu":65536`,
		"system-name":      `"server":"vpn.test","name":"oc0"`,
		"nat":              `"server":"vpn.test","udp_mapping":"bad"`,
		"unknown":          `"server":"vpn.test","not_implemented":true`,
	} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"endpoints":[{"type":"openconnect",` + change + `}]}`)
			if _, err := Parse(raw); err == nil {
				t.Fatal("invalid endpoint accepted")
			}
		})
	}
	for _, server := range []string{"vpn.test", "https://vpn.test/path%20name", "[::1]:444/portal"} {
		raw, _ := json.Marshal(map[string]any{"endpoints": map[string]any{"type": "openconnect", "tag": "vpn", "server": server}})
		cfg, err := Parse(raw)
		if err != nil {
			t.Fatal(server, err)
		}
		if !cfg.Outbounds[0].TLS.Enabled || cfg.Outbounds[0].ocEndpoint == nil {
			t.Fatal("endpoint did not normalize")
		}
	}
	if _, err := Parse([]byte(`{"endpoints":[{"type":"openconnect","tag":"same","server":"vpn.test"}],"outbounds":[{"type":"direct","tag":"same"}]}`)); err == nil {
		t.Fatal("duplicate tag accepted")
	}
}

func TestOpenConnectEndpointFingerprints(t *testing.T) {
	cert := certificate(t)
	block, _ := pem.Decode([]byte(strings.Join(cert.Certificate, "\n")))
	leaf, err := tls.X509KeyPair([]byte(strings.Join(cert.Certificate, "\n")), []byte(strings.Join(cert.Key, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	parsed := leaf.Leaf
	certSHA1 := sha1.Sum(block.Bytes)
	keySHA1 := sha1.Sum(parsed.RawSubjectPublicKeyInfo)
	keySHA256 := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	pins := []string{hex.EncodeToString(certSHA1[:]), "sha1:" + hex.EncodeToString(keySHA1[:]), "sha256:" + hex.EncodeToString(keySHA256[:]), "pin-sha256:" + base64.StdEncoding.EncodeToString(keySHA256[:]), "sha256:" + hex.EncodeToString(keySHA256[:])[:12]}
	for _, pin := range pins {
		t.Run(pin[:min(16, len(pin))], func(t *testing.T) {
			ep := &ocEndpointOptions{Server: "vpn.test", TLS: ocEndpointTLS{PeerFingerprint: []string{pin}, SystemTrustDisabled: true}}
			if _, err := ep.outbound(); err != nil {
				t.Fatal(err)
			}
			cfg := &tls.Config{ServerName: "wrong-host.test"}
			if err := ep.configureTLS(cfg); err != nil {
				t.Fatal(err)
			}
			state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{parsed}}
			if err := cfg.VerifyConnection(state); err != nil {
				t.Fatal(err)
			}
			if cfg.VerifyConnection(tls.ConnectionState{}) == nil {
				t.Fatal("missing certificate accepted")
			}
			ep.TLS.pins[0].prefix = strings.Repeat("0", len(ep.TLS.pins[0].prefix))
			ep.TLS.Insecure = true
			if err := ep.configureTLS(cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.VerifyConnection(state) == nil {
				t.Fatal("insecure bypassed a wrong pin")
			}
		})
	}
}

func TestOpenConnectEndpointFormAndIdentity(t *testing.T) {
	for _, get := range []bool{false, true} {
		t.Run(fmt.Sprint("GET", get), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				step := requests.Add(1)
				if r.URL.EscapedPath() != "/portal%20name" || r.UserAgent() != "Lanboat-test/1" {
					t.Error("URL or User-Agent lost", r.URL, r.UserAgent())
				}
				if step == 1 && get && r.Method != "GET" {
					t.Error("XML POST not disabled")
				}
				var reply ocXML
				if step == 1 {
					if !get {
						var msg ocXML
						if err := xml.NewDecoder(r.Body).Decode(&msg); err != nil || msg.Device != "linux-64" || msg.Agent == nil || msg.Agent.Value != "custom-version" {
							t.Error("client identity", msg, err)
						}
					}
					reply = ocXML{Type: "auth-request", Auth: &ocAuth{ID: "main", Form: &ocForm{Action: "/portal%20name", Inputs: []ocInput{{Type: "text", Name: "username"}, {Type: "password", Name: "password"}, {Type: "hidden", Name: "opaque", Value: "server-owned"}}}}}
				} else {
					var msg ocXML
					if err := xml.NewDecoder(r.Body).Decode(&msg); err != nil {
						t.Error(err)
					}
					values := map[string]string{}
					for _, f := range msg.Auth.Fields {
						values[f.XMLName.Local] = f.Value
					}
					if values["username"] != "client" || values["password"] != "interactive" || values["opaque"] != "server-owned" {
						t.Error("form override or hidden state", values)
					}
					reply = ocXML{Type: "complete", Token: "session-cookie"}
				}
				b, _ := ocMarshal(reply)
				w.Header().Set("Content-Type", "text/xml")
				w.Write(b)
			}))
			defer server.Close()
			ep := ocEndpointOptions{Tag: "proxy", Server: server.URL + "/portal%20name", OnDemand: true, XMLPostDisabled: get, ReportedOS: "linux-64", Version: "custom-version", UserAgent: "Lanboat-test/1", TLS: ocEndpointTLS{TLSOptions: TLSOptions{Insecure: true}}, FormEntries: []ocFormEntry{{SubmissionKey: "username", Value: "client"}, {FormID: "main", Name: "password", Value: "old"}, {SubmissionKey: "password", Promote: true}, {SubmissionKey: "opaque", Value: "bad"}}}
			r := ocEndpointRuntime(t, ep, Config{})
			prompts := 0
			r.SetOpenConnectAuthHandler(func(ctx context.Context, form OpenConnectAuthForm) (map[string]string, error) {
				prompts++
				return map[string]string{"password": "interactive"}, nil
			})
			if err := r.ocClients["proxy"].login(context.Background()); err != nil {
				t.Fatal(err)
			}
			if prompts != 1 || requests.Load() != 2 || r.ocClients["proxy"].cookie != "session-cookie" {
				t.Fatal("authentication flow", prompts, requests.Load())
			}
			r.ocClients["proxy"].o.ocEndpoint.PasswordAuthenticationDisabled = true
			requests.Store(0)
			if err := r.ocClients["proxy"].login(context.Background()); err == nil || errors.Is(err, context.Canceled) {
				t.Fatal("disabled password authentication accepted", err)
			}
			if requests.Load() != 1 {
				t.Fatal("disabled authentication submitted credentials")
			}
		})
	}
}

func FuzzOpenConnectEndpoint(f *testing.F) {
	f.Add([]byte(`{"endpoints":{"type":"openconnect","server":"vpn.test"}}`))
	f.Add([]byte(`{"endpoints":[{"type":"openconnect","server":"https://[::1]:443/a%20b","tls":{"peer_fingerprint":"sha256:1234"}}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) <= 32768 {
			_, _ = Parse(raw)
		}
	})
}
