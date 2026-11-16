package native

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRealityXrayReference(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_XRAY") == "" {
		t.Fatal("LANBOAT_TEST_XRAY required")
	}
	for _, vision := range []bool{false, true} {
		for _, side := range []string{"client", "server"} {
			t.Run(fmt.Sprintf("%s/vision-%t", side, vision), func(t *testing.T) {
				server, client := realityFixture(t)
				h := server.Reality.Handshake
				cfg := map[string]any{"log": map[string]any{"loglevel": "debug"}}
				port := unusedPort(t)
				user := map[string]any{"id": testUUID, "encryption": "none"}
				if vision {
					user["flow"] = visionFlow
				}
				stream := map[string]any{"network": "tcp", "security": "reality"}
				var c *Runtime
				if side == "client" {
					delete(user, "encryption")
					stream["realitySettings"] = map[string]any{"dest": portAddress(h.Server, h.ServerPort), "serverNames": []string{"localhost"}, "privateKey": server.Reality.PrivateKey, "shortIds": []string{"0123456789abcdef"}, "maxTimeDiff": 60000}
					cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{user}}, "streamSettings": stream}}
					cfg["outbounds"] = []any{map[string]any{"protocol": "freedom"}}
					xrayMuxReference(t, cfg, port)
					o := Outbound{Type: "vless", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, UUID: testUUID, TLS: client}
					if vision {
						o.Flow = visionFlow
					}
					c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				} else {
					in := testInbound(t, "vless")
					in.TLS = server
					if vision {
						in.Users[0].Flow = visionFlow
					}
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					host, p, _ := net.SplitHostPort(s.Address("server"))
					n, _ := shadowPort(p)
					port = unusedPort(t, n)
					stream["realitySettings"] = map[string]any{"serverName": "localhost", "publicKey": client.Reality.PublicKey, "shortId": "0123456789abcdef", "fingerprint": "chrome"}
					cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": true}}}
					cfg["outbounds"] = []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": n, "users": []any{user}}}}, "streamSettings": stream}}
					xrayMuxReference(t, cfg, port)
					c = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}}})
				}

				// Xray probes the cover site's post-handshake records for up to5s
				// before accepting its first Reality session.
				if side == "client" {
					realityReferenceReady(t, c)
				}
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 511, 4096})
				assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
				if vision {
					visionHTTPS(t, c, tls.VersionTLS13, side == "client", true)
					visionHTTPS(t, c, tls.VersionTLS12, side == "client")
				}
			})
		}
	}
}

func realityReferenceReady(t *testing.T, c *Runtime) {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ready")) }))
	defer origin.Close()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.Dial(ctx, network, address)
	}}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr, Timeout: 15 * time.Second}).Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || string(data) != "ready" {
		t.Fatal(string(data), err)
	}
}

func TestRealitySingBoxReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, vision := range []bool{false, true} {
		for _, side := range []string{"client", "server"} {
			t.Run(fmt.Sprintf("%s/vision-%t", side, vision), func(t *testing.T) {
				server, client := realityFixture(t)
				in := testInbound(t, "vless")
				in.TLS = server
				if vision {
					in.Users[0].Flow = visionFlow
				}
				var c *Runtime
				if side == "client" {
					in.ListenPort = unusedPort(t)
					referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = client
					if vision {
						out.Flow = visionFlow
					}
					c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					realityReferenceReady(t, c)
				} else {
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, s.Address("server"))
					out.TLS = client
					out.Username, out.Password = "", ""
					if vision {
						out.Flow = visionFlow
					}
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: out.Tag}})
					c = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: local.Listen, ServerPort: local.ListenPort}}})
				}
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 4096})
				if vision {
					visionHTTPS(t, c, tls.VersionTLS13, side == "client", true)
					visionHTTPS(t, c, tls.VersionTLS12, side == "client")
				}
			})
		}
	}
}
