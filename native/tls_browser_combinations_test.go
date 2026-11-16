package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"os"
	"testing"
	"time"
)

func TestBrowserECH(t *testing.T) {
	fixture := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		for _, group := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384} {
			t.Run(profile+"/"+group.String(), func(t *testing.T) {
				server, err := testECHServer(t, fixture, key).config(true, "")
				if err != nil {
					t.Fatal(err)
				}
				server.CurvePreferences = []tls.CurveID{group}
				clientOptions := testECHClient(fixture, config)
				clientOptions.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				clientConfig, err := clientOptions.config(false, "")
				if err != nil {
					t.Fatal(err)
				}
				a, b := kernelTLSTCPPair(t)
				capture := &echCaptureConn{Conn: a}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					s := tls.Server(b, server)
					err := s.HandshakeContext(ctx)
					if err == nil && !s.ConnectionState().ECHAccepted {
						err = io.ErrUnexpectedEOF
					}
					if err == nil {
						var data [7]byte
						_, err = io.ReadFull(s, data[:])
						if err == nil {
							_, err = s.Write(data[:])
						}
					}
					done <- err
				}()
				client := clientTLS(capture, clientConfig, clientOptions)
				if err = client.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				if !client.ConnectionState().ECHAccepted {
					t.Fatal("ECH not accepted")
				}
				if _, err = client.Write([]byte("payload")); err != nil {
					t.Fatal(err)
				}
				var data [7]byte
				if _, err = io.ReadFull(client, data[:]); err != nil || string(data[:]) != "payload" {
					t.Fatal(err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
				capture.mu.Lock()
				defer capture.mu.Unlock()
				if bytes.Contains(capture.b.Bytes(), []byte("example.com")) || !bytes.Contains(capture.b.Bytes(), []byte("public.test")) {
					t.Fatal("ECH privacy")
				}
			})
		}
	}
}

func TestBrowserReality(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		t.Run(profile, func(t *testing.T) {
			server, client := realityFixture(t)
			in := testInbound(t, "vless")
			in.TLS = server
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address("server"))
			out.TLS = client
			out.TLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
}

func TestBrowserRealityReference(t *testing.T) {
	for _, backend := range []string{"xray", "sing-box"} {
		t.Run(backend, func(t *testing.T) {
			server, client := realityFixture(t)
			in := testInbound(t, "vless")
			in.ListenPort = unusedPort(t)
			in.TLS = server
			in.Users[0].Flow = visionFlow
			if backend == "sing-box" {
				binary := os.Getenv("LANBOAT_TEST_SINGBOX15")
				if binary == "" {
					t.Fatal("LANBOAT_TEST_SINGBOX15 required")
				}
				t.Setenv("LANBOAT_TEST_REFERENCE", binary)
				referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			} else {
				if os.Getenv("LANBOAT_TEST_XRAY") == "" {
					t.Fatal("LANBOAT_TEST_XRAY required")
				}
				h := server.Reality.Handshake
				cfg := map[string]any{"log": map[string]any{"loglevel": "debug"}, "inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": in.ListenPort, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": testUUID, "flow": visionFlow}}}, "streamSettings": map[string]any{"network": "tcp", "security": "reality", "realitySettings": map[string]any{"dest": portAddress(h.Server, h.ServerPort), "serverNames": []string{"localhost"}, "privateKey": server.Reality.PrivateKey, "shortIds": []string{"0123456789abcdef"}, "maxTimeDiff": 60000}}}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}}
				xrayMuxReference(t, cfg, in.ListenPort)
			}
			for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
				t.Run(profile, func(t *testing.T) {
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.TLS = client
					out.Flow = visionFlow
					out.TLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
					c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					realityReferenceReady(t, c)
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 4096})
					visionHTTPS(t, c, tls.VersionTLS13, true, true)
				})
			}
		})
	}
}

func TestBrowserECHReference(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", binary)
	fixture := newMutualTLSFixture(t)
	config, key := testECHPair(t)
	in := testInbound(t, "trojan")
	in.ListenPort = unusedPort(t)
	in.TLS = testECHServer(t, fixture, key)
	referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		t.Run(profile, func(t *testing.T) {
			out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
			out.TLS = testECHClient(fixture, config)
			out.TLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
}
