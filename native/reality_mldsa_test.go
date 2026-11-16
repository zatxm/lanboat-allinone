package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func realityPQFixture(t *testing.T) (TLSOptions, TLSOptions) {
	t.Helper()
	server, client := realityFixture(t)
	seed, public, err := GenerateRealityMLDSA65KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server.Reality.MLDSA65Seed = seed
	client.Reality.MLDSA65Verify = public
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 1}, Value: make([]byte, 5000)}}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("cover")) }))
	cover.EnableHTTP2 = true
	cover.TLS = &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	cover.StartTLS()
	t.Cleanup(cover.Close)
	host, p, _ := net.SplitHostPort(cover.Listener.Addr().String())
	port, _ := shadowPort(p)
	server.Reality.Handshake = &ShadowTLSHandshake{Server: host, ServerPort: port}
	return server, client
}
func TestRealityMLDSA(t *testing.T) {
	server, client := realityPQFixture(t)
	in := testInbound(t, "vless")
	in.TLS = server
	in.Users[0].Flow = visionFlow
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.TLS = client
	out.Flow = visionFlow
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 4096, 60000})
	visionHTTPS(t, c, tls.VersionTLS13, true)
	for _, failure := range []string{"wrong-key", "missing-signature"} {
		t.Run(failure, func(t *testing.T) {
			o := out
			x := *client.Reality
			o.TLS.Reality = &x
			if failure == "wrong-key" {
				_, x.MLDSA65Verify, _ = GenerateRealityMLDSA65KeyPair()
			} else {
				plain, _ := realityFixture(t)
				in.TLS = plain
				ps := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o.Server, o.ServerPort = realityAddress(t, ps.Address("server"))
				_, x.PublicKey, _ = GenerateRealityKeyPair()
				private := plain.Reality.PrivateKey
				pk, _ := realityKey(private)
				key, _ := ecdh.X25519().NewPrivateKey(pk)
				x.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			}
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, err := bad.Dial(ctx, "tcp", "127.0.0.1:1"); err == nil {
				conn.Close()
				t.Fatal("invalid post-quantum authentication accepted")
			}
		})
	}
}
func TestRealityMLDSAConfig(t *testing.T) {
	server, client := realityPQFixture(t)
	for _, tc := range []struct {
		name   string
		server bool
		change func(*RealityOptions)
	}{
		{"seed-format", true, func(o *RealityOptions) { o.MLDSA65Seed = "bad" }},
		{"shared-seed", true, func(o *RealityOptions) { o.MLDSA65Seed = o.PrivateKey }},
		{"server-verify", true, func(o *RealityOptions) { o.MLDSA65Verify = client.Reality.MLDSA65Verify }},
		{"verify-format", false, func(o *RealityOptions) { o.MLDSA65Verify = "bad" }},
		{"client-seed", false, func(o *RealityOptions) { o.MLDSA65Seed = server.Reality.MLDSA65Seed }},
		{"disabled", false, func(o *RealityOptions) { o.Enabled = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := client
			if tc.server {
				o = server
			}
			x := *o.Reality
			o.Reality = &x
			tc.change(&x)
			if _, err := o.config(tc.server, "localhost"); err == nil {
				t.Fatal("invalid ML-DSA config accepted")
			}
		})
	}
	seed, public, err := GenerateRealityMLDSA65KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := realityMLDSAPrivate(seed)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := realityMLDSAPublic(public)
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), expected.Bytes()) {
		t.Fatal("key pair mismatch", err)
	}
	signature, err := key.SignDeterministic([]byte("vector"), nil)
	if err != nil || mldsa.Verify(expected, []byte("vector"), signature, nil) != nil {
		t.Fatal(err)
	}
}

func TestRealityMLDSAXrayReference(t *testing.T) {
	if os.Getenv("LANBOAT_TEST_XRAY") == "" {
		t.Fatal("LANBOAT_TEST_XRAY required")
	}
	for _, vision := range []bool{false, true} {
		for _, side := range []string{"client", "server"} {
			t.Run(fmt.Sprintf("%s/vision-%t", side, vision), func(t *testing.T) {
				server, client := realityPQFixture(t)
				user := map[string]any{"id": testUUID}
				if vision {
					user["flow"] = visionFlow
				}
				cfg := map[string]any{"log": map[string]any{"loglevel": "warning"}}
				stream := map[string]any{"network": "tcp", "security": "reality"}
				var c *Runtime
				port := unusedPort(t)
				if side == "client" {
					h := server.Reality.Handshake
					stream["realitySettings"] = map[string]any{"dest": portAddress(h.Server, h.ServerPort), "serverNames": []string{"localhost"}, "privateKey": server.Reality.PrivateKey, "shortIds": []string{"0123456789abcdef"}, "mldsa65Seed": server.Reality.MLDSA65Seed}
					cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{user}}, "streamSettings": stream}}
					cfg["outbounds"] = []any{map[string]any{"protocol": "freedom"}}
					xrayMuxReference(t, cfg, port)
					o := Outbound{Type: "vless", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, UUID: testUUID, TLS: client}
					if vision {
						o.Flow = visionFlow
					}
					c = newTestRuntime(t, Config{Outbounds: []Outbound{o}})
					realityReferenceReady(t, c)
				} else {
					in := testInbound(t, "vless")
					in.TLS = server
					if vision {
						in.Users[0].Flow = visionFlow
					}
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					host, n := realityAddress(t, s.Address("server"))
					user["encryption"] = "none"
					stream["realitySettings"] = map[string]any{"serverName": "localhost", "publicKey": client.Reality.PublicKey, "shortId": "0123456789abcdef", "fingerprint": "chrome", "mldsa65Verify": client.Reality.MLDSA65Verify}
					cfg["inbounds"] = []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": true}}}
					cfg["outbounds"] = []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": host, "port": n, "users": []any{user}}}}, "streamSettings": stream}}
					xrayMuxReference(t, cfg, port)
					c = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "front", Server: "127.0.0.1", ServerPort: port}}})
				}
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 4096})
				if vision {
					visionHTTPS(t, c, tls.VersionTLS13, side == "client", true)
				}
			})
		}
	}
}

func realityAddress(t *testing.T, address string) (string, uint16) {
	t.Helper()
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := shadowPort(p)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestRealityMLDSATranscript(t *testing.T) {
	for _, kind := range []string{"valid", "hello", "server-hello", "signature", "missing"} {
		t.Run(kind, func(t *testing.T) {
			server, client := realityPQFixture(t)
			cfg, err := client.config(false, "localhost")
			if err != nil {
				t.Fatal(err)
			}
			h, _ := newSTHello(cfg)
			hello, _ := h.marshal("", nil, false)
			hello, err = client.Reality.clientHello(h, hello)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := server.Reality.authenticate(hello, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer clear(auth)
			sh := []byte("authenticated-server-hello")
			cert, err := realityCertificate(auth, hello, sh, server.Reality)
			if err != nil {
				t.Fatal(err)
			}
			h.serverHello = bytes.Clone(sh)
			switch kind {
			case "hello":
				hello[len(hello)-1] ^= 1
			case "server-hello":
				h.serverHello[0] ^= 1
			case "signature":
				cert.Leaf.Extensions[0].Value[0] ^= 1
			case "missing":
				cert.Leaf.Extensions = nil
			}
			err = h.config.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert.Leaf}})
			if (err == nil) != (kind == "valid") {
				t.Fatal("transcript authentication", kind, err)
			}
		})
	}
}
func TestRealityCoverTooSmall(t *testing.T) {
	server, client := realityFixture(t)
	server.Reality.MLDSA65Seed, client.Reality.MLDSA65Verify, _ = GenerateRealityMLDSA65KeyPair()
	in := testInbound(t, "vless")
	in.TLS = server
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, s.Address("server"))
	out.TLS = client
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if conn, err := c.Dial(ctx, "tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Fatal("undersized cover accepted post-quantum flight")
	}
}
