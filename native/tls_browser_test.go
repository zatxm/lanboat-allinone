package native

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBrowserOpenSSL(t *testing.T) {
	fixture := newMutualTLSFixture(t)
	rsaCert := browserTLS12RSA(t)
	rsaKey, err := x509.MarshalPKCS8PrivateKey(rsaCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		h, err := newSTHello(&tls.Config{ServerName: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.initBrowser(profile); err != nil {
			t.Fatal(err)
		}
		for _, suite := range []struct {
			name       string
			id         uint16
			clientAuth string
		}{
			{"TLS_AES_128_GCM_SHA256", tls.TLS_AES_128_GCM_SHA256, ""},
			{"TLS_AES_256_GCM_SHA384", tls.TLS_AES_256_GCM_SHA384, ""},
			{"TLS_CHACHA20_POLY1305_SHA256", tls.TLS_CHACHA20_POLY1305_SHA256, ""},
			{"ECDHE-ECDSA-AES128-GCM-SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ""},
			{"ECDHE-ECDSA-AES256-GCM-SHA384", tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, ""},
			{"ECDHE-ECDSA-CHACHA20-POLY1305", tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, ""},
			{"ECDHE-RSA-AES128-GCM-SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ""},
			{"ECDHE-RSA-AES256-GCM-SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, ""},
			{"ECDHE-RSA-CHACHA20-POLY1305", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, ""},
			{"ECDHE-ECDSA-AES128-SHA", 0xc009, ""},
			{"ECDHE-ECDSA-AES256-SHA", 0xc00a, ""},
			{"ECDHE-ECDSA-AES128-SHA256", 0xc023, ""},
			{"ECDHE-ECDSA-AES256-SHA384", 0xc024, ""},
			{"ECDHE-RSA-AES128-SHA", 0xc013, ""},
			{"ECDHE-RSA-AES256-SHA", 0xc014, ""},
			{"ECDHE-RSA-AES128-SHA256", 0xc027, ""},
			{"ECDHE-RSA-AES256-SHA384", 0xc028, ""},
			{"AES128-GCM-SHA256", 0x009c, ""},
			{"AES256-GCM-SHA384", 0x009d, ""},
			{"AES128-SHA", 0x002f, ""},
			{"AES256-SHA", 0x0035, ""},
			{"AES128-SHA256", 0x003c, ""},
			{"AES256-SHA256", 0x003d, ""},
			{"ECDHE-RSA-AES128-SHA:@SECLEVEL=0", 0xc013, ""},
			{"ECDHE-ECDSA-AES128-SHA:@SECLEVEL=0", 0xc009, ""},
			{"ECDHE-RSA-AES128-SHA:@SECLEVEL=0", 0xc013, "rsa"},
			{"ECDHE-RSA-AES128-SHA:@SECLEVEL=0", 0xc013, "ecdsa"},
		} {
			if !slices.Contains(h.suites, suite.id) {
				continue
			}
			if strings.Contains(suite.name, "@SECLEVEL=0") && (!strings.HasPrefix(suite.name, "ECDHE-ECDSA-") && !slices.Contains(browserSignatures(profile), uint16(tls.PKCS1WithSHA1)) || strings.HasPrefix(suite.name, "ECDHE-ECDSA-") && !slices.Contains(browserSignatures(profile), uint16(tls.ECDSAWithSHA1))) {
				continue
			}
			t.Run(profile+"/"+suite.name+suite.clientAuth, func(t *testing.T) {
				version := uint16(tls.VersionTLS12)
				args := []string{"-tls1_2", "-cipher", suite.name}
				if strings.Contains(suite.name, "@SECLEVEL=0") {
					signature := "RSA+SHA1"
					if strings.HasPrefix(suite.name, "ECDHE-ECDSA-") {
						signature = "ECDSA+SHA1"
					}
					args = append(args, "-sigalgs", signature)
				}
				if strings.HasPrefix(suite.name, "TLS_") {
					version = tls.VersionTLS13
					args = []string{"-tls1_3", "-cert_comp", "-ciphersuites", suite.name}
				}
				dir := t.TempDir()
				cert, key, output := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "openssl.log")
				certificate, privateKey, ca := fixture.serverCert, fixture.serverKey, fixture.ca
				if spec, _ := browserTLS12Cipher(suite.id); spec.rsaCertificate {
					certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCert.Certificate[0]}))
					privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaKey}))
					ca = certificate
				}
				clientCert, clientKey := "", ""
				if suite.clientAuth != "" {
					trust, sig := fixture.ca, "ECDSA+SHA1"
					clientCert, clientKey = fixture.clientCert, fixture.clientKey
					if suite.clientAuth == "rsa" {
						clientCert, clientKey, trust, sig = certificate, privateKey, certificate, "RSA+SHA1"
					}
					clientCA := filepath.Join(dir, "client-ca.pem")
					if err := os.WriteFile(clientCA, []byte(trust), 0600); err != nil {
						t.Fatal(err)
					}
					args = append(args, "-Verify", "1", "-verify_return_error", "-CAfile", clientCA, "-client_sigalgs", sig)
				}
				for path, data := range map[string]string{cert: certificate, key: privateKey} {
					if err := os.WriteFile(path, []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
				logs, err := os.Create(output)
				if err != nil {
					t.Fatal(err)
				}
				defer logs.Close()
				address := portAddress("127.0.0.1", unusedPort(t))
				args = append([]string{"s_server", "-accept", address, "-cert", cert, "-key", key, "-trace", "-www", "-naccept", "1", "-alpn", "http/1.1", "-keylogfile", output + ".keys"}, args...)
				cmd := exec.Command("openssl", args...)
				cmd.Stdout, cmd.Stderr = logs, logs
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { cmd.Process.Kill(); cmd.Wait() }()
				var raw net.Conn
				for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
					raw, err = net.DialTimeout("tcp", address, 50*time.Millisecond)
					if err == nil {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if err != nil {
					data, _ := os.ReadFile(output)
					t.Fatal(err, string(data))
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				o := TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{ca}, UTLS: &BrowserTLSOptions{Enabled: true, Fingerprint: profile}}
				if clientCert != "" {
					o.ClientCertificate, o.ClientKey = []string{clientCert}, []string{clientKey}
				}
				cfg, err := o.config(false, "example.com")
				if err != nil {
					t.Fatal(err)
				}
				c := clientTLS(raw, cfg, o)
				if err := c.Handshake(); err != nil {
					t.Fatal(err)
				}
				if c.ConnectionState().CipherSuite != suite.id || c.ConnectionState().Version != version || len(c.ConnectionState().VerifiedChains) == 0 {
					t.Fatal("lost cipher selection or certificate validation")
				}
				exported, err := ocExporter(c)
				if err != nil {
					t.Fatal(err)
				}
				inner := *c.(*kernelTLSHandshake).secure.Load()
				var secret []byte
				label := "CLIENT_RANDOM"
				if version == tls.VersionTLS13 {
					label, secret = "EXPORTER_SECRET", bytes.Clone(inner.(*realityConn).tls.exporter)
				} else {
					secret = bytes.Clone(inner.(*ocTLS12).master)
				}
				if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(c), &http.Request{Method: "GET"})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 || len(body) < 100 {
					t.Fatal(response.StatusCode, len(body), err)
				}
				raw.Close()
				if err := cmd.Wait(); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				keys, err := os.ReadFile(output + ".keys")
				if err != nil {
					t.Fatal(err)
				}

				found := false
				for _, line := range strings.Split(string(keys), "\n") {
					fields := strings.Fields(line)
					if len(fields) == 3 && fields[0] == label {
						reference, err := hex.DecodeString(fields[2])
						found = err == nil && bytes.Equal(reference, secret)
					}
				}
				if !found || len(exported) != 32 {
					t.Fatal("OpenSSL exporter secret mismatch")
				}

				compressed := strings.Contains(string(data), "CompressedCertificate")
				if compressed != (version == tls.VersionTLS13 && browserCompressionOffered(profile, 1)) {
					t.Fatal("reference certificate compression was not exercised", compressed, string(data))
				}
			})
		}
	}
}

func TestBrowserProtocolPaths(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) { testBrowserProtocolPaths(t, version) })
	}
}

func testBrowserProtocolPaths(t *testing.T, version uint16) {
	for _, variant := range []string{"brook-wss", "vmess-ws", "vless-grpc", "vless-vision", "trojan", "anytls", "socks"} {
		if version == tls.VersionTLS12 && variant == "vless-vision" {
			continue // Vision requires TLS1.3.
		}
		t.Run(variant, func(t *testing.T) {
			kind, transport, _ := strings.Cut(variant, "-")
			in := testInbound(t, kind)
			in.TLS = certificate(t)
			if version == tls.VersionTLS12 {
				in.TLS.MaxVersion = "1.2"
			}
			if transport == "wss" || transport == "ws" {
				in.Transport = Transport{Type: "ws", Path: "/browser"}
			} else if transport == "grpc" {
				in.Transport = Transport{Type: "grpc", ServiceName: "browser"}
			} else if transport == "vision" {
				in.Users[0].Flow = visionFlow
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address(in.Tag))
			out.Transport = in.Transport
			out.TLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: "safari26_3"}
			if transport == "vision" {
				out.Flow = visionFlow
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 511, 4096})
			if transport == "vision" {
				visionHTTPS(t, c, tls.VersionTLS13, true)
			}
		})
	}
}

func TestBrowserCertificatePolicy(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) { testBrowserCertificatePolicy(t, version) })
	}
}

func testBrowserCertificatePolicy(t *testing.T, version uint16) {
	f, other := newMutualTLSFixture(t), newMutualTLSFixture(t)
	for _, scenario := range []string{"mutual", "wrong-ca", "no-client", "wrong-name", "wrong-pin"} {
		t.Run(scenario, func(t *testing.T) {
			server, err := f.server().config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			server.MinVersion, server.MaxVersion = version, version
			o := f.client()
			o.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: "safari26_3"}
			switch scenario {
			case "wrong-ca":
				o.Certificate = []string{other.ca}
			case "no-client":
				o.ClientCertificate, o.ClientKey = nil, nil
			case "wrong-name":
				o.ServerName = "wrong.example"
			case "wrong-pin":
				o.Certificate = nil
				o.CertificateSHA256 = []string{tlsPinFor(t, other.serverCert, false)}
			}
			cfg, err := o.config(false, "example.com")
			if err != nil {
				t.Fatal(err)
			}
			a, b := kernelTLSTCPPair(t)
			done := make(chan error, 1)
			go func() {
				defer b.Close()
				c := tls.Server(b, server)
				_, e := io.Copy(c, c)
				done <- e
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c := clientTLS(a, cfg, o)
			err = c.HandshakeContext(ctx)
			if err == nil {
				_, err = c.Write([]byte{1})
				if err == nil {
					var result [1]byte
					_, err = io.ReadFull(c, result[:])
				}
			}
			a.Close()
			if (err == nil) != (scenario == "mutual") {
				t.Fatal("certificate authentication result", err)
			}
			<-done
		})
	}
}

func FuzzBrowserCertificate(f *testing.F) {
	for _, algorithm := range []string{"brotli", "zstd"} {
		message, err := os.ReadFile(filepath.Join("testdata", "browser", "certificate-"+algorithm+".bin"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(message)
	}
	f.Add([]byte{})
	f.Add([]byte{25, 0, 0, 8, 0, 1, 0, 0, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 1<<20 {
			browserCertificate(b)
		}
	})
}

// Keep every static byte, extension order, vector length and GREASE position.
// Only entropy (random/session/key material) and GREASE values are normalized.
func browserShape(t *testing.T, record []byte) []byte {
	t.Helper()
	b := bytes.Clone(record)
	if len(b) < 80 || int(binary.BigEndian.Uint16(b[3:5])) != len(b)-5 {
		t.Fatal("invalid captured browser TLS record")
	}
	clear(b[11:43])
	p := 43
	sid := int(b[p])
	clear(b[p+1 : p+1+sid])
	p += 1 + sid
	n := int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	grease := func(at int) {
		id := binary.BigEndian.Uint16(b[at:])
		if id&0x0f0f == 0x0a0a && byte(id>>8) == byte(id) {
			b[at], b[at+1] = 0x0a, 0x0a
		}
	}
	for end := p + n; p < end; p += 2 {
		grease(p)
	}
	p += 1 + int(b[p]) + 2
	for p < len(b) {
		id, size := binary.BigEndian.Uint16(b[p:]), int(binary.BigEndian.Uint16(b[p+2:]))
		grease(p)
		p += 4
		switch id {
		case 10:
			for i := p + 2; i < p+size; i += 2 {
				grease(i)
			}
		case 43:
			for i := p + 1; i < p+size; i += 2 {
				grease(i)
			}
		case 51:
			for i := p + 2; i < p+size; {
				grease(i)
				n := int(binary.BigEndian.Uint16(b[i+2:]))
				clear(b[i+4 : i+4+n])
				i += 4 + n
			}
		}
		p += size
	}
	return b
}

func TestBrowserReferenceClientHello(t *testing.T) {
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		t.Run(profile, func(t *testing.T) {
			fixture, err := os.ReadFile(filepath.Join("testdata", "browser", profile+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var capture struct{ Record string }
			if err := json.Unmarshal(fixture, &capture); err != nil {
				t.Fatal(err)
			}
			wire, err := base64.StdEncoding.DecodeString(capture.Record)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &tls.Config{ServerName: "fingerprint.example", NextProtos: []string{"h2", "http/1.1"}}
			h, err := newSTHello(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = h.initBrowser(profile); err != nil {
				t.Fatal(err)
			}
			msg, err := h.marshal("", nil, false)
			if err != nil {
				t.Fatal(err)
			}
			record := shadowFrame(22, msg)
			record[2] = 1
			got, want := browserShape(t, record), browserShape(t, wire)
			if !bytes.Equal(got, want) {
				for i := range min(len(got), len(want)) {
					if got[i] != want[i] {
						t.Fatalf("reference differs at byte%d: %x / %x (sizes%d/%d)", i, got[i], want[i], len(got), len(want))
					}
				}
				t.Fatalf("record lengths%d/%d", len(got), len(want))
			}
		})
	}
}

func TestBrowserTLSHandshake(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		for _, group := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.X25519MLKEM768} {
			if !slices.Contains([]string{"safari26_3", "chrome140", "chrome150", "firefox148"}, profile) && group == tls.X25519MLKEM768 {
				continue
			}
			t.Run(profile+"/"+group.String(), func(t *testing.T) {
				server, err := certificate(t).config(true, "")
				if err != nil {
					t.Fatal(err)
				}
				server.MinVersion = tls.VersionTLS13
				server.CurvePreferences = []tls.CurveID{group}
				server.NextProtos = []string{"h2"}
				a, b := kernelTLSTCPPair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() {
					c := tls.Server(b, server)
					if e := c.HandshakeContext(ctx); e != nil {
						done <- e
						return
					}
					var buf [7]byte
					_, e := io.ReadFull(c, buf[:])
					if e == nil {
						_, e = c.Write(buf[:])
					}
					done <- e
				}()
				o := TLSOptions{Enabled: true, UTLS: &BrowserTLSOptions{Enabled: true, Fingerprint: profile}}
				c := clientTLS(a, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true}, o)
				if err := c.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				if c.ConnectionState().NegotiatedProtocol != "h2" {
					t.Fatal("browser ALPN not applied")
				}
				if _, err := c.Write([]byte("payload")); err != nil {
					t.Fatal(err)
				}
				var got [7]byte
				if _, err := io.ReadFull(c, got[:]); err != nil || string(got[:]) != "payload" {
					t.Fatal(string(got[:]), err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestBrowserCompressedCertificate(t *testing.T) {
	body := []byte("certificate-body")
	var compressed bytes.Buffer
	z := zlib.NewWriter(&compressed)
	z.Write(body)
	z.Close()
	message := func(algorithm, size int, data []byte) []byte {
		b := browserWords(uint16(algorithm))
		b = append(b, byte(size>>16), byte(size>>8), byte(size))
		return stMessage(25, append(b, stVector(data, 3)...))
	}
	valid := message(1, len(body), compressed.Bytes())
	got, err := browserCertificate(valid)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal(string(got), err)
	}
	for _, bad := range [][]byte{valid[:7], message(2, len(body), compressed.Bytes()), message(1, 1<<20+1, compressed.Bytes()), message(1, len(body)-1, compressed.Bytes()), message(1, len(body)+1, compressed.Bytes()), message(1, len(body), append(bytes.Clone(compressed.Bytes()), 0)), message(1, len(body), []byte("bad"))} {
		if _, err := browserCertificate(bad); err == nil {
			t.Fatal("accepted malformed compressed certificate")
		}
	}
}

func TestBrowserConfiguration(t *testing.T) {
	o := TLSOptions{Enabled: true, UTLS: &BrowserTLSOptions{Enabled: true, Fingerprint: "safari26_3"}}
	if err := o.configureProtocol(new(tls.Config), false); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*TLSOptions){func(o *TLSOptions) { o.Enabled = false }, func(o *TLSOptions) { o.MaxVersion = "1.1" }, func(o *TLSOptions) { o.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: "unknown"} }, func(o *TLSOptions) { o.CurvePreferences = []string{"X25519"} }} {
		bad := o
		change(&bad)
		if err := bad.configureProtocol(new(tls.Config), false); err == nil {
			t.Fatal("accepted incompatible browser options", bad)
		}
	}
	if err := o.configureProtocol(new(tls.Config), true); err == nil {
		t.Fatal("accepted inbound fingerprint")
	}
	if err := o.validateQUICVersion(); err == nil {
		t.Fatal("accepted TCP profile for QUIC")
	}
	for _, version := range []string{"1.2", "1.3"} {
		limited := o
		limited.MinVersion, limited.MaxVersion = version, version
		if _, err := limited.config(false, "example.com"); err != nil {
			t.Fatal("rejected supported browser version", version, err)
		}
	}
}

func TestBrowserEntropy(t *testing.T) {
	var previous *stClientHello
	for range 20 {
		h, err := newSTHello(&tls.Config{ServerName: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.initBrowser("safari26_3"); err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(h.suites, h.grease[2]) || h.grease[0] == h.grease[1] {
			t.Fatal("invalid GREASE")
		}
		if h.fallback == nil || bytes.Equal(h.key.PublicKey().Bytes(), h.fallback.PublicKey().Bytes()) {
			t.Fatal("browser hybrid and fallback reused one X25519 key")
		}
		if previous != nil && (bytes.Equal(h.random, previous.random) || bytes.Equal(h.session, previous.session) || bytes.Equal(h.key.PublicKey().Bytes(), previous.key.PublicKey().Bytes()) || reflect.DeepEqual(h.kem.EncapsulationKey().Bytes(), previous.kem.EncapsulationKey().Bytes())) {
			t.Fatal("reused browser entropy")
		}
		previous = h
	}
}
