package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func browserTLS12RSA(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(42), DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestBrowserTLS12(t *testing.T) {
	f := newMutualTLSFixture(t)
	rsaCert := browserTLS12RSA(t)
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		h, err := newSTHello(&tls.Config{ServerName: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.initBrowser(profile); err != nil {
			t.Fatal(err)
		}
		var suites []uint16
		for _, suite := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			if _, ok := browserTLS12Cipher(suite.ID); ok && slices.Contains(h.suites, suite.ID) {
				suites = append(suites, suite.ID)
			}
		}
		for _, suite := range suites {
			for _, mutual := range []bool{false, true} {
				name := profile + "/" + tls.CipherSuiteName(suite)
				if mutual {
					name += "/mutual"
				}
				t.Run(name, func(t *testing.T) {
					server, err := f.server().config(true, "")
					if err != nil {
						t.Fatal(err)
					}
					server.MinVersion, server.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
					server.CipherSuites, server.NextProtos = []uint16{suite}, []string{"h2"}
					if !mutual {
						server.ClientAuth = tls.NoClientCert
					}
					o := f.client()
					if mutual {
						o.MaxVersion = "1.2"
					}
					if strings.Contains(tls.CipherSuiteName(suite), "_RSA_") {
						server.Certificates = []tls.Certificate{rsaCert}
						o.Certificate = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCert.Certificate[0]}))}
					}
					// Exercise every supported group across the suite matrix.
					groups := []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
					server.CurvePreferences = []tls.CurveID{groups[int(suite)%len(groups)]}
					server.Certificates[0].OCSPStaple = []byte("ocsp-fixture")
					server.Certificates[0].SignedCertificateTimestamps = [][]byte{[]byte("sct-fixture")}
					o.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
					cfg, err := o.config(false, "example.com")
					if err != nil {
						t.Fatal(err)
					}
					a, b := kernelTLSTCPPair(t)
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					exporter := make(chan []byte, 1)
					done := make(chan error, 1)
					go func() {
						defer b.Close()
						c := tls.Server(b, server)
						err := c.HandshakeContext(ctx)
						if err == nil {
							state := c.ConnectionState()
							var key []byte
							key, err = state.ExportKeyingMaterial("browser-test", []byte("context"), 64)
							exporter <- key
							if err == nil {
								_, err = io.Copy(c, c)
							}
						}
						done <- err
					}()
					c := clientTLS(a, cfg, o)
					if err := c.HandshakeContext(ctx); err != nil {
						t.Fatal(err)
					}
					state := c.ConnectionState()
					if state.Version != tls.VersionTLS12 || state.CipherSuite != suite || !state.HandshakeComplete || state.NegotiatedProtocol != "h2" || len(state.VerifiedChains) == 0 || string(state.OCSPResponse) != "ocsp-fixture" || len(state.SignedCertificateTimestamps) != 1 {
						t.Fatal("lost TLS1.2 negotiated state", state)
					}
					session := (*c.(*kernelTLSHandshake).secure.Load()).(*ocTLS12)
					key, err := session.ExportKeyingMaterial("browser-test", []byte("context"), 64)
					if err != nil || !bytes.Equal(key, <-exporter) {
						t.Fatal("TLS1.2 exporter mismatch", err)
					}
					payload := bytes.Repeat([]byte("browserTLS12"), 9000)
					written := make(chan error, 1)
					go func() {
						_, err := c.Write(payload)
						if err == nil {
							err = c.CloseWrite()
						}
						written <- err
					}()
					response, err := io.ReadAll(c)
					if err != nil || !bytes.Equal(response, payload) {
						t.Fatal("TLS1.2 data/half-close failure", len(response), err)
					}
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func FuzzBrowserTLS12ServerFlight(f *testing.F) {
	cert := browserTLS12RSA(f)
	h, err := newSTHello(&tls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	if err != nil {
		f.Fatal(err)
	}
	if err := h.initBrowser("safari16_0"); err != nil {
		f.Fatal(err)
	}
	// Keep the signed seed valid in every fuzz worker.
	h.random = bytes.Repeat([]byte{7}, 32)
	ch, err := h.browserHello(nil)
	if err != nil {
		f.Fatal(err)
	}
	random := bytes.Repeat([]byte{42}, 32)
	ext := stExtension(nil, 23, nil)
	ext = stExtension(ext, 0xff01, []byte{0})
	body := append([]byte{3, 3}, random...)
	body = append(body, 0, 0xc0, 0x2f, 0)
	sh := stMessage(2, append(body, stVector(ext, 2)...))
	private, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	params := append([]byte{3, 0, 23}, stVector(private.PublicKey().Bytes(), 1)...)
	input := append(append(bytes.Clone(h.random), random...), params...)
	signature, err := ocTLS12Sign(&cert, []tls.SignatureScheme{tls.PSSWithSHA256}, input)
	if err != nil {
		f.Fatal(err)
	}
	flight := append(bytes.Clone(sh), ocTLS12Certificate(&cert)...)
	flight = append(flight, stMessage(12, append(params, signature...))...)
	for _, mutual := range []bool{false, true} {
		messages := bytes.Clone(flight)
		if mutual {
			request := []byte{2, 1, 64}
			request = append(request, stVector(browserWords(uint16(tls.PSSWithSHA256)), 2)...)
			request = append(request, 0, 0)
			messages = append(messages, stMessage(13, request)...)
		}
		messages = append(messages, stMessage(14, nil)...)
		wire := append(shadowFrame(22, messages), shadowFrame(20, []byte{1})...)
		f.Add(wire)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 1<<20 {
			return
		}
		conn := readerConn(wire)
		reader := &stTLSReader{conn: conn}
		sh, err := reader.message()
		if err != nil || sh[0] != 2 {
			return
		}
		flight := &stClientFlight{conn: conn, h: h, ch: ch, sh: sh, reader: reader}
		if session, err := flight.tls12(); err == nil {
			session.Close()
		}
	})
}

type browserTLS12AttackConn struct {
	net.Conn
	attack  string
	changed bool
}

func (c *browserTLS12AttackConn) Write(p []byte) (int, error) {
	data := bytes.Clone(p)
	for start := 0; start+5 <= len(data); {
		n := 5 + int(binary.BigEndian.Uint16(data[start+3:start+5]))
		if start+n > len(data) {
			break
		}
		if data[start] == 22 && !c.changed {
			for pos := start + 5; pos+4 <= start+n; {
				size := 4 + int(readUint24(data[pos+1:pos+4]))
				if pos+size > start+n {
					break
				}
				if data[pos] == 2 {
					suite := pos + 39 + int(data[pos+38])
					switch c.attack {
					case "downgrade":
						copy(data[pos+30:pos+38], "DOWNGRD\x01")
						c.changed = true
					case "version":
						data[pos+5] = 2
						c.changed = true
					case "suite":
						data[suite], data[suite+1] = 0xc0, 0x09
						c.changed = true
					case "ems", "renegotiation", "alpn", "duplicate":
						for offset := suite + 5; offset+4 <= pos+size; {
							id := binary.BigEndian.Uint16(data[offset:])
							length := int(binary.BigEndian.Uint16(data[offset+2:]))
							if id == 23 && c.attack == "ems" {
								data[offset+1] = 24
								c.changed = true
							} else if id == 23 && c.attack == "duplicate" {
								data[offset], data[offset+1] = 0xff, 1
								c.changed = true
							} else if id == 0xff01 && c.attack == "renegotiation" {
								data[offset+4] = 1
								c.changed = true
							} else if id == 16 && c.attack == "alpn" {
								data[offset+7] = 'q'
								c.changed = true
							}
							offset += 4 + length
						}
					}
				}
				if data[pos] == 12 && c.attack == "signature" {
					data[pos+size-1] ^= 1
					c.changed = true
				}
				pos += size
			}
		}
		if data[start] == 20 && c.attack == "ccs" {
			data[start+5] = 2
			c.changed = true
		}
		start += n
	}
	return c.Conn.Write(data)
}

func TestBrowserTLS12Attack(t *testing.T) {
	for _, attack := range []string{"downgrade", "version", "suite", "ems", "renegotiation", "alpn", "duplicate", "signature", "ccs"} {
		t.Run(attack, func(t *testing.T) {
			f := newMutualTLSFixture(t)
			server, err := f.server().config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			server.MaxVersion = tls.VersionTLS12
			server.NextProtos = []string{"h2"}
			a, b := kernelTLSTCPPair(t)
			wire := &browserTLS12AttackConn{Conn: b, attack: attack}
			done := make(chan error, 1)
			go func() { done <- tls.Server(wire, server).Handshake() }()
			o := f.client()
			o.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: "safari26_3"}
			cfg, err := o.config(false, "example.com")
			if err != nil {
				t.Fatal(err)
			}
			if err := clientTLS(a, cfg, o).Handshake(); err == nil {
				t.Fatal("accepted modified handshake", attack)
			}
			a.Close()
			<-done
			if !wire.changed {
				t.Fatal("attack was not exercised")
			}
		})
	}
}
