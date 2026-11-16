package native

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBrowserDelegatedCredential(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	delegationOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: delegationOID, Value: []byte{5, 0}}}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dcKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	public, _ := x509.MarshalPKIXPublicKey(dcKey.Public())
	credential := binary.BigEndian.AppendUint32(nil, uint32(now.Add(24*time.Hour).Sub(leaf.NotBefore)/time.Second))
	credential = append(credential, 0x04, 0x03)
	credential = append(credential, stVector(public, 3)...)
	credential = append(credential, 0x04, 0x03)
	input := bytes.Repeat([]byte{' '}, 64)
	input = append(input, "TLS, server delegated credentials\x00"...)
	input = append(input, leaf.Raw...)
	input = append(input, credential...)
	digest := sha256.Sum256(input)
	signature, err := key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	dc := append(bytes.Clone(credential), stVector(signature, 2)...)
	makeBody := func(dc []byte) []byte {
		entry := stVector(der, 3)
		entry = append(entry, stVector(stExtension(nil, 34, dc), 2)...)
		return append([]byte{0}, stVector(entry, 3)...)
	}
	body := makeBody(dc)
	if _, err = stCertificates(body, true); err != nil {
		t.Fatal(err)
	}
	got, scheme, err := browserDelegatedKey(body, leaf, "firefox148", now)
	if err != nil || scheme != tls.ECDSAWithP256AndSHA256 || !got.(*ecdsa.PublicKey).Equal(dcKey.Public()) {
		t.Fatal("valid credential", err)
	}
	for _, mutation := range []string{"signature", "algorithm", "public", "expiry", "certificate", "permission", "key-usage", "not-yet-valid", "expired", "too-long", "not-offered"} {
		t.Run(mutation, func(t *testing.T) {
			changed := bytes.Clone(dc)
			cert := *leaf
			when := now
			profile := "firefox148"
			switch mutation {
			case "signature":
				changed[len(changed)-1] ^= 1
			case "algorithm":
				changed[len(credential)-1] ^= 1
			case "public":
				changed[12] ^= 1
			case "expiry":
				changed[3] ^= 1
			case "certificate":
				cert.Raw = bytes.Clone(cert.Raw)
				cert.Raw[10] ^= 1
			case "permission":
				cert.Extensions = nil
			case "key-usage":
				cert.KeyUsage = 0
			case "not-yet-valid":
				when = leaf.NotBefore.Add(-time.Second)
			case "expired":
				when = now.Add(2 * 24 * time.Hour)
			case "too-long":
				when = now.Add(-8 * 24 * time.Hour)
			case "not-offered":
				profile = "chrome150"
			}
			if _, _, err = browserDelegatedKey(makeBody(changed), &cert, profile, when); err == nil {
				t.Fatal("invalid credential accepted")
			}
		})
	}
}

func TestBrowserMLDSA(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if err != nil {
				t.Fatal(err)
			}
			cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
			a, b := kernelTLSTCPPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				s := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
				err := s.HandshakeContext(ctx)
				if err == nil {
					var data [1]byte
					_, err = io.ReadFull(s, data[:])
				}
				done <- err
			}()
			options := TLSOptions{Enabled: true, ServerName: "localhost", Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, UTLS: &BrowserTLSOptions{Enabled: true, Fingerprint: "chrome150"}}
			cfg, err := options.config(false, "")
			if err != nil {
				t.Fatal(err)
			}
			client := clientTLS(a, cfg, options)
			if err = client.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err = client.Write([]byte{1}); err != nil {
				t.Fatal(err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestBrowserECHRejected(t *testing.T) {
	fixture := newMutualTLSFixture(t)
	config, _ := testECHPair(t)
	for _, profile := range append([]string{"safari26_3"}, browserProfiles...) {
		t.Run(profile, func(t *testing.T) {
			options := testECHClient(fixture, config)
			options.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
			cfg, err := options.config(false, "")
			if err != nil {
				t.Fatal(err)
			}
			serverOptions := fixture.server()
			serverOptions.ClientAuthentication = ""
			serverOptions.ClientCertificate = nil
			server, err := serverOptions.config(true, "")
			if err != nil {
				t.Fatal(err)
			}
			a, b := kernelTLSTCPPair(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); s := tls.Server(b, server); _ = s.HandshakeContext(ctx) }()
			capture := &echCaptureConn{Conn: a}
			client := clientTLS(capture, cfg, options)
			if err = client.HandshakeContext(ctx); err == nil {
				t.Fatal("ECH rejection accepted")
			}
			client.Close()
			<-done
			capture.mu.Lock()
			defer capture.mu.Unlock()
			if bytes.Contains(capture.b.Bytes(), []byte("example.com")) {
				t.Fatal("private SNI leaked")
			}
		})
	}
}

func TestBrowserFFDHEOpenSSL(t *testing.T) {
	fixture := newMutualTLSFixture(t)
	for _, profile := range []string{"firefox109", "firefox117", "firefox120", "firefox148", "random"} {
		for _, group := range []string{"ffdhe2048", "ffdhe3072"} {
			t.Run(profile+"/"+group, func(t *testing.T) {
				dir := t.TempDir()
				cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
				if err := os.WriteFile(cert, []byte(fixture.serverCert), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(key, []byte(fixture.serverKey), 0600); err != nil {
					t.Fatal(err)
				}
				address := portAddress("127.0.0.1", unusedPort(t))
				log, err := os.Create(filepath.Join(dir, "openssl.log"))
				if err != nil {
					t.Fatal(err)
				}
				defer log.Close()
				cmd := exec.Command("openssl", "s_server", "-accept", address, "-cert", cert, "-key", key, "-groups", group, "-tls1_3", "-www", "-naccept", "1")
				cmd.Stdout, cmd.Stderr = log, log
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					cmd.Process.Kill()
					cmd.Wait()
					if t.Failed() {
						b, _ := os.ReadFile(log.Name())
						t.Log(string(b))
					}
				}()
				var raw net.Conn
				for end := time.Now().Add(3 * time.Second); time.Now().Before(end); {
					raw, err = net.DialTimeout("tcp", address, 50*time.Millisecond)
					if err == nil {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				options := testECHClient(fixture, "")
				options.ECH = nil
				options.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				cfg, err := options.config(false, "")
				if err != nil {
					t.Fatal(err)
				}
				client := clientTLS(raw, cfg, options)
				if err = client.Handshake(); err != nil {
					t.Fatal(err)
				}
				if _, err = client.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")); err != nil {
					t.Fatal(err)
				}
				response, err := io.ReadAll(client)
				if err != nil || !bytes.HasPrefix(response, []byte("HTTP/1.0 200")) {
					t.Fatal(string(response), err)
				}
			})
		}
	}
}
