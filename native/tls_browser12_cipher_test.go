package native

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"testing"
)

func browserTLS12CBCSuites(t testing.TB) []uint16 {
	t.Helper()
	h, err := newSTHello(&tls.Config{ServerName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.initBrowser("safari15_3"); err != nil {
		t.Fatal(err)
	}
	var out []uint16
	for _, id := range h.suites {
		if spec, ok := browserTLS12Cipher(id); ok && spec.macSize != 0 {
			out = append(out, id)
		}
	}
	return out
}

func browserTLS12TestKeys(t testing.TB, suite uint16) [2]*ocTLS12Cipher {
	t.Helper()
	keys, err := browserTLS12Keys(suite, bytes.Repeat([]byte{3}, 48), bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func browserTLS12CBCOracle(c *ocTLS12Cipher, data []byte, padding int, corruptMAC, corruptPadding bool) []byte {
	b := c.cbc
	size := b.key.BlockSize()
	var aad [13]byte
	binary.BigEndian.PutUint64(aad[:8], c.sequence)
	aad[8], aad[9], aad[10] = 23, 3, 3
	binary.BigEndian.PutUint16(aad[11:], uint16(len(data)))
	b.mac.Reset()
	b.mac.Write(aad[:])
	b.mac.Write(data)
	tag := b.mac.Sum(nil)
	if corruptMAC {
		tag[0] ^= 1
	}
	plain := append(bytes.Clone(data), tag...)
	plain = append(plain, bytes.Repeat([]byte{byte(padding - 1)}, padding)...)
	if corruptPadding {
		plain[len(plain)-1] ^= 1
	}
	iv := bytes.Repeat([]byte{0x81}, size)
	cipher.NewCBCEncrypter(b.key, iv).CryptBlocks(plain, plain)
	frame := []byte{23, 3, 3, 0, 0}
	frame = append(frame, iv...)
	frame = append(frame, plain...)
	binary.BigEndian.PutUint16(frame[3:5], uint16(len(frame)-5))
	return frame
}

func TestBrowserTLS12CBCRecords(t *testing.T) {
	for _, suite := range browserTLS12CBCSuites(t) {
		t.Run(fmt.Sprintf("%04x", suite), func(t *testing.T) {
			keys := [2]*ocTLS12Cipher{browserTLS12TestKeys(t, suite)[0], browserTLS12TestKeys(t, suite)[0]}
			for _, n := range []int{0, 1, 15, 16, 255, 4096, 16384} {
				message := bytes.Repeat([]byte{0x42}, n)
				wire, err := keys[0].seal(23, message)
				if err != nil {
					t.Fatal(err)
				}
				saved := bytes.Clone(wire)
				got, err := keys[1].open(wire)
				if err != nil || !bytes.Equal(got, message) {
					t.Fatal(n, err)
				}
				if _, err := keys[1].open(saved); err == nil {
					t.Fatal("CBC replay accepted", n)
				}
			}
			keys[0].sequence = keys[0].limit
			if _, err := keys[0].seal(23, []byte{1}); err == nil {
				t.Fatal("record limit not enforced")
			}
			keys[0].sequence = 0
			if _, err := keys[0].seal(23, make([]byte, 16385)); err == nil {
				t.Fatal("oversized CBC record accepted")
			}
			if keys[0].cbc.key.BlockSize() == 8 && keys[0].limit != 1<<16 {
				t.Fatal("3DES exposure limit changed")
			}
		})
	}
}

func TestBrowserTLS12CBCPadding(t *testing.T) {
	for _, suite := range browserTLS12CBCSuites(t) {
		t.Run(fmt.Sprintf("%04x", suite), func(t *testing.T) {
			c := browserTLS12TestKeys(t, suite)[1]
			for pad := 1; pad <= 256; pad++ {
				size := c.cbc.key.BlockSize()
				n := (size - (c.cbc.mac.Size()+pad)%size) % size
				data := bytes.Repeat([]byte{0x42}, n)
				for _, attack := range []string{"mac", "padding"} {
					wire := browserTLS12CBCOracle(c, data, pad, attack == "mac", attack == "padding")
					seq := c.sequence
					if _, err := c.open(wire); err == nil || c.sequence != seq {
						t.Fatal("CBC authentication failure", pad, attack, err)
					}
				}
				wire := browserTLS12CBCOracle(c, data, pad, false, false)
				got, err := c.open(wire)
				if err != nil || !bytes.Equal(got, data) {
					t.Fatal("padding rejected", pad, err)
				}
			}
		})
	}
}

func TestBrowserTLS12SHA1Signature(t *testing.T) {
	message := []byte("client random, server random and ephemeral key")
	digest := sha1.Sum(message)
	rsaKey := browserTLS12RSA(t).PrivateKey.(*rsa.PrivateKey)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []crypto.Signer{rsaKey, ecdsaKey} {
		scheme := tls.PKCS1WithSHA1
		if signer == ecdsaKey {
			scheme = tls.ECDSAWithSHA1
		}
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA1)
		if err != nil {
			t.Fatal(err)
		}
		if err := browserTLS12Verify(signer.Public(), scheme, message, sig); err != nil {
			t.Fatal(err)
		}
		sig[len(sig)-1] ^= 1
		if err := browserTLS12Verify(signer.Public(), scheme, message, sig); err == nil {
			t.Fatal("invalid SHA1 signature accepted")
		}
	}
}

func TestBrowserTLS12ClientCertificateMatch(t *testing.T) {
	f := newMutualTLSFixture(t)
	cert, err := tls.X509KeyPair([]byte(f.clientCert), []byte(f.clientKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"sha1", "sha256", "ca", "wrong-ca", "wrong-type", "wrong-scheme", "restricted", "no-key", "wrong-key", "bad-der", "empty"} {
		t.Run(scenario, func(t *testing.T) {
			candidate := cert
			request := &tls.CertificateRequestInfo{Version: tls.VersionTLS12, SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithSHA1}}
			allowed := []byte{64}
			want := false
			switch scenario {
			case "sha1":
				want = true
			case "sha256":
				request.SignatureSchemes = []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
				want = true
			case "ca":
				request.AcceptableCAs = [][]byte{leaf.RawIssuer}
				want = true
			case "wrong-ca":
				request.AcceptableCAs = [][]byte{[]byte("untrusted-ca")}
			case "wrong-type":
				allowed = []byte{1}
			case "wrong-scheme":
				request.SignatureSchemes = []tls.SignatureScheme{tls.PKCS1WithSHA1}
			case "restricted":
				candidate.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
			case "no-key":
				candidate.PrivateKey = nil
			case "wrong-key":
				candidate.PrivateKey = browserTLS12RSA(t).PrivateKey
			case "bad-der":
				candidate.Certificate = [][]byte{[]byte("not a certificate")}
			case "empty":
				candidate.Certificate = nil
			}
			if got := browserTLS12ClientMatch(&candidate, request, allowed); got != want {
				t.Fatal(got, want)
			}
		})
	}
}

func TestBrowserTLS12SuiteCoverage(t *testing.T) {
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		h, err := newSTHello(&tls.Config{ServerName: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.initBrowser(profile); err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, id := range h.suites[4:] { // GREASE and the three TLS1.3 suites precede TLS1.2.
			if _, ok := browserTLS12Cipher(id); !ok {
				t.Fatal(profile, id)
			}
			count++
		}
		want := 17
		if profile == "safari15_3" {
			want = 23
		}
		if count != want {
			t.Fatal(profile, count, want)
		}
	}
}

func FuzzBrowserTLS12CBCRecord(f *testing.F) {
	for _, suite := range browserTLS12CBCSuites(f) {
		c := browserTLS12TestKeys(f, suite)[0]
		wire, err := c.seal(23, []byte("authenticated CBC seed"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(suite, wire)
	}
	f.Fuzz(func(t *testing.T, suite uint16, wire []byte) {
		if len(wire) > 16709 {
			return
		}
		spec, ok := browserTLS12Cipher(suite)
		if !ok || spec.macSize == 0 {
			return
		}
		c := browserTLS12TestKeys(t, suite)[0]
		_, _ = c.open(bytes.Clone(wire))
	})
}
