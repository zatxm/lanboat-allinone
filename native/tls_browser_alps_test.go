package native

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The fixture asserts the client flight order and record limits on the wire.
func browserExtensionServer(raw net.Conn, config *tls.Config, extensions []byte, alps uint16, limit int, compression string) error {
	cert := config.Certificates[0]
	reader := &stTLSReader{conn: raw}
	hello, err := reader.message()
	if err != nil {
		return err
	}
	if len(config.EncryptedClientHelloKeys) != 0 {
		hello, err = browserTestDecryptECH(config, hello)
		if err != nil {
			return err
		}
	}
	h, ext, err := realityClientParameters(hello)
	if err != nil {
		return err
	}
	p := stCursor{data: ext[51]}
	shares := stCursor{data: p.vector(2)}
	var public []byte
	for len(shares.data) > 0 && shares.err == nil {
		id := shares.number(2)
		key := shares.vector(2)
		if id == 29 {
			public = key
		}
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	peer, err := ecdh.X25519().NewPublicKey(public)
	if err != nil {
		return err
	}
	shared, err := private.ECDH(peer)
	if err != nil {
		return err
	}
	random := make([]byte, 32)
	rand.Read(random)
	body := append([]byte{3, 3}, random...)
	body = append(body, stVector(h.session, 1)...)
	body = append(body, 0x13, 1, 0)
	selection := stExtension(nil, 43, []byte{3, 4})
	selection = stExtension(selection, 51, append([]byte{0, 29}, stVector(private.PublicKey().Bytes(), 2)...))
	sh := stMessage(2, append(body, stVector(selection, 2)...))
	suite, _ := stSuite(0x1301)
	if len(config.EncryptedClientHelloKeys) != 0 {
		clear(sh[30:38])
		proof := suite.newHash()
		proof.Write(hello)
		proof.Write(sh)
		secret := suite.extract(make([]byte, 32), hello[6:38])
		copy(sh[30:38], suite.expand(secret, "ech accept confirmation", proof.Sum(nil), 8))
		clear(secret)
	}
	transcript := suite.newHash()
	transcript.Write(hello)
	transcript.Write(sh)
	zero := make([]byte, 32)
	early := suite.extract(zero, zero)
	empty := suite.newHash()
	handshake := suite.extract(suite.derive(early, "derived", empty), shared)
	clientSecret, serverSecret := suite.derive(handshake, "c hs traffic", transcript), suite.derive(handshake, "s hs traffic", transcript)
	reader.cipher, err = suite.recordCipher(clientSecret)
	if err != nil {
		return err
	}
	writer, err := suite.recordCipher(serverSecret)
	if err != nil {
		return err
	}
	if err = writeAll(raw, shadowFrame(22, sh)); err != nil {
		return err
	}
	send := func(kind byte, body []byte) error {
		message := stMessage(kind, body)
		transcript.Write(message)
		frame, err := writer.seal(22, message)
		if err != nil {
			return err
		}
		return writeAll(raw, frame)
	}
	if err = send(8, stVector(extensions, 2)); err != nil {
		return err
	}
	entry := append(stVector(cert.Certificate[0], 3), 0, 0)
	certificateBody := append([]byte{0}, stVector(entry, 3)...)
	if compression != "" {
		cmd := exec.Command("python3", filepath.Join("..", "tests", "encode-tls-certificate.py"), compression)
		cmd.Stdin = bytes.NewReader(certificateBody)
		compressed, err := cmd.Output()
		if err != nil {
			return err
		}
		id := byte(2)
		if compression == "zstd" {
			id = 3
		}
		data := []byte{0, id, byte(len(certificateBody) >> 16), byte(len(certificateBody) >> 8), byte(len(certificateBody))}
		data = append(data, stVector(compressed, 3)...)
		if err = send(25, data); err != nil {
			return err
		}
	} else if err = send(11, certificateBody); err != nil {
		return err
	}
	digest := suite.newHash()
	digest.Write(stSignatureInput(true, transcript))
	signature, err := cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest.Sum(nil), crypto.SHA256)
	if err != nil {
		return err
	}
	if err = send(15, append([]byte{4, 3}, stVector(signature, 2)...)); err != nil {
		return err
	}
	if err = send(20, suite.finished(serverSecret, transcript)); err != nil {
		return err
	}
	master := suite.extract(suite.derive(handshake, "derived", empty), zero)
	app, err := suite.recordCipher(suite.derive(master, "c ap traffic", transcript))
	if err != nil {
		return err
	}
	if alps != 0 {
		message, err := reader.message()
		if err != nil {
			return err
		}
		if !bytes.Equal(message, stMessage(8, stVector(stExtension(nil, alps, nil), 2))) {
			return errors.New("missing client ALPS encrypted extensions")
		}
		transcript.Write(message)
	}
	message, err := reader.message()
	if err != nil {
		return err
	}
	if !bytes.Equal(message, stMessage(20, suite.finished(clientSecret, transcript))) {
		return errors.New("client Finished did not cover ALPS")
	}
	total := 0
	for total < 512 {
		frame, err := shadowReadRecord(raw, reader.buffer[:])
		if err != nil {
			return err
		}
		kind, data, err := app.open(frame)
		if err != nil {
			return err
		}
		if kind != 23 || len(data) == 0 || len(data) > limit {
			return errors.New("record size limit ignored")
		}
		total += len(data)
	}
	return nil
}

func TestBrowserALPSAndRecordLimit(t *testing.T) {
	f := newMutualTLSFixture(t)
	server, err := f.server().config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"chrome100", "chrome110", "chrome120", "chrome140", "chrome150", "firefox109", "firefox117", "firefox120", "firefox148", "random"} {
		for _, bad := range []string{"", "malformed", "unsolicited", "unmatched-alpn"} {
			if bad == "unmatched-alpn" && name[0] != 'c' {
				continue
			}
			t.Run(name+"/"+bad, func(t *testing.T) {
				alpn := "h2"
				if bad == "unmatched-alpn" {
					alpn = "http/1.1"
				}
				ext := stExtension(nil, 16, stVector(stVector([]byte(alpn), 1), 2))
				alps := uint16(0)
				limit := 16384
				if name[0] == 'c' {
					alps = 17513
					if name == "chrome140" || name == "chrome150" {
						alps = 17613
					}
					id := alps
					if bad == "unsolicited" {
						id = 17614
					}
					value := []byte{0, 4, 0, 0, 0xff, 0xff}
					if bad == "malformed" {
						value = value[:5]
					}
					ext = stExtension(ext, id, value)
					if name == "chrome150" {
						ext = stExtension(ext, 51764, []byte{0, 2, 1, 1})
					}
				} else {
					limit = 127
					value := []byte{0, 128}
					if bad == "malformed" {
						value = []byte{0, 1}
					}
					id := uint16(28)
					if bad == "unsolicited" {
						id = 29
					}
					ext = stExtension(ext, id, value)
				}
				a, b := kernelTLSTCPPair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- browserExtensionServer(b, server, ext, alps, limit, "") }()
				options := f.client()
				options.ClientCertificate, options.ClientKey = nil, nil
				options.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: name}
				cfg, err := options.config(false, "")
				if err != nil {
					t.Fatal(err)
				}
				client := clientTLS(a, cfg, options)
				err = client.HandshakeContext(ctx)
				if bad != "" {
					client.Close()
					<-done
					if err == nil {
						t.Fatal("invalid extension accepted")
					}
					return
				}
				if err != nil {
					client.Close()
					t.Fatal(err)
				}
				if _, err = client.Write(make([]byte, 512)); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestBrowserCertificateCompressionHandshake(t *testing.T) {
	f := newMutualTLSFixture(t)
	server, err := f.server().config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"chrome100", "chrome110", "chrome120", "chrome140", "chrome150", "firefox148"} {
		for _, compression := range []string{"brotli", "zstd"} {
			if compression == "zstd" && profile != "firefox148" {
				continue
			}
			t.Run(profile+"/"+compression, func(t *testing.T) {
				ext := stExtension(nil, 16, stVector(stVector([]byte("h2"), 1), 2))
				alps := uint16(0)
				if profile[0] == 'c' {
					alps = 17513
					if profile == "chrome140" || profile == "chrome150" {
						alps = 17613
					}
					ext = stExtension(ext, alps, nil)
				}
				a, b := kernelTLSTCPPair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- browserExtensionServer(b, server, ext, alps, 16384, compression) }()
				options := f.client()
				options.ClientCertificate, options.ClientKey = nil, nil
				options.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				cfg, err := options.config(false, "")
				if err != nil {
					t.Fatal(err)
				}
				client := clientTLS(a, cfg, options)
				if err = client.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err = client.Write(make([]byte, 512)); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func browserTestDecryptECH(config *tls.Config, outer []byte) ([]byte, error) {
	h, _, err := realityClientParameters(outer)
	if err != nil {
		return nil, err
	}
	p := stCursor{data: outer[4:]}
	p.take(34)
	p.vector(1)
	p.vector(2)
	p.vector(1)
	block := p.vector(2)
	entries := stCursor{data: block}
	start := len(outer) - len(block)
	var ech []byte
	var offset int
	for len(entries.data) > 0 && entries.err == nil {
		before := len(entries.data)
		id := entries.number(2)
		value := entries.vector(2)
		if id == 0xfe0d {
			ech = value
			offset = start + len(block) - before + 4
		}
	}
	if p.end() != nil || entries.end() != nil {
		return nil, errors.New("invalid ECH outer")
	}
	q := stCursor{data: ech}
	kind, kdfID, aeadID, id := q.number(1), q.number(2), q.number(2), byte(q.number(1))
	enc, ciphertext := q.vector(2), q.vector(2)
	if q.end() != nil || kind != 0 {
		return nil, errors.New("invalid ECH envelope")
	}
	key := config.EncryptedClientHelloKeys[0]
	c, err := parseECHConfig(key.Config)
	if err != nil || id != c.id {
		return nil, errors.New("wrong ECH key")
	}
	private, err := c.kem.NewPrivateKey(key.PrivateKey)
	if err != nil {
		return nil, err
	}
	kdf, err := hpke.NewKDF(uint16(kdfID))
	if err != nil {
		return nil, err
	}
	aead, err := hpke.NewAEAD(uint16(aeadID))
	if err != nil {
		return nil, err
	}
	recipient, err := hpke.NewRecipient(enc, private, kdf, aead, append([]byte("tls ech\x00"), key.Config...))
	if err != nil {
		return nil, err
	}
	aad := bytes.Clone(outer)
	clear(aad[offset+len(ech)-len(ciphertext) : offset+len(ech)])
	encoded, err := recipient.Open(aad[4:], ciphertext)
	if err != nil {
		return nil, err
	}
	inner := stCursor{data: encoded}
	inner.take(34)
	if len(inner.vector(1)) != 0 {
		return nil, errors.New("ECH encoded SID")
	}
	inner.vector(2)
	inner.vector(1)
	prefix := len(encoded) - len(inner.data)
	list := stCursor{data: inner.vector(2)}
	if inner.err != nil || !bytes.Equal(inner.data, make([]byte, len(inner.data))) {
		return nil, errors.New("ECH padding")
	}
	_, outerExt, err := realityClientParameters(outer)
	if err != nil {
		return nil, err
	}
	var ext []byte
	for len(list.data) > 0 && list.err == nil {
		id, value := uint16(list.number(2)), list.vector(2)
		if id == 0xfd00 {
			if !bytes.Equal(value, []byte{2, 0, 51}) {
				return nil, errors.New("unexpected outer extension references")
			}
			id, value = 51, outerExt[51]
		}
		ext = stExtension(ext, id, value)
	}
	if list.end() != nil {
		return nil, errors.New("ECH inner extensions")
	}
	body := append(bytes.Clone(encoded[:34]), stVector(h.session, 1)...)
	body = append(body, encoded[35:prefix]...)
	body = append(body, stVector(ext, 2)...)
	return stMessage(1, body), nil
}

func TestBrowserECHCertificateCompression(t *testing.T) {
	f := newMutualTLSFixture(t)
	echConfig, key := testECHPair(t)
	server, err := testECHServer(t, f, key).config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"chrome100", "chrome110", "chrome120", "chrome140", "chrome150", "firefox148"} {
		for _, compression := range []string{"brotli", "zstd"} {
			if compression == "zstd" && profile != "firefox148" {
				continue
			}
			t.Run(profile+"/"+compression, func(t *testing.T) {
				ext := stExtension(nil, 16, stVector(stVector([]byte("h2"), 1), 2))
				a, b := kernelTLSTCPPair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- browserExtensionServer(b, server, ext, 0, 16384, compression) }()
				options := testECHClient(f, echConfig)
				options.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
				cfg, err := options.config(false, "")
				if err != nil {
					t.Fatal(err)
				}
				client := clientTLS(a, cfg, options)
				if err = client.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				if !client.ConnectionState().ECHAccepted {
					t.Fatal("ECH not accepted")
				}
				if _, err = client.Write(make([]byte, 512)); err != nil {
					t.Fatal(err)
				}
				if err = <-done; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
