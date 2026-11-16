package native

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func shadowFetch(c *stTLS13) error {
	frame, e := c.clientApp.seal(23, []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
	if e != nil {
		return e
	}
	if e = writeAll(c.conn, frame); e != nil {
		return e
	}
	var b [5 + shadowRecordLimit]byte
	for range 16 {
		frame, e = shadowReadRecord(c.conn, b[:])
		if e != nil {
			return e
		}
		kind, data, e := c.serverApp.open(frame)
		if e != nil {
			return e
		}
		if kind == 23 && bytes.HasPrefix(data, []byte("HTTP/1.")) && bytes.Contains(bytes.SplitN(data, []byte("\r\n"), 2)[0], []byte(" 200")) {
			return nil
		}
		if kind == 21 {
			return fmt.Errorf("cover rejected client: %x", data)
		}
	}
	return errors.New("cover did not return an HTTP response")
}
func shadowHandshake(t *testing.T, address string, options TLSOptions) (*stTLS13, error) {
	t.Helper()
	cfg, e := options.config(false, "example.com")
	if e != nil {
		return nil, e
	}
	conn, e := net.DialTimeout("tcp", address, time.Second)
	if e != nil {
		return nil, e
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	return shadowTLS13(context.Background(), conn, cfg, options, "private")
}
func TestShadowTLS13Cover(t *testing.T) {
	for _, group := range []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521} {
		for _, mutual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%v/mutual%v", group, mutual), func(t *testing.T) {
				f := newMutualTLSFixture(t)
				server := f.server()
				if !mutual {
					server.ClientAuthentication = "no"
					server.ClientCertificate = nil
				}
				cfg, e := server.config(true, "")
				if e != nil {
					t.Fatal(e)
				}
				cfg.MinVersion = tls.VersionTLS13
				cfg.MaxVersion = tls.VersionTLS13
				cfg.CurvePreferences = []tls.CurveID{group}
				cfg.SessionTicketsDisabled = true
				origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "verified-cover") }))
				origin.TLS = cfg
				origin.StartTLS()
				defer origin.Close()
				options := f.client()
				options.RecordFragment = true
				options.Fragment = true
				options.FragmentFallbackDelay = "1ms"
				c, e := shadowHandshake(t, origin.Listener.Addr().String(), options)
				if e != nil {
					t.Fatal(e)
				}
				if !c.state.HandshakeComplete || len(c.state.VerifiedChains) == 0 {
					t.Fatal("unverified handshake")
				}
				if e = shadowFetch(c); e != nil {
					t.Fatal(e)
				}
			})
		}
	}
}
func TestShadowTLS13Certificates(t *testing.T) {
	for _, check := range []string{"valid", "wrong-host", "untrusted", "wrong-pin", "missing-client", "h2-muddle"} {
		t.Run(check, func(t *testing.T) {
			f := newMutualTLSFixture(t)
			cfg, e := f.server().config(true, "")
			if e != nil {
				t.Fatal(e)
			}
			cfg.MinVersion = tls.VersionTLS13
			cfg.SessionTicketsDisabled = true
			var h2 atomic.Bool
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h2.Store(r.ProtoMajor == 2); fmt.Fprint(w, "verified") }))
			origin.EnableHTTP2 = true
			origin.TLS = cfg
			origin.StartTLS()
			defer origin.Close()
			options := f.client()
			switch check {
			case "wrong-host":
				options.ServerName = "wrong.example"
			case "untrusted":
				options.Certificate = []string{newMutualTLSFixture(t).ca}
			case "wrong-pin":
				options.CertificatePublicKeySHA256 = []string{strings.Repeat("00", 32)}
			case "missing-client":
				options.ClientCertificate = nil
				options.ClientKey = nil
			case "h2-muddle":
				options.ALPN = []string{"h2"}
			}
			c, e := shadowHandshake(t, origin.Listener.Addr().String(), options)
			if e == nil {
				if check == "h2-muddle" {
					c.muddle("example.com")
					if !h2.Load() {
						t.Fatal("muddle was not HTTP2")
					}
					return
				}
				e = shadowFetch(c)
			}
			if (check == "valid") != (e == nil) {
				t.Fatalf("unexpected %s result: %v", check, e)
			}
		})
	}
}
func TestShadowTLS13OpenSSL(t *testing.T) { testShadowTLSOpenSSL(t, "", 2) }

func TestShadowTLSBrowserOpenSSL(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		for _, version := range []int{2, 3} {
			t.Run(fmt.Sprintf("%s/v%d", profile, version), func(t *testing.T) { testShadowTLSOpenSSL(t, profile, version) })
		}
	}
}

func testShadowTLSOpenSSL(t *testing.T, profile string, version int) {
	openssl, e := exec.LookPath("openssl")
	if e != nil {
		t.Fatal(e)
	}
	for _, suite := range []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"} {
		t.Run(suite, func(t *testing.T) {
			f := newMutualTLSFixture(t)
			dir := t.TempDir()
			for name, value := range map[string]string{"cert.pem": f.serverCert, "key.pem": f.serverKey, "ca.pem": f.ca} {
				if e = os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); e != nil {
					t.Fatal(e)
				}
			}
			port := unusedPort(t)
			log, e := os.Create(filepath.Join(dir, "openssl.log"))
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(openssl, "s_server", "-accept", portAddress("127.0.0.1", port), "-cert", filepath.Join(dir, "cert.pem"), "-key", filepath.Join(dir, "key.pem"), "-CAfile", filepath.Join(dir, "ca.pem"), "-Verify", "1", "-verify_return_error", "-tls1_3", "-ciphersuites", suite, "-groups", "P-384", "-www", "-quiet")
			if profile != "" {
				cmd.Args = append(cmd.Args, "-cert_comp")
			}
			cmd.Stdout, cmd.Stderr = log, log
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				cmd.Process.Kill()
				cmd.Wait()
				log.Close()
				if t.Failed() {
					b, _ := os.ReadFile(log.Name())
					t.Log(string(b))
				}
			})
			waitPort(t, portAddress("127.0.0.1", port))
			c, e := shadowHandshake(t, portAddress("127.0.0.1", port), f.client())
			if e != nil {
				t.Fatal(e)
			}
			if tls.CipherSuiteName(c.state.CipherSuite) != suite {
				t.Fatal(c.state.CipherSuite)
			}
			if e = shadowFetch(c); e != nil {
				t.Fatal(e)
			}
			c.conn.Close()
			inner := testInbound(t, "shadowsocks")
			inner.Tag = "inner"
			h := ShadowTLSHandshake{Server: "127.0.0.1", ServerPort: port}
			in := Inbound{Type: "shadowtls", Tag: "st", Version: fmt.Sprint(version), Password: "private", Detour: "inner", ShadowTLSOptions: ShadowTLSOptions{Handshake: &h}}
			if version == 3 {
				in.Password = ""
				in.Users = []User{{Password: "private"}}
				in.StrictMode = true
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in, inner}})
			host, ptext, _ := net.SplitHostPort(s.Address("st"))
			p, _ := shadowPort(ptext)
			outer := Outbound{Type: "shadowtls", Tag: "outer", Version: fmt.Sprint(version), Password: "private", Server: host, ServerPort: p, TLS: f.client()}
			if profile != "" {
				outer.TLS.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
			}
			o := testOutbound(t, inner, s.Address("st"))
			o.Detour = "outer"
			client := newTestRuntime(t, Config{Outbounds: []Outbound{o, outer}})
			var wait sync.WaitGroup
			for range 16 {
				wait.Go(func() { assertTCP(t, client) })
			}
			wait.Wait()
		})
	}
}
func TestShadowTLS13Signatures(t *testing.T) {
	ec, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rsaKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	_, ed, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	for _, key := range []crypto.Signer{ec, rsaKey, ed} {
		t.Run(fmt.Sprintf("%T", key), func(t *testing.T) {
			template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, e := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
			if e != nil {
				t.Fatal(e)
			}
			cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
			cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true}
			s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "signature-verified") }))
			s.TLS = cfg
			s.StartTLS()
			defer s.Close()
			options := TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}
			c, e := shadowHandshake(t, s.Listener.Addr().String(), options)
			if e != nil {
				t.Fatal(e)
			}
			if e = shadowFetch(c); e != nil {
				t.Fatal(e)
			}
			h := sha256.New()
			h.Write([]byte("handshake"))
			scheme := tls.Ed25519
			switch key.(type) {
			case *ecdsa.PrivateKey:
				scheme = tls.ECDSAWithP256AndSHA256
			case *rsa.PrivateKey:
				scheme = tls.PSSWithSHA256
			}
			hash, _ := stSignatureHash(scheme)
			data := stSignatureInput(true, h)
			var opts crypto.SignerOpts = hash
			if hash != 0 {
				digest := hash.New()
				digest.Write(data)
				data = digest.Sum(nil)
			}
			if _, ok := key.(*rsa.PrivateKey); ok {
				opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash}
			}
			sig, e := key.Sign(rand.Reader, data, opts)
			if e != nil {
				t.Fatal(e)
			}
			body := binary.BigEndian.AppendUint16(nil, uint16(scheme))
			body = append(body, stVector(sig, 2)...)
			if e = stVerifyCertificateSignature(body, key.Public(), h); e != nil {
				t.Fatal(e)
			}
			body[len(body)-1] ^= 1
			if e = stVerifyCertificateSignature(body, key.Public(), h); e == nil {
				t.Fatal("accepted corrupted CertificateVerify")
			}
		})
	}
}

func TestShadowTLSMalformedData(t *testing.T) {
	capture := new(bytes.Buffer)
	writer := &shadowStream{Conn: memoryNetConn{bytes.NewReader(nil), capture}, version: 3, writeMAC: shadowMAC("private", []byte("challenge"))}
	writer.Write([]byte("first"))
	first := bytes.Clone(capture.Bytes())
	capture.Reset()
	writer.Write([]byte("second"))
	second := bytes.Clone(capture.Bytes())
	for _, test := range []struct {
		name    string
		frames  []byte
		firstOK bool
	}{
		{"corruption", append(bytes.Clone(first[:len(first)-1]), first[len(first)-1]^1), false},
		{"reorder", second, false},
		{"replay", append(bytes.Clone(first), first...), true},
		{"short", shadowFrame(23, []byte{1}), false},
		{"handshake", shadowFrame(22, []byte{1}), false},
		{"oversize", []byte{23, 3, 3, 255, 255}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			reader := &shadowStream{Conn: a, version: 3, readMAC: shadowMAC("private", []byte("challenge"))}
			go func() { writeAll(b, test.frames); io.Copy(io.Discard, b) }()
			var buffer [32]byte
			if test.firstOK {
				if n, e := reader.Read(buffer[:]); e != nil || string(buffer[:n]) != "first" {
					t.Fatal(n, e)
				}
			}
			if n, e := reader.Read(buffer[:]); e == nil || n != 0 {
				t.Fatal("accepted bad record", n, e)
			}
			if n, e := reader.Read(buffer[:]); e == nil || n != 0 {
				t.Fatal("authentication error not sticky", n, e)
			}
		})
	}
	t.Run("blocked-writer", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		stream := &shadowStream{Conn: a, version: 3, readMAC: shadowMAC("private", nil), writeMAC: shadowMAC("private", nil)}
		writeDone := make(chan error, 1)
		go func() { _, e := stream.Write([]byte("writer is blocked")); writeDone <- e }()
		go writeAll(b, shadowFrame(23, []byte{1}))
		var buffer [1]byte
		if _, e := stream.Read(buffer[:]); e == nil {
			t.Fatal("badMAC accepted")
		}
		select {
		case e := <-writeDone:
			if e == nil {
				t.Fatal("blocked writer accepted")
			}
		case <-time.After(time.Second):
			t.Fatal("badMAC deadlocked writer")
		}
	})
}
func TestShadowTLSBackendSelection(t *testing.T) {
	x := ShadowTLSOptions{Handshake: &ShadowTLSHandshake{Server: "default.example", ServerPort: 8443}, HandshakeForServerName: map[string]ShadowTLSHandshake{"named.example": {Server: "specific.example", ServerPort: 9443}}}
	for _, mode := range []string{"off", "authed", "all"} {
		x.WildcardSNI = mode
		for _, authed := range []bool{false, true} {
			h := x.backend("NaMeD.Example", authed)
			if h.Server != "specific.example" || h.ServerPort != 9443 {
				t.Fatal(h)
			}
			h = x.backend("other.example", authed)
			wildcard := mode == "all" || mode == "authed" && authed
			if wildcard && (h.Server != "other.example" || h.ServerPort != 443) || !wildcard && h.Server != "default.example" {
				t.Fatal(mode, authed, h)
			}
		}
	}
}
func TestShadowTLSBackendDetour(t *testing.T) {
	h, security := shadowCover(t, tls.VersionTLS13)
	socks := testInbound(t, "socks")
	forwarder := newTestRuntime(t, Config{Inbounds: []Inbound{socks}})
	forward := testOutbound(t, socks, forwarder.Address(socks.Tag))
	forward.Tag = "cover-detour"
	h.Detour = forward.Tag
	inner := testInbound(t, "vless")
	inner.Tag = "inner"
	inner.TLS = TLSOptions{}
	in := Inbound{Type: "shadowtls", Tag: "st", Version: "3", Detour: "inner", Users: []User{{Password: "private"}}, ShadowTLSOptions: ShadowTLSOptions{Handshake: &ShadowTLSHandshake{Server: "127.0.0.1", ServerPort: 1}, HandshakeForServerName: map[string]ShadowTLSHandshake{"EXAMPLE.COM": h}, StrictMode: true}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in, inner}, Outbounds: []Outbound{forward, {Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct"}})
	o := testOutbound(t, inner, s.Address("st"))
	o.TLS = TLSOptions{}
	o.Detour = "outer"
	host, port, _ := net.SplitHostPort(s.Address("st"))
	p, _ := shadowPort(port)
	outer := Outbound{Type: "shadowtls", Tag: "outer", Server: host, ServerPort: p, Version: "3", Password: "private", TLS: security}
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o, outer}})
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 60000})
}
func TestShadowTLSLifecycle(t *testing.T) {
	for _, v := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			version := uint16(tls.VersionTLS13)
			if v == 1 {
				version = tls.VersionTLS12
			}
			_, c := shadowPair(t, v, version, false, false, "vless")
			var wait sync.WaitGroup
			for range 8 {
				wait.Go(func() { assertTCP(t, c) })
			}
			wait.Wait()
		})
	}
	t.Run("cancel-handshake", func(t *testing.T) {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer listener.Close()
		done := make(chan error, 1)
		go func() {
			conn, e := listener.Accept()
			if e != nil {
				done <- e
				return
			}
			defer conn.Close()
			_, e = io.Copy(io.Discard, conn)
			done <- e
		}()
		host, port, _ := net.SplitHostPort(listener.Addr().String())
		p, _ := shadowPort(port)
		o := Outbound{Type: "shadowtls", Tag: "proxy", Version: "3", Password: "private", Server: host, ServerPort: p, TLS: TLSOptions{Enabled: true, Insecure: true}}
		c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		defer cancel()
		if conn, e := c.Dial(ctx, "tcp", "example.com:80"); e == nil {
			conn.Close()
			t.Fatal("handshake ignored cancellation")
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("handshake connection leaked")
		}
	})
}
func TestShadowTLS13RecordAuthentication(t *testing.T) {
	for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			suite, _ := stSuite(id)
			secret := bytes.Repeat([]byte{1}, suite.hash.Size())
			writer, _ := suite.recordCipher(secret)
			reader, _ := suite.recordCipher(secret)
			frame, e := writer.seal(22, []byte("authenticated handshake"))
			if e != nil {
				t.Fatal(e)
			}
			kind, body, e := reader.open(frame)
			if e != nil || kind != 22 || string(body) != "authenticated handshake" {
				t.Fatal(kind, string(body), e)
			}
			if _, _, e = reader.open(frame); e == nil {
				t.Fatal("replayed TLS record accepted")
			}
			reader, _ = suite.recordCipher(secret)
			frame[len(frame)-1] ^= 1
			if _, _, e = reader.open(frame); e == nil {
				t.Fatal("corrupted TLS record accepted")
			}
		})
	}
}
func TestShadowTLS2LateTickets(t *testing.T) {
	for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			suite, _ := stSuite(id)
			secret := bytes.Repeat([]byte{1}, suite.hash.Size())
			writer, _ := suite.recordCipher(secret)
			reader, _ := suite.recordCipher(secret)
			var wire []byte
			for range 2 {
				record, _ := writer.seal(22, stMessage(4, []byte("late session ticket")))
				wire = append(wire, record...)
			}
			wire = append(wire, shadowFrame(23, []byte("inner proxy reply"))...)
			c := &shadowStream{Conn: readerConn(wire), version: 2, coverCipher: reader}
			got, e := io.ReadAll(c)
			if e != nil || string(got) != "inner proxy reply" {
				t.Fatal(string(got), e)
			}
		})
	}
}
func TestShadowTLSMutualCover(t *testing.T) {
	testShadowTLSMutualCover(t, "")
}

func TestShadowTLSBrowserMutualCover(t *testing.T) {
	for _, profile := range append([]string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"}, browserProfiles...) {
		t.Run(profile, func(t *testing.T) { testShadowTLSMutualCover(t, profile) })
	}
}

func testShadowTLSMutualCover(t *testing.T, profile string) {
	for _, version := range []int{2, 3} {
		for _, tlsVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("v%d/tls%d", version, tlsVersion), func(t *testing.T) {
				f := newMutualTLSFixture(t)
				cfg, e := f.server().config(true, "")
				if e != nil {
					t.Fatal(e)
				}
				cfg.MinVersion = tlsVersion
				cfg.MaxVersion = tlsVersion
				cfg.CurvePreferences = []tls.CurveID{tls.CurveP384}
				cfg.SessionTicketsDisabled = true
				cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "mutual-cover") }))
				cover.TLS = cfg
				cover.StartTLS()
				defer cover.Close()
				host, port, _ := net.SplitHostPort(cover.Listener.Addr().String())
				p, _ := shadowPort(port)
				h := ShadowTLSHandshake{Server: host, ServerPort: p}
				inner := testInbound(t, "vless")
				inner.Tag = "inner"
				inner.TLS = TLSOptions{}
				in := Inbound{Type: "shadowtls", Tag: "st", Version: fmt.Sprint(version), Detour: "inner", ShadowTLSOptions: ShadowTLSOptions{Handshake: &h, StrictMode: version == 3 && tlsVersion == tls.VersionTLS13}}
				if version == 2 {
					in.Password = "private"
				} else {
					in.Users = []User{{Password: "private"}}
				}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in, inner}})
				host, port, _ = net.SplitHostPort(s.Address("st"))
				p, _ = shadowPort(port)
				security := f.client()
				if profile != "" {
					security.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
					security.RecordFragment, security.Fragment = true, true
					security.FragmentFallbackDelay = "1ms"
				}
				security.MaxVersion = "1.3"
				if tlsVersion == tls.VersionTLS12 {
					security.MaxVersion = "1.2"
				}
				security.RecordFragment = true
				outer := Outbound{Type: "shadowtls", Tag: "outer", Server: host, ServerPort: p, Version: fmt.Sprint(version), Password: "private", TLS: security}
				o := testOutbound(t, inner, s.Address("st"))
				o.TLS = TLSOptions{}
				o.Detour = "outer"
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o, outer}})
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 60000})
			})
		}
	}
}

type shadowDeadlineConn struct {
	net.Conn
	deadline atomic.Int64
}

func (c *shadowDeadlineConn) SetDeadline(d time.Time) error {
	c.deadline.Store(d.UnixNano())
	return c.Conn.SetDeadline(d)
}
func TestShadowTLSInnerHandshakeDeadline(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			tlsVersion := uint16(tls.VersionTLS13)
			if version == 1 {
				tlsVersion = tls.VersionTLS12
			}
			h, security := shadowCover(t, tlsVersion)
			in := Inbound{Version: fmt.Sprint(version), ShadowTLSOptions: ShadowTLSOptions{Handshake: &h}}
			if version == 2 {
				in.Password = "private"
			}
			if version == 3 {
				in.Users = []User{{Password: "private"}}
			}
			server := newTestRuntime(t, Config{})
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close()
				tracked := &shadowDeadlineConn{Conn: conn}
				tracked.SetDeadline(time.Now().Add(handshakeTimeout))
				stream, e := server.shadowAccept(tracked, in)
				if e != nil {
					done <- e
					return
				}
				if time.Unix(0, tracked.deadline.Load()).Before(time.Now().Add(handshakeTimeout / 2)) {
					done <- errors.New("inner authentication deadline missing")
					return
				}
				var buf [5]byte
				_, e = io.ReadFull(stream, buf[:])
				if e == nil && string(buf[:]) != "inner" {
					e = errors.New("inner data corrupted")
				}
				done <- e
			}()
			host, port, _ := net.SplitHostPort(listener.Addr().String())
			p, _ := shadowPort(port)
			o := Outbound{Type: "shadowtls", Tag: "proxy", Server: host, ServerPort: p, Version: fmt.Sprint(version), TLS: security}
			if version > 1 {
				o.Password = "private"
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			conn, e := client.Dial(ctx, "tcp", "example.com:80")
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			if e = writeAll(conn, []byte("inner")); e != nil {
				t.Fatal(e)
			}
			select {
			case e = <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
func FuzzShadowTLSHandshake(f *testing.F) {
	h, _ := newSTHello(&tls.Config{ServerName: "example.com"})
	hello, _ := h.marshal("private", nil, true)
	f.Add(hello)
	f.Add([]byte{2, 0, 0, 0})
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		shadowHelloAuth(b, "private")
		shadowServerHello(b)
		stExtensions(b)
		stCertificates(b)
		stCertificateRequest(b)
		shadowReadRecord(bytes.NewReader(b), make([]byte, 5+shadowRecordLimit))
		stServerParameters(b, h)
	})
}
func BenchmarkShadowTLSWrite(b *testing.B) {
	for _, v := range []int{2, 3} {
		b.Run(fmt.Sprint(v), func(b *testing.B) {
			c := &shadowStream{Conn: memoryNetConn{bytes.NewReader(nil), io.Discard}, version: v, writeMAC: shadowMAC("private", []byte("challenge"))}
			data := bytes.Repeat([]byte{1}, 1400)
			c.Write(data)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for range b.N {
				if _, e := c.Write(data); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
