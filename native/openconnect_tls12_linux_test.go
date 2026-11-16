//go:build linux

package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestOCTLS12RenegotiationGnuTLS(t *testing.T) {
	for _, suite := range ocTLS12Suites {
		for _, server := range []bool{false, true} {
			for _, initiator := range []string{"native", "reference"} {
				for _, mutual := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/server=%t/%s/mtls=%t", tls.CipherSuiteName(suite), server, initiator, mutual), func(t *testing.T) {
						testOCTLS12GnuTLS(t, suite, server, initiator, mutual, "")
					})
				}
			}
		}
	}
}

func TestBrowserOCTLS12RekeyGnuTLS(t *testing.T) {
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		h, err := newSTHello(&tls.Config{})
		if err != nil {
			t.Fatal(err)
		}
		if err := h.initBrowser(profile); err != nil {
			t.Fatal(err)
		}
		for _, suite := range h.suites {
			if _, ok := browserTLS12Cipher(suite); !ok {
				continue
			}
			for _, initiator := range []string{"native", "reference"} {
				for _, mutual := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%04x/%s/mtls=%t", profile, suite, initiator, mutual), func(t *testing.T) {
						testOCTLS12GnuTLS(t, suite, false, initiator, mutual, profile)
					})
				}
			}
		}
	}
}

func testOCTLS12GnuTLS(t *testing.T, suite uint16, server bool, initiator string, mutual bool, profile string) {
	t.Helper()

	f := newMutualTLSFixture(t)
	cert, key := f.serverCert, f.serverKey
	kx := "ECDHE-ECDSA"
	spec, _ := browserTLS12Cipher(suite)
	if spec.rsaCertificate {
		o := certificate(t)
		cert, key = o.Certificate[0], o.Key[0]
		kx = "ECDHE-RSA"
		if spec.rsaKeyExchange {
			kx = "RSA"
		}
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(f.ca))
	roots.AppendCertsFromPEM([]byte(cert))
	trust := f.ca + cert
	pair, e := tls.X509KeyPair([]byte(cert), []byte(key))
	if e != nil {
		t.Fatal(e)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{pair}}
	role := "client"
	if !server {
		role = "server"
		cfg.Certificates = nil
		cfg.ServerName = "example.com"
		cfg.RootCAs = roots
		if mutual {
			pair, e = tls.X509KeyPair([]byte(f.clientCert), []byte(f.clientKey))
			if e != nil {
				t.Fatal(e)
			}
			cfg.Certificates = []tls.Certificate{pair}
		}
	} else {
		cert, key = f.clientCert, f.clientKey
		if mutual {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
			cfg.ClientCAs = roots
		}
	}
	dir := t.TempDir()
	write := func(name, value string) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, []byte(value), 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	cipher, mac := "AES-128-GCM", "AEAD"
	if ocTLS12Hash(suite)().Size() == 48 {
		cipher = "AES-256-GCM"
	}
	if suite == tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 || suite == tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 {
		cipher = "CHACHA20-POLY1305"
	}
	if spec.macSize != 0 {
		cipher = "AES-128-CBC"
		if spec.keySize == 32 {
			cipher = "AES-256-CBC"
		}
		if spec.keySize == 24 {
			cipher = "3DES-CBC"
		}
		mac = map[int]string{20: "SHA1", 32: "SHA256", 48: "SHA384"}[spec.macSize]
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if !server {
		listener.Close()
	}
	request, _ := json.Marshal(map[string]any{"role": role, "initiator": initiator, "mutual": mutual, "port": port, "cipher": cipher, "mac": mac, "kx": kx, "cert": write("cert.pem", cert), "key": write("key.pem", key), "ca": write("ca.pem", trust)})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "../tests/tls12-rekey-reference.py")
	cmd.Stdin = bytes.NewReader(request)
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	output := bufio.NewReader(stdout)
	var raw net.Conn
	if !server {
		line, e := output.ReadString('\n')
		if e != nil || line != "READY\n" {
			t.Fatal(line, e)
		}
		raw, e = net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if e != nil {
			t.Fatal(e)
		}
	} else {
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
		raw, e = listener.Accept()
		if e != nil {
			t.Fatal(e)
		}
	}
	defer raw.Close()
	options := TLSOptions{}
	if profile != "" {
		options.UTLS = &BrowserTLSOptions{Enabled: true, Fingerprint: profile}
	}
	secured, e := handshakeOCTLS(ctx, raw, cfg, options, server)
	if e != nil {
		t.Fatal("initial handshake", e)
	}
	c := secured.(*ocTLS12)
	c.enabled.Store(true)
	defer c.Close()
	line, e := output.ReadString('\n')
	if e != nil || line != "HANDSHAKE\n" {
		t.Fatal(line, e)
	}
	reads := ocTLS12ReadLoop(c)
	exporters := make([]string, 0, 3)
	for round, size := range []int{1, 513, 16000} {
		var body []byte
		for len(body) < size {
			select {
			case b, ok := <-reads:
				if !ok {
					t.Fatal("native read closed")
				}
				body = append(body, b...)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		for i, b := range body {
			if b != byte(i+round) {
				t.Fatal("payload mismatch")
			}
		}
		exporter, e := ocExporter(c)
		if e != nil {
			t.Fatal(e)
		}
		exporters = append(exporters, hex.EncodeToString(exporter))
		if _, e = c.Write(body); e != nil {
			t.Fatal(e)
		}
		if round < 2 && initiator == "native" {
			if e = c.renegotiate(ctx); e != nil {
				t.Fatal("native rekey", e)
			}
		}
	}
	line, e = output.ReadString('\n')
	if e != nil && e != io.EOF {
		t.Fatal(e)
	}
	var result struct {
		Passed    bool
		Rekeys    int
		Version   string
		Exporters []string
	}
	if e = json.Unmarshal([]byte(line), &result); e != nil || !result.Passed || result.Rekeys != 2 {
		t.Fatal(line, e)
	}
	if !bytes.Equal([]byte(fmt.Sprint(result.Exporters)), []byte(fmt.Sprint(exporters))) {
		t.Fatal("GnuTLS exporter mismatch")
	}
	if c.generation.Load() != 2 {
		t.Fatal("rekey generation", c.generation.Load())
	}
	if e = cmd.Wait(); e != nil {
		t.Fatal(e)
	}
	t.Log("GnuTLS", result.Version, "two in-place rekeys and exporters matched")
}
