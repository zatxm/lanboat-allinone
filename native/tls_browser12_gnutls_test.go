package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBrowserTLS12GnuTLS(t *testing.T) {
	f := newMutualTLSFixture(t)
	rsaCert := browserTLS12RSA(t)
	rsaKey, err := x509.MarshalPKCS8PrivateKey(rsaCert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"safari15_3", "safari15_5", "safari16_0", "safari26_3"} {
		for _, suite := range []struct {
			kx string
			id uint16
		}{{"ECDHE-ECDSA", 0xc008}, {"ECDHE-RSA", 0xc012}, {"RSA", 0x000a}} {
			t.Run(profile+"/"+suite.kx, func(t *testing.T) {
				cert, key, ca := f.serverCert, f.serverKey, f.ca
				if suite.kx != "ECDHE-ECDSA" {
					cert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rsaCert.Certificate[0]}))
					key = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rsaKey}))
					ca = cert
				}
				dir := t.TempDir()
				certPath, keyPath := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key")
				for path, data := range map[string]string{certPath: cert, keyPath: key} {
					if err := os.WriteFile(path, []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "python3", filepath.Join("..", "tests", "tls12-gnutls.py"), "--cert", certPath, "--key", keyPath, "--kx", suite.kx)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				out, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { cmd.Process.Kill(); cmd.Wait() }()
				reader := bufio.NewReader(out)
				address, err := reader.ReadString('\n')
				if err != nil {
					cmd.Wait()
					t.Fatal(err, stderr.String())
				}
				raw, err := net.DialTimeout("tcp", strings.TrimSpace(address), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				o := TLSOptions{Enabled: true, ServerName: "example.com", Certificate: []string{ca}, UTLS: &BrowserTLSOptions{Enabled: true, Fingerprint: profile}}
				cfg, err := o.config(false, "example.com")
				if err != nil {
					t.Fatal(err)
				}
				c := clientTLS(raw, cfg, o)
				if err := c.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				if state := c.ConnectionState(); state.Version != tls.VersionTLS12 || state.CipherSuite != suite.id || len(state.VerifiedChains) == 0 {
					t.Fatal("wrong TLS1.2/3DES selection", state)
				}
				payload := bytes.Repeat([]byte("GnuTLS3DES"), 4096)
				written := make(chan error, 1)
				go func() {
					_, err := c.Write(payload)
					if err == nil {
						err = c.CloseWrite()
					}
					written <- err
				}()
				got, err := io.ReadAll(c)
				if err != nil || !bytes.Equal(got, payload) {
					t.Fatal("GnuTLS echo", len(got), err)
				}
				if err := <-written; err != nil {
					t.Fatal(err)
				}
				var report struct{ Version, Cipher, Kx string }
				if err := json.NewDecoder(reader).Decode(&report); err != nil {
					t.Fatal(err)
				}
				if err := cmd.Wait(); err != nil {
					t.Fatal(err, stderr.String())
				}
				if report.Version != "TLS1.2" || report.Cipher != "3DES-CBC" || report.Kx != suite.kx {
					t.Fatal("reference did not exercise the required suite", report)
				}
			})
		}
	}
}
