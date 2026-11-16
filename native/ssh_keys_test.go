package native

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sshKeygen(t *testing.T, kind, bits, cipher, password string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	args := []string{"-q", "-t", kind, "-N", password, "-a", "4", "-f", path}
	if bits != "" {
		args = append(args, "-b", bits)
	}
	if cipher != "" {
		args = append(args, "-Z", cipher)
	}
	if out, e := exec.Command("ssh-keygen", args...).CombinedOutput(); e != nil {
		t.Fatalf("ssh-keygen: %s %v", out, e)
	}
	pub, e := os.ReadFile(path + ".pub")
	if e != nil {
		t.Fatal(e)
	}
	return path, strings.TrimSpace(string(pub))
}

func TestSSHEncryptedPrivateKeyOracle(t *testing.T) {
	for _, cipher := range []string{"aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"} {
		t.Run(cipher, func(t *testing.T) {
			path, pub := sshKeygen(t, "ed25519", "", cipher, "解密-password")
			key, e := sshPrivate(nil, path, "解密-password")
			if e != nil {
				t.Fatal(e)
			}
			blob, _ := sshPubKey(key.Public())
			if !sshPinned(blob, []string{pub}) {
				t.Fatal("decrypted public key differs")
			}
			if _, e = sshPrivate(nil, path, "wrong"); e == nil {
				t.Fatal("wrong passphrase accepted")
			}
			if _, e = sshPrivate(nil, path); e == nil {
				t.Fatal("missing passphrase accepted")
			}
		})
	}
	for _, bits := range []string{"256", "384", "521"} {
		t.Run("ECDSA"+bits, func(t *testing.T) {
			path, pub := sshKeygen(t, "ecdsa", bits, "aes256-ctr", "password")
			key, e := sshPrivate(nil, path, "password")
			if e != nil {
				t.Fatal(e)
			}
			blob, _ := sshPubKey(key.Public())
			if !sshPinned(blob, []string{pub}) {
				t.Fatal("ECDSA key mismatch")
			}
			r := sshReader{b: blob}
			alg := string(r.str())
			sig, e := sshSign(key, alg, []byte("message"))
			if e != nil {
				t.Fatal(e)
			}
			if e = sshVerify(blob, alg, []byte("message"), sig); e != nil {
				t.Fatal(e)
			}
			if sshVerify(blob, alg, []byte("tampered"), sig) == nil {
				t.Fatal("modified message accepted")
			}
		})
	}
}

func TestSSHECDSAFormats(t *testing.T) {
	key, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	sec1, _ := x509.MarshalECPrivateKey(key)
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	for typ, der := range map[string][]byte{"EC PRIVATE KEY": sec1, "PRIVATE KEY": pkcs8} {
		got, e := sshPrivate([]string{string(pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}))}, "")
		if e != nil || !got.Public().(*ecdsa.PublicKey).Equal(key.Public()) {
			t.Fatal(typ, e)
		}
	}
}

func TestSSHPKCS8EncryptedOpenSSL(t *testing.T) {
	key, pub := sshTestKey(t)
	for _, cipher := range []string{"aes-128-cbc", "aes-192-cbc", "aes-256-cbc"} {
		for _, prf := range []string{"hmacWithSHA1", "hmacWithSHA256", "hmacWithSHA384", "hmacWithSHA512"} {
			t.Run(cipher+"/"+prf, func(t *testing.T) {
				cmd := exec.Command("openssl", "pkcs8", "-topk8", "-v2", cipher, "-v2prf", prf, "-iter", "128", "-passout", "pass:private-password")
				cmd.Stdin = strings.NewReader(key)
				raw, e := cmd.Output()
				if e != nil {
					t.Fatal(e)
				}
				k, e := sshPrivate([]string{string(raw)}, "", "private-password")
				if e != nil {
					t.Fatal(e)
				}
				blob, _ := sshPubKey(k.Public())
				if !sshPinned(blob, []string{pub}) {
					t.Fatal("PKCS8 key mismatch")
				}
				if _, e = sshPrivate([]string{string(raw)}, "", "wrong"); e == nil {
					t.Fatal("wrong PKCS8 password accepted")
				}
			})
		}
	}
}

func TestSSHKeyboardOpenSSHClientInterop(t *testing.T) {
	key, pub := sshTestKey(t)
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "ssh", Tag: "s", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{key}}, Users: []User{{Username: "user", Password: "secret"}}}}})
	h, p, _ := net.SplitHostPort(server.Address("s"))
	dir := t.TempDir()
	known := filepath.Join(dir, "known")
	ask := filepath.Join(dir, "ask")
	os.WriteFile(known, []byte("["+h+"]:"+p+" "+pub+"\n"), 0600)
	os.WriteFile(ask, []byte("#!/bin/sh\nprintf '%s\\n' secret\n"), 0700)
	ctx, cancel := context.WithCancel(context.Background())
	port := unusedPort(t)
	cmd := exec.CommandContext(ctx, "ssh", "-N", "-D", portAddress("127.0.0.1", port), "-p", p, "-o", "PreferredAuthentications=keyboard-interactive", "-o", "PubkeyAuthentication=no", "-o", "ExitOnForwardFailure=yes", "-o", "UserKnownHostsFile="+known, "user@"+h)
	cmd.Env = append(os.Environ(), "SSH_ASKPASS="+ask, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=:lanboat-test")
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		cancel()
		cmd.Wait()
		if t.Failed() {
			t.Log(log.String())
		}
	}()
	sshWait(t, port)
	client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: port}}})
	assertTCP(t, client)
}

func TestSSHECDSAOpenSSHServerInterop(t *testing.T) {
	for _, bits := range []string{"256", "384", "521"} {
		t.Run(bits, func(t *testing.T) {
			host, pub := sshKeygen(t, "ecdsa", bits, "", "")
			user, _ := sshKeygen(t, "ecdsa", bits, "aes256-ctr", "private")
			dir, port := t.TempDir(), unusedPort(t)
			cfg := filepath.Join(dir, "sshd_config")
			if e := os.WriteFile(cfg, []byte(fmtSSHConfig(dir, host, user+".pub", port)), 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", cfg)
			log, e := os.Create(filepath.Join(dir, "sshd.log"))
			if e != nil {
				t.Fatal(e)
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
			sshWait(t, port)
			client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "ssh", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Username: os.Getenv("USER"), SSHOptions: SSHOptions{PrivateKeyPath: user, PrivateKeyPassphrase: "private", HostKey: []string{pub}}}}})
			assertTCP(t, client)
		})
	}
}
func sshWait(t *testing.T, port uint16) {
	t.Helper()
	for range 300 {
		c, e := net.DialTimeout("tcp", portAddress("127.0.0.1", port), 10*time.Millisecond)
		if e == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("SSH did not listen")
}

func TestSSHECDSAOpenSSHClientInterop(t *testing.T) {
	for _, bits := range []string{"256", "384", "521"} {
		t.Run(bits, func(t *testing.T) {
			host, pub := sshKeygen(t, "ecdsa", bits, "aes256-ctr", "host-private")
			user, userPub := sshKeygen(t, "ecdsa", bits, "", "")
			in := Inbound{Type: "ssh", Tag: "s", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKeyPath: host, PrivateKeyPassphrase: "host-private"}, Users: []User{{Username: "user", AuthorizedKeys: []string{userPub}}}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			h, p, _ := net.SplitHostPort(server.Address("s"))
			known := filepath.Join(t.TempDir(), "known")
			os.WriteFile(known, []byte("["+h+"]:"+p+" "+pub+"\n"), 0600)
			port := unusedPort(t)
			ctx, cancel := context.WithCancel(context.Background())
			cmd := exec.CommandContext(ctx, "ssh", "-N", "-D", portAddress("127.0.0.1", port), "-i", user, "-p", p, "-o", "BatchMode=yes", "-o", "RekeyLimit=16K", "-o", "ExitOnForwardFailure=yes", "-o", "UserKnownHostsFile="+known, "user@"+h)
			log, _ := os.Create(filepath.Join(t.TempDir(), "ssh.log"))
			cmd.Stdout, cmd.Stderr = log, log
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				cancel()
				cmd.Wait()
				log.Close()
				if t.Failed() {
					b, _ := os.ReadFile(log.Name())
					t.Log(string(b))
				}
			})
			sshWait(t, port)
			client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: port}}})
			assertTCP(t, client)
		})
	}
}

func TestSSHKeyboardInteractive(t *testing.T) {
	key, pub := sshTestKey(t)
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "ssh", Tag: "s", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{key}}, Users: []User{{Username: "user", Password: "secret"}}}}})
	_, p, _ := net.SplitHostPort(server.Address("s"))
	port, _ := strconv.ParseUint(p, 10, 16)
	for _, answer := range []string{"secret", "wrong"} {
		client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "ssh", Tag: "proxy", Server: "127.0.0.1", ServerPort: uint16(port), Username: "user", SSHOptions: SSHOptions{HostKey: []string{pub}, KeyboardInteractive: []string{answer}}}}})
		if answer == "secret" {
			assertTCP(t, client)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if c, e := client.Dial(ctx, "tcp", "example.com:443"); e == nil {
				c.Close()
				t.Fatal("wrong interactive answer accepted")
			}
		}
	}
}
