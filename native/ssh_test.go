package native

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func sshTestKey(t *testing.T) (string, string) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	blob, _ := sshPubKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
}
func TestSSHIndependent(t *testing.T) {
	key, pub := sshTestKey(t)
	userKey, userPub := sshTestKey(t)
	for _, auth := range []string{"password", "publickey"} {
		t.Run(auth, func(t *testing.T) {
			in := Inbound{Type: "ssh", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{key}}, Users: []User{{Username: "user", Password: "private", AuthorizedKeys: []string{userPub}}}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.UUID = ""
			out.Username = "user"
			out.SSHOptions = SSHOptions{HostKey: []string{pub}}
			if auth == "publickey" {
				out.PrivateKey = []string{userKey}
				out.Password = ""
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096, 60000})
		})
	}
}
func TestSSHOpenSSHClientInterop(t *testing.T) {
	if _, e := exec.LookPath("ssh"); e != nil {
		t.Fatal(e)
	}
	key, pub := sshTestKey(t)
	dir := t.TempDir()
	userPath := filepath.Join(dir, "user")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", userPath)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatal(string(out), e)
	}
	userPub, _ := os.ReadFile(userPath + ".pub")
	in := Inbound{Type: "ssh", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{key}}, Users: []User{{Username: "user", AuthorizedKeys: []string{strings.TrimSpace(string(userPub))}}}}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	h, p, _ := net.SplitHostPort(server.Address("server"))
	hostFile := filepath.Join(dir, "known_hosts")
	os.WriteFile(hostFile, []byte("["+h+"]:"+p+" "+pub+"\n"), 0600)
	local := unusedPort(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd = exec.CommandContext(ctx, "ssh", "-N", "-D", portAddress("127.0.0.1", local), "-i", userPath, "-p", p, "-o", "BatchMode=yes", "-o", "RekeyLimit=16K", "-o", "ExitOnForwardFailure=yes", "-o", "UserKnownHostsFile="+hostFile, "user@"+h)
	log := filepath.Join(dir, "ssh.log")
	f, _ := os.Create(log)
	cmd.Stdout = f
	cmd.Stderr = f
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cancel()
		cmd.Wait()
		f.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log)
			t.Log(string(b))
		}
	})
	for range 300 {
		c, e := net.DialTimeout("tcp", portAddress("127.0.0.1", local), time.Millisecond*10)
		if e == nil {
			c.Close()
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: "127.0.0.1", ServerPort: local}}})
	assertTCP(t, client)
}
func TestSSHOpenSSHServerInterop(t *testing.T) {
	if _, e := exec.LookPath("sshd"); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	hostPath := filepath.Join(dir, "host")
	userPath := filepath.Join(dir, "user")
	for _, p := range []string{hostPath, userPath} {
		cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", p)
		if out, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(string(out), e)
		}
	}
	hostPub, _ := os.ReadFile(hostPath + ".pub")
	port := unusedPort(t)
	cfg := fmtSSHConfig(dir, hostPath, userPath+".pub", port)
	path := filepath.Join(dir, "sshd_config")
	os.WriteFile(path, []byte(cfg), 0600)
	cmd := exec.Command("/usr/sbin/sshd", "-D", "-e", "-f", path)
	log := filepath.Join(dir, "sshd.log")
	f, _ := os.Create(log)
	cmd.Stdout = f
	cmd.Stderr = f
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		f.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log)
			t.Log(string(b))
		}
	})
	for range 300 {
		c, e := net.DialTimeout("tcp", portAddress("127.0.0.1", port), time.Millisecond*10)
		if e == nil {
			c.Close()
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "ssh", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Username: os.Getenv("USER"), SSHOptions: SSHOptions{PrivateKeyPath: userPath, HostKey: []string{strings.TrimSpace(string(hostPub))}}}}})
	assertTCP(t, client)
}
func fmtSSHConfig(dir, host, authorized string, port uint16) string {
	return "ListenAddress 127.0.0.1\nPort " + strconv.Itoa(int(port)) + "\nHostKey " + host + "\nPidFile " + filepath.Join(dir, "sshd.pid") + "\nAuthorizedKeysFile " + authorized + "\nStrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\nAllowTcpForwarding yes\nRekeyLimit 16K\nLogLevel DEBUG\n"
}
func TestSSHRejectWrongHostAndPassword(t *testing.T) {
	key, pub := sshTestKey(t)
	_, wrong := sshTestKey(t)
	in := Inbound{Type: "ssh", Tag: "s", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{key}}, Users: []User{{Username: "user", Password: "secret"}}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	for _, test := range []struct{ pin, password string }{{wrong, "secret"}, {pub, "wrong"}} {
		o := testOutbound(t, in, s.Address("s"))
		o.Username = "user"
		o.Password = test.password
		o.HostKey = []string{test.pin}
		r := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if c, e := r.Dial(ctx, "tcp", "example.com:443"); e == nil {
			c.Close()
			t.Fatal("invalid credentials accepted")
		}
	}
}
func TestSSHMalformedPackets(t *testing.T) {
	for _, n := range []uint32{0, 1, 12, sshMaxPacket + 1, ^uint32(0)} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			var raw [16]byte
			raw[0] = byte(n >> 24)
			raw[1] = byte(n >> 16)
			raw[2] = byte(n >> 8)
			raw[3] = byte(n)
			b.Write(raw[:])
		}()
		w := &sshWire{Conn: a, reader: bufioForSSH(a)}
		if _, e := w.readPacket(); e == nil {
			t.Fatal("invalid SSH packet accepted")
		}
		a.Close()
		<-done
	}
}
func bufioForSSH(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

func TestSSHConcurrentChannelReuse(t *testing.T) {
	key, pub := sshTestKey(t)
	in := Inbound{Type: "ssh", Tag: "s", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{key}}, Users: []User{{Username: "user", Password: "private"}}}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("s"))
	out.Username = "user"
	out.HostKey = []string{pub}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	want := strings.Repeat("pooled SSH channel", 4000)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, want) }))
	defer origin.Close()
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return client.Dial(ctx, network, address)
	}}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	errors := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 16 {
				res, e := httpClient.Get(origin.URL)
				if e != nil {
					errors <- e
					return
				}
				b, e := io.ReadAll(res.Body)
				res.Body.Close()
				if e != nil {
					errors <- e
					return
				}
				if string(b) != want {
					errors <- fmt.Errorf("truncated SSH body: %d", len(b))
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	for e := range errors {
		t.Error(e)
	}
	client.sshClients["proxy"].mu.Lock()
	session := client.sshClients["proxy"].current
	client.sshClients["proxy"].mu.Unlock()
	if session == nil {
		t.Fatal("no shared SSH session")
	}
	session.mu.Lock()
	n := session.next
	session.mu.Unlock()
	if n != 128 {
		t.Fatalf("expected 128 channels in one session, got %d", n)
	}
}
