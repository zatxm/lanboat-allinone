//go:build linux

package native

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestAmneziaWGReference(t *testing.T) {
	if os.Getenv("LANBOAT_AWG_CHILD") != "1" {
		ref := os.Getenv("LANBOAT_TEST_AMNEZIA")
		if ref == "" {
			t.Fatal("LANBOAT_TEST_AMNEZIA required for official AmneziaWG interoperability")
		}
		data, err := os.ReadFile(ref)
		if err != nil {
			t.Fatal(err)
		}
		copyPath := filepath.Join(t.TempDir(), "amnezia-reference")
		if err = os.WriteFile(copyPath, data, 0700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("unshare", "-Urnm", os.Args[0], "-test.run", "^TestAmneziaWGReference$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_AWG_CHILD=1", "LANBOAT_TEST_AMNEZIA="+copyPath)
		data, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("AmneziaWG namespace: %v\n%s", err, data)
		}
		t.Log(string(data))
		return
	}
	// Keep the reference daemon's fixed UAPI socket directory off the host filesystem.
	if err := syscall.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	loop, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err = configureLink(loop.Index, 65536); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"plain", "v1", "v2", "v3-header", "v3-padding", "v3-trailers", "v3-timers", "v3"} {
		for _, direction := range []string{"client", "server"} {
			t.Run(version+"/"+direction, func(t *testing.T) {
				private, pub := wgTestKey(t)
				otherKey, otherPub := wgTestKey(t)
				psk, _ := wgTestKey(t)
				iface := "la" + strconv.Itoa(os.Getpid())
				startAWGReference(t, iface)
				runWGTest(t, "ip", "address", "add", "10.56.0.1/24", "dev", iface)
				runWGTest(t, "ip", "link", "set", iface, "mtu", "1420", "up")
				params := []string{"private_key=" + awgHexKey(t, private), "public_key=" + awgHexKey(t, otherPub), "preshared_key=" + awgHexKey(t, psk)}
				options := awgTestOptions(version)
				// Interface settings precede the peer section in the official UAPI.
				params = append(awgUAPIOptions(t, options), params...)
				if options.PersistentKeepalive != "" {
					params = append(params, "persistent_keepalive_interval="+string(options.PersistentKeepalive))
				}
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				if direction == "client" {
					port := unusedPort(t)
					params = append([]string{"listen_port=" + strconv.Itoa(int(port))}, params...)
					params = append(params, "allowed_ip=10.56.0.2/32")
					configureAWGReference(t, iface, params)
					out := Outbound{Type: "wireguard", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, SSHOptions: SSHOptions{PrivateKey: []string{otherKey}}, WireGuardOptions: WireGuardOptions{PublicKey: pub, PreSharedKey: psk, LocalAddress: []string{"10.56.0.2/32"}, Amnezia: options}}
					r := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					tcp, udp := awgEchoOrigin(t)
					conn, err := r.Dial(ctx, "tcp", tcp)
					if err != nil {
						t.Fatal(err)
					}
					wgRoundtripTCP(t, conn)
					conn, err = r.Dial(ctx, "udp", udp)
					if err != nil {
						t.Fatal(err)
					}
					if version == "v3" {
						awgLiveReference(t, conn)
					}
					wgRoundtripUDP(t, conn)
				} else {
					proxy := socksEchoProxy(t)
					out := testOutbound(t, Inbound{Type: "socks"}, proxy)
					out.Username, out.Password = "", ""
					in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{otherKey}}, WireGuardOptions: WireGuardOptions{Amnezia: options, Peers: []WireGuardPeer{{PublicKey: pub, PreSharedKey: psk, AllowedIPs: []string{"10.56.0.1/32"}}}}}
					r := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{out}})
					params = append(params, "allowed_ip=192.0.2.9/32", "endpoint="+r.Address("server"))
					configureAWGReference(t, iface, params)
					runWGTest(t, "ip", "route", "add", "192.0.2.9/32", "dev", iface)
					t.Cleanup(func() { exec.Command("ip", "route", "delete", "192.0.2.9/32", "dev", iface).Run() })
					conn, err := net.DialTimeout("tcp", "192.0.2.9:443", 8*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					wgRoundtripTCP(t, conn)
					conn, err = net.Dial("udp", "192.0.2.9:9000")
					if err != nil {
						t.Fatal(err)
					}
					if version == "v3" {
						awgLiveReference(t, conn)
					}
					wgRoundtripUDP(t, conn)
				}
			})
		}
	}
}

func awgLiveReference(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	for i := range 32 {
		want := []byte(fmt.Sprintf("official-active-rekey-%d", i))
		if _, err := conn.Write(want); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 512)
		n, err := conn.Read(b)
		if err != nil || string(b[:n]) != string(want) {
			t.Fatal("official live rekey", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func awgHexKey(t *testing.T, key string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func startAWGReference(t *testing.T, iface string) {
	t.Helper()
	log, err := os.Create(filepath.Join(t.TempDir(), "reference.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Getenv("LANBOAT_TEST_AMNEZIA"), "-f", iface)
	cmd.Stdout, cmd.Stderr = log, log
	cmd.Env = append(os.Environ(), "LOG_LEVEL=error")
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		os.Remove("/var/run/amneziawg/" + iface + ".sock")
		if t.Failed() {
			raw, _ := os.ReadFile(log.Name())
			t.Log(string(raw))
		}
	})
	for range 200 {
		conn, err := net.DialTimeout("unix", "/var/run/amneziawg/"+iface+".sock", 10*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("official AmneziaWG did not create UAPI socket")
}

func configureAWGReference(t *testing.T, iface string, params []string) {
	t.Helper()
	conn, err := net.Dial("unix", "/var/run/amneziawg/"+iface+".sock")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = io.WriteString(conn, "set=1\n"+strings.Join(params, "\n")+"\n\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || line != "errno=0\n" {
		t.Fatal("official UAPI rejected configuration", line, err)
	}
}

func awgUAPIOptions(t *testing.T, o *AmneziaWGOptions) []string {
	out := []string{fmt.Sprint("jc=", o.Jc), fmt.Sprint("jmin=", o.JMin), fmt.Sprint("jmax=", o.JMax), fmt.Sprint("s1=", o.S1), fmt.Sprint("s2=", o.S2), fmt.Sprint("s3=", o.S3), fmt.Sprint("s4=", o.S4)}
	for i, h := range []WGHeaderRange{o.H1, o.H2, o.H3, o.H4} {
		if h != "" {
			out = append(out, fmt.Sprintf("h%d=%s", i+1, h))
		}
	}
	for i, s := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
		if s != "" {
			out = append(out, fmt.Sprintf("i%d=%s", i+1, s))
		}
	}
	if o.HeaderProtectionKey != "" {
		out = append(out, "header_protection_key="+awgHexKey(t, o.HeaderProtectionKey))
	}
	for _, item := range []struct {
		name  string
		value WGHeaderRange
	}{
		{"content_padding_addition", o.ContentPaddingAddition}, {"rekey_after_time", o.RekeyAfterTime}, {"rekey_timeout", o.RekeyTimeout}, {"reject_after_time", o.RejectAfterTime}, {"keepalive_timeout", o.KeepaliveTimeout}, {"max_handshake_attempts", o.MaxHandshakeAttempts},
	} {
		if item.value != "" {
			out = append(out, item.name+"="+string(item.value))
		}
	}
	out = append(out, fmt.Sprint("random_trailers=", o.RandomTrailers), fmt.Sprint("disable_cookies=", o.DisableCookies))
	return out
}

func awgEchoOrigin(t *testing.T) (string, string) {
	t.Helper()
	tcp, err := net.Listen("tcp", "10.56.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tcp.Close() })
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udp, err := net.ListenPacket("udp", "10.56.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, err := udp.ReadFrom(b)
			if err != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	return tcp.Addr().String(), udp.LocalAddr().String()
}
