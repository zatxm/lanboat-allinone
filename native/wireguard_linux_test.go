//go:build linux

package native

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWireGuardKernelInterop(t *testing.T) {
	wireGuardKernelInterop(t, false)
}

func TestWGObfsKernelReference(t *testing.T) {
	wireGuardKernelInterop(t, true)
}

func wireGuardKernelInterop(t *testing.T, masked bool) {
	t.Helper()
	if os.Getenv("LANBOAT_WG_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=45s")
		source, e := exec.LookPath("wg")
		if e != nil {
			t.Fatal(e)
		}
		binary, e := os.ReadFile(source)
		if e != nil {
			t.Fatal(e)
		}
		reference := filepath.Join(t.TempDir(), "wireguard-reference")
		if e = os.WriteFile(reference, binary, 0700); e != nil {
			t.Fatal(e)
		}
		cmd.Env = append(os.Environ(), "LANBOAT_WG_CHILD=1", "LANBOAT_TEST_WG="+reference)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("WireGuard namespace: %v\n%s", e, out)
		}
		t.Log(string(out))
		return
	}
	loop, e := net.InterfaceByName("lo")
	if e != nil {
		t.Fatal(e)
	}
	if e = configureLink(loop.Index, 65536); e != nil {
		t.Fatal(e)
	}
	for _, direction := range []string{"client", "server"} {
		t.Run(direction, func(t *testing.T) {
			private, pub := wgTestKey(t)
			otherKey, otherPub := wgTestKey(t)
			psk, _ := wgTestKey(t)
			dir := t.TempDir()
			keyPath := filepath.Join(dir, "key")
			os.WriteFile(keyPath, []byte(private), 0600)
			pskPath := filepath.Join(dir, "psk")
			os.WriteFile(pskPath, []byte(psk), 0600)
			runWGTest(t, "ip", "link", "add", "lbwg0", "type", "wireguard")
			defer exec.Command("ip", "link", "delete", "lbwg0").Run()
			runWGTest(t, "ip", "address", "add", "10.55.0.1/24", "dev", "lbwg0")
			runWGTest(t, "ip", "link", "set", "lbwg0", "up")
			var mask *WGObfsOptions
			if masked {
				mask = &WGObfsOptions{Password: "kernel-wgobfs-test"}
				runWGTest(t, "ip", "link", "set", "lbwg0", "mtu", "1420")
			}
			if direction == "client" {
				port := unusedPort(t)
				runWGTest(t, "wg", "set", "lbwg0", "listen-port", strconv.Itoa(int(port)), "private-key", keyPath, "peer", otherPub, "preshared-key", pskPath, "allowed-ips", "10.55.0.2/32")
				if masked {
					ref := startWGObfsReference(t, "unobfs", portAddress("127.0.0.1", port), mask.Password)
					_, rawPort, _ := net.SplitHostPort(ref)
					n, _ := strconv.Atoi(rawPort)
					port = uint16(n)
				}
				r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "wireguard", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, SSHOptions: SSHOptions{PrivateKey: []string{otherKey}}, WireGuardOptions: WireGuardOptions{WGObfs: mask, PublicKey: pub, PreSharedKey: psk, LocalAddress: []string{"10.55.0.2/32"}}}}})
				tcp, e := net.Listen("tcp", "10.55.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer tcp.Close()
				go func() {
					for {
						c, e := tcp.Accept()
						if e != nil {
							return
						}
						go func() { defer c.Close(); io.Copy(c, c) }()
					}
				}()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c, e := r.Dial(ctx, "tcp", tcp.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				wgRoundtripTCP(t, c)
				udp, e := net.ListenPacket("udp", "10.55.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer udp.Close()
				go func() {
					b := make([]byte, 65535)
					for {
						n, a, e := udp.ReadFrom(b)
						if e != nil {
							return
						}
						udp.WriteTo(b[:n], a)
					}
				}()
				c, e = r.Dial(ctx, "udp", udp.LocalAddr().String())
				if e != nil {
					t.Fatal(e)
				}
				wgRoundtripUDP(t, c)
			} else {
				proxy := socksEchoProxy(t)
				out := testOutbound(t, Inbound{Type: "socks"}, proxy)
				out.Username, out.Password = "", ""
				in := Inbound{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{otherKey}}, WireGuardOptions: WireGuardOptions{WGObfs: mask, Peers: []WireGuardPeer{{PublicKey: pub, PreSharedKey: psk, AllowedIPs: []string{"10.55.0.1/32"}}}}}
				r := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{out}})
				endpoint := r.Address("server")
				if masked {
					endpoint = startWGObfsReference(t, "obfs", endpoint, mask.Password)
				}
				runWGTest(t, "wg", "set", "lbwg0", "private-key", keyPath, "peer", otherPub, "preshared-key", pskPath, "allowed-ips", "192.0.2.9/32", "endpoint", endpoint)
				runWGTest(t, "ip", "route", "add", "192.0.2.9/32", "dev", "lbwg0")
				c, e := net.DialTimeout("tcp", "192.0.2.9:443", 5*time.Second)
				if e != nil {
					t.Fatal(e)
				}
				wgRoundtripTCP(t, c)
				c, e = net.Dial("udp", "192.0.2.9:9000")
				if e != nil {
					t.Fatal(e)
				}
				wgRoundtripUDP(t, c)
			}
		})
	}
}
func runWGTest(t *testing.T, name string, args ...string) {
	t.Helper()
	if name == "wg" {
		name = os.Getenv("LANBOAT_TEST_WG")
	}
	cmd := exec.Command(name, args...)
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), e, b)
	}
}
func wgRoundtripTCP(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	want := bytes.Repeat([]byte("WireGuard external TCP"), 10000)
	done := make(chan error, 1)
	go func() { done <- writeAll(c, want) }()
	got := make([]byte, len(want))
	if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, want) {
		t.Fatalf("TCP echo: %v", e)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func wgRoundtripUDP(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	for _, size := range []int{1, 511, 4096, 60000} {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		want := bytes.Repeat([]byte{byte(size)}, size)
		if _, e := c.Write(want); e != nil {
			t.Fatal(size, e)
		}
		got := make([]byte, 65535)
		n, e := c.Read(got)
		if e != nil || !bytes.Equal(want, got[:n]) {
			t.Fatalf("UDP %d got %d: %v", size, n, e)
		}
	}
}
