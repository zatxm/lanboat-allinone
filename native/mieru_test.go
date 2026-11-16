package native

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func mieruPair(t *testing.T, network string, mode byte) (*Runtime, *Runtime) {
	t.Helper()
	in := Inbound{Type: "mieru", Tag: "server", Listen: "127.0.0.1", Network: network, Users: []User{{Username: "client", Password: "private"}}, MieruOptions: MieruOptions{LowEntropy: mode}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	host, p, _ := net.SplitHostPort(s.Address("server"))
	port, _ := shadowPort(p)
	out := Outbound{Type: "mieru", Tag: "proxy", Server: host, ServerPort: port, Username: "client", Password: "private", Network: network, MieruOptions: MieruOptions{LowEntropy: mode}}
	return s, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}
func TestMieruIndependent(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for mode := byte(0); mode <= 4; mode++ {
			t.Run(fmt.Sprintf("%s/%d", network, mode), func(t *testing.T) {
				_, c := mieruPair(t, network, mode)
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
				c.resetNetworkTransports()
				assertTCP(t, c)
			})
		}
	}
}
func TestMieruConcurrent(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			_, c := mieruPair(t, network, 0)
			target := echoUDP(t)
			var workers sync.WaitGroup
			for i := 0; i < 16; i++ {
				workers.Go(func() {
					conn, e := c.Dial(context.Background(), "udp", target)
					if e != nil {
						t.Error(e)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					want := bytes.Repeat([]byte{byte(i)}, 4096)
					for range 4 {
						if _, e = conn.Write(want); e != nil {
							t.Error(e)
							return
						}
						b := make([]byte, 8192)
						n, e := conn.Read(b)
						if e != nil || !bytes.Equal(b[:n], want) {
							t.Error("crossed Mieru flows", n, e)
							return
						}
					}
				})
			}
			workers.Wait()
		})
	}
}

func TestMieruReference(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, side := range []string{"client", "server"} {
			for mode := byte(0); mode <= 4; mode++ {
				t.Run(fmt.Sprintf("%s/%s/%d", network, side, mode), func(t *testing.T) {
					var c *Runtime
					if side == "client" {
						port := unusedPort(t)
						address := portAddress("127.0.0.1", port)
						mieruReference(t, "server", network, address, "unused", fmt.Sprint(mode))
						out := Outbound{Type: "mieru", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Username: "client", Password: "private", Network: network, MieruOptions: MieruOptions{LowEntropy: mode}}
						c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						s, _ := mieruPair(t, network, mode)
						local := portAddress("127.0.0.1", unusedPort(t))
						mieruReference(t, "client", network, s.Address("server"), local, fmt.Sprint(mode))
						out := testOutbound(t, Inbound{Type: "socks"}, local)
						out.Username, out.Password = "", ""
						c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					}
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 511, 4096, 14000})
					assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
				})
			}
		}
	}
}
func mieruReference(t *testing.T, args ...string) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_MIERU")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_MIERU required")
	}
	log, e := os.Create(filepath.Join(t.TempDir(), "reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, args...)
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
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		b, _ := os.ReadFile(log.Name())
		if bytes.Contains(b, []byte("ready")) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	b, _ := os.ReadFile(log.Name())
	t.Fatalf("Mieru reference not ready: %s", b)
}
