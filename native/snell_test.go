package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSnellIndependentTCPUDP(t *testing.T) {
	for _, version := range []string{"1", "2", "3", "4", "5"} {
		t.Run(version, func(t *testing.T) {
			in := Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Password: "private", Version: version}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Version = version
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			if version >= "3" {
				assertUDPSizes(t, client, []int{0, 1, 511, 1024})
			}
		})
	}
}

func TestSnellOfficialServer(t *testing.T) {
	dir := os.Getenv("LANBOAT_TEST_SNELL_DIR")
	if dir == "" {
		t.Skip("LANBOAT_TEST_SNELL_DIR required for official Snell servers")
	}
	for _, version := range []string{"1", "2", "3", "4", "5"} {
		masks := []string{"none", "http"}
		if version <= "3" {
			masks = append(masks, "tls")
		}
		for _, mask := range masks {
			t.Run(version+"/"+mask, func(t *testing.T) {
				release := "legacy-server"
				if version == "4" {
					release = "4.1.1"
				}
				if version == "5" {
					release = "5.0.1"
				}
				binary := filepath.Join(dir, release, "snell-server")
				if release == "legacy-server" {
					binary = filepath.Join(dir, release)
				}
				port := unusedPort(t)
				path := filepath.Join(t.TempDir(), "snell.conf")
				if err := os.WriteFile(path, fmt.Appendf(nil, "[snell-server]\nlisten = 127.0.0.1:%d\npsk = private\nobfs = %s\n", port, mask), 0600); err != nil {
					t.Fatal(err)
				}
				log, err := os.Create(filepath.Join(t.TempDir(), "server.log"))
				if err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(binary, "-c", path)
				cmd.Stdout = log
				cmd.Stderr = log
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
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
				address := portAddress("127.0.0.1", port)
				waitPort(t, address)
				out := Outbound{Type: "snell", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Password: "private", Version: version, Obfs: Obfuscation(mask), ObfsParam: "example.com"}
				out.Multiplex.Enabled = version == "2" || version == "4" || version == "5"
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				if out.Multiplex.Enabled {
					assertTCP(t, client)
					p := client.snellClients[out.Tag]
					p.mu.Lock()
					n := len(p.all)
					p.mu.Unlock()
					if n != 1 {
						t.Fatal("official server did not reuse the physical connection", n)
					}
				}
				if version >= "3" {
					// Reference servers drop empty UDP; native endpoints test it separately.
					assertUDPSizes(t, client, []int{1, 511, 1024})
				}
			})
		}
	}
}

func TestSnellRecordAuthenticationAndHalfClose(t *testing.T) {
	for _, version := range []string{"1", "2", "3", "4", "5"} {
		t.Run(version, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(3 * time.Second))
			_ = b.SetDeadline(time.Now().Add(3 * time.Second))
			x := newSnellConn(a, "key", version, &replayWindow{})
			y := newSnellConn(b, "key", version, &replayWindow{})
			payload := bytes.Repeat([]byte("independent Snell"), 1000)
			done := make(chan error, 1)
			go func() {
				err := writeAll(x, payload)
				if err == nil {
					err = x.CloseWrite()
				}
				done <- err
			}()
			got, err := io.ReadAll(y)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal(len(got), err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSnellRejectsWrongPassword(t *testing.T) {
	in := Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Password: "private", Version: "4"}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Version = "4"
	out.Password = "wrong"
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	c, err := client.Dial(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = c.Read(make([]byte, 1))
	}
	if err == nil {
		t.Fatal("wrong password accepted")
	}
}

func TestSnell5QUICDatagramProxy(t *testing.T) {
	for _, mode := range []string{"independent", "official"} {
		t.Run(mode, func(t *testing.T) {
			target := testQUICListener(t)
			var out Outbound
			if mode == "independent" {
				in := Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Password: "private", Version: "5"}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out = testOutbound(t, in, server.Address("server"))
				out.Version = "5"
			} else {
				dir := os.Getenv("LANBOAT_TEST_SNELL_DIR")
				if dir == "" {
					t.Skip("LANBOAT_TEST_SNELL_DIR is required")
				}
				port := unusedPort(t)
				path := filepath.Join(t.TempDir(), "snell.conf")
				os.WriteFile(path, fmt.Appendf(nil, "[snell-server]\nlisten=127.0.0.1:%d\npsk=private\n", port), 0600)
				cmd := exec.Command(filepath.Join(dir, "5.0.1", "snell-server"), "-c", path)
				logs, e := os.Create(filepath.Join(t.TempDir(), "snell.log"))
				if e != nil {
					t.Fatal(e)
				}
				cmd.Stdout, cmd.Stderr = logs, logs
				if e = cmd.Start(); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() {
					cmd.Process.Kill()
					cmd.Wait()
					logs.Close()
					if t.Failed() {
						b, _ := os.ReadFile(logs.Name())
						t.Log(string(b))
					}
				})
				waitPort(t, portAddress("127.0.0.1", port))
				out = Outbound{Type: "snell", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Password: "private", Version: "5"}
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			raw, e := client.Dial(ctx, "udp", target.packet.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			trace := &snellQUICTrace{Conn: raw}
			raw = trace
			t.Cleanup(func() {
				if t.Failed() {
					trace.mu.Lock()
					t.Log(trace.events)
					trace.mu.Unlock()
					target.mu.Lock()
					t.Log("target QUIC sessions", len(target.conns))
					target.mu.Unlock()
				}
			})
			cert := certificate(t)
			cert.Insecure = true
			cert.Key = nil
			cert.Certificate = nil
			cert.ALPN = []string{"lanboat-quic-test"}
			cfg, e := cert.config(false, "example.com")
			if e != nil {
				t.Fatal(e)
			}
			c, e := dialQUIC(ctx, context.Background(), raw, cfg)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			server, e := target.Accept(ctx)
			if e != nil {
				t.Fatal(e)
			}
			go func() {
				s, e := server.AcceptStream(ctx)
				if e == nil {
					defer s.Close()
					io.Copy(s, s)
					s.CloseWrite()
				}
			}()
			s, e := c.OpenStream(ctx, false)
			if e != nil {
				t.Fatal(e)
			}
			s.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte("independent Snell5 QUIC"), 16000)
			done := make(chan error, 1)
			go func() {
				e := writeAll(s, want)
				if e == nil {
					e = s.CloseWrite()
				}
				done <- e
			}()
			got, e := io.ReadAll(s)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal(len(got), e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestSnellObfuscationIndependent(t *testing.T) {
	for _, version := range []string{"1", "2", "3", "4", "5"} {
		for _, mask := range []string{"http", "tls"} {
			if mask == "tls" && version >= "4" {
				continue // These versions removed TLS obfuscation from the protocol.
			}
			t.Run(version+"/"+mask, func(t *testing.T) {
				in := Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Password: "private", Version: version, Obfs: Obfuscation(mask), ObfsParam: "example.com"}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Version = version
				out.Obfs = in.Obfs
				out.ObfsParam = in.ObfsParam
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				if version >= "3" {
					assertUDPSizes(t, client, []int{0, 1, 511, 1024})
				}
			})
		}
	}
}

func TestSnellObfuscationVersionCompatibility(t *testing.T) {
	for _, version := range []string{"1", "2", "3", "4", "5"} {
		for _, obfs := range []string{`"tls"`, `{"type":"tls","host":"example.com"}`} {
			for _, role := range []string{"inbound", "outbound"} {
				t.Run(version+"/"+obfs+"/"+role, func(t *testing.T) {
					endpoint := `"listen":"127.0.0.1","listen_port":0`
					if role == "outbound" {
						endpoint = `"server":"127.0.0.1","server_port":443`
					}
					raw := fmt.Sprintf(`{"%ss":[{"type":"snell","tag":"proxy","password":"private","version":%q,"obfs":%s,%s}]}`, role, version, obfs, endpoint)
					_, err := Parse([]byte(raw))
					if version <= "3" && err != nil {
						t.Fatal("legacy TLS obfuscation rejected", err)
					}
					if version >= "4" && (err == nil || !strings.Contains(err.Error(), "TLS obfuscation requires version1-3")) {
						t.Fatal("unsupported Snell4/5 TLS combination was not rejected at configuration check", err)
					}
				})
			}
		}
	}
}

func TestSnellPoolReuseAndExpiry(t *testing.T) {
	for _, version := range []string{"2", "4", "5"} {
		t.Run(version, func(t *testing.T) {
			in := Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Password: "private", Version: version}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Version = version
			out.Multiplex.Enabled = true
			out.IdleSessionTimeout = "100ms"
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			p := client.snellClients[out.Tag]
			var original *snellConn
			for range 8 {
				assertTCP(t, client)
				limit := time.Now().Add(time.Second)
				for {
					p.mu.Lock()
					idle := len(p.idle)
					if idle == 1 {
						current := p.idle[0].stream
						if original == nil {
							original = current
						} else if original != current {
							p.mu.Unlock()
							t.Fatal("physical Snell connection not reused")
						}
					}
					p.mu.Unlock()
					if idle == 1 {
						break
					}
					if time.Now().After(limit) {
						t.Fatal("session not returned to pool")
					}
					time.Sleep(time.Millisecond)
				}
			}
			time.Sleep(150 * time.Millisecond)
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.idle) != 0 || len(p.all) != 0 {
				t.Fatal("idle Snell connections retained")
			}
		})
	}
}

func waitPacketPort(t *testing.T, address string) {
	t.Helper()
	for range 200 {
		p, e := net.ListenPacket("udp", address)
		if e != nil {
			return
		}
		p.Close()
		time.Sleep(time.Millisecond * 10)
	}
	t.Fatal("reference UDP listener not ready")
}

type snellQUICTrace struct {
	net.Conn
	mu     sync.Mutex
	events []string
}

func (c *snellQUICTrace) record(prefix string, b []byte) {
	c.mu.Lock()
	if len(c.events) < 32 {
		c.events = append(c.events, fmt.Sprintf("%s n=%d h=%x", prefix, len(b), b[:min(len(b), 16)]))
	}
	c.mu.Unlock()
}
func (c *snellQUICTrace) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.record("read", b[:n])
	}
	return n, e
}
func (c *snellQUICTrace) Write(b []byte) (int, error) { c.record("write", b); return c.Conn.Write(b) }
