//go:build linux

package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMasqueReference(t *testing.T) {
	if os.Getenv("LANBOAT_MASQUE_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^TestMasqueReference$", "-test.v", "-test.timeout=60s")
		cmd.Env = append(os.Environ(), "LANBOAT_MASQUE_CHILD=1")
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("MASQUE isolatednamespace: %v\n%s", e, out)
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
	t.Run("native-client", func(t *testing.T) {
		in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", ListenPort: unusedPort(t), TLS: certificate(t)}
		address := portAddress("127.0.0.1", in.ListenPort)
		dir := t.TempDir()
		cert := trustReferenceFile(t, dir, "cert.pem", strings.Join(in.TLS.Certificate, "\n"))
		key := trustReferenceFile(t, dir, "key.pem", strings.Join(in.TLS.Key, "\n"))
		masqueReferenceProcess(t, "server", address, cert, key)
		for _, mode := range []string{"ip", "udp"} {
			t.Run(mode, func(t *testing.T) {
				out := testOutbound(t, in, address)
				out.Username, out.Password = "client", "private"
				out.MasqueOptions.Mode = mode
				var c *Runtime
				if mode == "ip" {
					c = masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": out.Server, "server_port": out.ServerPort, "username": "client", "password": "private", "version": 3, "disable_version_fallback": true, "tls": out.TLS})
				} else {
					c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				}
				target := masqueEcho(t, "tcp", "10.44.0.1:0")
				conn, e := c.Dial(context.Background(), "tcp", target)
				if e != nil {
					t.Fatal(e)
				}
				wgRoundtripTCP(t, conn)
				direct := masqueEcho(t, "udp", "10.44.0.1:0")
				assertUDPAddress(t, c, []int{1, 511, 1000, 1232}, direct)
				if mode == "ip" {
					target = masqueEcho(t, "tcp", "[fd44::1]:0")
					conn, e = c.Dial(context.Background(), "tcp", target)
					if e != nil {
						t.Fatal(e)
					}
					wgRoundtripTCP(t, conn)
					assertUDPAddress(t, c, []int{1, 511, 1232}, masqueEcho(t, "udp", "[fd44::1]:0"))
				}
			})
		}
	})
	t.Run("native-server-ip", func(t *testing.T) {
		server := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 3, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "tls": certificate(t)})
		writer, reader := masqueReferenceProcess(t, "client-ip", server.Address("server"))
		r := newTestRuntime(t, Config{})
		done := make(chan struct{})
		var mu sync.Mutex
		endpoint := &ipEndpoint{runtime: r, local: []netip.Addr{netip.MustParseAddr("10.44.0.2"), netip.MustParseAddr("fd44::2")}, mtu: 1050, done: done, ensure: func(context.Context) error { return nil }, sendIP: func(b []byte) error {
			mu.Lock()
			defer mu.Unlock()
			h := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
			if e := writeAll(writer, h); e != nil {
				return e
			}
			return writeAll(writer, b)
		}}
		stack := newIPStack(endpoint)
		t.Cleanup(func() { close(done); writer.Close(); stack.close() })
		go func() {
			for {
				var h [2]byte
				if _, e := io.ReadFull(reader, h[:]); e != nil {
					return
				}
				b := make([]byte, int(binary.BigEndian.Uint16(h[:])))
				if _, e := io.ReadFull(reader, b); e != nil {
					return
				}
				p, e := parseTunPacket(b)
				if e == nil {
					stack.input(p)
				}
			}
		}()
		conn, e := stack.dial(context.Background(), "tcp", relayEchoTCP(t))
		if e != nil {
			t.Fatal(e)
		}
		wgRoundtripTCP(t, conn)
		for _, size := range []int{1, 511, 1000, 1232} {
			conn, e = stack.dial(context.Background(), "udp", echoUDP(t))
			if e != nil {
				t.Fatal(e)
			}
			conn.SetDeadline(time.Now().Add(4 * time.Second))
			b := make([]byte, size)
			for i := range b {
				b[i] = byte(i)
			}
			if _, e = conn.Write(b); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, size)
			n, e := conn.Read(got)
			conn.Close()
			if e != nil || n != size || string(b) != string(got) {
				t.Fatal(n, e)
			}
		}
	})
	t.Run("native-server-udp", func(t *testing.T) {
		server, _ := masquePair(t, "udp")
		writer, reader := masqueReferenceProcess(t, "client-udp", server.Address("server"), echoUDP(t))
		for _, size := range []int{1, 511, 1000, 1232} {
			want := strings.Repeat("u", size)
			h := binary.BigEndian.AppendUint16(nil, uint16(size))
			if e = writeAll(writer, append(h, []byte(want)...)); e != nil {
				t.Fatal(e)
			}
			var header [2]byte
			if _, e = io.ReadFull(reader, header[:]); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, int(binary.BigEndian.Uint16(header[:])))
			if _, e = io.ReadFull(reader, got); e != nil || string(got) != want {
				t.Fatal(e, len(got))
			}
		}
	})
	t.Run("native-server-scoped", func(t *testing.T) {
		for _, scoped := range [][3]string{{"/vpn/{target}/{ipproto}/", "/vpn/127.0.0.1/17/", "127.0.0.1"}, {"/vpn/{target}/{ipproto}/", "/vpn/%3A%3A1/17/", "::1"}, {"/vpn{?target,ipproto}", "/vpn?target=127.0.0.0%2F8&ipproto=17", "127.0.0.1"}, {"/vpn{?target,ipproto}", "/vpn?target=%3A%3A1&ipproto=17", "::1"}} {
			t.Run(scoped[1], func(t *testing.T) {
				server := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 3, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "users": []User{{Username: "client", Password: "private"}}, "path": scoped[0], "tls": certificate(t)})
				writer, reader := masqueReferenceProcess(t, "client-ip", server.Address("server"), scoped[1])
				destination := netip.MustParseAddr(scoped[2])
				source := netip.MustParseAddr("10.44.0.2")
				if destination.Is6() {
					source = netip.MustParseAddr("fd44::2")
				}
				target := masqueEcho(t, "udp", net.JoinHostPort(destination.String(), "0"))
				_, port, _ := net.SplitHostPort(target)
				n, _ := shadowPort(port)
				for _, size := range []int{1, 511, 1232} {
					want := strings.Repeat("s", size)
					packet := makeUDPPacket(source, destination, 32000, n, []byte(want))
					if err := writeAll(writer, append(binary.BigEndian.AppendUint16(nil, uint16(len(packet))), packet...)); err != nil {
						t.Fatal(err)
					}
					var header [2]byte
					if _, err := io.ReadFull(reader, header[:]); err != nil {
						t.Fatal(err)
					}
					reply := make([]byte, int(binary.BigEndian.Uint16(header[:])))
					if _, err := io.ReadFull(reader, reply); err != nil {
						t.Fatal(err)
					}
					parsed, err := parseTunPacket(reply)
					if err != nil || parsed.source != destination || parsed.destination != source || parsed.protocol != 17 || len(parsed.data) < parsed.header+8 || string(parsed.data[parsed.header+8:]) != want {
						t.Fatal("scoped upstream packet mismatch", err)
					}
				}
			})
		}
	})
}
func masqueReferenceProcess(t *testing.T, args ...string) (io.WriteCloser, io.Reader) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_MASQUE")
	if binary == "" {
		t.Skip("LANBOAT_TEST_MASQUE required")
	}
	cmd := exec.Command(binary, args...)
	writer, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	reader, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(t.TempDir(), "reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		writer.Close()
		cmd.Process.Kill()
		_ = cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	})
	for i := 0; i < 600; i++ {
		b, _ := os.ReadFile(log.Name())
		if strings.Contains(string(b), "ready") {
			return writer, reader
		}
		time.Sleep(5 * time.Millisecond)
	}
	b, _ := os.ReadFile(log.Name())
	t.Fatalf("MASQUE reference not ready: %s", b)
	return nil, nil
}

func TestMasqueNetworkConfigurationReference(t *testing.T) {
	configs := []MasqueDNSConfiguration{masqueTestDNS("192.0.2.33:53", ""), masqueTestDNS("[2001:db8::1]:853", "doq")}
	configs[0].InternalDomains = []string{"internal.corp.example"}
	prefixes := []netip.Prefix{netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("2001:db8::/64")}
	t.Run("native-client", func(t *testing.T) {
		in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", ListenPort: unusedPort(t), TLS: certificate(t)}
		dir := t.TempDir()
		cert := trustReferenceFile(t, dir, "cert.pem", strings.Join(in.TLS.Certificate, "\n"))
		key := trustReferenceFile(t, dir, "key.pem", strings.Join(in.TLS.Key, "\n"))
		address := portAddress(in.Listen, in.ListenPort)
		writer, _ := masqueReferenceProcess(t, "configuration-server", address, cert, key)
		out := testOutbound(t, in, address)
		out.AcceptDNS, out.AcceptPREF64 = true, true
		c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
		if err := json.NewEncoder(writer).Encode(map[string]any{"dns": configs, "pref64": prefixes}); err != nil {
			t.Fatal(err)
		}
		state := masqueWaitNetwork(t, c, true, true)
		assertMasqueConfiguration(t, state, configs, prefixes)
		version := state.Version
		if err := json.NewEncoder(writer).Encode(map[string]any{"dns": []MasqueDNSConfiguration{}, "pref64": []netip.Prefix{}}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for {
			state, err := c.WaitMasqueConfiguration(ctx, "proxy", version)
			if err != nil {
				t.Fatal(err)
			}
			version = state.Version
			if len(state.DNS) == 0 && len(state.PREF64) == 0 {
				break
			}
		}
	})
	t.Run("native-server", func(t *testing.T) {
		in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Username: "client", Password: "private"}}, MasqueOptions: MasqueOptions{DNS: configs, PREF64: prefixes}}
		s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		_, reader := masqueReferenceProcess(t, "configuration-client", s.Address("server"))
		type update struct {
			Event  string                   `json:"event"`
			DNS    []MasqueDNSConfiguration `json:"dns"`
			PREF64 []netip.Prefix           `json:"pref64"`
		}
		updates := make(chan update, 32)
		go func() {
			defer close(updates)
			dec := json.NewDecoder(reader)
			for {
				var u update
				if dec.Decode(&u) != nil {
					return
				}
				updates <- u
			}
		}()
		wait := func(dns []MasqueDNSConfiguration, pref64 []netip.Prefix) {
			t.Helper()
			var state MasqueNetworkConfiguration
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			for {
				select {
				case u, ok := <-updates:
					if !ok {
						t.Fatal("reference closed before configuration")
					}
					if u.Event == "dns" {
						state.DNS, state.DNSReceived = u.DNS, true
					}
					if u.Event == "pref64" {
						state.PREF64, state.PREF64Received = u.PREF64, true
					}
					if state.DNSReceived && state.PREF64Received {
						assertMasqueConfiguration(t, state, dns, pref64)
						return
					}
				case <-deadline.C:
					t.Fatal("reference configuration timed out")
				}
			}
		}
		wait(configs, prefixes)
		if err := s.PublishMasqueConfiguration(context.Background(), "server", nil, nil); err != nil {
			t.Fatal(err)
		}
		wait(nil, nil)
	})
}

func assertMasqueConfiguration(t *testing.T, state MasqueNetworkConfiguration, configs []MasqueDNSConfiguration, prefixes []netip.Prefix) {
	t.Helper()
	want, e := masqueDNSBytes(configs)
	got, err := masqueDNSBytes(state.DNS)
	if e != nil || err != nil || string(want) != string(got) {
		t.Fatal("DNS configuration differs from upstream", e, err, state)
	}
	want, e = masquePREF64Bytes(prefixes)
	got, err = masquePREF64Bytes(state.PREF64)
	if e != nil || err != nil || string(want) != string(got) {
		t.Fatal("PREF64 configuration differs from upstream", e, err, state)
	}
}
