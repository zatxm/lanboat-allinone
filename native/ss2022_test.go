package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var ss2022Methods = []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}

func ss2022PSK(method string, fill byte) string {
	size := 32
	if method == ss2022Methods[0] {
		size = 16
	}
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, size))
}

func ss2022Inbound(method string, multi bool) Inbound {
	in := Inbound{Type: "shadowsocks", Tag: "server", Listen: "127.0.0.1", Method: method, Password: ss2022PSK(method, 7)}
	if multi {
		in.Users = []User{{Name: "alice", Password: ss2022PSK(method, 11)}, {Name: "bob", Password: ss2022PSK(method, 13)}}
	}
	return in
}

func ss2022Outbound(t *testing.T, in Inbound, address string) Outbound {
	o := testOutbound(t, in, address)
	o.Password, o.Username, o.UUID = in.Password, "", ""
	if len(in.Users) > 0 {
		o.Password += ":" + in.Users[0].Password
	}
	return o
}

func TestSS2022Independent(t *testing.T) {
	for _, method := range ss2022Methods {
		for _, multi := range []bool{false, true} {
			if multi && method == ss2022Methods[2] {
				continue
			}
			name := method
			if multi {
				name += "/multi-user"
			}
			t.Run(name, func(t *testing.T) {
				in := ss2022Inbound(method, multi)
				serverConfig := Config{Inbounds: []Inbound{in}}
				if multi {
					serverConfig.Outbounds = []Outbound{{Type: "block", Tag: "blocked"}, {Type: "direct", Tag: "direct"}}
					serverConfig.Route = Route{Final: "blocked", Rules: []Rule{{AuthUser: []string{"alice"}, Outbound: "direct"}}}
				}
				server := newTestRuntime(t, serverConfig)
				out := ss2022Outbound(t, in, server.Address(in.Tag))
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000, 65400})
			})
		}
	}
}

func TestSS2022OfficialReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Skip("LANBOAT_TEST_SINGBOX15 required for Shadowsocks2022 interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, method := range ss2022Methods {
		for _, multi := range []bool{false, true} {
			if multi && method == ss2022Methods[2] {
				continue
			}
			for _, direction := range []string{"client", "server"} {
				name := method + "/" + direction
				if multi {
					name += "/multi-user"
				}
				t.Run(name, func(t *testing.T) {
					in := ss2022Inbound(method, multi)
					var client *Runtime
					if direction == "client" {
						in.ListenPort = unusedPort(t)
						referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
						out := ss2022Outbound(t, in, portAddress(in.Listen, in.ListenPort))
						client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						out := ss2022Outbound(t, in, server.Address(in.Tag))
						local := Inbound{Type: "mixed", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: out.Tag}})
						front := testOutbound(t, Inbound{Type: "socks"}, portAddress(local.Listen, local.ListenPort))
						front.Username, front.Password = "", ""
						client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
					}
					assertTCP(t, client)
					// This reference build drops/truncates60000-byte datagrams in
					// its packet path; independent endpoints separately test65400.
					assertUDPSizes(t, client, []int{1, 511, 4096, 14000})
				})
			}
		}
	}
}

func TestSS2022Transports(t *testing.T) {
	for _, transport := range []string{"ws", "httpupgrade", "http", "grpc"} {
		t.Run(transport, func(t *testing.T) {
			in := ss2022Inbound(ss2022Methods[0], false)
			in.Transport = Transport{Type: transport}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := ss2022Outbound(t, in, server.Address(in.Tag))
			out.Transport = in.Transport
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
		})
	}
}

func TestSS2022PacketWindow(t *testing.T) {
	var w packetWindow
	for _, id := range []uint64{0, 1, 64, 63, 9000, 8999, 809, ^uint64(0)} {
		if !w.accept(id) || w.accept(id) {
			t.Fatal("replay or out-of-order handling", id)
		}
	}
	if w.accept(0) || w.accept(^uint64(0)-8192) {
		t.Fatal("out-of-window packet accepted")
	}
}

func TestSS2022PacketIntegrity(t *testing.T) {
	for _, method := range ss2022Methods {
		t.Run(method, func(t *testing.T) {
			key, err := newSS2022Key(method, ss2022PSK(method, 7))
			if err != nil {
				t.Fatal(err)
			}
			sender, err := newSS2022Sender(key, [8]byte{})
			if err != nil {
				t.Fatal(err)
			}
			b, err := sender.seal("example.com:53", []byte("authenticated UDP"), false)
			if err != nil {
				t.Fatal(err)
			}
			m, err := openSS2022Packet(key, b, true, nil)
			if err != nil || m.address != "example.com:53" || string(m.payload) != "authenticated UDP" || m.id != sender.id {
				t.Fatal(m, err)
			}
			for i := range b {
				bad := append([]byte(nil), b...)
				bad[i] ^= 1
				if _, err := openSS2022Packet(key, bad, true, nil); err == nil {
					t.Fatalf("tamper accepted at%d", i)
				}
			}
			if _, err := openSS2022Packet(key, b, false, nil); err == nil {
				t.Fatal("reflected request accepted as response")
			}
			for i := range len(b) {
				if _, err := openSS2022Packet(key, b[:i], true, nil); err == nil {
					t.Fatal("truncated UDP accepted", i)
				}
			}
			sender.next = ^uint64(0)
			if _, err := sender.seal("example.com:53", nil, false); err != nil {
				t.Fatal(err)
			}
			if _, err := sender.seal("example.com:53", nil, false); err == nil {
				t.Fatal("UDP packet ID wrapped")
			}
		})
	}
}

func TestSS2022InvalidKeys(t *testing.T) {
	for _, method := range ss2022Methods {
		for _, password := range []string{"password", "", base64.StdEncoding.EncodeToString(make([]byte, 24)), ss2022PSK(method, 1) + ":"} {
			if _, err := newSSKey(method, password); err == nil {
				t.Fatal("invalid PSK accepted", method)
			}
		}
	}
	if _, err := newSSKey(ss2022Methods[2], ss2022PSK(ss2022Methods[2], 7)+":"+ss2022PSK(ss2022Methods[2], 8)); err == nil {
		t.Fatal("ChaCha identity headers accepted")
	}
	for _, method := range ss2022Methods {
		for _, stamp := range []uint64{0, ^uint64(0), uint64(time.Now().Unix() - 300), uint64(time.Now().Unix() + 300)} {
			if ss2022Stamp(binary.BigEndian.AppendUint64([]byte{0}, stamp), 0) == nil {
				t.Fatal("invalid timestamp accepted", method, stamp)
			}
		}
	}
}

func TestSS2022TCPReplayAndResponseBinding(t *testing.T) {
	for _, method := range ss2022Methods {
		t.Run(method, func(t *testing.T) {
			key, _ := newSS2022Key(method, ss2022PSK(method, 7))
			var wire bytes.Buffer
			client, err := ss2022Client(memoryNetConn{bytes.NewReader(nil), &wire}, key, "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			request := append([]byte(nil), wire.Bytes()...)
			server, address, err := readSS2022Header(readerConn(request), key, false, nil)
			if err != nil || address != "example.com:80" {
				t.Fatal(address, err)
			}
			wire.Reset()
			server.Conn = memoryNetConn{bytes.NewReader(nil), &wire}
			if _, err := server.Write([]byte("server response")); err != nil {
				t.Fatal(err)
			}
			response := append([]byte(nil), wire.Bytes()...)
			c := client.(*ss2022Conn)
			got, _, err := readSS2022Header(readerConn(response), key, true, c.requestSalt)
			if err != nil || string(got.pending) != "server response" {
				t.Fatal("response decode", err)
			}
			wrong := append([]byte(nil), c.requestSalt...)
			wrong[0] ^= 1
			if _, _, err := readSS2022Header(readerConn(response), key, true, wrong); err == nil {
				t.Fatal("response bound to wrong request")
			}
			for i := range request {
				bad := append([]byte(nil), request...)
				bad[i] ^= 1
				if _, _, err := readSS2022Header(readerConn(bad), key, false, nil); err == nil {
					t.Fatalf("request tamper accepted at%d", i)
				}
			}
			cipher := server.writer
			for i := range cipher.nonce {
				cipher.nonce[i] = 255
			}
			if _, err := cipher.seal(nil, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := cipher.seal(nil, nil); err == nil {
				t.Fatal("TCP nonce wrapped")
			}
		})
	}
}

func TestSS2022UDPRebindAndReplay(t *testing.T) {
	for _, method := range ss2022Methods {
		t.Run(method, func(t *testing.T) {
			in := ss2022Inbound(method, false)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			key, _ := newSS2022Key(method, in.Password)
			sender, _ := newSS2022Sender(key, [8]byte{})
			target := echoUDP(t)
			var old []byte
			var serverID [8]byte
			for i := range 2 {
				c, err := net.Dial("udp", server.Address(in.Tag))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				packet, _ := sender.seal(target, []byte("rebind"), false)
				if i == 0 {
					bad := append([]byte(nil), packet...)
					bad[len(bad)-1] ^= 1
					_, _ = c.Write(bad) // Unauthenticated packet IDs must not poison the window.
				}
				if i == 1 {
					_, _ = c.Write(old) // Replaying an authenticated packet must not move the peer.
					_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
					if _, err := c.Read(make([]byte, 65535)); err == nil {
						t.Fatal("replayed packet generated a response")
					}
				}
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Write(packet)
				buffer := make([]byte, 65535)
				n, err := c.Read(buffer)
				if err != nil {
					t.Fatal(err)
				}
				m, err := openSS2022Packet(key, buffer[:n], false, nil)
				if err != nil || string(m.payload) != "rebind" || m.clientID != sender.id {
					t.Fatal(m, err)
				}
				if i == 1 && m.id != serverID {
					t.Fatal("network change discarded server session")
				}
				old, serverID = packet, m.id
			}
		})
	}
}

func FuzzSS2022(f *testing.F) {
	keys := make([]*ssKey, len(ss2022Methods))
	for i, method := range ss2022Methods {
		key, _ := newSS2022Key(method, ss2022PSK(method, 7))
		keys[i] = key
		sender, _ := newSS2022Sender(key, [8]byte{})
		for _, response := range []bool{false, true} {
			packet, _ := sender.seal("example.com:53", []byte("seed"), response)
			f.Add(uint8(i), packet)
		}
		var wire bytes.Buffer
		_, _ = ss2022Client(memoryNetConn{bytes.NewReader(nil), &wire}, key, "example.com:443")
		f.Add(uint8(i), append([]byte(nil), wire.Bytes()...))
		wire.Reset()
		server := &ss2022Conn{Conn: memoryNetConn{bytes.NewReader(nil), &wire}, key: key, requestSalt: make([]byte, len(key.master))}
		_, _ = server.Write([]byte("response seed"))
		f.Add(uint8(i), append([]byte(nil), wire.Bytes()...))
	}
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, method uint8, b []byte) {
		if len(b) > 70000 {
			return
		}
		key := keys[int(method)%len(keys)]
		_, _ = openSS2022Packet(key, b, true, nil)
		_, _ = openSS2022Packet(key, b, false, nil)
		_, _, _ = readSS2022Header(readerConn(b), key, false, nil)
		_, _, _ = readSS2022Header(readerConn(b), key, true, make([]byte, len(key.master)))
	})
}

func TestSS2022TCPReplayAndFailedAuthentication(t *testing.T) {
	for _, method := range ss2022Methods {
		t.Run(method, func(t *testing.T) {
			in := ss2022Inbound(method, false)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			var hits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "response") }))
			defer origin.Close()
			address := strings.TrimPrefix(origin.URL, "http://")
			key, _ := newSS2022Key(method, in.Password)
			var wire bytes.Buffer
			_, err := ss2022Client(memoryNetConn{bytes.NewReader(nil), &wire}, key, address)
			if err != nil {
				t.Fatal(err)
			}
			for i := range 2 {
				raw, err := net.Dial("tcp", server.Address(in.Tag))
				if err != nil {
					t.Fatal(err)
				}
				_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = raw.Write(wire.Bytes())
				client := &ss2022Conn{Conn: raw, key: key, requestSalt: append([]byte(nil), wire.Bytes()[:len(key.master)]...)}
				// Recreate the request cipher at counter2 after its two header chunks.
				_ = client.initWriter(client.requestSalt)
				client.writer.nonce[0] = 2
				_, writeErr := client.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
				response, readErr := io.ReadAll(client)
				raw.Close()
				if i == 0 && (writeErr != nil || readErr != nil || !bytes.Contains(response, []byte("response"))) {
					t.Fatal("initial request failed", writeErr, readErr)
				}
				if i == 1 && writeErr == nil && readErr == nil {
					t.Fatal("TCP replay succeeded")
				}
			}
			out := ss2022Outbound(t, in, server.Address(in.Tag))
			out.Password = ss2022PSK(method, 99)
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return bad.Dial(ctx, n, a) }}
			defer transport.CloseIdleConnections()
			resp, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(origin.URL)
			if err == nil {
				resp.Body.Close()
				t.Fatal("wrong PSK accepted")
			}
			if hits.Load() != 1 {
				t.Fatal("failed authentication/replay reached destination", hits.Load())
			}
		})
	}
}

func TestSS2022UDPSourcePortAndServerRestart(t *testing.T) {
	for _, method := range ss2022Methods {
		t.Run(method, func(t *testing.T) {
			in := ss2022Inbound(method, false)
			in.ListenPort = unusedPort(t)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			key, _ := newSS2022Key(method, in.Password)
			sender, _ := newSS2022Sender(key, [8]byte{})
			var source string
			var oldServerID [8]byte
			for i := range 3 {
				origin, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer origin.Close()
				go func() {
					b := make([]byte, 65535)
					n, from, err := origin.ReadFrom(b)
					if err == nil {
						_, _ = origin.WriteTo(append([]byte(from.String()+"|"), b[:n]...), from)
					}
				}()
				client, err := net.Dial("udp", server.Address(in.Tag))
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				packet, _ := sender.seal(origin.LocalAddr().String(), []byte("persistent session"), false)
				_, _ = client.Write(packet)
				_ = client.SetDeadline(time.Now().Add(2 * time.Second))
				buffer := make([]byte, 65535)
				n, err := client.Read(buffer)
				if err != nil {
					t.Fatal(err)
				}
				m, err := openSS2022Packet(key, buffer[:n], false, nil)
				if err != nil {
					t.Fatal(err)
				}
				port, data, _ := strings.Cut(string(m.payload), "|")
				if data != "persistent session" || m.clientID != sender.id {
					t.Fatal("corrupt response after rebind/restart")
				}
				if i == 1 && (port != source || m.id != oldServerID) {
					t.Fatal("destination/client port change replaced UDP session", source, port)
				}
				if i == 2 && m.id == oldServerID {
					t.Fatal("server restart reused server session ID")
				}
				source, oldServerID = port, m.id
				if i == 1 {
					if err := server.Close(); err != nil {
						t.Fatal(err)
					}
					server = newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				}
			}
		})
	}
}

func TestSS2022PersistentClientSurvivesServerRestart(t *testing.T) {
	for _, method := range ss2022Methods {
		t.Run(method, func(t *testing.T) {
			in := ss2022Inbound(method, false)
			in.ListenPort = unusedPort(t)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := ss2022Outbound(t, in, server.Address(in.Tag))
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			c, err := client.Dial(context.Background(), "udp", echoUDP(t))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for i := range 3 {
				if i > 0 {
					if err := server.Close(); err != nil {
						t.Fatal(err)
					}
					server = newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				}
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				if _, err := c.Write([]byte("same client session")); err != nil {
					t.Fatal(err)
				}
				var buffer [128]byte
				n, err := c.Read(buffer[:])
				if err != nil || string(buffer[:n]) != "same client session" {
					t.Fatal("persistent UDP failed after restart", i, err)
				}
			}
		})
	}
}

func TestSS2022UDPRoutingAndPreProxy(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		t.Run(fmt.Sprint(proxy), func(t *testing.T) {
			in := ss2022Inbound(ss2022Methods[0], false)
			config := Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "blocked"}}, Route: Route{Final: "direct"}}
			if proxy {
				up := testInbound(t, "socks")
				upstream := newTestRuntime(t, Config{Inbounds: []Inbound{up}})
				config.Outbounds = append(config.Outbounds, testOutbound(t, up, upstream.Address(up.Tag)))
				config.Route.Final = "proxy"
			}
			denied := echoUDP(t)
			_, port, _ := net.SplitHostPort(denied)
			number, _ := strconv.Atoi(port)
			config.Route.Rules = []Rule{{Port: []uint16{uint16(number)}, Outbound: "blocked"}}
			server := newTestRuntime(t, config)
			out := ss2022Outbound(t, in, server.Address(in.Tag))
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertUDP(t, client)
			c, err := client.Dial(context.Background(), "udp", denied)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = c.Write([]byte("blocked"))
			if _, err := c.Read(make([]byte, 64)); err == nil {
				t.Fatal("UDP rule bypassed")
			}
		})
	}
}

func TestSS2022UDPDirectIPv6AndForeignSource(t *testing.T) {
	origin, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	foreign, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	in := ss2022Inbound(ss2022Methods[0], false)
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := ss2022Outbound(t, in, server.Address(in.Tag))
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	c, err := client.Dial(context.Background(), "udp", origin.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = c.Write([]byte("IPv6"))
	_ = origin.SetDeadline(time.Now().Add(2 * time.Second))
	var buffer [128]byte
	n, from, err := origin.ReadFrom(buffer[:])
	if err != nil || string(buffer[:n]) != "IPv6" {
		t.Fatal("IPv6 direct request", err)
	}
	if _, err := foreign.WriteTo([]byte("unrequested source"), from); err != nil {
		t.Fatal(err)
	}
	// The only queued reply is from an address this session never contacted.
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := c.Read(buffer[:]); err == nil {
		t.Fatal("unrequested UDP source forwarded to client")
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = origin.WriteTo([]byte("authorized source"), from)
	n, err = c.Read(buffer[:])
	if err != nil || string(buffer[:n]) != "authorized source" {
		t.Fatal("IPv6 direct reply", err)
	}
}

func TestSS2022UDPDirectResolverOverrides(t *testing.T) {
	for _, perOutbound := range []bool{false, true} {
		t.Run(fmt.Sprint(perOutbound), func(t *testing.T) {
			origin, err := net.ListenPacket("udp6", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			in := ss2022Inbound(ss2022Methods[0], false)
			config := Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, DNS: DNSConfig{Final: "wrong", Servers: []DNSServer{
				{Type: "hosts", Tag: "wrong", Predefined: map[string][]string{"mapped.example": {"127.0.0.2"}}},
				{Type: "hosts", Tag: "chosen", Predefined: map[string][]string{"mapped.example": {"::1"}}},
			}}}
			if perOutbound {
				config.Outbounds[0].DomainResolver = "chosen"
			} else {
				config.Route.DefaultDomainResolver = "chosen"
			}
			server := newTestRuntime(t, config)
			out := ss2022Outbound(t, in, server.Address(in.Tag))
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			_, port, _ := net.SplitHostPort(origin.LocalAddr().String())
			c, err := client.Dial(context.Background(), "udp", net.JoinHostPort("mapped.example", port))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = c.Write([]byte("resolver override"))
			_ = origin.SetDeadline(time.Now().Add(2 * time.Second))
			var buffer [128]byte
			n, from, err := origin.ReadFrom(buffer[:])
			if err != nil || string(buffer[:n]) != "resolver override" {
				t.Fatal("direct UDP ignored explicit resolver", err)
			}
			_, _ = origin.WriteTo(buffer[:n], from)
			n, err = c.Read(buffer[:])
			if err != nil || string(buffer[:n]) != "resolver override" {
				t.Fatal("resolved response", err)
			}
		})
	}
}

func BenchmarkSS2022Records(b *testing.B) {
	for _, method := range ss2022Methods {
		b.Run(method, func(b *testing.B) {
			key, err := newSS2022Key(method, ss2022PSK(method, 7))
			if err != nil {
				b.Fatal(err)
			}
			c := &ss2022Conn{Conn: memoryNetConn{bytes.NewReader(nil), io.Discard}, key: key, requestSalt: make([]byte, len(key.master))}
			data := make([]byte, 32768)
			_, _ = c.Write(data)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			b.ResetTimer()
			for b.Loop() {
				if _, err := c.Write(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
