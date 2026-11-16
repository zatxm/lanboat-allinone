package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func ss2022RelayInbound(t *testing.T, method, address, nextPSK string, fill byte) Inbound {
	t.Helper()
	host, port := splitTestAddress(t, address)
	return Inbound{Type: "shadowsocks", Tag: "relay", Listen: "127.0.0.1", Method: method, Password: ss2022PSK(method, fill),
		Destinations: []ShadowsocksDestination{{Name: "next", Server: host, ServerPort: port, Password: nextPSK}}}
}

func ss2022RelayChain(t *testing.T, method string, multi bool, hops int, official string) (*Runtime, *Runtime, Inbound, string) {
	t.Helper()
	if official != "" && os.Getenv("LANBOAT_TEST_SINGBOX15") == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	terminal := ss2022Inbound(method, multi)
	var server *Runtime
	address := ""
	if official == "terminal" {
		terminal.ListenPort = unusedPort(t)
		shadowReference(t, Config{Inbounds: []Inbound{terminal}})
		address = portAddress(terminal.Listen, terminal.ListenPort)
	} else {
		server = newTestRuntime(t, Config{Inbounds: []Inbound{terminal}})
		address = server.Address(terminal.Tag)
	}
	password, nextPSK := terminal.Password, terminal.Password
	if multi {
		password += ":" + terminal.Users[0].Password
	}
	for i := hops - 1; i >= 0; i-- {
		in := ss2022RelayInbound(t, method, address, nextPSK, byte(32+i))
		if official == "relay" && i == 0 {
			in.ListenPort = unusedPort(t)
			shadowReference(t, Config{Inbounds: []Inbound{in}})
			address = portAddress(in.Listen, in.ListenPort)
		} else {
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			address = r.Address(in.Tag)
		}
		password, nextPSK = in.Password+":"+password, in.Password
	}
	out := ss2022Outbound(t, terminal, address)
	out.Password = password
	if official == "client" {
		front := Inbound{Type: "mixed", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
		shadowReference(t, Config{Inbounds: []Inbound{front}, Outbounds: []Outbound{out}, Route: Route{Final: out.Tag}})
		out = testOutbound(t, Inbound{Type: "socks"}, portAddress(front.Listen, front.ListenPort))
		out.Username, out.Password = "", ""
	}
	return newTestRuntime(t, Config{Outbounds: []Outbound{out}}), server, terminal, password
}

func TestSS2022RelayIndependent(t *testing.T) {
	for _, method := range ss2022Methods[:2] {
		for _, multi := range []bool{false, true} {
			for _, count := range []int{1, 2, 8} {
				hops := count
				if multi && hops == 8 {
					hops = 7
				}
				t.Run(fmt.Sprintf("%s/multi=%v/hops=%d", method, multi, hops), func(t *testing.T) {
					c, _, _, _ := ss2022RelayChain(t, method, multi, hops, "")
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000, 65000})
				})
			}
		}
	}
}

func TestSS2022RelayOfficialReference(t *testing.T) {
	for _, method := range ss2022Methods[:2] {
		for _, side := range []string{"client", "relay", "terminal"} {
			for _, multi := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/multi=%v", method, side, multi), func(t *testing.T) {
					c, _, _, _ := ss2022RelayChain(t, method, multi, 2, side)
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 511, 4096, 14000})
				})
			}
		}
	}
}

func TestSS2022RelayConfiguration(t *testing.T) {
	base := ss2022RelayInbound(t, ss2022Methods[0], "127.0.0.1:8388", ss2022PSK(ss2022Methods[0], 7), 32)
	for _, change := range []struct {
		name string
		edit func(*Inbound)
	}{
		{"other-type", func(in *Inbound) { in.Type = "direct" }},
		{"legacy", func(in *Inbound) { in.Method = "aes-128-gcm" }},
		{"chacha", func(in *Inbound) { in.Method = ss2022Methods[2]; in.Password = ss2022PSK(in.Method, 32) }},
		{"users", func(in *Inbound) { in.Users = []User{{Password: ss2022PSK(in.Method, 7)}} }},
		{"bad-root-key", func(in *Inbound) { in.Password = "invalid" }},
		{"root-key-chain", func(in *Inbound) { in.Password += ":" + ss2022PSK(in.Method, 7) }},
		{"bad-target-key", func(in *Inbound) { in.Destinations[0].Password = "invalid" }},
		{"target-key-chain", func(in *Inbound) { in.Destinations[0].Password += ":" + ss2022PSK(in.Method, 8) }},
		{"target-port", func(in *Inbound) { in.Destinations[0].ServerPort = 0 }},
		{"target-host", func(in *Inbound) { in.Destinations[0].Server = "bad/host" }},
		{"empty-host", func(in *Inbound) { in.Destinations[0].Server = "" }},
		{"duplicate-key", func(in *Inbound) { in.Destinations = append(in.Destinations, in.Destinations[0]) }},
		{"too-many", func(in *Inbound) { in.Destinations = make([]ShadowsocksDestination, 1025) }},
		{"timeout", func(in *Inbound) { in.UDPTimeout = "59s" }},
		{"bad-timeout", func(in *Inbound) { in.UDPTimeout = "invalid" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			in := base
			in.Destinations = append([]ShadowsocksDestination(nil), base.Destinations...)
			change.edit(&in)
			b, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
			if _, err := Parse(b); err == nil {
				t.Fatal("invalid relay configuration accepted")
			}
		})
	}
	base.UDPTimeout = "5m"
	b, _ := json.Marshal(Config{Inbounds: []Inbound{base}})
	parsed, err := Parse(b)
	if err != nil || len(parsed.Inbounds[0].Destinations) != 1 {
		t.Fatal(err)
	}
	b, _ = json.Marshal(parsed)
	if _, err = Parse(b); err != nil {
		t.Fatal("configuration round-trip", err)
	}
}

func TestSS2022RelayWire(t *testing.T) {
	for _, method := range ss2022Methods[:2] {
		t.Run(method, func(t *testing.T) {
			target := ss2022PSK(method, 7)
			in := ss2022RelayInbound(t, method, "127.0.0.1:8388", target, 32)
			key, _ := newSSInboundKey(in)
			clientKey, _ := newSS2022Key(method, in.Password+":"+target)
			var raw bytes.Buffer
			_, err := ss2022Client(memoryNetConn{bytes.NewReader(nil), &raw}, clientKey, "example.com:443")
			if err != nil {
				t.Fatal(err)
			}
			initial := bytes.Clone(raw.Bytes())
			next, wire, err := ss2022RelayTCP(key, bytes.Clone(initial))
			if err != nil || next.relayAddress != "127.0.0.1:8388" || len(wire) != len(initial)-16 {
				t.Fatal(err)
			}
			size := len(key.master)
			if !bytes.Equal(wire[:size], initial[:size]) || !bytes.Equal(wire[size:], initial[size+16:]) {
				t.Fatal("TCP bytes changed beyond identity removal")
			}
			if _, address, err := readSS2022Header(readerConn(wire), next, false, nil); err != nil || address != "example.com:443" {
				t.Fatal(address, err)
			}
			for n := range size + 16 + 27 {
				if _, _, err := ss2022RelayTCP(key, bytes.Clone(initial[:n])); err == nil {
					t.Fatal("truncated TCP header accepted", n)
				}
			}
			bad := bytes.Clone(initial)
			bad[size] ^= 1
			if _, _, err := ss2022RelayTCP(key, bad); err == nil {
				t.Fatal("unknown TCP identity accepted")
			}
			sender, _ := newSS2022Sender(clientKey, [8]byte{})
			packet, _ := sender.seal("example.com:443", []byte("relay"), false)
			next, wire, err = ss2022RelayPacket(key, bytes.Clone(packet))
			if err != nil || len(wire) != len(packet)-16 || !bytes.Equal(wire[16:], packet[32:]) {
				t.Fatal("UDP body changed", err)
			}
			m, err := openSS2022Packet(next, wire, true, nil)
			if err != nil || m.id != sender.id || string(m.payload) != "relay" {
				t.Fatal(m, err)
			}
			for _, bad := range [][]byte{packet[:30], make([]byte, 65508), bytes.Clone(packet)} {
				if len(bad) == len(packet) {
					bad[16] ^= 1
				}
				if _, _, err := ss2022RelayPacket(key, bad); err == nil {
					t.Fatal("invalid relay datagram accepted")
				}
			}
		})
	}
}

func TestSS2022RelayTransport(t *testing.T) {
	for _, kind := range []string{"ws", "httpupgrade", "http", "grpc"} {
		t.Run(kind, func(t *testing.T) {
			terminal := ss2022Inbound(ss2022Methods[0], false)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{terminal}})
			in := ss2022RelayInbound(t, terminal.Method, s.Address(terminal.Tag), terminal.Password, 32)
			in.Transport = Transport{Type: kind}
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := ss2022Outbound(t, terminal, r.Address(in.Tag))
			out.Password = in.Password + ":" + terminal.Password
			out.Transport = in.Transport
			assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{out}}))
		})
	}
}

func TestSS2022RelayDestinationsAndRouting(t *testing.T) {
	for _, proxy := range []bool{false, true} {
		t.Run(fmt.Sprint(proxy), func(t *testing.T) {
			method := ss2022Methods[0]
			a, b := ss2022Inbound(method, false), ss2022Inbound(method, false)
			b.Password = ss2022PSK(method, 15)
			as := newTestRuntime(t, Config{Inbounds: []Inbound{a}})
			bs := newTestRuntime(t, Config{Inbounds: []Inbound{b}})
			in := ss2022RelayInbound(t, method, as.Address(a.Tag), a.Password, 32)
			in.Destinations[0].Name = "allowed"
			other := ss2022RelayInbound(t, method, bs.Address(b.Tag), b.Password, 32).Destinations[0]
			other.Name = "denied"
			in.Destinations = append(in.Destinations, other)
			in.Destinations[0].Server = "relay-target.test"
			cfg := Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}},
				Route: Route{Final: "deny", Rules: []Rule{{AuthUser: []string{"allowed"}, Outbound: "direct"}}},
				DNS:   DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "h", Predefined: map[string][]string{"relay-target.test": {"127.0.0.1"}}}}}}
			var upstream *Runtime
			if proxy {
				front := testInbound(t, "socks")
				upstream = newTestRuntime(t, Config{Inbounds: []Inbound{front}, DNS: cfg.DNS})
				cfg.Outbounds = append(cfg.Outbounds, testOutbound(t, front, upstream.Address(front.Tag)))
				cfg.Route.Rules[0].Outbound = "proxy"
			}
			r := newTestRuntime(t, cfg)
			out := ss2022Outbound(t, a, r.Address(in.Tag))
			out.Password = in.Password + ":" + a.Password
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 511, 4096})
			if as.Stats().Uplink == 0 || bs.Stats().Uplink != 0 {
				t.Fatal("identity sent to wrong backend")
			}
			if proxy && upstream.Stats().Uplink == 0 {
				t.Fatal("relay bypassed selected proxy")
			}
			out.Password = in.Password + ":" + b.Password
			denied := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			for _, network := range []string{"tcp", "udp"} {
				address := tcpEcho(t)
				if network == "udp" {
					address = echoUDP(t)
				}
				c, err := denied.Dial(context.Background(), network, address)
				if err != nil {
					continue
				}
				c.SetDeadline(time.Now().Add(100 * time.Millisecond))
				c.Write([]byte("denied"))
				_, err = c.Read(make([]byte, 64))
				c.Close()
				if err == nil {
					t.Fatal("relay auth_user policy bypassed", network)
				}
			}
			if bs.Stats().Uplink != 0 {
				t.Fatal("denied identity reached backend")
			}
		})
	}
}

func TestSS2022RelayUDPRebindAndReplay(t *testing.T) {
	for _, method := range ss2022Methods[:2] {
		t.Run(method, func(t *testing.T) {
			client, _, _, password := ss2022RelayChain(t, method, false, 2, "")
			out := client.config.Outbounds[0]
			address := portAddress(out.Server, out.ServerPort)
			key, _ := newSS2022Key(method, password)
			sender, _ := newSS2022Sender(key, [8]byte{})
			origin, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer origin.Close()
			peers := make(chan net.Addr, 8)
			go func() {
				b := make([]byte, 65535)
				for {
					n, from, err := origin.ReadFrom(b)
					if err != nil {
						return
					}
					peers <- from
					origin.WriteTo(b[:n], from)
				}
			}()
			first, err := net.Dial("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			second, err := net.Dial("udp", address)
			if err != nil {
				t.Fatal(err)
			}
			defer second.Close()
			read := func(c net.Conn, want string) [8]byte {
				t.Helper()
				c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buffer := make([]byte, 65535)
				n, err := c.Read(buffer)
				if err != nil {
					t.Fatal(err)
				}
				m, err := openSS2022Packet(key, buffer[:n], false, nil)
				if err != nil || m.clientID != sender.id || string(m.payload) != want {
					t.Fatal(m, err)
				}
				return m.id
			}
			initial, _ := sender.seal(origin.LocalAddr().String(), []byte("first"), false)
			first.Write(initial)
			serverID := read(first, "first")
			peer := <-peers
			second.Write(initial)
			second.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := second.Read(make([]byte, 65535)); err == nil {
				t.Fatal("replayed UDP generated response")
			}
			origin.WriteTo([]byte("late-first"), peer)
			if read(first, "late-first") != serverID {
				t.Fatal("server session changed")
			}
			sender.next = 1 << 40
			forged, _ := sender.seal(origin.LocalAddr().String(), []byte("forged"), false)
			forged[len(forged)-1] ^= 1
			second.Write(forged)
			second.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := second.Read(make([]byte, 65535)); err == nil {
				t.Fatal("invalid AEAD accepted")
			}
			origin.WriteTo([]byte("still-first"), peer)
			read(first, "still-first")
			sender.next = 1
			next, _ := sender.seal(origin.LocalAddr().String(), []byte("second"), false)
			second.Write(next)
			if read(second, "second") != serverID {
				t.Fatal("rebinding discarded server session")
			}
			if actual := <-peers; actual.String() != peer.String() {
				t.Fatal("final UDP source port changed", actual, peer)
			}
			origin.WriteTo([]byte("late-second"), peer)
			read(second, "late-second")
		})
	}
}

func TestSS2022RelayTCPReplayAndAuthentication(t *testing.T) {
	for _, method := range ss2022Methods[:2] {
		t.Run(method, func(t *testing.T) {
			terminal := ss2022Inbound(method, false)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{terminal}})
			in := ss2022RelayInbound(t, method, s.Address(terminal.Tag), terminal.Password, 32)
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			key, _ := newSS2022Key(method, in.Password+":"+terminal.Password)
			var hits atomic.Int32
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); io.WriteString(w, "reply") }))
			defer origin.Close()
			var wire bytes.Buffer
			_, err := ss2022Client(memoryNetConn{bytes.NewReader(nil), &wire}, key, strings.TrimPrefix(origin.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			tampered := bytes.Clone(wire.Bytes())
			tampered[len(tampered)-1] ^= 1
			probe, err := net.Dial("tcp", r.Address(in.Tag))
			if err != nil {
				t.Fatal(err)
			}
			probe.SetDeadline(time.Now().Add(time.Second))
			probe.Write(tampered)
			io.ReadAll(probe)
			probe.Close()
			for i := range 2 {
				raw, err := net.Dial("tcp", r.Address(in.Tag))
				if err != nil {
					t.Fatal(err)
				}
				raw.SetDeadline(time.Now().Add(2 * time.Second))
				raw.Write(wire.Bytes())
				c := &ss2022Conn{Conn: raw, key: key, requestSalt: bytes.Clone(wire.Bytes()[:len(key.master)])}
				c.initWriter(c.requestSalt)
				c.writer.nonce[0] = 2
				_, writeErr := c.Write([]byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"))
				response, readErr := io.ReadAll(c)
				c.Close()
				if i == 0 && (writeErr != nil || readErr != nil || !bytes.Contains(response, []byte("reply"))) {
					t.Fatal(writeErr, readErr)
				}
				if i == 1 && writeErr == nil && readErr == nil {
					t.Fatal("relay TCP salt replay accepted")
				}
			}
			for _, password := range []string{ss2022PSK(method, 99) + ":" + terminal.Password, in.Password + ":" + ss2022PSK(method, 99)} {
				out := ss2022Outbound(t, terminal, r.Address(in.Tag))
				out.Password = password
				bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				c, err := bad.Dial(context.Background(), "tcp", strings.TrimPrefix(origin.URL, "http://"))
				if err != nil {
					continue
				}
				c.SetDeadline(time.Now().Add(time.Second))
				c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
				_, err = c.Read(make([]byte, 64))
				c.Close()
				if err == nil {
					t.Fatal("unknown relay identity accepted")
				}
			}
			if hits.Load() != 1 {
				t.Fatal("replay or failed authentication reached target", hits.Load())
			}
		})
	}
}

func TestSS2022RelayClose(t *testing.T) {
	terminal := ss2022Inbound(ss2022Methods[0], false)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{terminal}})
	in := ss2022RelayInbound(t, terminal.Method, s.Address(terminal.Tag), terminal.Password, 32)
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := ss2022Outbound(t, terminal, r.Address(in.Tag))
	out.Password = in.Password + ":" + terminal.Password
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	var conns []net.Conn
	for range 8 {
		for _, network := range []string{"tcp", "udp"} {
			target := tcpEcho(t)
			if network == "udp" {
				target = echoUDP(t)
			}
			conn, err := c.Dial(context.Background(), network, target)
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			conn.Write([]byte("alive"))
			buffer := make([]byte, 5)
			if _, err = io.ReadFull(conn, buffer); err != nil || string(buffer) != "alive" {
				t.Fatal(err)
			}
			conns = append(conns, conn)
		}
	}
	done := make(chan error, 1)
	go func() { done <- r.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("relay close blocked with active sessions")
	}
	if n := r.Stats().Connections; n != 0 {
		t.Fatal("relay connections retained", n)
	}
	for _, conn := range conns {
		conn.Close()
	}
}

func TestSS2022RelayFanout(t *testing.T) {
	for _, method := range ss2022Methods[:2] {
		t.Run(method, func(t *testing.T) {
			a, b := ss2022Inbound(method, false), ss2022Inbound(method, false)
			b.Password = ss2022PSK(method, 15)
			as := newTestRuntime(t, Config{Inbounds: []Inbound{a}})
			bs := newTestRuntime(t, Config{Inbounds: []Inbound{b}})
			in := ss2022RelayInbound(t, method, as.Address(a.Tag), a.Password, 32)
			in.Destinations = append(in.Destinations, ss2022RelayInbound(t, method, bs.Address(b.Tag), b.Password, 32).Destinations[0])
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			peer, err := net.Dial("udp", r.Address(in.Tag))
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			peer.SetDeadline(time.Now().Add(3 * time.Second))
			target := echoUDP(t)
			for _, terminal := range []Inbound{a, b} {
				key, _ := newSS2022Key(method, in.Password+":"+terminal.Password)
				sender, _ := newSS2022Sender(key, [8]byte{})
				sender.id = [8]byte{42}
				sender.cipher, _ = ss2022PacketBody(key, sender.id)
				packet, _ := sender.seal(target, []byte(terminal.Password), false)
				peer.Write(packet)
				buffer := make([]byte, 65535)
				n, err := peer.Read(buffer)
				if err != nil {
					t.Fatal(err)
				}
				m, err := openSS2022Packet(key, buffer[:n], false, nil)
				if err != nil || string(m.payload) != terminal.Password {
					t.Fatal("fanout crossed identities", err)
				}
				out := ss2022Outbound(t, terminal, r.Address(in.Tag))
				out.Password = in.Password + ":" + terminal.Password
				assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{out}}))
			}
		})
	}
}

func TestSS2022RelayLargeInitialAndPacketLimit(t *testing.T) {
	for _, method := range ss2022Methods[:2] {
		t.Run(method, func(t *testing.T) {
			terminal := ss2022Inbound(method, false)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{terminal}})
			in := ss2022RelayInbound(t, method, s.Address(terminal.Tag), terminal.Password, 32)
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			key, _ := newSS2022Key(method, in.Password+":"+terminal.Password)
			raw, err := net.Dial("tcp", r.Address(in.Tag))
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(3 * time.Second))
			c := &ss2022Conn{Conn: raw, key: key, requestSalt: bytes.Repeat([]byte{11}, len(key.master))}
			c.initWriter(c.requestSalt)
			payload := bytes.Repeat([]byte("large-initial"), 4500)
			target, _ := encodeAddress(tcpEcho(t))
			variable := append(append(target, 0, 0), payload...)
			header := binary.BigEndian.AppendUint16(ss2022Header(0), uint16(len(variable)))
			initial := bytes.Clone(c.requestSalt)
			initial = append(initial, ss2022Identity(key.identities[0], c.requestSalt, key.master)...)
			initial, _ = c.writer.seal(initial, header)
			initial, _ = c.writer.seal(initial, variable)
			if _, err = raw.Write(initial); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(c, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatal("large initial corrupted", err)
			}
			sender, _ := newSS2022Sender(key, [8]byte{})
			maximum := 65507 - 43 - 7 - 16
			packet, err := sender.seal("127.0.0.1:443", make([]byte, maximum), false)
			if err != nil || len(packet) != 65507 {
				t.Fatal("maximum relay packet", len(packet), err)
			}
			relayKey, _ := newSSInboundKey(in)
			next, wire, err := ss2022RelayPacket(relayKey, packet)
			if err != nil {
				t.Fatal(err)
			}
			if m, err := openSS2022Packet(next, wire, true, nil); err != nil || len(m.payload) != maximum {
				t.Fatal("maximum packet changed", err)
			}
			if _, err = sender.seal("127.0.0.1:443", make([]byte, maximum+1), false); err == nil {
				t.Fatal("oversized relay packet accepted")
			}
		})
	}
}

func TestSS2022RelayIPv6(t *testing.T) {
	terminal := ss2022Inbound(ss2022Methods[0], false)
	terminal.Listen = "::1"
	s := newTestRuntime(t, Config{Inbounds: []Inbound{terminal}})
	in := ss2022RelayInbound(t, terminal.Method, s.Address(terminal.Tag), terminal.Password, 32)
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := ss2022Outbound(t, terminal, r.Address(in.Tag))
	out.Password = in.Password + ":" + terminal.Password
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{0, 1, 4096, 14000})
}

func TestSS2022RelayTLS(t *testing.T) {
	for _, kind := range []string{"", "ws"} {
		t.Run("transport="+kind, func(t *testing.T) {
			terminal := ss2022Inbound(ss2022Methods[0], false)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{terminal}})
			in := ss2022RelayInbound(t, terminal.Method, s.Address(terminal.Tag), terminal.Password, 32)
			in.TLS = certificate(t)
			in.Transport = Transport{Type: kind}
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := ss2022Outbound(t, terminal, r.Address(in.Tag))
			out.Password = in.Password + ":" + terminal.Password
			out.TLS = TLSOptions{Enabled: true, ServerName: "example.com", Certificate: in.TLS.Certificate}
			out.Transport = in.Transport
			assertTCP(t, newTestRuntime(t, Config{Outbounds: []Outbound{out}}))
		})
	}
}

func TestSS2022RelayUDPAssociationLimit(t *testing.T) {
	backend, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	method := ss2022Methods[0]
	in := ss2022RelayInbound(t, method, backend.LocalAddr().String(), ss2022PSK(method, 7), 32)
	r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	key, _ := newSS2022Key(method, in.Password+":"+in.Destinations[0].Password)
	sender, _ := newSS2022Sender(key, [8]byte{})
	packet, _ := sender.seal("127.0.0.1:443", []byte("bounded"), false)
	var peers []net.Conn
	defer func() {
		for _, c := range peers {
			c.Close()
		}
	}()
	for range 256 {
		c, err := net.Dial("udp", r.Address(in.Tag))
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, c)
		c.Write(packet)
		backend.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err = backend.ReadFrom(make([]byte, 65535)); err != nil {
			t.Fatal(err)
		}
	}
	extra, err := net.Dial("udp", r.Address(in.Tag))
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.Write(packet)
	backend.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err = backend.ReadFrom(make([]byte, 65535)); err == nil {
		t.Fatal("relay exceeded256 UDP associations")
	}
	if n := r.Stats().Connections; n != 256 {
		t.Fatal("unexpected UDP socket count", n)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if n := r.Stats().Connections; n != 0 {
		t.Fatal("UDP sockets retained on close", n)
	}
}

func FuzzSS2022Relay(f *testing.F) {
	var keys []*ssKey
	for i, method := range ss2022Methods[:2] {
		in := Inbound{Method: method, Password: ss2022PSK(method, 32), Destinations: []ShadowsocksDestination{{Server: "127.0.0.1", ServerPort: 8388, Password: ss2022PSK(method, 7)}}}
		key, err := newSSInboundKey(in)
		if err != nil {
			f.Fatal(err)
		}
		keys = append(keys, key)
		client, _ := newSS2022Key(method, in.Password+":"+in.Destinations[0].Password)
		var wire bytes.Buffer
		ss2022Client(memoryNetConn{bytes.NewReader(nil), &wire}, client, "example.com:443")
		f.Add(uint8(i), bytes.Clone(wire.Bytes()))
		sender, _ := newSS2022Sender(client, [8]byte{})
		b, _ := sender.seal("example.com:443", []byte("test"), false)
		f.Add(uint8(i), b)
	}
	f.Add(uint8(0), []byte{})
	f.Fuzz(func(t *testing.T, method uint8, b []byte) {
		if len(b) > 70000 {
			return
		}
		key := keys[int(method)%len(keys)]
		if _, out, err := ss2022RelayTCP(key, bytes.Clone(b)); err == nil {
			size := len(key.master)
			if len(out) != len(b)-16 || !bytes.Equal(out[:size], b[:size]) || !bytes.Equal(out[size:], b[size+16:]) {
				t.Fatal("invalid TCP rewrite")
			}
		}
		if next, out, err := ss2022RelayPacket(key, bytes.Clone(b)); err == nil {
			var before, after [16]byte
			key.udpBlock.Decrypt(before[:], b[:16])
			next.udpBlock.Decrypt(after[:], out[:16])
			if len(out) != len(b)-16 || before != after || !bytes.Equal(out[16:], b[32:]) {
				t.Fatal("invalid UDP rewrite")
			}
		}
	})
}

func BenchmarkSS2022RelayUDP(b *testing.B) {
	method := ss2022Methods[0]
	in := Inbound{Method: method, Password: ss2022PSK(method, 32), Destinations: []ShadowsocksDestination{{Server: "127.0.0.1", ServerPort: 8388, Password: ss2022PSK(method, 7)}}}
	key, _ := newSSInboundKey(in)
	client, _ := newSS2022Key(method, in.Password+":"+in.Destinations[0].Password)
	sender, _ := newSS2022Sender(client, [8]byte{})
	packet, _ := sender.seal("127.0.0.1:443", make([]byte, 1200), false)
	work := make([]byte, len(packet))
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	for b.Loop() {
		copy(work, packet)
		if _, _, err := ss2022RelayPacket(key, work); err != nil {
			b.Fatal(err)
		}
	}
}
