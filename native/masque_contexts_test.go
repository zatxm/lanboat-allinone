package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMasqueContextCapabilities(t *testing.T) {
	for _, protocol := range []string{"connect-ip", "connect-udp"} {
		c, err := parseMasqueContextCapabilities(masqueContextsAdvertisement(protocol))
		if err != nil || c != masqueLocalContexts(protocol) {
			t.Fatal(protocol, c, err)
		}
	}
	for _, suffix := range []string{`, new=(1 "x";a=?1 foo);q=:YWJj:`, `, future=@1700000000;flag, text=%"hello%20world"`, `, text=%"caf%c3%a9", fraction=999999999999.999, negative=-999999999999.999, integer=000000000000001`, `, bytes=:YQ:, padbits=:YWJ:`, `, max-templates=4, derived=(0;v=1 8 99)`} {
		if _, err := parseMasqueContextCapabilities(masqueContextsAdvertisement("connect-ip") + suffix); err != nil {
			t.Fatal(suffix, err)
		}
	}
	for _, bad := range []string{"", "max-templates=-1", "mtu=1.2", "checksum=1", "checksum=?2", "derived=(0 \"x\")", "derived=(0 1", "derived=(0)junk", "max-templates=3,", "Key=1", "x=:???=:", "x=:YW\nJj:", "x=:YW\rJj:", "x=(())", "x=\"a\\q\"", "x=@", `x=%"%ff"`, `x=%"%C3%a9"`, "x=1234567890123.1", "x=-1234567890123.1", "x=0000000000000001", "x=-0000000000000001", "x=@0000000000000001", strings.Repeat("x", 4097)} {
		if _, err := parseMasqueContextCapabilities(bad); err == nil {
			t.Fatal("accepted malformed capability", bad)
		}
	}
	if masqueContextsResponse("connect-ip", "x=?2") != "" || masqueContextsResponse("", "checksum=?1") != "" {
		t.Fatal("invalid extension negotiated")
	}
}

func masqueContextFlow(t *testing.T, protocol string, server bool) (*masqueFlow, *masqueContexts) {
	t.Helper()
	m := newMasqueHTTPSession(context.Background())
	a, b := net.Pipe()
	f, err := m.registerFlow(a, 0, a)
	if err != nil {
		t.Fatal(err)
	}
	f.negotiateContexts(protocol, masqueContextsAdvertisement(protocol), server)
	done := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, b); close(done) }()
	t.Cleanup(func() {
		f.Close()
		b.Close()
		m.close()
		m.workers.Wait()
		<-done
		if m.contextBytes.Load() != 0 {
			t.Error("context memory not released", m.contextBytes.Load())
		}
	})
	return f, f.contexts.Load()
}
func contextAssign(id, next uint64, values ...uint64) []byte {
	b := quicVar(nil, id)
	b = quicVar(b, next)
	for _, v := range values {
		b = quicVar(b, v)
	}
	return b
}

func TestMasqueContextRegistry(t *testing.T) {
	for _, server := range []bool{false, true} {
		t.Run(fmt.Sprint("server=", server), func(t *testing.T) {
			f, s := masqueContextFlow(t, "connect-ip", server)
			id := uint64(2)
			if !server {
				id = 1
			}
			derived := contextAssign(id, 0, 0, 4)
			if err := s.handle(f, masqueDerivedAssign, derived); err != nil {
				t.Fatal(err)
			}
			template := &masqueProcessingContext{id: id + 2, next: id, kind: masqueTemplateAssign, segments: []masqueStaticSegment{{0, []byte{0x45}}}}
			if err := s.handle(f, masqueTemplateAssign, masqueContextWire(template)); err != nil {
				t.Fatal(err)
			}
			if err := s.handle(f, masqueDerivedClose, quicVar(nil, id)); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.decode(id+2, []byte{0}); ok {
				t.Fatal("closed child still usable")
			}
			if err := s.handle(f, masqueDerivedAssign, derived); err == nil {
				t.Fatal("closed ID reused")
			}
			for _, tc := range []struct {
				kind uint64
				data []byte
			}{
				{masqueDerivedAssign, contextAssign(0, 0, 0)},
				{masqueDerivedAssign, contextAssign(id+1, 0, 0)},
				{masqueDerivedAssign, contextAssign(id+4, 300, 0)},
				{masqueDerivedAssign, contextAssign(id+4, 0, 0, 0)},
				{masqueDerivedAssign, contextAssign(id+4, 0, 9)},
				{masqueDerivedAssign, contextAssign(id+4, 0)},
				{masqueChecksumAssign, contextAssign(id+4, 0, 10, 0)},
				{masqueChecksumAssign, contextAssign(id+4, 0, 65535, 1)},
				{masqueDerivedACK, quicVar(nil, id)},
				{masqueTemplateClose, quicVar(nil, id)},
				{masqueDerivedClose, append(quicVar(nil, id), 1)},
				{masqueTemplateAssign, contextAssign(id+4, 0)},
				{masqueTemplateAssign, append(contextAssign(id+4, 0, 0, 4), 'x')},
			} {
				if err := s.handle(f, tc.kind, tc.data); err == nil {
					t.Fatalf("accepted malformed context: %x %x", tc.kind, tc.data)
				}
			}
		})
	}
}

func TestMasqueContextChains(t *testing.T) {
	cases := []struct {
		name                 string
		first, second, third *masqueProcessingContext
		valid                bool
	}{
		{"template-derived-checksum", &masqueProcessingContext{kind: masqueTemplateAssign, segments: []masqueStaticSegment{{0, []byte{0x45}}}}, &masqueProcessingContext{kind: masqueDerivedAssign, fields: 1}, &masqueProcessingContext{kind: masqueChecksumAssign, checksumField: 26, checksumStart: 20}, true},
		{"duplicate-derived", &masqueProcessingContext{kind: masqueDerivedAssign, fields: 1}, &masqueProcessingContext{kind: masqueDerivedAssign, fields: 16}, nil, false},
		{"conflicting-checksums", &masqueProcessingContext{kind: masqueDerivedAssign, fields: 128}, &masqueProcessingContext{kind: masqueChecksumAssign, checksumField: 26, checksumStart: 20}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, s := masqueContextFlow(t, "connect-ip", true)
			tc.first.id = 2
			if err := s.handle(f, tc.first.kind, masqueContextWire(tc.first)); err != nil {
				t.Fatal(err)
			}
			tc.second.id, tc.second.next = 4, 2
			err := s.handle(f, tc.second.kind, masqueContextWire(tc.second))
			if (err == nil) != tc.valid {
				t.Fatal(err)
			}
			if tc.third != nil {
				tc.third.id, tc.third.next = 6, 4
				if err := s.handle(f, tc.third.kind, masqueContextWire(tc.third)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestMasqueContextTemplate(t *testing.T) {
	f, s := masqueContextFlow(t, "connect-udp", true)
	c := &masqueProcessingContext{id: 2, kind: masqueTemplateAssign, segments: []masqueStaticSegment{{0, []byte("AB")}, {5, []byte("Z")}}}
	if err := s.handle(f, c.kind, masqueContextWire(c)); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.decode(2, []byte("cdeFG")); !ok || string(got) != "ABcdeZFG" {
		t.Fatal(string(got), ok)
	}
	for _, data := range [][]byte{nil, []byte("a"), make([]byte, 65535)} {
		if _, ok := s.decode(2, data); ok {
			t.Fatal("accepted impossible template reconstruction", len(data))
		}
	}
	if _, ok := s.decode(4, []byte("ignored")); ok {
		t.Fatal("unknown Context accepted")
	}
	c.id, c.segments = 4, []masqueStaticSegment{{0, []byte{1}}, {1, []byte{2}}}
	if err := s.handle(f, c.kind, masqueContextWire(c)); err == nil {
		t.Fatal("adjacent segments accepted")
	}
	if err := s.handle(f, masqueDerivedAssign, contextAssign(6, 0, 0)); err == nil {
		t.Fatal("IP fields advertised for opaque UDP")
	}
}

func TestMasqueContextDerivedRoundtrip(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, tcp := range []bool{false, true} {
			for _, size := range []int{0, 1, 511, 4096, 60000} {
				t.Run(fmt.Sprintf("v6=%t/tcp=%t/size=%d", v6, tcp, size), func(t *testing.T) {
					src, dst := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("198.51.100.3")
					if v6 {
						src, dst = netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8:1::3")
					}
					packet := makeUDPPacket(src, dst, 2010, 3001, bytes.Repeat([]byte{71}, size))
					if tcp {
						segment := make([]byte, 20+size)
						binary.BigEndian.PutUint16(segment, 2010)
						binary.BigEndian.PutUint16(segment[2:], 3001)
						segment[12], segment[13] = 0x50, 0x18
						copy(segment[20:], bytes.Repeat([]byte{71}, size))
						packet = makeWGIP(src, dst, 6, segment)
						p, _ := parseTunPacket(packet)
						binary.BigEndian.PutUint16(packet[p.header+16:], transportChecksum(p, packet[p.header:]))
					}
					compact, mask, holes := masqueRemoveDerived(packet, 511)
					if mask == 0 || len(holes) < 2 {
						t.Fatal("no derived fields", mask)
					}
					got, ok := masqueInsertDerived(compact, mask, 65535)
					if !ok || !bytes.Equal(got, packet) {
						t.Fatalf("derived changed packet: %x -> %x -> %x mask=%x ok=%t", packet[:min(60, len(packet))], compact[:min(60, len(compact))], got[:min(60, len(got))], mask, ok)
					}
					if _, ok := masqueInsertDerived(compact, mask, len(packet)-1); ok {
						t.Fatal("reconstruction exceeded MTU")
					}
					segments := masqueStaticFields(packet, holes)
					c := &masqueProcessingContext{id: 4, next: 2, kind: masqueTemplateAssign, segments: segments}
					f, s := masqueContextFlow(t, "connect-ip", true)
					if err := s.handle(f, masqueDerivedAssign, masqueContextWire(&masqueProcessingContext{id: 2, kind: masqueDerivedAssign, fields: mask})); err != nil {
						t.Fatal(err)
					}
					if err := s.handle(f, masqueTemplateAssign, masqueContextWire(c)); err != nil {
						t.Fatal(err)
					}
					wire := masqueTemplateRemove(compact, segments)
					if got, ok := s.decode(4, wire); !ok || !bytes.Equal(got, packet) {
						t.Fatal("template+derived changed packet", ok)
					}
				})
			}
		}
	}
}

func TestMasqueContextChecksum(t *testing.T) {
	src, dst := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("198.51.100.3")
	want := makeUDPPacket(src, dst, 2010, 3001, []byte("odd-payload"))
	packet := bytes.Clone(want)
	// Independently supply the IPv4 pseudo-header sum, not the packet's complete checksum.
	sum := uint32(17 + len(packet) - 20)
	for _, part := range [][]byte{packet[12:16], packet[16:20]} {
		for i := 0; i < len(part); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(part[i:]))
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[26:], uint16(sum))
	f, s := masqueContextFlow(t, "connect-ip", true)
	if err := s.handle(f, masqueChecksumAssign, contextAssign(2, 0, 26, 20)); err != nil {
		t.Fatal(err)
	}
	got, ok := s.decode(2, packet)
	if !ok || !bytes.Equal(got, want) {
		t.Fatal("partial checksum failed", got, want, ok)
	}
	for _, offset := range [][2]int{{0, 0}, {len(packet), 1}, {2, len(packet) + 1}} {
		if masqueCompleteChecksum(bytes.Clone(packet), offset[0], offset[1], true) {
			t.Fatal("invalid checksum bounds accepted", offset)
		}
	}
}

func TestMasqueContextsIndependent(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), MasqueOptions: MasqueOptions{DatagramContexts: true}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.HTTPVersion = version
			out.Username, out.Password = "client", "private"
			out.DatagramContexts = true
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			for _, host := range []string{"127.0.0.1", "::1"} {
				address := masqueEcho(t, "tcp", net.JoinHostPort(host, "0"))
				conn, err := client.Dial(context.Background(), "tcp", address)
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				want := bytes.Repeat([]byte{53}, 70000)
				sent := make(chan error, 1)
				go func() { sent <- writeAll(conn, want) }()
				got := make([]byte, len(want))
				_, readErr := io.ReadFull(conn, got)
				writeErr := <-sent
				conn.Close()
				if readErr != nil || writeErr != nil || !bytes.Equal(got, want) {
					t.Fatal("TCP echo changed", readErr, writeErr)
				}
				assertUDPAddress(t, client, []int{1, 511, 4096, 60000}, masqueEcho(t, "udp", net.JoinHostPort(host, "0")))
			}
			c := client.masqueClients[out.Tag]
			p := c.ip.Load()
			state := p.flow.contexts.Load()
			if state == nil {
				t.Fatal("context negotiation missing")
			}
			state.mu.Lock()
			used := 0
			for _, e := range state.entries {
				if state.localID(e.id) && e.used > 0 {
					used++
				}
			}
			state.mu.Unlock()
			if used == 0 {
				t.Fatal("all traffic silently used Context0")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			status, err := client.ProbeMasquePath(ctx, out.Tag)
			cancel()
			if err != nil || status.MTU != 1280 || version == 3 && !status.DatagramVerified {
				t.Fatal("compressed flow invalidated path probe", status, err)
			}
			t.Log("active compression contexts used", used, "session budget", state.session.contextBytes.Load())
		})
	}
}

func FuzzMasqueContextCapabilities(f *testing.F) {
	f.Add(masqueContextsAdvertisement("connect-ip"))
	f.Add(`x=(1 "foo";q=?1), checksum=?1`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			s = s[:8192]
		}
		_, _ = parseMasqueContextCapabilities(s)
	})
}
func FuzzMasqueContextDerived(f *testing.F) {
	b := makeUDPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 1, 2, []byte("seed"))
	f.Add(b, uint16(511))
	f.Fuzz(func(t *testing.T, b []byte, mask uint16) {
		if len(b) > 65535 {
			b = b[:65535]
		}
		compact, fields, _ := masqueRemoveDerived(b, mask)
		if fields != 0 {
			got, ok := masqueInsertDerived(compact, fields, 65535)
			if !ok || !bytes.Equal(got, b) {
				t.Fatalf("non-reversible fields %x", fields)
			}
		}
		_, _ = masqueInsertDerived(b, mask, 65535)
	})
}

func TestMasqueContextGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/masque-contexts.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name, Original, Compact string
		Mask                    uint16
	}
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			original, err := hex.DecodeString(v.Original)
			if err != nil {
				t.Fatal(err)
			}
			want, err := hex.DecodeString(v.Compact)
			if err != nil {
				t.Fatal(err)
			}
			got, mask, _ := masqueRemoveDerived(original, v.Mask)
			if mask != v.Mask || !bytes.Equal(got, want) {
				t.Fatal("wire differs from independent vector", mask, v.Mask, hex.EncodeToString(got))
			}
			decoded, ok := masqueInsertDerived(want, mask, 65535)
			if !ok || !bytes.Equal(decoded, original) {
				t.Fatal("independent vector decode failed", ok, hex.EncodeToString(decoded))
			}
		})
	}
}

func TestMasqueContextOffloadSelection(t *testing.T) {
	for _, header := range []string{`checksum=?1`, `checksum=?1, derived=(0 1 2 3 4)`, `max-templates=4, checksum=?1`, `max-templates=4, checksum=?1, derived=(0 1 2 3 4)`} {
		t.Run(header, func(t *testing.T) {
			a, b := net.Pipe()
			m1, m2 := newMasqueHTTPSession(context.Background()), newMasqueHTTPSession(context.Background())
			f1, err := m1.registerFlow(a, 0, a)
			if err != nil {
				t.Fatal(err)
			}
			f2, err := m2.registerFlow(b, 0, b)
			if err != nil {
				t.Fatal(err)
			}
			f1.negotiateContexts("connect-ip", header, false)
			f2.negotiateContexts("connect-ip", masqueContextsAdvertisement("connect-ip"), true)
			t.Cleanup(func() {
				m1.close()
				m2.close()
				m1.workers.Wait()
				m2.workers.Wait()
				if m1.contextBytes.Load() != 0 || m2.contextBytes.Load() != 0 {
					t.Error("flow close leaked context state")
				}
			})
			m1.goWork(func() { _ = f1.readCapsules() })
			m2.goWork(func() { _ = f2.readCapsules() })
			for _, v6 := range []bool{false, true} {
				src, dst := netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("198.51.100.3")
				if v6 {
					src, dst = netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::3")
				}
				want := makeUDPPacket(src, dst, 20, 30, bytes.Repeat([]byte("offload"), 99))
				buffer := make([]byte, 65535)
				for range 12 {
					if _, err := f1.Write(want); err != nil {
						t.Fatal(err)
					}
					f2.SetReadDeadline(time.Now().Add(time.Second))
					n, err := f2.Read(buffer)
					if err != nil || !bytes.Equal(buffer[:n], want) {
						t.Fatal("offload changed payload", n, err)
					}
				}
			}
			state := f1.contexts.Load()
			state.mu.Lock()
			used := 0
			for _, c := range state.entries {
				if c.used == 0 {
					continue
				}
				p, ok := state.plan(c)
				if ok && p.checksum {
					used++
				}
			}
			state.mu.Unlock()
			if used == 0 {
				t.Fatal("offload never selected")
			}
		})
	}
}

func TestMasqueContextBounds(t *testing.T) {
	f, s := masqueContextFlow(t, "connect-ip", true)
	for i := uint64(1); i <= 32; i++ {
		c := &masqueProcessingContext{id: 2 * i, kind: masqueTemplateAssign, segments: []masqueStaticSegment{{0, []byte{1}}}}
		if err := s.handle(f, c.kind, masqueContextWire(c)); err != nil {
			t.Fatal(i, err)
		}
	}
	c := &masqueProcessingContext{id: 66, kind: masqueTemplateAssign, segments: []masqueStaticSegment{{0, []byte{1}}}}
	if err := s.handle(f, c.kind, masqueContextWire(c)); err == nil {
		t.Fatal("active template limit ignored")
	}
	for i := uint64(1); i <= 32; i++ {
		if err := s.handle(f, masqueTemplateClose, quicVar(nil, 2*i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.handle(f, c.kind, masqueContextWire(c)); err != nil {
		t.Fatal("closed templates consumed active capacity", err)
	}
	if s.session.contextBytes.Load() > 20000 {
		t.Fatal("closed templates retained payload")
	}
	c.id = 68
	c.segments[0].data = make([]byte, 65535)
	s.session.contextBytes.Store(masqueContextBudget)
	if err := s.handle(f, c.kind, masqueContextWire(c)); err == nil {
		t.Fatal("shared context budget ignored")
	}
	s.session.contextBytes.Store(s.budget)
	s.peer.mtu = 0
	if _, _, err := s.encode(f, []byte{1}); err == nil {
		t.Fatal("explicit zero MTU treated as absent")
	}
}

func TestMasqueContextConfiguration(t *testing.T) {
	for _, raw := range []string{
		`{"outbounds":[{"type":"direct","masque_contexts":true}]}`,
		`{"outbounds":[{"type":"masque","server":"127.0.0.1","server_port":443,"tls":{"enabled":true},"masque_headers":{"http-datagram-contexts":"max-templates=1"}}]}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("accepted invalid context configuration", raw)
		}
	}
	for _, kind := range []string{"masque-client", "masque-server"} {
		endpoint := map[string]any{"type": kind, "tag": "m", "masque_contexts": true}
		if kind == "masque-client" {
			endpoint["server"] = "127.0.0.1"
			endpoint["server_port"] = 443
			endpoint["tls"] = TLSOptions{Enabled: true, Insecure: true}
		} else {
			endpoint["listen"] = "127.0.0.1"
			endpoint["address"] = []string{"10.44.0.1/24"}
			endpoint["users"] = []User{{Username: "client", Password: "private"}}
			endpoint["tls"] = certificate(t)
		}
		data, err := json.Marshal(map[string]any{"endpoints": []any{endpoint}})
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := Parse(data)
		if err != nil {
			t.Fatal(kind, err)
		}
		enabled := false
		for _, o := range cfg.Outbounds {
			enabled = enabled || o.DatagramContexts
		}
		for _, in := range cfg.Inbounds {
			enabled = enabled || in.DatagramContexts
		}
		if !enabled {
			t.Fatal("endpoint discarded context setting")
		}
	}

}

func TestMasqueContextPythonReference(t *testing.T) {
	script := filepath.Join("..", "tests", "masque-context-reference.py")
	t.Run("native-server", func(t *testing.T) {
		in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: 1, Users: []User{{Username: "client", Password: "private"}}, MasqueOptions: MasqueOptions{DatagramContexts: true}}
		server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		_, port, _ := net.SplitHostPort(server.Address("server"))
		_, target, _ := net.SplitHostPort(echoUDP(t))
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "python3", script, "client", port, target).CombinedOutput()
		if err != nil {
			t.Fatal(err, string(out))
		}
		t.Log(string(out))
	})
	t.Run("native-client", func(t *testing.T) {
		port := unusedPort(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "python3", script, "server", strconv.Itoa(int(port)))
		pipe, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stderr = os.Stderr
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waited := false
		t.Cleanup(func() {
			if !waited {
				cmd.Process.Kill()
				cmd.Wait()
			}
		})
		reader := bufio.NewReader(pipe)
		line, err := reader.ReadString('\n')
		if err != nil || line != "ready\n" {
			t.Fatal(line, err)
		}
		client := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "masque", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, HTTPVersion: 1, Username: "client", Password: "private", MasqueOptions: MasqueOptions{Mode: "udp", DatagramContexts: true}}}})
		conn, err := client.Dial(ctx, "udp", "127.0.0.1:20000")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		for _, size := range []int{1, 511, 4096} {
			want := append([]byte("reference-"), bytes.Repeat([]byte{37}, size)...)
			if _, err = conn.Write(want); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, 8192)
			n, err := conn.Read(got)
			if err != nil || !bytes.Equal(got[:n], want) {
				t.Fatal(n, err)
			}
		}
		rest, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		err = cmd.Wait()
		waited = true
		if err != nil {
			t.Fatal(err, string(rest))
		}
		t.Log(string(rest))
	})
}

func TestMasqueContextConcurrentDuplex(t *testing.T) {
	a, b := net.Pipe()
	left, right := newMasqueHTTPSession(context.Background()), newMasqueHTTPSession(context.Background())
	f1, err := left.registerFlow(a, 0, a)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := right.registerFlow(b, 0, b)
	if err != nil {
		t.Fatal(err)
	}
	f1.negotiateContexts("connect-ip", masqueContextsAdvertisement("connect-ip"), false)
	f2.negotiateContexts("connect-ip", masqueContextsAdvertisement("connect-ip"), true)
	var workers sync.WaitGroup
	t.Cleanup(func() { left.close(); right.close(); workers.Wait(); left.workers.Wait(); right.workers.Wait() })
	left.goWork(func() { _ = f1.readCapsules() })
	right.goWork(func() { _ = f2.readCapsules() })
	f1.SetDeadline(time.Now().Add(5 * time.Second))
	f2.SetDeadline(time.Now().Add(5 * time.Second))
	packet := makeUDPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 20, 30, bytes.Repeat([]byte{87}, 1200))
	done := make(chan error, 4)
	for _, flow := range []*masqueFlow{f1, f2} {
		workers.Go(func() {
			for range 64 {
				if _, err := flow.Write(packet); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		})
		workers.Go(func() {
			buffer := make([]byte, 65535)
			for range 64 {
				n, err := flow.Read(buffer)
				if err != nil {
					done <- err
					return
				}
				if !bytes.Equal(buffer[:n], packet) {
					done <- fmt.Errorf("duplex packet changed")
					return
				}
			}
			done <- nil
		})
	}
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestMasqueContextIDLifetime(t *testing.T) {
	_, s := masqueContextFlow(t, "connect-ip", true)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := uint64(2); id <= 8192; id += 2 {
		c := &masqueProcessingContext{id: id, kind: masqueDerivedAssign, fields: 1}
		if err := s.install(c, false); err != nil {
			t.Fatal(id, err)
		}
		s.retire(c)
	}
	if err := s.install(&masqueProcessingContext{id: 8194, kind: masqueDerivedAssign, fields: 1}, false); err == nil {
		t.Fatal("unbounded context ID history")
	}
	if s.session.contextBytes.Load() != 4096*128 {
		t.Fatal("unexpected tombstone accounting", s.session.contextBytes.Load())
	}
}

func FuzzMasqueContextControl(f *testing.F) {
	f.Add(byte(3), contextAssign(4, 2, 4))
	f.Add(byte(0), masqueContextWire(&masqueProcessingContext{id: 4, next: 2, kind: masqueTemplateAssign, segments: []masqueStaticSegment{{0, []byte{0x45}}}}))
	m := newMasqueHTTPSession(context.Background())
	a, b := net.Pipe()
	flow, err := m.registerFlow(a, 0, a)
	if err != nil {
		f.Fatal(err)
	}
	drain := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, b); close(drain) }()
	f.Cleanup(func() { flow.Close(); b.Close(); m.close(); <-drain })
	f.Fuzz(func(t *testing.T, kind byte, data []byte) {
		if len(data) > 65536 {
			data = data[:65536]
		}
		s := &masqueContexts{session: m, local: masqueLocalContexts("connect-ip"), peer: masqueLocalContexts("connect-ip"), ip: true, server: true, entries: map[uint64]*masqueProcessingContext{}, acks: make(chan masqueContextACK, 2)}
		if err := s.install(&masqueProcessingContext{id: 2, kind: masqueDerivedAssign, fields: 1}, false); err != nil {
			t.Fatal(err)
		}
		_ = s.handle(flow, masqueTemplateAssign+uint64(kind%9), data)
		_, _ = s.decode(4, data)
		s.close()
		if m.contextBytes.Load() != 0 {
			t.Fatal("control parser retained memory")
		}
	})
}

func BenchmarkMasqueContextDerived(b *testing.B) {
	for _, size := range []int{1280, 60000} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			packet := makeUDPPacket(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.2"), 20, 30, make([]byte, size-28))
			b.SetBytes(int64(len(packet)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				compact, mask, _ := masqueRemoveDerived(packet, 511)
				got, ok := masqueInsertDerived(compact, mask, 65535)
				if !ok || len(got) != len(packet) {
					b.Fatal("reconstruction failed")
				}
			}
		})
	}
}

func TestMasqueContextSourceValidation(t *testing.T) {
	in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Username: "client", Password: "private"}}, MasqueOptions: MasqueOptions{DatagramContexts: true}}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Username, out.Password = "client", "private"
	out.DatagramContexts = true
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := client.masqueClients[out.Tag].ipSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint(v6), func(t *testing.T) {
			host, source, allowed := "127.0.0.1", "192.0.2.254", "10.44.0.2"
			if v6 {
				host, source, allowed = "::1", "2001:db8:bad::1", "fd44::2"
			}
			sink, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			target := sink.LocalAddr().(*net.UDPAddr)
			packet := makeUDPPacket(netip.MustParseAddr(source), netip.MustParseAddr(host), 2010, uint16(target.Port), []byte("spoofed-source"))
			state := p.flow.contexts.Load()
			before := uint64(0)
			state.mu.Lock()
			before = state.epoch
			state.mu.Unlock()
			for i := 0; i < 100; i++ {
				if _, err := p.flow.Write(packet); err != nil {
					t.Fatal(err)
				}
				state.mu.Lock()
				used := state.epoch > before
				state.mu.Unlock()
				if used {
					break
				}
				if i == 99 {
					t.Fatal("spoof packet never used compression")
				}
				time.Sleep(time.Millisecond)
			}
			sink.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buffer := make([]byte, 100)
			if _, _, err = sink.ReadFrom(buffer); !os.IsTimeout(err) {
				t.Fatal("compressed packet bypassed source validation", err)
			}
			packet = makeUDPPacket(netip.MustParseAddr(allowed), netip.MustParseAddr(host), 2011, uint16(target.Port), []byte("valid-source"))
			if _, err = p.flow.Write(packet); err != nil {
				t.Fatal(err)
			}
			sink.SetReadDeadline(time.Now().Add(time.Second))
			n, _, err := sink.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "valid-source" {
				t.Fatal("valid compressed transport stopped", n, err)
			}
		})
	}
}
