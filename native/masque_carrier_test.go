package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func natCarrierInbound(t *testing.T, kind string) Inbound {
	t.Helper()
	in := testInbound(t, kind)
	switch kind {
	case "ss2022":
		in = ss2022Inbound(ss2022Methods[0], false)
	case "ss2022-aes256":
		in = ss2022Inbound(ss2022Methods[1], false)
	case "ss2022-chacha":
		in = ss2022Inbound(ss2022Methods[2], false)
	case "ssr":
		in = Inbound{Type: "shadowsocksr", Tag: "server", Listen: "127.0.0.1", Method: "aes-256-cfb", Password: "private", Protocol: "auth_chain_a"}
	case "snell3", "snell4":
		in = Inbound{Type: "snell", Tag: "server", Listen: "127.0.0.1", Password: "private", Version: kind[5:]}
	case "hysteria", "hysteria2", "tuic":
		in.TLS, in.Users = certificate(t), []User{{UUID: testUUID, Password: "private"}}
	case "tuic4", "tuic-stream":
		in.Type, in.TLS, in.Users = "tuic", certificate(t), []User{{UUID: testUUID, Password: "private"}}
		if kind == "tuic4" {
			in.Version = "4"
		}
	}
	return in
}

func natCarrierOutbound(t *testing.T, in Inbound, address string) Outbound {
	t.Helper()
	out := testOutbound(t, in, address)
	out.Version, out.Protocol = in.Version, in.Protocol
	if isSS2022(in.Method) {
		out = ss2022Outbound(t, in, address)
	}
	return out
}

func natCarrierCheck(t *testing.T, s *masqueNATScope, mapping, host string, size int) {
	t.Helper()
	peers := []*net.UDPConn{natSocket(t, host), natSocket(t, host)}
	if host == "127.0.0.1" {
		peers = append(peers, natSocket(t, "127.0.0.2"))
	}
	type response struct{ data, from string }
	responses := make(chan response, len(peers))
	reply := func(data []byte, from string) error { responses <- response{string(data), from}; return nil }
	for i, peer := range peers {
		payload := bytes.Repeat([]byte{byte(i + 1)}, size)
		q := natRequest(peer.LocalAddr().String())
		if host == "::1" {
			q.source = "[fd44::2]:40000"
		}
		if err := s.send(q, payload, reply); err != nil {
			t.Fatal(err)
		}
		from := natRead(t, peer, payload)
		if _, err := peer.WriteToUDPAddrPort(payload, from); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-responses:
			if got.data != string(payload) || got.from != q.address {
				t.Fatal("carrier changed reply identity", got.from, q.address, len(got.data))
			}
		case <-time.After(3 * time.Second):
			t.Fatal("carrier reply missing")
		}
	}
	want := 1
	if mapping == "address_dependent" && len(peers) == 3 {
		want = 2
	} else if mapping == "address_and_port_dependent" {
		want = len(peers)
	}
	s.table.mu.Lock()
	defer s.table.mu.Unlock()
	if len(s.table.entries) != want {
		t.Fatal("wrong carrier association count", len(s.table.entries), want)
	}
	for _, e := range s.table.entries {
		if e.carrier == nil || e.key.carrier != "" {
			t.Fatal("carrier still fixed to first destination", e.key)
		}
	}
}

func TestMasqueNATCarrierMapping(t *testing.T) {
	for _, kind := range []string{"socks", "shadowsocks", "ss2022", "ss2022-aes256", "ss2022-chacha", "ssr", "trojan", "snell3", "snell4", "hysteria", "hysteria2", "tuic", "tuic4", "tuic-stream"} {
		for _, mapping := range masqueNATModes {
			for _, host := range []string{"127.0.0.1", "::1"} {
				t.Run(kind+"/"+mapping+"/"+host, func(t *testing.T) {
					in := natCarrierInbound(t, kind)
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := natCarrierOutbound(t, in, server.Address(in.Tag))
					if kind == "tuic-stream" {
						out.UDPRelayMode = "quic"
					}
					r := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					s := natTable(t, masqueNATOptions{Mapping: mapping, Filtering: "address_and_port_dependent"}, r)
					natCarrierCheck(t, s, mapping, host, 1024)
				})
			}
		}
	}
}

func TestMasqueNATCarrierEmptyPackets(t *testing.T) {
	for _, kind := range []string{"socks", "shadowsocks", "ss2022", "ss2022-aes256", "ss2022-chacha", "ssr", "trojan", "snell3", "snell4", "hysteria", "hysteria2", "tuic", "tuic4", "tuic-stream"} {
		t.Run(kind, func(t *testing.T) {
			in := natCarrierInbound(t, kind)
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := natCarrierOutbound(t, in, server.Address(in.Tag))
			if kind == "tuic-stream" {
				out.UDPRelayMode = "quic"
			}
			r := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			s := natTable(t, masqueNATOptions{}, r)
			natCarrierCheck(t, s, "endpoint_independent", "127.0.0.1", 0)
		})
	}
}

func TestMasqueNATCarrierWire(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		for _, kind := range []string{"socks", "ss2022", "hysteria2"} {
			t.Run(fmt.Sprint(version)+"/"+kind, func(t *testing.T) {
				in := natCarrierInbound(t, kind)
				proxy := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				endpoint := map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "tls": certificate(t), "udp_mapping": "endpoint_independent", "path": "/vpn/{target}/{ipproto}/", "users": []User{{Username: "client", Password: "private"}}}
				b, _ := json.Marshal(map[string]any{"endpoints": []any{endpoint}, "outbounds": []Outbound{natCarrierOutbound(t, in, proxy.Address(in.Tag))}, "route": Route{Final: "proxy"}})
				s, err := New(context.Background(), b, zap.NewNop())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				if err = s.Start(); err != nil {
					t.Fatal(err)
				}
				c := masqueEndpointClient(t, s, version, true)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				p, err := c.masqueClients["proxy"].ipSession(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, host := range []string{"127.0.0.1", "::1"} {
					for range 2 {
						peer := natSocket(t, host)
						c := natVirtualConn(t, p, peer.LocalAddr().(*net.UDPAddr).AddrPort())
						c.SetDeadline(time.Now().Add(3 * time.Second))
						if _, err := c.Write([]byte("shared source")); err != nil {
							t.Fatal(err)
						}
						from := natRead(t, peer, []byte("shared source"))
						peer.WriteToUDPAddrPort([]byte("reply"), from)
						var b [32]byte
						if n, err := c.Read(b[:]); err != nil || string(b[:n]) != "reply" {
							t.Fatal("wire carrier identity", n, err)
						}
					}
					table := s.masqueServers["server"].nat
					table.mu.Lock()
					count := 0
					for key, entry := range table.entries {
						if key.source.Port() == 40000 && key.source.Addr().Is6() == (host == "::1") {
							count++
							if entry.carrier == nil {
								t.Error("wire path did not use multi-target carrier")
							}
						}
					}
					table.mu.Unlock()
					if count != 1 {
						t.Fatal("wire source did not reuse carrier", count)
					}
					assertUDPAddress(t, c, []int{0, 1, 4096, 60000}, masqueEcho(t, "udp", net.JoinHostPort(host, "0")))
				}
				if len(p.addresses()) != 2 {
					t.Fatal("lost client address family")
				}
			})
		}
	}
}

func TestMasqueNATCarrierReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required for UDP carrier interoperability")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, kind := range []string{"socks", "shadowsocks", "ss2022", "trojan", "hysteria", "hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			in := natCarrierInbound(t, kind)
			in.ListenPort = unusedPort(t)
			ins := []Inbound{in}
			if isQUICProxy(kind) {
				in.TLS.ALPN = quicALPN(kind)
				ins = []Inbound{{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t, in.ListenPort)}, in}
			}
			if kind == "hysteria" || kind == "hysteria2" || kind == "trojan" {
				in.Users[0].UUID = ""
			}
			ins[len(ins)-1] = in
			referenceRuntime(t, Config{Inbounds: ins, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			r := newTestRuntime(t, Config{Outbounds: []Outbound{natCarrierOutbound(t, in, portAddress(in.Listen, in.ListenPort))}})
			s := natTable(t, masqueNATOptions{Filtering: "address_and_port_dependent"}, r)
			size := 14000
			if kind == "hysteria2" {
				// This reference's HY2 UDP receive buffer truncates larger replies.
				// Independent endpoints separately verify full60000-byte packets.
				size = 4096
			}
			natCarrierCheck(t, s, "endpoint_independent", "127.0.0.1", size)
		})
	}
}

func TestMasqueNATCarrierFiltering(t *testing.T) {
	for _, mapping := range masqueNATModes {
		for _, filtering := range masqueNATModes {
			t.Run(mapping+"/"+filtering, func(t *testing.T) {
				packets := natSocket(t, "127.0.0.1")
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { listener.Close() })
				finished := make(chan error, 1)
				go func() {
					c, err := listener.Accept()
					if err != nil {
						finished <- err
						return
					}
					defer c.Close()
					err = func() error {
						var greeting [2]byte
						if _, err := io.ReadFull(c, greeting[:]); err != nil {
							return err
						}
						if _, err := io.CopyN(io.Discard, c, int64(greeting[1])); err != nil {
							return err
						}
						if err := writeAll(c, []byte{5, 0}); err != nil {
							return err
						}
						var h [3]byte
						if _, err := io.ReadFull(c, h[:]); err != nil {
							return err
						}
						if _, err := readAddress(c); err != nil {
							return err
						}
						address, _ := encodeAddress(packets.LocalAddr().String())
						if err := writeAll(c, append([]byte{5, 0, 0}, address...)); err != nil {
							return err
						}
						_, err := io.Copy(io.Discard, c)
						return err
					}()
					finished <- err
				}()
				host, port, _ := net.SplitHostPort(listener.Addr().String())
				number, _ := shadowPort(port)
				r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: host, ServerPort: number}}})
				s := natTable(t, masqueNATOptions{Mapping: mapping, Filtering: filtering}, r)
				responses := make(chan string, 8)
				if err := s.send(natRequest("192.0.2.1:1234"), []byte("request"), func(_ []byte, from string) error { responses <- from; return nil }); err != nil {
					t.Fatal(err)
				}
				packets.SetReadDeadline(time.Now().Add(time.Second))
				b := make([]byte, 65535)
				_, peer, err := packets.ReadFromUDPAddrPort(b)
				if err != nil {
					t.Fatal(err)
				}
				for _, from := range []string{"192.0.2.1:1234", "192.0.2.1:1235", "192.0.2.2:1234", "invalid.test:1234"} {
					address, _ := encodeAddress(from)
					packets.WriteToUDPAddrPort(append(append([]byte{0, 0, 0}, address...), 'r'), peer)
					allowed := from == "192.0.2.1:1234" || filtering == "endpoint_independent" && from != "invalid.test:1234" || filtering == "address_dependent" && from == "192.0.2.1:1235"
					select {
					case got := <-responses:
						if !allowed || got != from {
							t.Fatal("carrier filter bypass", got, from)
						}
					case <-time.After(30 * time.Millisecond):
						if allowed {
							t.Fatal("carrier filtered allowed reply", from)
						}
					}
				}
				s.close()
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("SOCKS association control leaked")
				}
			})
		}
	}
}

func TestMasqueNATCarrierRewrite(t *testing.T) {
	in := natCarrierInbound(t, "socks")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	peer := natSocket(t, "127.0.0.1")
	port := uint16(peer.LocalAddr().(*net.UDPAddr).Port)
	r := newTestRuntime(t, Config{Outbounds: []Outbound{natCarrierOutbound(t, in, server.Address(in.Tag))}, Route: Route{Final: "proxy", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}, Outbound: "proxy", OverrideAddress: "127.0.0.1", OverridePort: port}}}})
	s := natTable(t, masqueNATOptions{Filtering: "address_and_port_dependent"}, r)
	responses := make(chan string, 2)
	for _, original := range []string{"192.0.2.1:53", "192.0.2.2:53"} {
		if err := s.send(natRequest(original), []byte(original), func(_ []byte, from string) error { responses <- from; return nil }); err != nil {
			t.Fatal(err)
		}
		from := natRead(t, peer, []byte(original))
		peer.WriteToUDPAddrPort([]byte("reply"), from)
		select {
		case got := <-responses:
			if got != original {
				t.Fatal("rewrite reply leaked actual address", got)
			}
		case <-time.After(time.Second):
			t.Fatal("rewrite reply missing")
		}
	}
	s.table.mu.Lock()
	defer s.table.mu.Unlock()
	if len(s.table.entries) != 2 {
		t.Fatal("ambiguous rewrites shared a carrier")
	}
	for _, e := range s.table.entries {
		if e.target != netip.MustParseAddrPort(peer.LocalAddr().String()) {
			t.Fatal("carrier filter uses original destination", e.target)
		}
	}
}

func TestMasqueNATCarrierLifecycle(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(interrupt), func(t *testing.T) {
			in := natCarrierInbound(t, "socks")
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			a := natCarrierOutbound(t, in, server.Address(in.Tag))
			b := a
			a.Tag, b.Tag = "a", "b"
			r := newTestRuntime(t, Config{Outbounds: []Outbound{a, b, {Type: "selector", Tag: "inner", Outbounds: []string{"a", "b"}, InterruptExistConnections: interrupt}, {Type: "selector", Tag: "outer", Outbounds: []string{"inner"}}}, Route: Route{Final: "outer"}})
			s := natTable(t, masqueNATOptions{}, r)
			peer := natSocket(t, "127.0.0.1")
			responses := make(chan string, 16)
			reply := func(data []byte, _ string) error { responses <- string(data); return nil }
			var jobs sync.WaitGroup
			for range 12 {
				jobs.Go(func() {
					if err := s.send(natRequest(peer.LocalAddr().String()), []byte("parallel"), reply); err != nil {
						t.Error(err)
					}
				})
			}
			jobs.Wait()
			var before netip.AddrPort
			for range 12 {
				before = natRead(t, peer, []byte("parallel"))
			}
			s.table.mu.Lock()
			if len(s.table.entries) != 1 {
				t.Error("concurrent send created duplicate carriers", len(s.table.entries))
			}
			var old *masqueNATEntry
			for _, entry := range s.table.entries {
				old = entry
			}
			s.table.mu.Unlock()
			if err := r.SelectOutbound("inner", "b"); err != nil {
				t.Fatal(err)
			}
			if interrupt {
				select {
				case <-old.ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("group did not close carrier")
				}
			} else {
				peer.WriteToUDPAddrPort([]byte("old"), before)
				select {
				case got := <-responses:
					if got != "old" {
						t.Fatal(got)
					}
				case <-time.After(time.Second):
					t.Fatal("noninterrupting group closed carrier")
				}
			}
			if err := s.send(natRequest(peer.LocalAddr().String()), []byte("new"), reply); err != nil {
				t.Fatal(err)
			}
			after := natRead(t, peer, []byte("new"))
			if after == before {
				t.Fatal("new group reused old carrier")
			}
			s.close()
			for _, tag := range []string{"outer", "inner"} {
				g := r.groups[tag]
				g.mu.Lock()
				count := len(g.conns)
				g.mu.Unlock()
				if count != 0 {
					t.Fatal("group carrier leak", tag, count)
				}
			}
			r.mu.Lock()
			count := len(r.connections)
			r.mu.Unlock()
			if count != 0 {
				t.Fatal("carrier socket or control leak", count)
			}
		})
	}
}

func TestMasqueNATCarrierFixedDestination(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "relay", "snell5"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			if kind == "snell5" {
				in.Type, in.Version, in.Password = "snell", "5", "private"
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := natCarrierOutbound(t, in, server.Address(in.Tag))
			r := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			s := natTable(t, masqueNATOptions{}, r)
			for range 2 {
				peer := natSocket(t, "127.0.0.1")
				responses := make(chan string, 1)
				if err := s.send(natRequest(peer.LocalAddr().String()), []byte("fixed"), func(data []byte, from string) error { responses <- from + "/" + string(data); return nil }); err != nil {
					t.Fatal(err)
				}
				from := natRead(t, peer, []byte("fixed"))
				peer.WriteToUDPAddrPort([]byte("reply"), from)
				select {
				case got := <-responses:
					if got != peer.LocalAddr().String()+"/reply" {
						t.Fatal("fixed carrier reply", got)
					}
				case <-time.After(time.Second):
					t.Fatal("fixed carrier reply missing")
				}
			}
			s.table.mu.Lock()
			defer s.table.mu.Unlock()
			if len(s.table.entries) != 2 {
				t.Fatal("fixed carrier reused first destination", len(s.table.entries))
			}
			for _, e := range s.table.entries {
				if e.carrier != nil || e.key.carrier == "" {
					t.Fatal("fixed carrier falsely advertised multiple targets")
				}
			}
		})
	}
}
