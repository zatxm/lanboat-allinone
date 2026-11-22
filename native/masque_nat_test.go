package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

var masqueNATModes = []string{"endpoint_independent", "address_dependent", "address_and_port_dependent"}

func natSocket(t *testing.T, host string) *net.UDPConn {
	t.Helper()
	address, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func natRead(t *testing.T, c *net.UDPConn, want []byte) netip.AddrPort {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 65535)
	n, from, err := c.ReadFromUDPAddrPort(b)
	if err != nil || !bytes.Equal(b[:n], want) {
		t.Fatal("NAT destination", n, err)
	}
	return from
}

func natTable(t *testing.T, o masqueNATOptions, r *Runtime) *masqueNATScope {
	t.Helper()
	settings, err := o.settings()
	if err != nil {
		t.Fatal(err)
	}
	n := newMasqueNAT(r, settings)
	s := n.scope()
	t.Cleanup(s.close)
	return s
}

func natRequest(target string) request {
	return request{network: "udp", source: "10.44.0.2:40000", address: target}
}

func TestMasqueNATConfig(t *testing.T) {
	for _, kind := range []string{"masque-client", "masque-server"} {
		for _, mapping := range masqueNATModes {
			for _, filtering := range masqueNATModes {
				ep := map[string]any{"type": kind, "tag": "proxy", "version": 2, "udp_timeout": "150ms", "udp_mapping": mapping, "udp_filtering": filtering, "udp_nat_max": 2}
				if kind == "masque-client" {
					ep["server"], ep["server_port"] = "127.0.0.1", 443
				} else {
					ep["address"] = []string{"10.44.0.1/24"}
				}
				b, _ := json.Marshal(map[string]any{"endpoints": []any{ep}})
				c, err := Parse(b)
				if err != nil {
					t.Fatal(string(b), err)
				}
				var s *masqueNATSettings
				if kind == "masque-client" {
					s = c.Outbounds[0].nat
				} else {
					s = c.Inbounds[0].nat
				}
				if s == nil || s.mapping != mapping || s.filtering != filtering || s.timeout != 150*time.Millisecond || s.maximum != 2 {
					t.Fatal(s)
				}
			}
		}
	}
	for _, o := range []masqueNATOptions{{Mapping: "cone"}, {Filtering: "strict"}, {Timeout: "-1s"}, {Timeout: "1ns"}, {Timeout: "25h"}, {Maximum: -1}, {Maximum: 65537}} {
		if _, err := o.settings(); err == nil {
			t.Fatal("invalid NAT accepted", o)
		}
	}
	s, err := (masqueNATOptions{Timeout: "0s"}).settings()
	if err != nil || s.timeout != 5*time.Minute || s.maximum != 4096 {
		t.Fatal(s, err)
	}
}

func TestMasqueNATMappingFiltering(t *testing.T) {
	for _, mapping := range masqueNATModes {
		for _, filtering := range masqueNATModes {
			t.Run(mapping+"/"+filtering, func(t *testing.T) {
				r := newTestRuntime(t, Config{})
				s := natTable(t, masqueNATOptions{Mapping: mapping, Filtering: filtering}, r)
				a, b, c := natSocket(t, "127.0.0.1"), natSocket(t, "127.0.0.1"), natSocket(t, "127.0.0.2")
				replies := make(chan string, 16)
				reply := func(data []byte, from string) error { replies <- string(data) + "/" + from; return nil }
				if err := s.send(natRequest(a.LocalAddr().String()), []byte("a"), reply); err != nil {
					t.Fatal(err)
				}
				first := natRead(t, a, []byte("a"))
				// Two previously uncontacted endpoints send to the mapped socket.
				for _, peer := range []*net.UDPConn{b, c} {
					peer.WriteToUDPAddrPort([]byte(peer.LocalAddr().String()), first)
				}
				want := 0
				if filtering == "endpoint_independent" {
					want = 2
				} else if filtering == "address_dependent" {
					want = 1
				}
				for range want {
					select {
					case <-replies:
					case <-time.After(time.Second):
						t.Fatal("allowed reply filtered")
					}
				}
				select {
				case unexpected := <-replies:
					t.Fatal("uncontacted endpoint bypassed filter", unexpected)
				case <-time.After(30 * time.Millisecond):
				}
				var sources []netip.AddrPort
				for i, peer := range []*net.UDPConn{a, b, c} {
					payload := []byte(fmt.Sprint(i))
					if err := s.send(natRequest(peer.LocalAddr().String()), payload, reply); err != nil {
						t.Fatal(err)
					}
					from := natRead(t, peer, payload)
					sources = append(sources, from)
					peer.WriteToUDPAddrPort(payload, from)
					select {
					case <-replies:
					case <-time.After(time.Second):
						t.Fatal("contacted reply filtered")
					}
				}
				switch mapping {
				case "endpoint_independent":
					if sources[0] != sources[1] || sources[0] != sources[2] {
						t.Fatal("mapping not reused", sources)
					}
				case "address_dependent":
					if sources[0] != sources[1] || sources[0] == sources[2] {
						t.Fatal("wrong address mapping", sources)
					}
				case "address_and_port_dependent":
					if sources[0] == sources[1] || sources[0] == sources[2] || sources[1] == sources[2] {
						t.Fatal("wrong endpoint mapping", sources)
					}
				}
			})
		}
	}
}

func TestMasqueNATLifecycle(t *testing.T) {
	t.Run("endpoint-lru-and-scope-isolation", func(t *testing.T) {
		r := newTestRuntime(t, Config{})
		s := natTable(t, masqueNATOptions{Maximum: 2}, r)
		other := s.table.scope()
		t.Cleanup(other.close)
		peer := natSocket(t, "127.0.0.1")
		q := natRequest(peer.LocalAddr().String())
		discard := func([]byte, string) error { return nil }
		if err := s.send(q, []byte("one"), discard); err != nil {
			t.Fatal(err)
		}
		first := natRead(t, peer, []byte("one"))
		if err := other.send(q, []byte("two"), discard); err != nil {
			t.Fatal(err)
		}
		second := natRead(t, peer, []byte("two"))
		if first == second {
			t.Fatal("tunnel source tuples mixed")
		}
		if err := s.send(q, []byte("refresh"), discard); err != nil {
			t.Fatal(err)
		}
		natRead(t, peer, []byte("refresh"))
		q.source = "10.44.0.3:40000"
		if err := s.send(q, []byte("three"), discard); err != nil {
			t.Fatal(err)
		}
		natRead(t, peer, []byte("three"))
		n := s.table
		n.mu.Lock()
		if len(n.entries) != 2 {
			t.Fatal(len(n.entries))
		}
		for k := range n.entries {
			if k.scope == other {
				t.Fatal("LRU kept older mapping")
			}
		}
		n.mu.Unlock()
		s.close()
		if err := s.send(q, nil, discard); !errors.Is(err, net.ErrClosed) {
			t.Fatal("closed tunnel reopened", err)
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if len(n.entries) != 0 || n.lru.Len() != 0 {
			t.Fatal("mapping leak")
		}
	})
	t.Run("activity-and-expiry", func(t *testing.T) {
		r := newTestRuntime(t, Config{})
		s := natTable(t, masqueNATOptions{Timeout: "100ms"}, r)
		peer := natSocket(t, "127.0.0.1")
		q := natRequest(peer.LocalAddr().String())
		reply := func([]byte, string) error { return nil }
		for range 3 {
			if err := s.send(q, []byte("keep"), reply); err != nil {
				t.Fatal(err)
			}
			natRead(t, peer, []byte("keep"))
			time.Sleep(50 * time.Millisecond)
		}
		s.table.mu.Lock()
		live := len(s.table.entries)
		s.table.mu.Unlock()
		if live != 1 {
			t.Fatal("active mapping expired")
		}
		for end := time.Now().Add(time.Second); time.Now().Before(end); {
			s.table.mu.Lock()
			live = len(s.table.entries)
			s.table.mu.Unlock()
			if live == 0 {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("idle socket not reclaimed")
	})
	t.Run("parallel-and-close", func(t *testing.T) {
		r := newTestRuntime(t, Config{})
		s := natTable(t, masqueNATOptions{}, r)
		peer := natSocket(t, "127.0.0.1")
		var group sync.WaitGroup
		for range 20 {
			group.Go(func() {
				_ = s.send(natRequest(peer.LocalAddr().String()), []byte("parallel"), func([]byte, string) error { return nil })
			})
		}
		group.Wait()
		s.table.mu.Lock()
		live := len(s.table.entries)
		s.table.mu.Unlock()
		if live != 1 {
			t.Fatal("duplicate mapping opened", live)
		}
		for range 8 {
			group.Go(s.close)
		}
		group.Wait()
	})
}

func TestMasqueNATRouting(t *testing.T) {
	peer := natSocket(t, "127.0.0.1")
	blocked := natSocket(t, "127.0.0.1")
	port := blocked.LocalAddr().(*net.UDPAddr).Port
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct", Rules: []Rule{{Port: []uint16{uint16(port)}, Action: "reject"}}}})
	s := natTable(t, masqueNATOptions{}, r)
	reply := func([]byte, string) error { return nil }
	if err := s.send(natRequest(peer.LocalAddr().String()), []byte("ok"), reply); err != nil {
		t.Fatal(err)
	}
	natRead(t, peer, []byte("ok"))
	if err := s.send(natRequest(blocked.LocalAddr().String()), []byte("bad"), reply); !errors.Is(err, ErrRejected) {
		t.Fatal("route bypass", err)
	}
	blocked.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, _, err := blocked.ReadFromUDP(make([]byte, 4)); err == nil {
		t.Fatal("rejected packet sent")
	}
}

func FuzzMasqueNATOptions(f *testing.F) {
	for _, seed := range []string{`{}`, `{"udp_timeout":"0s"}`, `{"udp_mapping":"address_dependent","udp_filtering":"endpoint_independent","udp_nat_max":2}`, `{"udp_nat_max":-1}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			return
		}
		var o masqueNATOptions
		if decodeOptions([]byte(raw), &o) != nil {
			return
		}
		s, err := o.settings()
		if err != nil {
			return
		}
		if s.timeout < time.Millisecond || s.timeout > 24*time.Hour || s.maximum < 1 || s.maximum > 65536 {
			t.Fatal(s)
		}
	})
}

func natVirtualConn(t *testing.T, p *masqueIP, target netip.AddrPort) *wgUDPConn {
	t.Helper()
	var local netip.Addr
	for _, a := range p.addresses() {
		if a.Is4() == target.Addr().Is4() {
			local = a
			break
		}
	}
	if !local.IsValid() {
		t.Fatal("missing virtual source address")
	}
	c := &wgUDPConn{stack: p.stack, key: tunFlowKey{source: local, destination: target.Addr(), sport: 40000, dport: target.Port()}, incoming: make(chan []byte, 64), closed: make(chan struct{}), wake: make(chan struct{}, 1), last: time.Now()}
	p.stack.mu.Lock()
	p.stack.udp[c.key] = c
	p.stack.mu.Unlock()
	t.Cleanup(func() { c.Close() })
	return c
}

func natWireCheck(t *testing.T, p *masqueIP, mapping, filtering, host string, size int) {
	t.Helper()
	a, b := natSocket(t, host), natSocket(t, host)
	ca, cb := natVirtualConn(t, p, a.LocalAddr().(*net.UDPAddr).AddrPort()), natVirtualConn(t, p, b.LocalAddr().(*net.UDPAddr).AddrPort())
	ca.SetDeadline(time.Now().Add(3 * time.Second))
	cb.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := ca.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	fromA := natRead(t, a, []byte("first"))
	b.WriteToUDPAddrPort([]byte("other-port"), fromA)
	cb.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buffer := make([]byte, 65535)
	n, err := cb.Read(buffer)
	if filtering == "address_and_port_dependent" {
		if err == nil {
			t.Fatal("wire filter bypass")
		}
	} else if err != nil || string(buffer[:n]) != "other-port" {
		t.Fatal("wire reply", n, err)
	}
	cb.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = cb.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	fromB := natRead(t, b, []byte("second"))
	if (fromA == fromB) != (mapping != "address_and_port_dependent") {
		t.Fatal("wire mapping", fromA, fromB, mapping)
	}
	payload := bytes.Repeat([]byte{0x61}, size)
	if _, err = ca.Write(payload); err != nil {
		t.Fatal(err)
	}
	fromA = natRead(t, a, payload)
	a.WriteToUDPAddrPort(payload, fromA)
	n, err = ca.Read(buffer)
	if err != nil || !bytes.Equal(payload, buffer[:n]) {
		t.Fatal("wire large UDP", n, err)
	}
}

func TestMasqueNATWire(t *testing.T) {
	for i, mapping := range masqueNATModes {
		for j, filtering := range masqueNATModes {
			version := 1 + (i+j)%3
			t.Run(fmt.Sprintf("http%d/%s/%s", version, mapping, filtering), func(t *testing.T) {
				server := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "tls": certificate(t), "udp_mapping": mapping, "udp_filtering": filtering, "udp_timeout": "1m", "udp_nat_max": 16})
				host, port, _ := net.SplitHostPort(server.Address("server"))
				number, _ := shadowPort(port)
				client := masqueEndpointRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": number, "version": version, "disable_version_fallback": true, "tls": TLSOptions{Enabled: true, Insecure: true}})
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				p, err := client.masqueClients["proxy"].ipSession(ctx)
				if err != nil {
					t.Fatal(err)
				}
				natWireCheck(t, p, mapping, filtering, "127.0.0.1", 60000)
				natWireCheck(t, p, mapping, filtering, "::1", 60000)
			})
		}
	}
}

func TestMasqueNATReverse(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := masqueReverseServer(t, version, false)
			host, port, _ := net.SplitHostPort(s.Address("server"))
			number, _ := shadowPort(port)
			_ = masqueReverseRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": number, "username": "client", "password": "private", "version": version, "disable_version_fallback": true, "tls": TLSOptions{Enabled: true, Insecure: true}, "advertise_routes": []string{"127.0.0.0/8", "::1/128"}, "udp_mapping": "address_dependent", "udp_filtering": "address_dependent", "udp_nat_max": 16, "udp_timeout": "1m"}, Route{Final: "direct", Rules: []Rule{{Inbound: []string{"proxy"}, Outbound: "direct"}}})
			p := masqueWaitPeer(t, s, "127.0.0.1")
			natWireCheck(t, p, "address_dependent", "address_dependent", "127.0.0.1", 60000)
			natWireCheck(t, p, "address_dependent", "address_dependent", "::1", 60000)
		})
	}
}

func TestMasqueNATRewriteAndProxy(t *testing.T) {
	t.Run("override-aliases", func(t *testing.T) {
		target := natSocket(t, "127.0.0.1")
		port := uint16(target.LocalAddr().(*net.UDPAddr).Port)
		r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct", Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}, Outbound: "direct", OverrideAddress: "127.0.0.1", OverridePort: port}}}})
		s := natTable(t, masqueNATOptions{}, r)
		responses := make(chan string, 4)
		reply := func(_ []byte, from string) error { responses <- from; return nil }
		var mapped []netip.AddrPort
		for _, address := range []string{"192.0.2.1:53", "192.0.2.2:53"} {
			if err := s.send(natRequest(address), []byte(address), reply); err != nil {
				t.Fatal(err)
			}
			mapped = append(mapped, natRead(t, target, []byte(address)))
		}
		if mapped[0] == mapped[1] {
			t.Fatal("overrides have ambiguous reply identity")
		}
		for i, from := range mapped {
			target.WriteToUDPAddrPort([]byte("reply"), from)
			select {
			case address := <-responses:
				if address != fmt.Sprintf("192.0.2.%d:53", i+1) {
					t.Fatal(address)
				}
			case <-time.After(time.Second):
				t.Fatal("missing override reply")
			}
		}
	})
	t.Run("socks-carrier", func(t *testing.T) {
		proxy := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "socks", Tag: "in", Listen: "127.0.0.1"}}})
		host, port, _ := net.SplitHostPort(proxy.Address("in"))
		number, _ := shadowPort(port)
		r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "socks", Tag: "proxy", Server: host, ServerPort: number}}, Route: Route{Final: "proxy"}})
		s := natTable(t, masqueNATOptions{Timeout: "100ms", Maximum: 2}, r)
		peer := natSocket(t, "127.0.0.1")
		responses := make(chan string, 1)
		if err := s.send(natRequest(peer.LocalAddr().String()), []byte("proxy"), func(data []byte, from string) error { responses <- string(data) + "/" + from; return nil }); err != nil {
			t.Fatal(err)
		}
		from := natRead(t, peer, []byte("proxy"))
		peer.WriteToUDPAddrPort([]byte("reply"), from)
		select {
		case response := <-responses:
			if response != "reply/"+peer.LocalAddr().String() {
				t.Fatal(response)
			}
		case <-time.After(time.Second):
			t.Fatal("carrier reply missing")
		}
	})
}

func TestMasqueNATIdleBuffers(t *testing.T) {
	r := newTestRuntime(t, Config{})
	s := natTable(t, masqueNATOptions{}, r)
	peer := natSocket(t, "127.0.0.1")
	q := natRequest(peer.LocalAddr().String())
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range 512 {
		q.source = fmt.Sprintf("10.44.0.2:%d", 20000+i)
		if err := s.send(q, nil, func([]byte, string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		natRead(t, peer, nil)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("512 idle direct mappings retain %d heap bytes", delta)
	if delta > 24<<20 {
		t.Fatal("idle mappings retain full UDP buffers", delta)
	}
	s.table.mu.Lock()
	count := len(s.table.entries)
	s.table.mu.Unlock()
	if count != 512 {
		t.Fatal("idle mappings disappeared", count)
	}
}

func TestUDPFlowsDoNotHoldIdlePacketBuffers(t *testing.T) {
	r := newTestRuntime(t, Config{})
	flows := newUDPFlows(r)
	defer flows.Close()
	flows.direct = true
	peer := natSocket(t, "127.0.0.1")
	q := natRequest(peer.LocalAddr().String())

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := range 128 {
		key := fmt.Sprint(i)
		if err := flows.send(key, q, nil, func([]byte, string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		natRead(t, peer, nil)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("128 idle UDP flows retain %d heap bytes", delta)
	if delta > 5<<20 {
		t.Fatal("idle flows retain full UDP buffers", delta)
	}
}

func TestMasqueNATGroupSwitch(t *testing.T) {
	for _, interrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(interrupt), func(t *testing.T) {
			r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "a"}, {Type: "direct", Tag: "b"}, {Type: "selector", Tag: "inner", Outbounds: []string{"a", "b"}, InterruptExistConnections: interrupt}, {Type: "selector", Tag: "outer", Outbounds: []string{"inner"}}}, Route: Route{Final: "outer"}})
			s := natTable(t, masqueNATOptions{}, r)
			peer := natSocket(t, "127.0.0.1")
			q := natRequest(peer.LocalAddr().String())
			responses := make(chan string, 4)
			reply := func(data []byte, _ string) error { responses <- string(data); return nil }
			if err := s.send(q, []byte("before"), reply); err != nil {
				t.Fatal(err)
			}
			before := natRead(t, peer, []byte("before"))
			s.table.mu.Lock()
			var old *masqueNATEntry
			for _, e := range s.table.entries {
				old = e
			}
			s.table.mu.Unlock()
			if err := r.SelectOutbound("inner", "b"); err != nil {
				t.Fatal(err)
			}
			if interrupt {
				select {
				case <-old.ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("group kept old NAT socket")
				}
				peer.WriteToUDPAddrPort([]byte("old"), before)
				select {
				case value := <-responses:
					t.Fatal("old group delivered data", value)
				case <-time.After(30 * time.Millisecond):
				}
			} else {
				peer.WriteToUDPAddrPort([]byte("old"), before)
				select {
				case value := <-responses:
					if value != "old" {
						t.Fatal(value)
					}
				case <-time.After(time.Second):
					t.Fatal("noninterrupting group closed mapping")
				}
			}
			if err := s.send(q, []byte("after"), reply); err != nil {
				t.Fatal(err)
			}
			after := natRead(t, peer, []byte("after"))
			if after == before {
				t.Fatal("new packets reused old group socket")
			}
			s.close()
			for _, name := range []string{"outer", "inner"} {
				g := r.groups[name]
				g.mu.Lock()
				count := len(g.conns)
				g.mu.Unlock()
				if count != 0 {
					t.Fatal("group registration leak", name, count)
				}
			}
		})
	}
}

func TestMasqueNATGroupKeys(t *testing.T) {
	a, b := natSocket(t, "127.0.0.1"), natSocket(t, "127.0.0.1")
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "b/c"}, {Type: "direct", Tag: "c"}, {Type: "selector", Tag: "a", Outbounds: []string{"b/c"}}, {Type: "selector", Tag: "a/b", Outbounds: []string{"c"}}}, Route: Route{Final: "a", Rules: []Rule{{Port: []uint16{uint16(b.LocalAddr().(*net.UDPAddr).Port)}, Outbound: "a/b"}}}})
	s := natTable(t, masqueNATOptions{}, r)
	reply := func([]byte, string) error { return nil }
	if err := s.send(natRequest(a.LocalAddr().String()), []byte("one"), reply); err != nil {
		t.Fatal(err)
	}
	first := natRead(t, a, []byte("one"))
	if err := s.send(natRequest(b.LocalAddr().String()), []byte("two"), reply); err != nil {
		t.Fatal(err)
	}
	second := natRead(t, b, []byte("two"))
	if first == second {
		t.Fatal("slash-containing group tags share a mapping", first, second)
	}
}
