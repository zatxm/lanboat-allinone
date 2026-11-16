package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func wgEndpointRuntime(t *testing.T, ep wgEndpointOptions, cfg Config) *Runtime {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	json.Unmarshal(data, &doc)
	ep.Type = "wireguard"
	doc["endpoints"], _ = json.Marshal([]wgEndpointOptions{ep})
	raw, _ := json.Marshal(doc)
	r, err := New(context.Background(), raw, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestWireGuardEndpointLegacyServer(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.44.0.2/32", "fd44::2/128"}}}}}}})
	host, port, _ := net.SplitHostPort(s.Address("server"))
	pn, _ := strconv.Atoi(port)
	c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "proxy", PrivateKey: []string{clientKey}, Address: []string{"10.44.0.2/32", "fd44::2/128"}, Workers: 2, Peers: []WireGuardPeer{{Address: host, Port: uint16(pn), PublicKey: serverPub, AllowedIPs: []string{"0.0.0.0/0", "::/0"}}}}, Config{})
	assertTCP(t, c)
	assertUDP(t, c)
	if c.Address("proxy") == "" {
		t.Fatal("missing shared socket address")
	}
	peer, err := c.wireGuardSession(context.Background(), "proxy", netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if peer.mtu != 1408 {
		t.Fatal("wrong endpoint MTU default", peer.mtu)
	}
}

func TestWireGuardEndpointBidirectional(t *testing.T) {
	for _, reserved := range []bool{false, true} {
		t.Run(map[bool]string{false: "standard", true: "reserved"}[reserved], func(t *testing.T) {
			serverKey, serverPub := wgTestKey(t)
			clientKey, clientPub := wgTestKey(t)
			psk, _ := wgTestKey(t)
			serverPeer := WireGuardPeer{PublicKey: clientPub, PreSharedKey: psk, AllowedIPs: []string{"10.44.0.2/32", "fd44::2/128"}, PersistentKeepaliveInterval: 1}
			if reserved {
				serverPeer.Reserved = []byte{1, 2, 3}
			}
			s := wgEndpointRuntime(t, wgEndpointOptions{Tag: "server", PrivateKey: []string{serverKey}, Address: []string{"10.44.0.1/24", "fd44::1/64"}, Workers: 2, Peers: []WireGuardPeer{serverPeer}}, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct"}})
			host, port, _ := net.SplitHostPort(s.Address("server"))
			_ = host
			pn, _ := strconv.Atoi(port)
			clientPeer := WireGuardPeer{Address: "127.0.0.1", Port: uint16(pn), PublicKey: serverPub, PreSharedKey: psk, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, PersistentKeepaliveInterval: 1}
			if reserved {
				clientPeer.Reserved = []byte{4, 5, 6}
			}
			c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "proxy", PrivateKey: []string{clientKey}, Address: []string{"10.44.0.2/32", "fd44::2/128"}, Workers: 2, Peers: []WireGuardPeer{clientPeer}}, Config{})
			assertTCP(t, c)
			assertUDP(t, c)
			peer, err := s.wireGuardSession(context.Background(), "server", netip.MustParseAddr("10.44.0.2"))
			if err != nil {
				t.Fatal(err)
			}
			peer.mu.Lock()
			learned := peer.remote
			peer.mu.Unlock()
			if learned == nil {
				t.Fatal("passive peer failed to learn endpoint")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := peer.ensure(ctx); err != nil {
				t.Fatal("passive peer cannot initiate after authenticated learning", err)
			}
		})
	}
}

func TestWireGuardEndpointValidation(t *testing.T) {
	key, pub := wgTestKey(t)
	base := wgEndpointOptions{Type: "wireguard", Tag: "wg", PrivateKey: []string{key}, Address: []string{"10.44.0.2/32"}, Peers: []WireGuardPeer{{PublicKey: pub, AllowedIPs: []string{"0.0.0.0/0"}}}}
	for name, edit := range map[string]func(*wgEndpointOptions){
		"missing-address":          func(e *wgEndpointOptions) { e.Address = nil },
		"invalid-address":          func(e *wgEndpointOptions) { e.Address = []string{"0.0.0.0/32"} },
		"mapped-address":           func(e *wgEndpointOptions) { e.Address = []string{"::ffff:192.0.2.2/128"} },
		"port-without-address":     func(e *wgEndpointOptions) { e.Peers[0].Port = 1234 },
		"address-without-port":     func(e *wgEndpointOptions) { e.Peers[0].Address = "127.0.0.1" },
		"bad-remote":               func(e *wgEndpointOptions) { e.Peers[0].Address = "https://bad"; e.Peers[0].Port = 1234 },
		"invalid-host":             func(e *wgEndpointOptions) { e.Peers[0].Address = "bad:address"; e.Peers[0].Port = 1234 },
		"reserved":                 func(e *wgEndpointOptions) { e.Peers[0].Reserved = []byte{1} },
		"keepalive":                func(e *wgEndpointOptions) { e.Peers[0].PersistentKeepaliveInterval = -1 },
		"workers":                  func(e *wgEndpointOptions) { e.Workers = -1 },
		"mtu":                      func(e *wgEndpointOptions) { e.MTU = 1 },
		"oversized-datagram":       func(e *wgEndpointOptions) { e.MTU = 65473 },
		"interface-without-system": func(e *wgEndpointOptions) { e.Name = "wg0" },
		"empty-allowed":            func(e *wgEndpointOptions) { e.Peers[0].AllowedIPs = nil },
		"duplicate-peer":           func(e *wgEndpointOptions) { e.Peers = append(e.Peers, e.Peers[0]) },
		"nat":                      func(e *wgEndpointOptions) { e.Mapping = "invalid" },
	} {
		t.Run(name, func(t *testing.T) {
			e := base
			e.Peers = append([]WireGuardPeer(nil), base.Peers...)
			edit(&e)
			raw, _ := json.Marshal(map[string]any{"endpoints": []wgEndpointOptions{e}})
			if _, err := Parse(raw); err == nil {
				t.Fatal("invalid endpoint accepted")
			}
		})
	}
	raw, _ := json.Marshal(map[string]any{"endpoints": base})
	if _, err := Parse(raw); err != nil {
		t.Fatal("single endpoint object", err)
	}
	var fields map[string]any
	json.Unmarshal(raw, &fields)
	fields["outbounds"] = []Outbound{{Type: "direct", Tag: "wg"}}
	raw, _ = json.Marshal(fields)
	if _, err := Parse(raw); err == nil {
		t.Fatal("duplicate tag accepted")
	}
}

func TestWireGuardEndpointLongestPrefix(t *testing.T) {
	serverKeys := make([]string, 2)
	serverPubs := make([]string, 2)
	var servers []*Runtime
	clientKey, clientPub := wgTestKey(t)
	for i := range 2 {
		serverKeys[i], serverPubs[i] = wgTestKey(t)
		s := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKeys[i]}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.44.0.2/32"}}}}}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{IPCIDR: []string{[]string{"127.0.0.1/32", "127.0.0.2/32"}[i]}, Outbound: "direct"}}}})
		servers = append(servers, s)
	}
	var peers []WireGuardPeer
	for i, s := range servers {
		_, port, _ := net.SplitHostPort(s.Address("server"))
		pn, _ := strconv.Atoi(port)
		peers = append(peers, WireGuardPeer{Address: "127.0.0.1", Port: uint16(pn), PublicKey: serverPubs[i], AllowedIPs: []string{[]string{"127.0.0.0/8", "127.0.0.2/32"}[i]}})
	}
	c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "proxy", PrivateKey: []string{clientKey}, Address: []string{"10.44.0.2/32"}, Workers: 4, Peers: peers}, Config{})
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		l, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer conn.Close(); io.Copy(conn, conn) }()
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := c.Dial(ctx, "tcp", l.Addr().String())
		cancel()
		if err != nil {
			t.Fatal(ip, err)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		_, err = conn.Write([]byte(ip))
		reply := make([]byte, len(ip))
		if err == nil {
			_, err = io.ReadFull(conn, reply)
		}
		conn.Close()
		if err != nil || string(reply) != ip {
			t.Fatal(ip, string(reply), err)
		}
	}
	s, err := c.wgEndpoints["proxy"].session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.peerFor(netip.MustParseAddr("127.0.0.2")) != s.peers[1].peer || s.peers[0].peer.ownsSource(netip.MustParseAddr("127.0.0.2")) {
		t.Fatal("broader peer can impersonate a specific peer")
	}
	if s.peerFor(netip.MustParseAddr("192.0.2.1")) != nil {
		t.Fatal("unmatched destination selected a peer")
	}
}

func TestWireGuardEndpointOnDemandLifecycle(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.44.0.2/32"}}}}}}})
	_, port, _ := net.SplitHostPort(s.Address("server"))
	pn, _ := strconv.Atoi(port)
	c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "proxy", PrivateKey: []string{clientKey}, Address: []string{"10.44.0.2/32"}, Workers: 2, OnDemand: true, Peers: []WireGuardPeer{{Address: "127.0.0.1", Port: uint16(pn), PublicKey: serverPub, AllowedIPs: []string{"0.0.0.0/0"}}}}, Config{})
	if c.Address("proxy") != "" {
		t.Fatal("on-demand endpoint started eagerly")
	}
	assertUDP(t, c)
	if c.Address("proxy") == "" {
		t.Fatal("on-demand endpoint failed to start")
	}
	if err := c.DisconnectWireGuard("proxy"); err != nil {
		t.Fatal(err)
	}
	if c.Address("proxy") != "" {
		t.Fatal("disconnect retained socket")
	}
	assertUDP(t, c)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.DisconnectWireGuard("proxy"); err == nil {
		t.Fatal("closed endpoint disconnected")
	}
}

func TestWireGuardEndpointConcurrentClose(t *testing.T) {
	key, pub := wgTestKey(t)
	c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "wg", PrivateKey: []string{key}, Address: []string{"10.44.0.2/32"}, Workers: 2, OnDemand: true, Peers: []WireGuardPeer{{PublicKey: pub, AllowedIPs: []string{"0.0.0.0/0"}}}}, Config{})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 8 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
				conn, err := c.Dial(ctx, "udp", "192.0.2.1:1234")
				cancel()
				if conn != nil {
					conn.Close()
				}
				if err == nil {
					t.Error("passive peer dial succeeded")
				}
				c.DisconnectWireGuard("wg")
			}
		})
	}
	workers.Wait()
	c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Dial(ctx, "udp", "192.0.2.1:1"); !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestWireGuardEndpointReset(t *testing.T) {
	for _, onDemand := range []bool{false, true} {
		t.Run(map[bool]string{false: "eager", true: "on-demand"}[onDemand], func(t *testing.T) {
			key, pub := wgTestKey(t)
			r := wgEndpointRuntime(t, wgEndpointOptions{Tag: "wg", PrivateKey: []string{key}, Address: []string{"10.44.0.2/32"}, Workers: 1, OnDemand: onDemand, Peers: []WireGuardPeer{{PublicKey: pub, AllowedIPs: []string{"0.0.0.0/0"}}}}, Config{})
			e := r.wgEndpoints["wg"]
			previous, err := e.session(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			e.reset(true)
			if previous.ctx.Err() == nil {
				t.Fatal("network reset retained the old session")
			}
			if onDemand != (r.Address("wg") == "") {
				t.Fatal("network reset ignored on_demand")
			}
			current, err := e.session(context.Background())
			if err != nil || current == previous {
				t.Fatal("network reset failed to create a new session", err)
			}
			if !onDemand && r.DisconnectWireGuard("wg") == nil {
				t.Fatal("manual disconnect accepted an eager endpoint")
			}
		})
	}
}

func TestWireGuardEndpointPacketBounds(t *testing.T) {
	key, pub := wgTestKey(t)
	c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "wg", PrivateKey: []string{key}, Address: []string{"10.44.0.2/32"}, Workers: 1, Peers: []WireGuardPeer{{PublicKey: pub, AllowedIPs: []string{"0.0.0.0/0"}}}}, Config{})
	pc, err := net.Dial("udp", c.Address("wg"))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for i := 0; i < 512; i++ {
		_, _ = pc.Write(bytes.Repeat([]byte{byte(i)}, min(65507, i)))
	}
}

func TestWireGuardEndpointDetourAndBootstrap(t *testing.T) {
	serverKey, serverPub := wgTestKey(t)
	clientKey, clientPub := wgTestKey(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "wireguard", Tag: "server", Listen: "127.0.0.1", SSHOptions: SSHOptions{PrivateKey: []string{serverKey}}, WireGuardOptions: WireGuardOptions{Peers: []WireGuardPeer{{PublicKey: clientPub, AllowedIPs: []string{"10.44.0.2/32"}}}}}}})
	hop := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "socks", Tag: "hop", Listen: "127.0.0.1"}}})
	_, port, _ := net.SplitHostPort(s.Address("server"))
	pn, _ := strconv.Atoi(port)
	hopHost, hopPort, _ := net.SplitHostPort(hop.Address("hop"))
	hopPN, _ := strconv.Atoi(hopPort)
	c := wgEndpointRuntime(t, wgEndpointOptions{Tag: "proxy", PrivateKey: []string{clientKey}, Address: []string{"10.44.0.2/32"}, Workers: 2, Detour: "hop", DomainResolver: "bootstrap", Peers: []WireGuardPeer{{Address: "peer.test", Port: uint16(pn), PublicKey: serverPub, AllowedIPs: []string{"0.0.0.0/0"}}}}, Config{Outbounds: []Outbound{{Type: "socks", Tag: "hop", Server: hopHost, ServerPort: uint16(hopPN)}}, Route: Route{Final: "proxy"}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "bootstrap", Predefined: map[string][]string{"peer.test": {"127.0.0.1"}}}}}})
	assertTCP(t, c)
	assertUDP(t, c)
	e := c.wgEndpoints["proxy"]
	session, err := e.session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p := session.peers[0]
	p.netMu.Lock()
	proxyConn := p.conn
	p.netMu.Unlock()
	if proxyConn == nil {
		t.Fatal("detour was not used")
	}
	proxyConn.Close()
	deadline := time.Now().Add(time.Second)
	for {
		p.netMu.Lock()
		closed := p.conn == nil
		p.netMu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("failed detour connection retained")
		}
		time.Sleep(time.Millisecond)
	}
	assertUDP(t, c)
}

func TestWireGuardEndpointCookieDetourIsolation(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	s := &wgEndpointSession{ctx: context.Background(), endpoint: &wgEndpoint{o: wgEndpointOptions{Detour: "hop"}}, packets: [2]*net.UDPConn{pc, nil}}
	if err := s.writeCookie([]byte("cookie"), pc.LocalAddr()); err == nil {
		t.Fatal("cookie bypassed missing detour")
	}
	pc.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	b := make([]byte, 64)
	if n, _, err := pc.ReadFromUDP(b); err == nil {
		t.Fatal("cookie escaped via the direct UDP socket", n)
	}
}

func FuzzWireGuardEndpointConfiguration(f *testing.F) {
	f.Add([]byte(`{"endpoints":{"type":"wireguard","tag":"wg","address":"10.44.0.2/32","peers":[]}}`))
	f.Add([]byte(`{"endpoints":[{"type":"wireguard","workers":2,"peers":[{"reserved":[1,2,3]}]}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32768 {
			return
		}
		_, _ = Parse(raw)
	})
}
