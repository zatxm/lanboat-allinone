package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func masqueReverseRuntime(t *testing.T, endpoint map[string]any, route Route) *Runtime {
	t.Helper()
	b, err := json.Marshal(map[string]any{"endpoints": []any{endpoint}, "outbounds": []Outbound{{Type: "direct", Tag: "direct"}}, "route": route})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), b, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Start(); err != nil {
		r.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func masqueReverseServer(t *testing.T, version int, cleartext bool) *Runtime {
	t.Helper()
	tls := TLSOptions{}
	if !cleartext {
		tls = certificate(t)
	}
	return masqueReverseRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": version, "address": []string{"10.44.0.1/24", "fd44::1/64"}, "tls": tls, "users": []User{{Username: "client", Password: "private"}}}, Route{Final: "server", Rules: []Rule{{Inbound: []string{"server"}, Outbound: "direct"}}})
}

func masqueReverseClient(t *testing.T, s *Runtime, version int, cleartext bool, prefixes []string, rules []Rule) *Runtime {
	t.Helper()
	host, port, _ := net.SplitHostPort(s.Address("server"))
	n, _ := shadowPort(port)
	return masqueReverseRuntime(t, map[string]any{"type": "masque-client", "tag": "proxy", "server": host, "server_port": n, "username": "client", "password": "private", "version": version, "disable_version_fallback": true, "advertise_routes": prefixes, "on_demand": true, "tls": TLSOptions{Enabled: !cleartext, Insecure: !cleartext}}, Route{Final: "direct", Rules: rules})
}

func masqueWaitPeer(t *testing.T, s *Runtime, destination string) *masqueIP {
	t.Helper()
	for until := time.Now().Add(3 * time.Second); time.Now().Before(until); {
		if p, err := s.masqueServers["server"].peer(netip.MustParseAddr(destination), 6); err == nil {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("client route not registered", destination)
	return nil
}

func TestMasqueReverse(t *testing.T) {
	for _, cleartext := range []bool{false, true} {
		for _, version := range []int{1, 2, 3} {
			if cleartext && version == 3 {
				continue
			}
			t.Run(fmt.Sprintf("%d/cleartext-%t", version, cleartext), func(t *testing.T) {
				s := masqueReverseServer(t, version, cleartext)
				c := masqueReverseClient(t, s, version, cleartext, []string{"127.0.0.1/32", "::1/128"}, []Rule{{Inbound: []string{"proxy"}, Outbound: "direct"}})
				p := masqueWaitPeer(t, s, "127.0.0.1")
				assertTCP(t, s)
				assertUDPSizes(t, s, []int{0, 1, 4096, 60000})
				wg, err := s.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "[::1]:0"))
				if err != nil {
					t.Fatal(err)
				}
				masqueReverseRoundtrip(t, wg)
				assertUDPAddress(t, s, []int{1, 4096, 60000}, masqueEcho(t, "udp", "[::1]:0"))
				var jobs sync.WaitGroup
				for range 8 {
					jobs.Go(func() { assertTCP(t, s) })
				}
				jobs.Wait()
				client := c.masqueClients["proxy"]
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if _, err = client.ipSession(ctx); err != nil {
					t.Fatal(err)
				}
				conn, err := c.dialOutbound(ctx, "proxy", "tcp", relayEchoTCP(t))
				if err != nil {
					t.Fatal("forward and reverse must share a live tunnel", err)
				}
				masqueReverseRoundtrip(t, conn)
				if !p.allowed(netip.MustParseAddr("127.0.0.1")) || p.allowed(netip.MustParseAddr("192.0.2.99")) {
					t.Fatal("source filtering lost")
				}
			})
		}
	}
}

func TestMasqueReverseRouting(t *testing.T) {
	s := masqueReverseServer(t, 2, false)
	target := relayEchoTCP(t)
	_, port, _ := net.SplitHostPort(target)
	pn, _ := shadowPort(port)
	masqueReverseClient(t, s, 2, false, []string{"192.0.2.0/24", "2001:db8:44::/64"}, []Rule{
		{Inbound: []string{"proxy"}, IPCIDR: []string{"192.0.2.42/32", "2001:db8:44::42/128"}, Outbound: "direct", OverrideAddress: "127.0.0.1", OverridePort: pn},
		{Inbound: []string{"proxy"}, Action: "reject"},
	})
	masqueWaitPeer(t, s, "192.0.2.42")
	for _, host := range []string{"192.0.2.42", "2001:db8:44::42"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		conn, err := s.Dial(ctx, "tcp", net.JoinHostPort(host, "443"))
		cancel()
		if err != nil {
			t.Fatal("client inbound override was not applied", err)
		}
		masqueReverseRoundtrip(t, conn)
	}
	for _, host := range []string{"192.0.2.43", "2001:db8:44::43", "127.0.0.1"} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := s.Dial(ctx, "tcp", net.JoinHostPort(host, port))
		cancel()
		if err == nil {
			conn.Close()
			t.Fatal("missing route or client rejection bypassed", host)
		}
	}
}

func TestMasqueReversePacketPolicy(t *testing.T) {
	s := masqueReverseServer(t, 2, false)
	c := masqueReverseClient(t, s, 2, false, []string{"192.0.2.0/24"}, nil)
	remote := masqueWaitPeer(t, s, "192.0.2.42")
	local := c.masqueClients["proxy"].ip.Load()
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	_, port, _ := net.SplitHostPort(sink.LocalAddr().String())
	pn, _ := shadowPort(port)
	packets := []struct {
		flow   *masqueFlow
		source netip.Addr
	}{
		{remote.flow, netip.MustParseAddr("10.44.0.1")},
		{local.flow, netip.MustParseAddr("198.51.100.7")},
	}
	for _, packet := range packets {
		// Deliberately bypass sender-side policy, testing the receiver itself.
		if _, err = packet.flow.Write(makeUDPPacket(packet.source, netip.MustParseAddr("127.0.0.1"), 1234, pn, []byte{42})); err != nil {
			t.Fatal(err)
		}
		sink.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		if _, _, err = sink.ReadFrom(make([]byte, 128)); err == nil {
			t.Fatal("receiver accepted forged packet")
		}
	}
}

func TestMasqueReverseICMP(t *testing.T) {
	s := masqueReverseServer(t, 2, false)
	masqueReverseClient(t, s, 2, false, []string{"192.0.2.0/24", "2001:db8:44::/64"}, []Rule{{Network: []string{"icmp"}, Action: "reject", Method: "reply"}})
	for _, host := range []string{"192.0.2.42", "2001:db8:44::42"} {
		p := masqueWaitPeer(t, s, host)
		kind, protocol, reply := byte(8), byte(1), byte(0)
		if netip.MustParseAddr(host).Is6() {
			kind, protocol, reply = 128, 58, 129
		}
		p, err := s.masqueServers["server"].peer(netip.MustParseAddr(host), protocol)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		response, err := p.stack.exchangeICMP(ctx, netip.MustParseAddr(host), []byte{kind, 0, 0, 0, 0, 7, 0, 3, 9}, 63)
		cancel()
		if err != nil || len(response.data) != 9 || response.data[0] != reply {
			t.Fatal("reverse ICMP", host, response, err)
		}
		ctx, cancel = context.WithCancel(context.Background())
		packets := make(chan []byte, 1)
		stack := newIPStack(&ipEndpoint{runtime: s, inbound: "tun", done: ctx.Done(), mtu: 1280, sendIP: func(b []byte) error { packets <- b; return nil }})
		source := netip.MustParseAddr("10.200.0.2")
		if kind == 128 {
			source = netip.MustParseAddr("fd20::2")
		}
		packet, _ := parseTunPacket(testICMPSegment(source, netip.MustParseAddr(host), kind, []byte{42}))
		stack.input(packet)
		select {
		case b := <-packets:
			got, e := parseTunPacket(b)
			if e != nil || got.source != netip.MustParseAddr(host) || got.destination != source || got.data[got.header] != reply {
				t.Error("TUN reverse ICMP", got, e)
			}
		case <-time.After(time.Second):
			t.Error("TUN reverse ICMP timeout")
		}
		cancel()
		stack.close()
	}
}

func TestMasqueReverseSessions(t *testing.T) {
	s := masqueReverseServer(t, 2, false)
	c1 := masqueReverseClient(t, s, 2, false, []string{"192.0.2.0/24"}, nil)
	c2 := masqueReverseClient(t, s, 2, false, []string{"192.0.2.1/32"}, nil)
	p1 := masqueWaitPeer(t, s, "192.0.2.2")
	var p2 *masqueIP
	for until := time.Now().Add(3 * time.Second); ; {
		p2 = masqueWaitPeer(t, s, "192.0.2.1")
		if p1 != p2 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("more specific client route lost")
		}
		time.Sleep(time.Millisecond)
	}
	p1.mu.Lock()
	a1 := p1.assigned[0].prefix
	p1.mu.Unlock()
	p2.mu.Lock()
	a2 := p2.assigned[0].prefix
	p2.mu.Unlock()
	if a1 == a2 {
		t.Fatal("clients share assigned address")
	}
	c3 := masqueReverseClient(t, s, 2, false, []string{"192.0.2.1/32"}, nil)
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err := s.masqueServers["server"].peer(netip.MustParseAddr("192.0.2.1"), 6)
		if errors.Is(err, ErrRejected) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ambiguous client routes were accepted")
		}
		time.Sleep(time.Millisecond)
	}
	c3.Close()
	if got := masqueWaitPeer(t, s, "192.0.2.1"); got != p2 {
		t.Fatal("stale client route retained")
	}
	// A fresh advertisement replaces, rather than accumulates, previous routes.
	client := c2.masqueClients["proxy"].ip.Load()
	if err := client.flow.capsule(3, nil); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(time.Second); ; {
		got, err := s.masqueServers["server"].peer(netip.MustParseAddr("192.0.2.1"), 6)
		if err == nil && got == p1 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("withdrawn route retained")
		}
		time.Sleep(time.Millisecond)
	}
	c1.Close()
	c2.Close()
}

func TestMasqueReverseReconnect(t *testing.T) {
	s := masqueReverseServer(t, 2, false)
	c := masqueReverseClient(t, s, 2, false, []string{"127.0.0.1/32"}, nil)
	old := masqueWaitPeer(t, s, "127.0.0.1")
	c.resetNetworkTransports()
	for until := time.Now().Add(3 * time.Second); ; {
		p := masqueWaitPeer(t, s, "127.0.0.1")
		if p != old {
			break
		}
		if time.Now().After(until) {
			t.Fatal("network reset retained old endpoint")
		}
		time.Sleep(time.Millisecond)
	}
	assertTCP(t, s)
	if err := c.DisconnectMasque("proxy"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := s.masqueServers["server"].peer(netip.MustParseAddr("127.0.0.1"), 6); !errors.Is(err, ErrRejected) {
		t.Fatal("explicit disconnect reconnected in background", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.masqueClients["proxy"].ipSession(ctx); err != nil {
		t.Fatal(err)
	}
	masqueWaitPeer(t, s, "127.0.0.1")
	assertTCP(t, s)
	conn, err := s.Dial(ctx, "udp", echoUDP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	blocked := make(chan error, 1)
	go func() { _, err := conn.Read(make([]byte, 1)); blocked <- err }()
	c.Close()
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("reverse flow survived client close")
		}
	case <-time.After(time.Second):
		t.Fatal("reverse reader leaked")
	}
}

func TestMasqueAddressPool(t *testing.T) {
	for _, tt := range []struct {
		address  []string
		capacity int
	}{
		{[]string{"10.44.0.1/30"}, 1},
		{[]string{"fd44::1/126"}, 2},
		{[]string{"10.44.0.1/30", "fd44::1/126"}, 1},
		{[]string{"10.44.0.0/31"}, 1},
		{[]string{"fd44::/127"}, 1},
	} {
		t.Run(fmt.Sprint(tt.address), func(t *testing.T) {
			s := newMasqueServer(Inbound{MasqueOptions: MasqueOptions{serverAddress: tt.address}})
			var flows []*masqueFlow
			for range tt.capacity {
				f := &masqueFlow{}
				assigned, err := s.allocate(f)
				if err != nil || len(assigned) != len(tt.address) {
					t.Fatal(assigned, err)
				}
				flows = append(flows, f)
			}
			if _, err := s.allocate(&masqueFlow{}); err == nil {
				t.Fatal("exhausted address pool accepted")
			}
			s.remove(flows[0])
			if _, err := s.allocate(&masqueFlow{}); err != nil {
				t.Fatal("released addresses not reusable", err)
			}
		})
	}
}

func TestMasqueReverseHalfClose(t *testing.T) {
	s := masqueReverseServer(t, 2, false)
	masqueReverseClient(t, s, 2, false, []string{"127.0.0.1/32"}, nil)
	masqueWaitPeer(t, s, "127.0.0.1")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		c, e := l.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		b, e := io.ReadAll(c)
		if e == nil {
			_, e = c.Write(b)
		}
		done <- e
	}()
	c, err := s.Dial(context.Background(), "tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	want := bytes.Repeat([]byte{42}, 70000)
	if _, err = c.Write(want); err == nil {
		err = c.(interface{ CloseWrite() error }).CloseWrite()
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(c)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("reverse half-close", len(got), err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func masqueReverseRoundtrip(t *testing.T, c net.Conn) {
	t.Helper()
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	want := bytes.Repeat([]byte("reverse tunnel"), 10000)
	done := make(chan error, 1)
	go func() { done <- writeAll(c, want) }()
	got := make([]byte, len(want))
	_, err := io.ReadFull(c, got)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("reverse TCP", len(got), err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
