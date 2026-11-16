package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHysteriaHopConfig(t *testing.T) {
	o := HysteriaHopOptions{ServerPorts: []string{"443", "400:403", "402-405", "65535"}}
	p, err := o.ports()
	if err != nil || !slices.Equal(p, []uint16{400, 401, 402, 403, 404, 405, 443, 65535}) {
		t.Fatal(p, err)
	}
	for _, entry := range []string{"", "0", "-1", "1:", ":2", "1::2", "1-2-3", "3:2", "65536", " 443", "1,2", "1:65536", "1-:2"} {
		o.ServerPorts = []string{entry}
		if _, err := o.ports(); err == nil {
			t.Fatal("accepted", entry)
		}
	}
	for _, raw := range []string{
		`{"type":"hysteria","server_port":443,"server_ports":["443"]}`,
		`{"type":"tuic","server_ports":["443"]}`,
		`{"type":"hysteria2","hop_interval":"30s"}`,
		`{"type":"hysteria2","server_ports":["443"],"hop_interval":"0s"}`,
		`{"type":"hysteria2","server_ports":["443"],"hop_interval":"500ms"}`,
		`{"type":"hysteria2","server_ports":["443"],"hop_interval_max":"29s"}`,
		`{"type":"hysteria","server_ports":["443"],"hop_interval_max":"40s"}`,
	} {
		var out Outbound
		if err := json.Unmarshal([]byte(raw), &out); err != nil {
			t.Fatal(err)
		}
		if out.HysteriaHopOptions.validate(out.Type, out.ServerPort) == nil {
			t.Fatal("accepted", raw)
		}
	}
	for _, kind := range []string{"hysteria", "hysteria2"} {
		out := Outbound{Type: kind, Tag: "proxy", Server: "example.com", Password: "private", TLS: TLSOptions{Enabled: true}, HysteriaHopOptions: HysteriaHopOptions{ServerPorts: []string{"443", "5000:5002"}}}
		b, _ := json.Marshal(Config{Outbounds: []Outbound{out}})
		if _, err := Parse(b); err != nil {
			t.Fatal(err)
		}
	}
}

// Real UDP relays emulate NAT/port-forwarding without changing host firewall
// rules. Every new source socket gets a different upstream port. Once traffic
// moves, replies to the old tuple are discarded, forcing actual path validation.
type hopTestRelay struct {
	mu          sync.Mutex
	latest      string
	connections map[string]net.Conn
	fronts      []net.PacketConn
	done        bool
	workers     sync.WaitGroup
	dropFirst   bool
	dropped     map[string]bool
}

func testHopRelays(t *testing.T, target string, ipv6 bool) ([]string, *hopTestRelay) {
	t.Helper()
	r := &hopTestRelay{connections: map[string]net.Conn{}, dropped: map[string]bool{}}
	var ports []string
	network, listen := "udp4", "127.0.0.1:0"
	if ipv6 {
		network, listen = "udp6", "[::1]:0"
	}
	for range 3 {
		front, err := net.ListenPacket(network, listen)
		if err != nil {
			t.Fatal(err)
		}
		r.fronts = append(r.fronts, front)
		_, port, _ := net.SplitHostPort(front.LocalAddr().String())
		ports = append(ports, port+":"+port)
		r.workers.Add(1)
		go func() {
			defer r.workers.Done()
			buffer := make([]byte, 65535)
			for {
				n, remote, err := front.ReadFrom(buffer)
				if err != nil {
					return
				}
				key := front.LocalAddr().String() + "/" + remote.String()
				r.mu.Lock()
				if r.done {
					r.mu.Unlock()
					return
				}
				back := r.connections[key]
				if back == nil {
					back, err = net.Dial(network, target)
					if err != nil {
						r.mu.Unlock()
						return
					}
					r.connections[key] = back
					// Old in-flight datagrams cannot replace a newer NAT mapping.
					r.latest = key
					r.workers.Add(1)
					go func() {
						defer r.workers.Done()
						data := make([]byte, 65535)
						for {
							n, err := back.Read(data)
							if err != nil {
								return
							}
							r.mu.Lock()
							active := r.latest == key
							if active && r.dropFirst && !r.dropped[key] {
								r.dropped[key] = true
								active = false
							}
							r.mu.Unlock()
							if active {
								front.WriteTo(data[:n], remote)
							}
						}
					}()
				}
				r.mu.Unlock()
				back.Write(buffer[:n])
			}
		}()
	}
	t.Cleanup(func() {
		r.mu.Lock()
		r.done = true
		for _, front := range r.fronts {
			front.Close()
		}
		for _, back := range r.connections {
			back.Close()
		}
		r.mu.Unlock()
		r.workers.Wait()
	})
	return ports, r
}

func (r *hopTestRelay) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.connections) }

func testHysteriaHop(t *testing.T, kind, obfs, direction string, ipv6, detour bool, protocol string) {
	t.Helper()
	ip := "127.0.0.1"
	if ipv6 {
		ip = "::1"
	}
	in := Inbound{Type: kind, Tag: "server", Listen: ip, TLS: certificate(t), Users: []User{{Password: "private"}}}
	in.Protocol = protocol
	in.TLS.ALPN = quicALPN(kind)
	if obfs == "xplus" {
		in.Obfs = "hop-mask"
	}
	if obfs == "salamander" {
		in.Obfs = Obfuscation(`{"type":"salamander","password":"hop-mask"}`)
	}
	if obfs == "gecko" {
		in.Obfs = Obfuscation(`{"type":"gecko","password":"hop-mask"}`)
	}
	var server *Runtime
	address := ""
	if direction == "client" {
		in.ListenPort = unusedPort(t)
		address = portAddress(ip, in.ListenPort)
		ready := Inbound{Type: "mixed", Tag: "ready", Listen: ip, ListenPort: unusedPort(t)}
		referenceRuntime(t, Config{Inbounds: []Inbound{ready, in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	} else {
		server = newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
		address = server.Address("server")
	}
	ports, relays := testHopRelays(t, address, ipv6)
	// The extra detour case loses the first server datagram on each new path.
	relays.mu.Lock()
	relays.dropFirst = detour
	relays.mu.Unlock()
	out := testOutbound(t, in, address)
	out.Protocol = protocol
	out.Username, out.UUID = "", ""
	out.Obfs = in.Obfs
	out.ServerPort = 0
	out.HysteriaHopOptions = HysteriaHopOptions{ServerPorts: ports, HopInterval: "1s"}
	if obfs == "gecko" {
		out.HopIntervalMax = "1500ms"
	}
	var client *Runtime
	if direction == "server" {
		out.HopInterval = "5s"
		if obfs == "gecko" {
			out.HopIntervalMax = "6s"
		}
		local := Inbound{Type: "mixed", Tag: "local", Listen: ip, ListenPort: unusedPort(t)}
		referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
		front := testOutbound(t, local, portAddress(ip, local.ListenPort))
		front.Username, front.Password, front.UUID = "", "", ""
		client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
	} else {
		outs := []Outbound{out}
		if detour {
			proxy := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "socks", Tag: "socks", Listen: ip}}})
			chain := testOutbound(t, Inbound{Type: "socks"}, proxy.Address("socks"))
			chain.Tag = "chain"
			chain.Username, chain.Password = "", ""
			outs[0].Detour = "chain"
			outs = append(outs, chain)
		}
		client = newTestRuntime(t, Config{Outbounds: outs})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	tcp, err := client.Dial(ctx, "tcp", tcpEcho(t))
	if err != nil {
		t.Fatal("initial TCP dial", err)
	}
	defer tcp.Close()
	udp, err := client.Dial(ctx, "udp", echoUDP(t))
	if err != nil {
		t.Fatal("initial UDP dial", err)
	}
	defer udp.Close()
	tcp.SetDeadline(time.Now().Add(20 * time.Second))
	udp.SetDeadline(time.Now().Add(20 * time.Second))
	want := bytes.Repeat([]byte("continuous hop data"), 512)
	got := make([]byte, len(want))
	for i := 0; i < 100; i++ {
		if _, err = tcp.Write(want); err != nil {
			t.Fatal("TCP", i, err)
		}
		if _, err = io.ReadFull(tcp, got); err != nil || !bytes.Equal(want, got) {
			t.Fatal("TCP echo", i, err)
		}
		if _, err = udp.Write(want[:511]); err != nil {
			t.Fatal("UDP", i, err)
		}
		n, e := udp.Read(got)
		if e != nil || !bytes.Equal(want[:511], got[:n]) {
			t.Fatal("UDP echo", i, n, e)
		}
		if relays.count() >= 3 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if relays.count() < 3 {
		t.Fatal("did not hop twice", relays.count())
	}
	if server != nil {
		endpoint := server.quicListeners["server"]
		endpoint.mu.Lock()
		count := len(endpoint.conns)
		endpoint.mu.Unlock()
		if count != 1 {
			t.Fatal("reconnected instead of retaining QUIC", count)
		}
	}
	sizes := []int{4096}
	if direction == "" {
		sizes = append(sizes, 60000)
	}
	assertUDPSizes(t, client, sizes)
}

func TestHysteriaHopIndependent(t *testing.T) {
	for _, c := range []struct {
		kind, mask   string
		ipv6, detour bool
	}{
		{"hysteria", "", false, false}, {"hysteria", "xplus", false, false},
		{"hysteria2", "", false, false}, {"hysteria2", "salamander", false, false},
		{"hysteria2", "gecko", false, false}, {"hysteria2", "", true, false}, {"hysteria2", "", false, true},
	} {
		t.Run(c.kind+"/"+c.mask+"/"+strconv.FormatBool(c.ipv6)+"/"+strconv.FormatBool(c.detour), func(t *testing.T) { testHysteriaHop(t, c.kind, c.mask, "", c.ipv6, c.detour, "") })
	}
}

func TestHysteriaHopReference(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		t.Fatal("LANBOAT_TEST_SINGBOX15 required")
	}
	t.Setenv("LANBOAT_TEST_REFERENCE", ref)
	for _, c := range [][2]string{{"hysteria", ""}, {"hysteria", "xplus"}, {"hysteria2", ""}, {"hysteria2", "salamander"}, {"hysteria2", "gecko"}} {
		for _, direction := range []string{"client", "server"} {
			t.Run(c[0]+"/"+c[1]+"/"+direction, func(t *testing.T) { testHysteriaHop(t, c[0], c[1], direction, false, false, "") })
		}
	}
}

func TestQUICPathAuthentication(t *testing.T) {
	key, err := newQUICKey(bytes.Repeat([]byte{1}, 32), tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	old := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	next := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	var sent [][]byte
	c := &quicConn{cid: []byte("12345678"), dcid: []byte("abcdefgh"), remote: old, pathRemote: old, established: true, srtt: time.Millisecond}
	c.spaces[2] = quicSpace{read: key, write: key, largest: -1}
	c.sendTo = func(b []byte, remote net.Addr) error { sent = append(sent, append([]byte{}, b...)); return nil }
	packet := sealQUICPacket([]byte{1}, c.cid, nil, nil, 2, 0, false, key)
	c.packetRemote = next
	corrupt := append([]byte{}, packet...)
	corrupt[len(corrupt)-1] ^= 1
	if err = c.handleDatagram(corrupt); err != nil || c.path != nil || len(sent) != 0 {
		t.Fatal("unauthenticated path", err)
	}
	if err = c.handleDatagram(packet); err != nil || c.path == nil || len(sent) != 1 {
		t.Fatal("authenticated path", err)
	}
	if c.path.sent > 3*len(packet) || c.pathRemote != old {
		t.Fatal("amplification or unvalidated switch")
	}
	before := c.path.received
	if err = c.handleDatagram(packet); err != nil || c.path.received != before {
		t.Fatal("replay added budget", err)
	}
	token := append([]byte{}, c.path.token[:]...)
	c.packetRemote = old
	c.pathResponse(token)
	if c.pathRemote != old {
		t.Fatal("wrong source accepted")
	}
	c.packetRemote = next
	c.pathResponse(make([]byte, 8))
	if c.pathRemote != old {
		t.Fatal("wrong token accepted")
	}
	c.pathResponse(token)
	if c.pathRemote != next || c.path != nil {
		t.Fatal("valid response rejected")
	}
	foreign := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 2000}
	c.observePath(foreign, 1200, time.Now())
	if c.path != nil {
		t.Fatal("active IP migration accepted")
	}
	// A delayed, previously unseen packet from the old port must not start
	// validating backwards after a newer packet arrived on the current path.
	c.packetRemote = next
	if err = c.handleDatagram(sealQUICPacket([]byte{1}, c.cid, nil, nil, 2, 3, false, key)); err != nil {
		t.Fatal(err)
	}
	c.packetRemote = old
	if err = c.handleDatagram(sealQUICPacket([]byte{1}, c.cid, nil, nil, 2, 1, false, key)); err != nil {
		t.Fatal(err)
	}
	if c.path != nil || c.pathRemote != next {
		t.Fatal("reordered packet reversed path")
	}
}

func TestQUICPathBuffersDatagrams(t *testing.T) {
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	old := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	next := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	c := &quicConn{dcid: []byte("abcdefgh"), pathRemote: old, srtt: time.Millisecond, cwnd: 12000}
	c.spaces[2] = quicSpace{write: key, sent: map[uint64]quicSent{}}
	c.sendTo = func([]byte, net.Addr) error { return nil }
	var targets []net.Addr
	c.send = func([]byte) error { targets = append(targets, c.pathRemote); return nil }
	frame := quicFrame{data: []byte{0x31, 1, 42}, level: 2}
	c.enqueue(frame)
	c.observePath(next, 1200, time.Now())
	if err = c.flush(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 || len(c.spaces[2].queue) != 1 {
		t.Fatal("sent UDP to old path")
	}
	c.packetRemote = next
	c.pathResponse(c.path.token[:])
	if err = c.flush(time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != next || len(c.spaces[2].queue) != 0 {
		t.Fatal("did not release UDP to validated path", targets)
	}
}

func TestHysteriaHopUDPFirst(t *testing.T) {
	for _, kind := range []string{"hysteria", "hysteria2"} {
		t.Run(kind, func(t *testing.T) {
			in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}}
			if kind == "hysteria2" {
				in.Obfs = Obfuscation(`{"type":"salamander","password":"mask"}`)
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			ports, relay := testHopRelays(t, server.Address("server"), false)
			out := testOutbound(t, in, server.Address("server"))
			out.Username, out.UUID = "", ""
			out.Obfs = in.Obfs
			out.ServerPort = 0
			out.HysteriaHopOptions = HysteriaHopOptions{ServerPorts: ports, HopInterval: "1s"}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			udp, err := client.Dial(ctx, "udp", echoUDP(t))
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			want := bytes.Repeat([]byte{42}, 511)
			buffer := make([]byte, 1024)
			for i := 0; i < 3; i++ {
				udp.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = udp.Write(want); err != nil {
					t.Fatal(err)
				}
				n, err := udp.Read(buffer)
				if err != nil || !bytes.Equal(want, buffer[:n]) {
					t.Fatal("first UDP after hop lost", i, n, err)
				}
				relay.mu.Lock()
				relay.dropFirst = true
				relay.mu.Unlock()
				if i < 2 {
					time.Sleep(1100 * time.Millisecond)
				}
			}
			if relay.count() < 3 {
				t.Fatal("did not hop twice")
			}
		})
	}
}

func TestQUICHopLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var peers []net.Conn
	fail := false
	dial := func(ctx context.Context, port uint16) (net.Conn, error) {
		if fail {
			return nil, errors.New("test dial failure")
		}
		left, right := net.Pipe()
		peers = append(peers, right)
		return left, nil
	}
	c, err := newQUICHopConn(ctx, []uint16{1, 2, 3}, time.Hour, time.Hour, dial)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	defer func() {
		for _, p := range peers {
			p.Close()
		}
	}()
	initial := c.active
	fail = true
	if c.hop() == nil || c.active != initial {
		t.Fatal("failed dial changed socket")
	}
	fail = false
	for range 20 {
		if err = c.hop(); err != nil {
			t.Fatal(err)
		}
	}
	if c.active == initial || c.previous == initial {
		t.Fatal("retained initial socket")
	}
	c.SetReadDeadline(time.Now().Add(time.Millisecond))
	if _, err = c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Time{})
	read := make(chan error, 1)
	go func() { _, e := c.Read(make([]byte, 1)); read <- e }()
	c.SetReadDeadline(time.Now().Add(time.Millisecond))
	select {
	case e := <-read:
		if !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline update blocked")
	}
	c.SetReadDeadline(time.Time{})
	go func() { _, e := c.Read(make([]byte, 1)); read <- e }()
	cancel()
	select {
	case e := <-read:
		if !errors.Is(e, net.ErrClosed) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
	c.Close()
}

func TestQUICPathRetriesAndExpiry(t *testing.T) {
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	old := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	next := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	now := time.Now()
	sent := 0
	c := &quicConn{dcid: []byte("abcdefgh"), pathRemote: old, srtt: time.Millisecond}
	c.spaces[2].write = key
	c.sendTo = func(b []byte, a net.Addr) error { sent += len(b); return nil }
	c.observePath(next, 1200, now)
	if c.path.attempts != 1 {
		t.Fatal("no initial challenge")
	}
	for i := 1; i <= 20; i++ {
		c.servicePath(now.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	if c.path.attempts != 3 || sent != 3600 || c.pathRemote != old {
		t.Fatal("unbounded retry or premature migration", c.path, sent)
	}
	for range 10 {
		c.observePath(next, 1200, now)
	}
	if c.path.attempts != 3 {
		t.Fatal("new packet reset retry budget")
	}
	c.servicePath(now.Add(4 * time.Second))
	if c.path != nil {
		t.Fatal("expired path retained")
	}
	c.observePath(next, 1200, time.Now())
	c.path.expires = time.Now().Add(-time.Second)
	c.packetRemote = next
	c.pathResponse(c.path.token[:])
	if c.pathRemote != old {
		t.Fatal("expired response accepted")
	}
}

func TestQUICPathLatestCandidate(t *testing.T) {
	key, err := newQUICKey(bytes.Repeat([]byte{1}, 32), tls.TLS_AES_128_GCM_SHA256)
	if err != nil {
		t.Fatal(err)
	}
	old := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1000}
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2000}
	next := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 3000}
	c := &quicConn{cid: []byte("12345678"), dcid: []byte("abcdefgh"), remote: old, pathRemote: old, established: true, srtt: time.Millisecond}
	c.spaces[2] = quicSpace{read: key, write: key, largest: -1}
	c.sendTo = func([]byte, net.Addr) error { return nil }
	packet := func(remote net.Addr, pn uint64) {
		t.Helper()
		c.packetRemote = remote
		if err := c.handleDatagram(sealQUICPacket([]byte{1}, c.cid, nil, nil, 2, pn, false, key)); err != nil {
			t.Fatal(err)
		}
	}
	packet(first, 0)
	stale := bytes.Clone(c.path.token[:])
	// The next hop can happen before a delayed/lost challenge is answered.
	packet(next, 2)
	if c.path == nil || !sameQUICAddress(c.path.remote, next) || c.pathRemote != old {
		t.Fatal("stale candidate blocked newer authenticated NAT rebinding", c.path)
	}
	current := bytes.Clone(c.path.token[:])
	if bytes.Equal(stale, current) || c.path.sent > 3*c.path.received {
		t.Fatal("challenge identity or amplification budget", c.path)
	}
	// Even unseen packets with older packet numbers cannot move validation back.
	packet(first, 1)
	if !sameQUICAddress(c.path.remote, next) {
		t.Fatal("reordered packet replaced newest candidate")
	}
	c.packetRemote = first
	c.pathResponse(stale)
	c.packetRemote = next
	c.pathResponse(stale)
	if c.pathRemote != old || c.path == nil {
		t.Fatal("obsolete token validated a different tuple")
	}
	c.pathResponse(current)
	if c.pathRemote != next || c.path != nil {
		t.Fatal("latest candidate did not validate")
	}
}

func FuzzHysteriaHopPorts(f *testing.F) {
	for _, seed := range []string{"443", "1:65535", "400:405,403:410", "0", "65536", "1::2", "-1", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 256 {
			return
		}
		ports, err := (HysteriaHopOptions{ServerPorts: strings.Split(raw, ",")}).ports()
		if err != nil {
			return
		}
		if len(ports) == 0 || len(ports) > 65535 {
			t.Fatal("invalid port count")
		}
		for i, port := range ports {
			if port == 0 || i > 0 && ports[i-1] >= port {
				t.Fatal("invalid port set")
			}
		}
	})
}

func BenchmarkQUICHopRoundTrip(b *testing.B) {
	left, right := net.Pipe()
	c, err := newQUICHopConn(context.Background(), []uint16{443}, time.Hour, time.Hour, func(context.Context, uint16) (net.Conn, error) { return left, nil })
	if err != nil {
		b.Fatal(err)
	}
	defer right.Close()
	defer c.Close()
	go io.Copy(right, right)
	payload := make([]byte, 1200)
	buffer := make([]byte, 1200)
	c.Write(payload)
	c.Read(buffer)
	b.ReportAllocs()
	b.SetBytes(1200)
	b.ResetTimer()
	for range b.N {
		if _, err = c.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err = c.Read(buffer); err != nil {
			b.Fatal(err)
		}
	}
}
