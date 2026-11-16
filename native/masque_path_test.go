package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestMasquePathProbe(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			s := masqueEndpointServer(t, version)
			c := masqueEndpointClient(t, s, version, true)
			for range 2 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				status, err := c.ProbeMasquePath(ctx, "proxy")
				cancel()
				if err != nil || status.HTTPVersion != version || status.MTU != 1280 || !status.Peer.Is6() || status.DatagramVerified != (version == 3) {
					t.Fatal(status, err)
				}
				assertTCP(t, c)
				assertUDPAddress(t, c, []int{0, 1, 4096, 60000}, masqueEcho(t, "udp", "127.0.0.1:0"))
				assertUDPAddress(t, c, []int{0, 1, 4096, 60000}, masqueEcho(t, "udp", "[::1]:0"))
				c.resetNetworkTransports()
			}
		})
	}
}

func TestMasquePathOpaqueIntermediary(t *testing.T) {
	for _, version := range []int{1, 3} {
		for _, via := range []bool{false, true} {
			t.Run(fmt.Sprint(version, "/", via), func(t *testing.T) {
				in := Inbound{Type: "masque", Tag: "server", Listen: "127.0.0.1", HTTPVersion: version, Users: []User{{Username: "client", Password: "private"}}}
				if version == 3 {
					in.TLS = certificate(t)
				}
				origin := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				client := masqueIntermediaryClient(t, masqueIntermediary(t, origin, via, true), "ip", nil)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				status, err := client.ProbeMasquePath(ctx, "proxy")
				if err != nil || status.MTU != 1280 || status.DatagramVerified {
					t.Fatal(status, err)
				}
				if !client.masqueClients["proxy"].ip.Load().flow.reliableOnly.Load() {
					t.Fatal("unverified datagram path still selected")
				}
				assertTCP(t, client)
				assertUDPAddress(t, client, []int{0, 1, 511, 1232, 4096, 60000}, masqueEcho(t, "udp", "127.0.0.1:0"))
				assertUDPAddress(t, client, []int{1, 1232, 60000}, masqueEcho(t, "udp", "[::1]:0"))
			})
		}
	}
}

func TestMasquePathCarrierSelection(t *testing.T) {
	s := masqueEndpointServer(t, 3)
	c := masqueEndpointClient(t, s, 3, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p, err := c.masqueClients["proxy"].ipSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p.flow.reliableOnly.Store(true)
	if _, err := p.probeMTU(ctx, netip.MustParseAddr("fd44::2"), netip.MustParseAddr("fd44::1"), false); err != nil {
		t.Fatal("reliable unicast Echo", err)
	}
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 511, 4096})
	status, err := c.ProbeMasquePath(ctx, "proxy")
	if err != nil || !status.DatagramVerified || p.flow.reliableOnly.Load() {
		t.Fatal(status, err)
	}
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 511, 4096})
}

func TestMasquePathProbeConcurrency(t *testing.T) {
	s := masqueEndpointServer(t, 3)
	c := masqueEndpointClient(t, s, 3, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			status, err := c.ProbeMasquePath(ctx, "proxy")
			if err != nil || !status.DatagramVerified {
				t.Error(status, err)
			}
		})
	}
	group.Wait()
	p := c.masqueClients["proxy"].ip.Load()
	p.pathGate <- struct{}{}
	limited, stop := context.WithTimeout(ctx, 10*time.Millisecond)
	_, err := c.ProbeMasquePath(limited, "proxy")
	stop()
	<-p.pathGate
	if !errors.Is(err, context.DeadlineExceeded) || p.flow.isClosed() || p.flow.reliableOnly.Load() {
		t.Fatal("cancelled waiter changed tunnel", err)
	}
	assertTCP(t, c)
}

func masqueProbePipe(t *testing.T) (*Runtime, *masqueIP, net.Conn) {
	t.Helper()
	r := newTestRuntime(t, Config{})
	m := newMasqueHTTPSession(r.ctx)
	m.version = 1
	a, b := net.Pipe()
	f, err := m.registerFlow(a, 0, a)
	if err != nil {
		t.Fatal(err)
	}
	p := newMasqueIP(r, f, "", false, 1280, nil, []string{"fd44::2/128"}, "", nil)
	if err := p.control(3, nil); err != nil {
		t.Fatal(err)
	}
	p.start()
	c := &masqueClient{runtime: r, outbound: Outbound{Type: "masque", Tag: "probe"}}
	c.ip.Store(p)
	r.masqueClients["probe"] = c
	t.Cleanup(func() { b.Close(); m.close(); m.workers.Wait() })
	return r, p, b
}

func TestMasquePathProbeFailureAndCancel(t *testing.T) {
	for _, mode := range []string{"no-reply", "cancel-read", "blocked-write"} {
		t.Run(mode, func(t *testing.T) {
			r, p, peer := masqueProbePipe(t)
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if mode != "blocked-write" {
				go func() {
					_, _ = readQUICVar(peer)
					n, err := readQUICVar(peer)
					if err == nil {
						_, _ = io.CopyN(io.Discard, peer, int64(n))
					}
					if mode == "cancel-read" {
						// Let the fully written capsule release its cancellation hook.
						time.Sleep(5 * time.Millisecond)
						cancel()
					}
				}()
			}
			_, err := r.ProbeMasquePath(ctx, "probe")
			if err == nil {
				t.Fatal("unanswered probe succeeded")
			}
			if mode == "cancel-read" {
				if !errors.Is(err, context.Canceled) || p.flow.isClosed() {
					t.Fatal("read cancellation closed working tunnel", err)
				}
			} else if !p.flow.isClosed() {
				t.Fatal("failed path or incomplete capsule not closed", err)
			}
		})
	}
}

func TestMasquePathProbeInvalid(t *testing.T) {
	r := newTestRuntime(t, Config{})
	if _, err := r.ProbeMasquePath(context.Background(), "missing"); err == nil {
		t.Fatal("unknown tag accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ProbeMasquePath(ctx, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_, udp := masquePair(t, "udp")
	if _, err := udp.ProbeMasquePath(context.Background(), "proxy"); err == nil {
		t.Fatal("CONNECT-UDP accepted for ICMP probe")
	}
	s := masqueEndpointRuntime(t, map[string]any{"type": "masque-server", "tag": "server", "listen": "127.0.0.1", "version": 3, "address": []string{"10.44.0.1/24"}, "tls": certificate(t), "path": "/vpn/{target}/{ipproto}/", "users": []User{{Username: "client", Password: "private"}}})
	c := masqueEndpointClient(t, s, 3, true)
	if _, err := c.ProbeMasquePath(context.Background(), "proxy"); err == nil {
		t.Fatal("IPv4-only tunnel claimed IPv6 MTU verification")
	}
}

func TestMasquePathProbeReplyValidation(t *testing.T) {
	local := netip.MustParseAddr("fd44::2")
	m := newMasqueHTTPSession(context.Background())
	defer m.close()
	raw := memoryNetConn{bytes.NewReader(nil), io.Discard}
	flow, _ := m.registerFlow(raw, 0, raw)
	p := &masqueIP{flow: flow, local: []netip.Addr{local}}
	peer := netip.MustParseAddr("fe80::1")
	segment := make([]byte, 1240)
	segment[0] = 129
	copy(segment[4:], []byte("fixed challenge for validation"))
	probe := &masqueMTUProbe{local: local, target: peer, data: append([]byte{}, segment[4:]...), reply: make(chan netip.Addr, 1)}
	p.pathProbe = probe
	for _, invalid := range []string{"checksum", "nonce", "destination", "short", "type", "code", "source", "wrong-peer"} {
		t.Run(invalid, func(t *testing.T) {
			b := append([]byte{}, segment...)
			source, destination := peer, local
			switch invalid {
			case "nonce":
				b[40] ^= 1
			case "destination":
				destination = netip.MustParseAddr("fd44::9")
			case "short":
				b = b[:len(b)-1]
			case "type":
				b[0] = 128
			case "code":
				b[1] = 1
			case "source":
				source = masqueAllNodes
			case "wrong-peer":
				source = netip.MustParseAddr("fd44::99")
			}
			packet := makeWGIP(source, destination, 58, b)
			ip, _ := parseTunPacket(packet)
			binary.BigEndian.PutUint16(packet[42:], transportChecksum(ip, packet[40:]))
			if invalid == "checksum" {
				packet[43] ^= 1
			}
			p.linkPacket(ip, true)
			if len(probe.reply) != 0 {
				t.Fatal("invalid echo satisfied probe")
			}
		})
	}
	packet := makeWGIP(peer, local, 58, segment)
	ip, _ := parseTunPacket(packet)
	binary.BigEndian.PutUint16(packet[42:], transportChecksum(ip, packet[40:]))
	p.linkPacket(ip, false)
	if len(probe.reply) != 0 {
		t.Fatal("wrong response carrier satisfied probe")
	}
	if !p.linkPacket(ip, true) || len(probe.reply) != 1 {
		t.Fatal("valid echo not accepted")
	}
	<-probe.reply
	p.pathProbe = nil
	p.linkPacket(ip, true)
	if len(probe.reply) != 0 {
		t.Fatal("expired probe accepted")
	}
}

func TestMasqueLinkEchoAuthorization(t *testing.T) {
	local, peer := netip.MustParseAddr("fd44::1"), netip.MustParseAddr("fd44::2")
	for _, mode := range []string{"valid", "unassigned", "unspecified", "multicast", "oversize", "checksum", "code"} {
		t.Run(mode, func(t *testing.T) {
			m := newMasqueHTTPSession(context.Background())
			defer m.close()
			var wire bytes.Buffer
			raw := memoryNetConn{bytes.NewReader(nil), &wire}
			flow, _ := m.registerFlow(raw, 0, raw)
			p := &masqueIP{flow: flow, server: true, local: []netip.Addr{local}, haveAssignment: true, assigned: []masqueAssignment{{prefix: netip.PrefixFrom(peer, 128)}}}
			source := peer
			size := 1240
			switch mode {
			case "unassigned":
				source = netip.MustParseAddr("fd44::99")
			case "unspecified":
				source = netip.IPv6Unspecified()
			case "multicast":
				source = masqueAllNodes
			case "oversize":
				size++
			}
			segment := make([]byte, size)
			segment[0] = 128
			if mode == "code" {
				segment[1] = 1
			}
			packet := makeWGIP(source, masqueAllNodes, 58, segment)
			ip, _ := parseTunPacket(packet)
			binary.BigEndian.PutUint16(packet[42:], transportChecksum(ip, packet[40:]))
			if mode == "checksum" {
				packet[43] ^= 1
			}
			if !p.linkPacket(ip, true) {
				t.Fatal("all-nodes control escaped to routing")
			}
			if mode != "valid" {
				if wire.Len() != 0 {
					t.Fatal("invalid source/control amplified")
				}
				return
			}
			kind, _ := readQUICVar(&wire)
			n, _ := readQUICVar(&wire)
			b := make([]byte, n)
			if _, err := io.ReadFull(&wire, b); err != nil || kind != 0 || len(b) != 1281 || b[0] != 0 {
				t.Fatal("invalid echo capsule", err)
			}
			reply, err := parseTunPacket(b[1:])
			if err != nil || reply.source != local || reply.destination != peer || reply.data[40] != 129 || transportChecksum(reply, reply.data[40:]) != 0 {
				t.Fatal("invalid echo reply", err)
			}
		})
	}
}

func TestMasqueLinkLocalIsolation(t *testing.T) {
	_, p, _ := masqueProbePipe(t)
	for _, pair := range [][2]string{{"fd44::2", "ff02::1"}, {"fe80::9", "2001:db8::1"}, {"2001:db8::1", "fe80::9"}, {"169.254.1.1", "192.0.2.1"}, {"192.0.2.1", "224.0.0.1"}} {
		b := makeUDPPacket(netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1]), 20000, 20001, []byte{1})
		packet, _ := parseTunPacket(b)
		if !p.linkPacket(packet, true) {
			t.Fatal("link-local forwarding not stopped", pair)
		}
	}
	b := makeUDPPacket(netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("fd44::2"), 20000, 20001, []byte{1})
	ip, _ := parseTunPacket(b)
	if p.linkPacket(ip, true) {
		t.Fatal("ordinary packet consumed as control")
	}
	segment := make([]byte, 1241)
	segment[0] = 128
	packet := makeWGIP(netip.MustParseAddr("fd44::1"), netip.MustParseAddr("fd44::2"), 58, segment)
	ip, _ = parseTunPacket(packet)
	binary.BigEndian.PutUint16(packet[42:], transportChecksum(ip, packet[40:]))
	if p.linkPacket(ip, true) {
		t.Fatal("large ordinary unicast Echo bypassed IP stack")
	}
}

func TestMasqueNonminimalLargeCapsule(t *testing.T) {
	m := newMasqueHTTPSession(context.Background())
	defer m.close()
	a, b := net.Pipe()
	defer b.Close()
	f, err := m.registerFlow(a, 0, a)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m.goWork(func() { _ = f.readCapsules() })
	contextID := []byte{0xc0, 0, 0, 0, 0, 0, 0, 0}
	want := bytes.Repeat([]byte{23}, 65535)
	data := append(contextID, want...)
	wire := quicVar(nil, 0)
	wire = quicVar(wire, uint64(len(data)))
	wire = append(wire, data...)
	written := make(chan error, 1)
	go func() { written <- writeAll(b, wire) }()
	f.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 65535)
	if n, err := f.Read(got); err != nil || n != len(want) || !bytes.Equal(got, want) {
		t.Fatal("valid large nonminimal-context capsule rejected", n, err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func FuzzMasqueLinkPacket(f *testing.F) {
	local, peer := netip.MustParseAddr("fd44::1"), netip.MustParseAddr("fd44::2")
	segment := make([]byte, 1240)
	segment[0] = 128
	packet := makeWGIP(peer, masqueAllNodes, 58, segment)
	ip, _ := parseTunPacket(packet)
	binary.BigEndian.PutUint16(packet[42:], transportChecksum(ip, packet[40:]))
	f.Add(packet)
	f.Add(makeUDPPacket(peer, local, 1234, 53, []byte{1}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		packet, err := parseTunPacket(b)
		if err != nil {
			return
		}
		m := newMasqueHTTPSession(context.Background())
		defer m.close()
		var output bytes.Buffer
		raw := memoryNetConn{bytes.NewReader(nil), &output}
		flow, err := m.registerFlow(raw, 0, raw)
		if err != nil {
			t.Fatal(err)
		}
		p := &masqueIP{flow: flow, server: true, local: []netip.Addr{local}, haveAssignment: true, assigned: []masqueAssignment{{prefix: netip.PrefixFrom(peer, 128)}}}
		p.linkPacket(packet, true)
		if output.Len() > 1296 {
			t.Fatal("link-local echo amplified or unbounded")
		}
	})
}

type masqueCountWriter struct {
	bytes.Buffer
	writes int
}

func (w *masqueCountWriter) Write(b []byte) (int, error) { w.writes++; return w.Buffer.Write(b) }

func TestMasqueCapsuleCoalescing(t *testing.T) {
	m := newMasqueHTTPSession(context.Background())
	defer m.close()
	w := &masqueCountWriter{}
	raw := memoryNetConn{bytes.NewReader(nil), w}
	f, err := m.registerFlow(raw, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{42}, 1281)
	for range 100 {
		if err := f.capsule(0, data); err != nil {
			t.Fatal(err)
		}
	}
	if w.writes != 100 || cap(f.writeBuffer) > 4096 {
		t.Fatal("capsule not coalesced or small buffer grew", w.writes, cap(f.writeBuffer))
	}
	for range 100 {
		kind, _ := readQUICVar(&w.Buffer)
		n, _ := readQUICVar(&w.Buffer)
		got := make([]byte, n)
		_, err := io.ReadFull(&w.Buffer, got)
		if kind != 0 || err != nil || !bytes.Equal(got, data) {
			t.Fatal("coalesced wire changed", err)
		}
	}
	if err := f.capsule(0, make([]byte, 65536)); err != nil || cap(f.writeBuffer) != 0 {
		t.Fatal("large scratch retained", err)
	}
}
