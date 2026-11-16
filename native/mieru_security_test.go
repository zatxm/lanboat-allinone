package native

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMieruCloseDrainsQueuedTail(t *testing.T) {
	r := newTestRuntime(t, Config{})
	left, right := net.Pipe()
	defer right.Close()
	m := newMieruCarrier(r, left, false, true, nil, MieruOptions{}, 0)
	defer m.close()
	p := m.newFlow(1)
	p.mu.Lock()
	locked := true
	defer func() {
		if locked {
			p.mu.Unlock()
		}
	}()
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() { b := make([]byte, 16); n, err := p.Read(b); done <- result{b[:n], err} }()
	// Wait for Read to block on its state mutex, without adding a product hook.
	for until := time.Now().Add(time.Second); ; {
		count, _ := runtime.GoroutineProfile(nil)
		records := make([]runtime.StackRecord, count+16)
		n, ok := runtime.GoroutineProfile(records)
		waiting := false
		if ok {
			for _, record := range records[:n] {
				frames := runtime.CallersFrames(record.Stack())
				read, mutex := false, false
				for {
					frame, more := frames.Next()
					read = read || strings.Contains(frame.Function, ".(*mieruFlow).Read")
					mutex = mutex || strings.Contains(frame.Function, "Mutex).lockSlow")
					if !more {
						break
					}
				}
				if read && mutex {
					waiting = true
					break
				}
			}
		}
		if waiting {
			break
		}
		if time.Now().After(until) {
			t.Fatal("reader did not reach controlled state lock")
		}
		runtime.Gosched()
	}
	want := []byte("final tail")
	if !m.reserve(len(want)) {
		t.Fatal("tail budget")
	}
	p.incoming <- bytes.Clone(want)
	p.closed = true
	p.cancel()
	close(p.done)
	p.mu.Unlock()
	locked = false
	select {
	case got := <-done:
		if got.err != nil || !bytes.Equal(got.data, want) {
			t.Fatalf("tail lost on close:%q,%v", got.data, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader stalled")
	}
	if n, err := p.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatal("missing final EOF", n, err)
	}
	if m.budget.Load() != 0 || r.mieruBudget.Load() != 0 {
		t.Fatal("tail budget leaked")
	}
}

func mieruTestPattern(mode, rotation byte) string {
	// Explicit fragment, printable nonce, bounded padding, and low-entropy protobuf fields.
	b := []byte{0x1a, 4, 8, 1, 16, 1, 0x22, 8, 8, 1, 16, 1, 24, 6, 32, 8, 0x2a, 5, 8, 64, 16, 128, 1}
	low := []byte{8, mode, 16}
	low = binary.AppendUvarint(low, uint64(rotation))
	b = append(b, 0x32, byte(len(low)))
	b = append(b, low...)
	return base64.StdEncoding.EncodeToString(b)
}

func TestMieruPatternReference(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, side := range []string{"client", "server"} {
			t.Run(network+"/"+side, func(t *testing.T) {
				pattern := mieruTestPattern(1, 112)
				options := MieruOptions{UserHint: true, TrafficPattern: pattern}
				var c *Runtime
				if side == "client" {
					port := unusedPort(t)
					mieruReference(t, "server", network, portAddress("127.0.0.1", port), "unused", "0", pattern)
					c = newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "mieru", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Username: "client", Password: "private", Network: network, MieruOptions: options}}})
				} else {
					s := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "mieru", Tag: "server", Listen: "127.0.0.1", Network: network, Users: []User{{Username: "client", Password: "private"}}, MieruOptions: options}}})
					local := portAddress("127.0.0.1", unusedPort(t))
					mieruReference(t, "client", network, s.Address("server"), local, "0", pattern)
					out := testOutbound(t, Inbound{Type: "socks"}, local)
					out.Username, out.Password = "", ""
					c = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				}
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 511, 4096, 14000})
			})
		}
	}
}

func TestMieruWireAuthentication(t *testing.T) {
	u := newMieruUser("alice", "private")
	key := u.ciphers()[1]
	for _, packet := range []bool{false, true} {
		t.Run(fmt.Sprint(packet), func(t *testing.T) {
			codec := mieruCodec{key: key, user: u}
			var stream bytes.Buffer
			for i := range 4 {
				b, e := codec.encode(mieruFrame{kind: 6, id: 1, seq: uint32(i), body: []byte("payload")}, packet, true)
				if e != nil {
					t.Fatal(e)
				}
				stream.Write(b)
			}
			if !packet {
				var replay replayWindow
				receiver := mieruCodec{}
				for i := range 4 {
					f, e := receiver.read(&stream, []*mieruUser{u}, &replay)
					if e != nil || f.seq != uint32(i) || string(f.body) != "payload" {
						t.Fatal(i, e)
					}
				}
				return
			}
			codec = mieruCodec{key: key, user: u, pattern: &mieruPattern{}}
			b, _ := codec.encode(mieruFrame{kind: 6, id: 1, body: []byte("payload")}, true, true)
			b = bytes.Clone(b)
			if _, _, _, e := mieruDecodePacket(b, []*mieruUser{newMieruUser("alice", "wrong")}, nil); e == nil {
				t.Fatal("accepted wrong password")
			}
			for _, offset := range []int{0, 24, 60, 72} {
				damaged := bytes.Clone(b)
				damaged[offset] ^= 128
				if _, _, _, e := mieruDecodePacket(damaged, []*mieruUser{u}, nil); e == nil {
					t.Fatal("accepted tampered packet", offset)
				}
			}
			var replay replayWindow
			if e := replay.claimFor(mieruReplayKey(b), time.Minute); e != nil {
				t.Fatal(e)
			}
			if e := replay.claimFor(mieruReplayKey(b), time.Minute); e == nil {
				t.Fatal("accepted replay")
			}
		})
	}
	var nonce [24]byte
	for i := range nonce {
		nonce[i] = 255
	}
	if mieruIncrement(&nonce) == nil {
		t.Fatal("nonce wrap accepted")
	}
	for _, kind := range []byte{2, 6, 10} {
		f := mieruFrame{kind: kind, id: 1, mode: 1, mask: 0xffff, body: []byte{1}}
		h := f.metadata(0, 0, 1)
		binary.BigEndian.PutUint32(h[2:], 0)
		if _, _, _, _, e := mieruParseHeader(h[:]); e == nil {
			t.Fatal("accepted old timestamp")
		}
	}
}

func TestMieruUDPKeyRotation(t *testing.T) {
	r := newTestRuntime(t, Config{})
	capture := &fragmentCapture{}
	m := newMieruCarrier(r, capture, true, true, nil, MieruOptions{}, 1400)
	defer m.close()
	u := newMieruUser("client", "private")
	m.user = u
	epoch := time.Now().Round(2 * time.Minute).Unix()
	salt := sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(epoch-240)))
	material, _ := pbkdf2.Key(sha256.New, string(u.hash[:]), salt[:], 64, 32)
	old, _ := newChaChaAEAD(material, true)
	m.key = old
	m.recv.key = old
	m.recv.keyEpoch = epoch - 120
	codec := mieruCodec{key: old, user: u}
	packet, e := codec.encode(mieruFrame{kind: 9, id: 1}, true, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.decodePacket(packet); e == nil {
		t.Fatal("expired cached UDP key bypassed time-key discovery")
	}
	if e = m.wire(mieruFrame{kind: 8, id: 1}, time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, _, _, e = mieruDecodePacket(capture.parts[0], []*mieruUser{u}, nil); e != nil {
		t.Fatal("sender retained stale key", e)
	}
}

func TestMieruLowEntropyVector(t *testing.T) {
	src, _ := hex.DecodeString("12345678")
	want, _ := hex.DecodeString("0102030405060708")
	got, e := mieruLowEntropy(src, 1, 0x0f0f0f0f, 0, 4, true)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal(got, e)
	}
	for _, ones := range []bool{false, true} {
		encoded := bytes.Clone(want)
		if ones {
			for i := range encoded {
				encoded[i] |= 0xf0
			}
		}
		decoded, e := mieruLowEntropy(encoded, 1, 0x0f0f0f0f, 0, 4, false)
		if e != nil || !bytes.Equal(decoded, src) {
			t.Fatal(decoded, e)
		}
	}
	for mode := byte(1); mode <= 4; mode++ {
		for _, rotation := range []byte{0, 7, 112} {
			for n := 1; n < 64; n++ {
				body := bytes.Repeat([]byte{byte(n)}, n)
				mask := uint32(1)<<(12+4*mode) - 1
				encoded, e := mieruLowEntropy(body, mode, mask, rotation, n, true)
				if e != nil {
					t.Fatal(e)
				}
				got, e := mieruLowEntropy(encoded, mode, mask, rotation, n, false)
				if e != nil || !bytes.Equal(got, body) {
					t.Fatal(n, mode, rotation, e)
				}
			}
		}
	}
	// The unused selected bits of a partial final chunk are padding too.
	b := []byte{0, 0, 0, 0, 0, 1, 2, 3}
	if _, e := mieruLowEntropy(b, 1, 0xffff, 0, 1, false); e == nil {
		t.Fatal("accepted mixed partial padding")
	}
}

func TestMieruPatternValidation(t *testing.T) {
	p, e := parseMieruPattern(mieruTestPattern(4, 112), 0)
	if e != nil || !p.fragment || p.mode != 4 || p.rotation != 112 || p.middle != 64 || p.end != 128 {
		t.Fatal(p, e)
	}
	for _, encoded := range []string{"!", base64.StdEncoding.EncodeToString([]byte{0x22, 5, 8, 3, 0x2a, 1, 'z'}), base64.StdEncoding.EncodeToString([]byte{0x1a, 2, 16, 101}), base64.StdEncoding.EncodeToString([]byte{0x32, 2, 16, 17}), base64.StdEncoding.EncodeToString([]byte{0xff})} {
		if _, e := parseMieruPattern(encoded, 0); e == nil {
			t.Fatal("accepted invalid pattern", encoded)
		}
	}
	for _, network := range []string{"tcp", "udp"} {
		u := newMieruUser("client", "private")
		key := u.ciphers()[1]
		p, _ := parseMieruPattern(mieruTestPattern(1, 7), 0)
		c := mieruCodec{key: key, user: u, pattern: p, mtu: 1280}
		for range 4 {
			b, e := c.encode(mieruFrame{kind: 10, id: 1, mode: 1, rotation: p.rotation, body: bytes.Repeat([]byte("x"), 500)}, network == "udp", true)
			if e != nil {
				t.Fatal(e)
			}
			if network == "udp" {
				if len(b) > 1280 {
					t.Fatal("MTU exceeded")
				}
				if _, _, _, e := mieruDecodePacket(b, []*mieruUser{u}, nil); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
}

func TestMieruMultiplexAndReset(t *testing.T) {
	for _, level := range []string{"off", "low", "middle", "high"} {
		t.Run(level, func(t *testing.T) {
			s, _ := mieruPair(t, "tcp", 0)
			out := testOutbound(t, Inbound{Type: "mieru"}, s.Address("server"))
			out.Username, out.Password = "client", "private"
			out.MieruMultiplexing = level
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			var conns []net.Conn
			for range 6 {
				conn, e := c.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "127.0.0.1:0"))
				if e != nil {
					t.Fatal(e)
				}
				conns = append(conns, conn)
			}
			client := c.mieruClients[out.Tag]
			want := 1
			if level == "off" {
				want = 6
			}
			if level == "low" {
				want = 2
			}
			if len(client.carriers) != want {
				t.Fatal("wrong multiplex allocation", len(client.carriers), want)
			}
			c.resetNetworkTransports()
			for _, conn := range conns {
				conn.SetReadDeadline(time.Now().Add(time.Second))
				if _, e := conn.Read(make([]byte, 1)); e == nil {
					t.Fatal("reset did not close flow")
				}
				conn.Close()
			}
			if c.mieruBudget.Load() != 0 {
				t.Fatal("retained bytes", c.mieruBudget.Load())
			}
			assertTCP(t, c)
		})
	}
}

func TestMieruDeadlinesAndWrongCredentials(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			s, c := mieruPair(t, network, 0)
			conn, e := c.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "127.0.0.1:0"))
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			if _, e = conn.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal(e)
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			conn.Write([]byte("retry"))
			b := make([]byte, 5)
			if _, e = io.ReadFull(conn, b); e != nil || string(b) != "retry" {
				t.Fatal(string(b), e)
			}
			out := testOutbound(t, Inbound{Type: "mieru"}, s.Address("server"))
			out.Network = network
			out.Username, out.Password = "client", "incorrect"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			if conn, e := bad.Dial(ctx, "tcp", masqueEcho(t, "tcp", "127.0.0.1:0")); e == nil {
				conn.Close()
				t.Fatal("wrong password accepted")
			}
		})
	}
}

func TestMieruWriteDeadlineIsolatesFlows(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			_, c := mieruPair(t, network, 0)
			target := masqueEcho(t, "tcp", "127.0.0.1:0")
			a, e := c.Dial(context.Background(), "tcp", target)
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			b, e := c.Dial(context.Background(), "tcp", target)
			if e != nil {
				t.Fatal(e)
			}
			defer b.Close()
			a.SetWriteDeadline(time.Now().Add(-time.Second))
			if _, e = a.Write([]byte("expired")); !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal(e)
			}
			flow := a.(*ownedConn).Conn.(*mieruFlow)
			flow.m.gate <- struct{}{}
			a.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
			_, e = a.Write([]byte("queued"))
			<-flow.m.gate
			if !errors.Is(e, os.ErrDeadlineExceeded) {
				t.Fatal("queued write did not time out", e)
			}
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			for _, conn := range []net.Conn{a, b} {
				if _, e = conn.Write([]byte("ok")); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, 2)
				if _, e = io.ReadFull(conn, got); e != nil || string(got) != "ok" {
					t.Fatal(string(got), e)
				}
			}
		})
	}
}

func mieruLossRelay(t *testing.T, address string) string {
	t.Helper()
	remote, e := net.ResolveUDPAddr("udp", address)
	if e != nil {
		t.Fatal(e)
	}
	front, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	back, e := net.DialUDP("udp", nil, remote)
	if e != nil {
		front.Close()
		t.Fatal(e)
	}
	var mu sync.Mutex
	var client net.Addr
	var workers sync.WaitGroup
	forward := func(read func([]byte) (int, error), write func([]byte) error) {
		defer workers.Done()
		b := make([]byte, 2048)
		var held []byte
		count := 0
		for {
			n, e := read(b)
			if e != nil {
				return
			}
			count++
			if count%17 == 0 {
				continue
			}
			if count%19 == 0 && held == nil {
				held = bytes.Clone(b[:n])
				continue
			}
			if write(b[:n]) != nil {
				return
			}
			if count%13 == 0 {
				write(b[:n])
			}
			if held != nil {
				write(held)
				held = nil
			}
		}
	}
	workers.Add(2)
	go forward(func(b []byte) (int, error) {
		n, from, e := front.ReadFrom(b)
		mu.Lock()
		client = from
		mu.Unlock()
		return n, e
	}, func(b []byte) error { _, e := back.Write(b); return e })
	go forward(back.Read, func(b []byte) error {
		mu.Lock()
		to := client
		mu.Unlock()
		if to == nil {
			return nil
		}
		_, e := front.WriteTo(b, to)
		return e
	})
	t.Cleanup(func() { front.Close(); back.Close(); workers.Wait() })
	return front.LocalAddr().String()
}
func TestMieruUDPLossAndReordering(t *testing.T) {
	s, _ := mieruPair(t, "udp", 0)
	relay := mieruLossRelay(t, s.Address("server"))
	out := testOutbound(t, Inbound{Type: "mieru"}, relay)
	out.Network = "udp"
	out.Username, out.Password = "client", "private"
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{0, 1, 4096, 14000})
	c.Close()
	if c.mieruBudget.Load() != 0 {
		t.Fatal("retained data", c.mieruBudget.Load())
	}
}

func TestMieruConfigRejectsUnsupported(t *testing.T) {
	base := map[string]any{"type": "mieru", "tag": "proxy", "server": "127.0.0.1", "server_port": 8080, "username": "client", "password": "private"}
	for field, value := range map[string]any{"network": "quic", "low_entropy": 5, "traffic_pattern": "bad", "multiplexing": "invalid", "tls": map[string]any{"enabled": true}, "mtu": 1500} {
		copy := map[string]any{}
		for k, v := range base {
			copy[k] = v
		}
		copy[field] = value
		raw, _ := json.Marshal(map[string]any{"outbounds": []any{copy}})
		if _, e := Parse(raw); e == nil {
			t.Fatal("accepted unsupported config", field)
		}
	}
}

func TestMieruCloseBeforeOrderedData(t *testing.T) {
	r := newTestRuntime(t, Config{})
	m := newMieruCarrier(r, &fragmentCapture{}, true, true, nil, MieruOptions{}, 1400)
	m.user = newMieruUser("client", "private")
	m.key = m.user.ciphers()[1]
	p := m.newFlow(1)
	for _, f := range []mieruFrame{{kind: 7, id: 1, seq: 1, body: []byte("b")}, {kind: 4, id: 1, seq: 2}, {kind: 7, id: 1, seq: 0, body: []byte("a")}} {
		if e := m.handle(f); e != nil {
			t.Fatal(e)
		}
	}
	b, e := io.ReadAll(p)
	if e != nil || string(b) != "ab" {
		t.Fatal(string(b), e)
	}
	p.Close()
	m.close()
	if r.mieruBudget.Load() != 0 {
		t.Fatal("retained ordered data")
	}
}

func TestMieruReceiveWindowReopens(t *testing.T) {
	r := newTestRuntime(t, Config{})
	m := newMieruCarrier(r, &fragmentCapture{}, true, true, nil, MieruOptions{}, 1400)
	m.user = newMieruUser("client", "private")
	m.key = m.user.ciphers()[1]
	p := m.newFlow(1)
	var want []byte
	for i := range 256 {
		body := []byte{byte(i)}
		want = append(want, body...)
		if e := m.handle(mieruFrame{kind: 7, id: 1, seq: uint32(i), body: body}); e != nil {
			t.Fatal(e)
		}
	}
	if e := m.handle(mieruFrame{kind: 4, id: 1, seq: 256}); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(p)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal("closed window lost data", len(got), e)
	}
	p.Close()
	m.close()
	if r.mieruBudget.Load() != 0 {
		t.Fatal("retained queued data")
	}
}

func TestMieruReplayCannotAllocatePeers(t *testing.T) {
	s, _ := mieruPair(t, "udp", 0)
	target, e := net.ResolveUDPAddr("udp", s.Address("server"))
	if e != nil {
		t.Fatal(e)
	}
	u := newMieruUser("client", "private")
	codec := mieruCodec{key: u.ciphers()[1], user: u}
	packet, e := codec.encode(mieruFrame{kind: 2, id: 1}, true, true)
	if e != nil {
		t.Fatal(e)
	}
	for range 12 {
		c, e := net.DialUDP("udp", nil, target)
		if e != nil {
			t.Fatal(e)
		}
		c.Write(packet)
		c.Close()
	}
	l := s.mieruListeners["server"]
	for until := time.Now().Add(time.Second); ; {
		l.mu.Lock()
		n := len(l.peers)
		l.mu.Unlock()
		if n > 1 {
			t.Fatal("replay allocated carriers", n)
		}
		if n == 1 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("first valid open not received")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	l.mu.Lock()
	n := len(l.peers)
	l.mu.Unlock()
	if n != 1 {
		t.Fatal(n)
	}
}

func TestMieruAuthenticatedRoutesAndDetour(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			in := Inbound{Type: "mieru", Tag: "server", Listen: "127.0.0.1", Network: network, Users: []User{{Name: "alice", Password: "private"}, {Name: "bob", Password: "other"}}}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "blocked"}}, Route: Route{Final: "blocked", Rules: []Rule{{AuthUser: []string{"alice"}, Outbound: "direct"}}}})
			out := testOutbound(t, Inbound{Type: "mieru"}, s.Address("server"))
			out.Network = network
			out.Username, out.Password = "alice", "private"
			out.UserHint = true
			out.Detour = "hop"
			hop := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "socks", Tag: "hop", Listen: "127.0.0.1"}}})
			detour := testOutbound(t, Inbound{Type: "socks"}, hop.Address("hop"))
			detour.Tag = "hop"
			detour.Username, detour.Password = "", ""
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out, detour}})
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 4096})
			out.Username, out.Password = "bob", "other"
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out, detour}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, e := bad.Dial(ctx, "tcp", masqueEcho(t, "tcp", "127.0.0.1:0")); e == nil {
				conn.Close()
				t.Fatal("user bypassed route policy")
			}
		})
	}
}

func FuzzMieruHeader(f *testing.F) {
	h := mieruFrame{kind: 6, id: 1}.metadata(0, 0, 0)
	f.Add(h[:])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _, _ = mieruParseHeader(b)
		_, _ = parseMieruPattern(base64.StdEncoding.EncodeToString(b), 0)
	})
}
func BenchmarkMieruPacketEncode(b *testing.B) {
	u := newMieruUser("client", "private")
	codec := mieruCodec{key: u.ciphers()[1], user: u}
	frame := mieruFrame{kind: 6, id: 1, body: make([]byte, 1240)}
	b.ReportAllocs()
	b.SetBytes(1240)
	for b.Loop() {
		if _, e := codec.encode(frame, true, false); e != nil {
			b.Fatal(e)
		}
	}
}
