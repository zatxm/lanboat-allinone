package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMKCPConfig(t *testing.T) {
	for _, bad := range []string{
		`{"type":"ws","kcp":{}}`, `{"type":"mkcp","path":"/"}`,
		`{"type":"mkcp","kcp":{"mtu":575}}`, `{"type":"mkcp","kcp":{"mtu":1461}}`,
		`{"type":"mkcp","kcp":{"tti":9}}`, `{"type":"mkcp","kcp":{"tti":101}}`,
		`{"type":"mkcp","kcp":{"read_buffer_size":4095}}`, `{"type":"mkcp","kcp":{"write_buffer_size":4194305}}`,
		`{"type":"mkcp","kcp":{"uplink_capacity":-1}}`, `{"type":"mkcp","kcp":{"downlink_capacity":1025}}`,
		`{"type":"mkcp","kcp":{"packet_encoding":"unknown"}}`, `{"type":"mkcp","kcp":{"packet_encoding":"raw","seed":"x"}}`,
		`{"type":"mkcp","kcp":{"header":{"type":"unknown"}}}`, `{"type":"mkcp","kcp":{"header":{"type":"none","domain":"a"}}}`,
		`{"type":"mkcp","kcp":{"header":{"type":"dns","domain":"a..b"}}}`,
	} {
		var tr Transport
		if e := json.Unmarshal([]byte(bad), &tr); e != nil {
			t.Fatal(e)
		}
		if e := tr.validate(); e == nil {
			t.Fatal("accepted", bad)
		}
	}
	if e := (Transport{Type: "mkcp"}).validateFor("brook"); e == nil {
		t.Fatal("accepted unsupported protocol")
	}
	seed := "a"
	o := Transport{Type: "mkcp", KCP: &MKCPOptions{Seed: &seed}}.mkcpOptions()
	packet := newMKCPCodec(o).seal(make([]byte, 16))
	seed = "b"
	if _, e := newMKCPCodec(o).open(packet); e == nil {
		t.Fatal("wrong seed accepted")
	}
}

func mkcpLossRelay(t *testing.T, target string) string {
	t.Helper()
	front, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	back, e := net.Dial("udp", target)
	if e != nil {
		front.Close()
		t.Fatal(e)
	}
	var mu sync.Mutex
	var remote net.Addr
	var workers sync.WaitGroup
	t.Cleanup(func() { front.Close(); back.Close(); workers.Wait() })
	fault := func(send func([]byte) error) func([]byte) {
		count := 0
		var held []byte
		return func(b []byte) {
			count++
			if count%13 == 0 {
				return
			}
			if count%7 == 0 && held == nil {
				held = append([]byte{}, b...)
				return
			}
			send(b)
			if held != nil {
				send(held)
				held = nil
			}
			if count%11 == 0 {
				send(b)
			}
		}
	}
	workers.Go(func() {
		send := fault(func(b []byte) error { _, e := back.Write(b); return e })
		b := make([]byte, 2048)
		for {
			n, from, e := front.ReadFrom(b)
			if e != nil {
				return
			}
			mu.Lock()
			remote = from
			mu.Unlock()
			send(b[:n])
		}
	})
	workers.Go(func() {
		send := fault(func(b []byte) error {
			mu.Lock()
			to := remote
			mu.Unlock()
			if to == nil {
				return nil
			}
			_, e := front.WriteTo(b, to)
			return e
		})
		b := make([]byte, 2048)
		for {
			n, e := back.Read(b)
			if e != nil {
				return
			}
			send(b[:n])
		}
	})
	return front.LocalAddr().String()
}

func TestMKCPLossReorderDuplicate(t *testing.T) {
	in := testInbound(t, "vless")
	seed := "loss-test"
	in.Transport = Transport{Type: "mkcp", KCP: &MKCPOptions{Seed: &seed, Congestion: true}}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, mkcpLossRelay(t, s.Address("server")))
	o.Transport = in.Transport
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	conn, e := c.Dial(context.Background(), "tcp", relayEchoTCP(t))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	want := bytes.Repeat([]byte("reliable丢包重传"), 60000)
	written := make(chan error, 1)
	go func() { written <- writeAll(conn, want) }()
	got := make([]byte, len(want))
	if _, e = io.ReadFull(conn, got); e != nil || !bytes.Equal(got, want) {
		t.Fatal("loss/reorder transfer", e)
	}
	if e = <-written; e != nil {
		t.Fatal(e)
	}
}

func TestMKCPConcurrentShutdown(t *testing.T) {
	in := testInbound(t, "vless")
	in.Transport = Transport{Type: "mkcp"}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	o.Transport = in.Transport
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	target := relayEchoTCP(t)
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Go(func() {
			conn, e := c.Dial(context.Background(), "tcp", target)
			if e != nil {
				t.Error(e)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 35000)
			if e = writeAll(conn, want); e != nil {
				t.Error(e)
				return
			}
			got := make([]byte, len(want))
			if _, e = io.ReadFull(conn, got); e != nil || !bytes.Equal(got, want) {
				t.Error("crossed stream", e)
			}
		})
	}
	workers.Wait()
	conn, e := c.Dial(context.Background(), "tcp", target)
	if e != nil {
		t.Fatal(e)
	}
	read := make(chan error, 1)
	go func() { _, e := conn.Read(make([]byte, 1)); read <- e }()
	c.Close()
	select {
	case e := <-read:
		if e == nil {
			t.Fatal("shutdown read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not unblock read")
	}
	c.mkcpMu.Lock()
	remaining := len(c.mkcpConns)
	c.mkcpMu.Unlock()
	if remaining != 0 || c.mkcpBudget.Load() != 0 {
		t.Fatal("unreleased connections or memory", remaining, c.mkcpBudget.Load())
	}
}

func TestMKCPBoundedMemory(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	o := Transport{Type: "mkcp"}.mkcpOptions()
	o.WriteBuffer = 4096
	o.ReadBuffer = 4096
	c, e := r.newMKCP(o, newMKCPCodec(o), 1, &net.UDPAddr{}, &net.UDPAddr{}, nil, func([]byte) error { return nil }, nil, "")
	if e != nil {
		t.Fatal(e)
	}
	c.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	n, e := c.Write(make([]byte, 10000))
	if n > 4096 || !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("unbounded writer", n, e)
	}
	c.mu.Lock()
	seq := c.queue[0].seq
	c.acknowledge(seq)
	if c.queue[0].data != nil {
		t.Fatal("acked data retained")
	}
	c.mu.Unlock()
	c.abort(net.ErrClosed)
	c.workers.Wait()
	if r.mkcpBudget.Load() != 0 {
		t.Fatal("memory leaked")
	}
}

func TestMKCPPeerCloseDrainsUnreadData(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	o := Transport{Type: "mkcp"}.mkcpOptions()
	c, e := r.newMKCP(o, newMKCPCodec(o), 1, &net.UDPAddr{}, &net.UDPAddr{}, nil, func([]byte) error { return nil }, nil, "")
	if e != nil {
		t.Fatal(e)
	}
	c.input([]mkcpFrame{{conv: 1, cmd: 1, flags: 1, number: 1, body: []byte("b")}})
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, e = c.Read(make([]byte, 2)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("close flag discarded missing data", e)
	}
	c.input([]mkcpFrame{{conv: 1, cmd: 1, number: 0, body: []byte("a")}})
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [2]byte
	if _, e = io.ReadFull(c, b[:]); e != nil || string(b[:]) != "ab" {
		t.Fatal("lost buffered response", e)
	}
	c.input([]mkcpFrame{{conv: 1, cmd: 2, number: 2}})
	if _, e = c.Read(b[:]); e != io.EOF {
		t.Fatal("missing EOF after drain", e)
	}
}

func TestMKCPTerminationPacing(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	var packets atomic.Int64
	o := Transport{Type: "mkcp"}.mkcpOptions()
	c, e := r.newMKCP(o, newMKCPCodec(o), 1, &net.UDPAddr{}, &net.UDPAddr{}, nil, func([]byte) error { packets.Add(1); return nil }, nil, "")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	now := time.Now()
	for range 500 {
		c.input([]mkcpFrame{{conv: 1, cmd: 2}})
		c.flush(now)
	}
	if n := packets.Load(); n > 3 {
		t.Fatal("termination packet feedback loop", n)
	}
}

func TestMKCPClosedSessionsReleaseSlots(t *testing.T) {
	in := testInbound(t, "vless")
	in.Transport = Transport{Type: "mkcp"}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	o.Transport = in.Transport
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	target := relayEchoTCP(t)
	for i := range 140 {
		conn, e := c.Dial(context.Background(), "tcp", target)
		if e != nil {
			t.Fatal(i, e)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		_, e = conn.Write([]byte{byte(i)})
		var b [1]byte
		if e == nil {
			_, e = io.ReadFull(conn, b[:])
		}
		conn.Close()
		if e != nil || b[0] != byte(i) {
			t.Fatal("closed sessions exhausted connection slots", i, e)
		}
	}
	until := time.Now().Add(time.Second)
	for {
		c.mkcpMu.Lock()
		clients := len(c.mkcpConns)
		c.mkcpMu.Unlock()
		s.mkcpMu.Lock()
		servers := len(s.mkcpConns)
		s.mkcpMu.Unlock()
		if clients+servers == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("completed close handshake retained slots", clients, servers)
		}
		time.Sleep(time.Millisecond)
	}
	if c.mkcpBudget.Load() != 0 || s.mkcpBudget.Load() != 0 {
		t.Fatal("closed sessions retained payload memory")
	}
}

func TestMKCPReceiveHeadroom(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(map[bool]string{false: "unequal-peer-mtu", true: "global-budget"}[global], func(t *testing.T) {
			r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			o := Transport{Type: "mkcp", KCP: &MKCPOptions{MTU: 576, ReadBuffer: 4096}}.mkcpOptions()
			c, e := r.newMKCP(o, newMKCPCodec(o), 1, &net.UDPAddr{}, &net.UDPAddr{}, nil, func([]byte) error { return nil }, nil, "")
			if e != nil {
				t.Fatal(e)
			}
			if global {
				r.mkcpBudget.Store(mkcpMemoryLimit - 2*(1460-18))
				defer func() { c.abort(net.ErrClosed); r.mkcpBudget.Store(0) }()
			}
			payload := bytes.Repeat([]byte("x"), 1460-18)
			c.input([]mkcpFrame{{conv: 1, cmd: 1, number: 1, body: payload}, {conv: 1, cmd: 1, number: 2, body: payload}, {conv: 1, cmd: 1, number: 0, body: payload}})
			c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
			got := make([]byte, len(payload))
			if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, payload) {
				t.Fatal("out-of-order data starved the missing first segment", e)
			}
		})
	}
}

func TestMKCPIPv6DetourAndAuthentication(t *testing.T) {
	in := testInbound(t, "vless")
	in.Listen = "::1"
	in.TLS = certificate(t)
	in.Transport = Transport{Type: "mkcp"}
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	front := testInbound(t, "socks")
	chain := newTestRuntime(t, Config{Inbounds: []Inbound{front}})
	o := testOutbound(t, in, s.Address("server"))
	o.Transport = in.Transport
	o.Detour = "chain"
	via := testOutbound(t, front, chain.Address("server"))
	via.Tag = "chain"
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o, via}})
	assertTCP(t, c)
	assertUDPAddress(t, c, []int{1, 4096}, masqueEcho(t, "udp", "[::1]:0"))
	for _, bad := range []string{"uuid", "ca", "detour"} {
		t.Run(bad, func(t *testing.T) {
			out := o
			out.Detour = ""
			var extra []Outbound
			switch bad {
			case "uuid":
				out.UUID = "00000000-0000-0000-0000-000000000001"
			case "ca":
				out.TLS.Insecure = false
			case "detour":
				out.Detour = "blocked"
				extra = []Outbound{{Type: "block", Tag: "blocked"}}
			}
			client := newTestRuntime(t, Config{Outbounds: append([]Outbound{out}, extra...)})
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			conn, e := client.Dial(ctx, "tcp", relayEchoTCP(t))
			if e == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
				_, e = conn.Write([]byte("denied"))
				if e == nil {
					_, e = conn.Read(make([]byte, 1))
				}
			}
			if e == nil {
				t.Fatal("authentication failure bypassed mKCP")
			}
		})
	}
}
