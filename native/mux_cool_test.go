package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestMuxCoolIndependent(t *testing.T) {
	for _, kind := range []string{"vmess", "vless"} {
		for _, tr := range []string{"", "ws", "httpupgrade", "http", "grpc", "quic"} {
			t.Run(kind+"/"+tr, func(t *testing.T) {
				in := testInbound(t, kind)
				in.Transport = Transport{Type: tr}
				if tr == "http" || tr == "grpc" || tr == "quic" {
					in.TLS = certificate(t)
				}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := testOutbound(t, in, s.Address("server"))
				o.Transport, o.Multiplex.Enabled = in.Transport, true
				o.Multiplex.Protocol = "mux.cool"
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
				current := c.proxyMuxClients[o.Tag].current
				assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
				assertTCP(t, c)
				if c.proxyMuxClients[o.Tag].current != current {
					t.Fatal("mux session not reused")
				}
				c.resetNetworkTransports()
				assertTCP(t, c)
				if c.proxyMuxClients[o.Tag].current == current {
					t.Fatal("network reset retained mux session")
				}
			})
		}
	}
}

func TestMuxCoolConcurrentAndReject(t *testing.T) {
	for _, kind := range []string{"vmess", "vless"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "block"}}, Route: Route{Rules: []Rule{{Port: []uint16{1}, Outbound: "block"}}}})
			o := testOutbound(t, in, s.Address("server"))
			o.Multiplex.Enabled = true
			o.Multiplex.Protocol = "mux.cool"
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			bad, err := c.Dial(context.Background(), "tcp", "127.0.0.1:1")
			if err == nil {
				bad.SetDeadline(time.Now().Add(time.Second))
				if _, err = bad.Read(make([]byte, 1)); err == nil {
					t.Fatal("rejected stream worked")
				}
				bad.Close()
			}
			target := relayEchoTCP(t)
			var workers sync.WaitGroup
			for i := range 24 {
				workers.Go(func() {
					conn, err := c.Dial(context.Background(), "tcp", target)
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					payload := bytes.Repeat([]byte{byte(i)}, 70000)
					if err = writeAll(conn, payload); err == nil {
						reply := make([]byte, len(payload))
						_, err = io.ReadFull(conn, reply)
						if err == nil && !bytes.Equal(reply, payload) {
							err = fmt.Errorf("stream %d corrupted", i)
						}
					}
					if err != nil {
						t.Error(err)
					}
				})
			}
			workers.Wait()
			assertTCP(t, c)
		})
	}
}

func TestV2rayWebSocketPluginIndependent(t *testing.T) {
	for _, tls := range []bool{false, true} {
		for _, mux := range []string{"", ";mux=0", ";mux=8"} {
			t.Run(fmt.Sprint(tls, mux), func(t *testing.T) {
				in := testInbound(t, "shadowsocks")
				if tls {
					in.TLS = certificate(t)
				}
				in.SIP003Options = SIP003Options{Plugin: "v2ray-plugin", PluginOpts: "server;host=example.com;path=/plugin" + mux}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := testOutbound(t, in, s.Address("server"))
				o.Plugin, o.PluginOpts = in.Plugin, "host=example.com;path=/plugin"+mux
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 511, 4096, 60000})
			})
		}
	}
}

func TestMuxCoolWireAndIsolation(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := newMuxSession(context.Background(), a, false, true)
	defer s.close(net.ErrClosed)
	write := func(id uint16, status, flags byte, target string, data []byte) {
		t.Helper()
		m := binary.BigEndian.AppendUint16(nil, id)
		m = append(m, status, flags)
		if target != "" {
			v, err := vlessAddress(target)
			if err != nil {
				t.Fatal(err)
			}
			m = append(m, 2)
			m = append(m, v...)
		}
		frame := binary.BigEndian.AppendUint16(nil, uint16(len(m)))
		frame = append(frame, m...)
		if flags&1 != 0 {
			frame = binary.BigEndian.AppendUint16(frame, uint16(len(data)))
			frame = append(frame, data...)
		}
		b.SetWriteDeadline(time.Now().Add(time.Second))
		if err := writeAll(b, frame); err != nil {
			t.Fatal(err)
		}
	}
	write(7, 1, 1, "127.0.0.1:53", []byte("first"))
	c := <-s.accept
	write(7, 2, 1, "127.0.0.2:53", []byte("second"))
	for i, want := range []string{"first", "second"} {
		var buf [20]byte
		n, target, err := c.readTarget(buf[:])
		if err != nil || string(buf[:n]) != want || target != fmt.Sprintf("127.0.0.%d:53", i+1) {
			t.Fatal(n, target, err)
		}
	}
	write(0, 4, 1, "", []byte("discard"))
	write(7, 3, 2, "", nil)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("error END not applied")
	}
}

func FuzzMuxCoolFrame(f *testing.F) {
	f.Add([]byte{0, 4, 0, 1, 4, 0})
	f.Add([]byte{0, 4, 0, 1, 2, 1, 0, 1, 42})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = readCoolFrame(bytes.NewReader(b), make([]byte, 65535)) })
}

func TestMuxCoolHalfCloseDeadlinesAndPool(t *testing.T) {
	in := testInbound(t, "vless")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	o.Multiplex.Enabled = true
	o.Multiplex.Protocol = "mux.cool"
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer, e := listener.Accept()
		if e != nil {
			return
		}
		defer peer.Close()
		b, e := io.ReadAll(peer)
		if e == nil {
			_ = writeAll(peer, append([]byte("reply:"), b...))
		}
	}()
	conn, err := c.Dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err = writeAll(conn, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(conn)
	if err != nil || string(b) != "reply:payload" {
		t.Fatal(string(b), err)
	}
	conn.Close()
	<-done
	target := relayEchoTCP(t)
	var streams []net.Conn
	defer func() {
		for _, stream := range streams {
			stream.Close()
		}
	}()
	for range 129 {
		stream, e := c.Dial(context.Background(), "tcp", target)
		if e != nil {
			t.Fatal(e)
		}
		streams = append(streams, stream)
		stream.SetDeadline(time.Now().Add(5 * time.Second))
		if e = writeAll(stream, []byte("x")); e != nil {
			t.Fatal(e)
		}
		if _, e = io.ReadFull(stream, make([]byte, 1)); e != nil {
			t.Fatal(e)
		}
	}
	pool := c.proxyMuxClients[o.Tag]
	if len(pool.all) != 2 {
		t.Fatal("129 active streams should use two bounded sessions", len(pool.all))
	}
	stream := streams[0]
	stream.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err = stream.Read(make([]byte, 1)); !os.IsTimeout(err) {
		t.Fatal("read deadline", err)
	}
	stream.SetReadDeadline(time.Time{})
	if err = writeAll(stream, []byte("again")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(stream, make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	for _, item := range streams {
		item.Close()
	}
	streams = nil
	pool.current.mu.Lock()
	pool.current.next = 65536
	pool.current.mu.Unlock()
	assertTCP(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if peer, e := c.Dial(ctx, "tcp", target); e == nil {
		peer.Close()
		t.Fatal("canceled dial accepted")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestMuxCoolXUDPMultiTarget(t *testing.T) {
	in := testInbound(t, "vless")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := testOutbound(t, in, s.Address("server"))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	raw, err := c.dialProxyTransport(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = vlessClient(raw, o, "mux", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = raw.SetDeadline(time.Time{})
	mux := newMuxSession(c.ctx, raw, true, true)
	defer mux.close(net.ErrClosed)
	first, second := echoUDP(t), echoUDP(t)
	stream, err := mux.openCool(ctx, "udp", first)
	if err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(3 * time.Second))
	for _, target := range []string{first, second} {
		if err = mux.sendTarget(ctx, 2, stream.id, []byte(target), stream, target); err != nil {
			t.Fatal(err)
		}
		var b [100]byte
		n, from, e := stream.readTarget(b[:])
		if e != nil || from != target || string(b[:n]) != target {
			t.Fatal(n, from, e)
		}
	}
}

func TestMuxCoolRejectMalformedFrames(t *testing.T) {
	for _, frame := range [][]byte{
		{0, 3, 0, 1, 1}, {2, 1}, {0, 4, 0, 1, 0, 0}, {0, 4, 0, 1, 2, 4}, {0, 4, 0, 1, 2, 2},
		{0, 4, 0, 1, 1, 0}, {0, 8, 0, 1, 1, 0, 3, 0, 1, 1}, {0, 8, 0, 1, 1, 0, 1, 0, 1, 4},
		{0, 4, 0, 1, 2, 1, 0, 2, 1},
	} {
		if _, err := readCoolFrame(bytes.NewReader(frame), make([]byte, 65535)); err == nil {
			t.Fatalf("accepted %x", frame)
		}
	}
}
