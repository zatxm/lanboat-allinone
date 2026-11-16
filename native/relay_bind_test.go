package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func relayBindPair(t *testing.T, transport string) (*Runtime, *Runtime) {
	t.Helper()
	in := testInbound(t, "relay")
	in.Bind = true
	in.Transport = Transport{Type: transport}
	if transport != "" {
		in.TLS = certificate(t)
	}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Transport = in.Transport
	return server, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}

func exerciseRelayTCPBind(t *testing.T, client *Runtime) {
	t.Helper()
	l, err := client.ListenRelay(context.Background(), "proxy", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var server sync.WaitGroup
	server.Go(func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			server.Go(func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); _, _ = io.Copy(c, c) })
		}
	})
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Go(func() {
			c, e := net.DialTimeout("tcp", l.Addr().String(), time.Second)
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			p := bytes.Repeat([]byte{byte(i)}, 60000+i)
			if e = writeAll(c, p); e != nil {
				t.Error(e)
				return
			}
			b := make([]byte, len(p))
			if _, e = io.ReadFull(c, b); e != nil || !bytes.Equal(b, p) {
				t.Error("remote bind stream corruption", i, e)
			}
		})
	}
	workers.Wait()
	l.Close()
	server.Wait()
}

func exerciseRelayUDPBind(t *testing.T, client *Runtime, sizes []int) {
	t.Helper()
	l, err := client.ListenRelayPacket(context.Background(), "proxy", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 65507)
		for {
			n, a, e := l.ReadFrom(buf)
			if e == nil {
				_, e = l.WriteTo(buf[:n], a)
			}
			if e != nil {
				done <- e
				return
			}
		}
	}()
	direct := newTestRuntime(t, Config{})
	assertUDPAddress(t, direct, sizes, l.LocalAddr().String())
	l.Close()
	<-done
}

func TestRelayBindIndependent(t *testing.T) {
	for _, tr := range []string{"", "ws", "httpupgrade", "http", "grpc"} {
		t.Run(tr, func(t *testing.T) {
			_, client := relayBindPair(t, tr)
			exerciseRelayTCPBind(t, client)
			exerciseRelayUDPBind(t, client, []int{0, 1, 511, 4096, 60000, 65507})
		})
	}
}

func TestRelayPacketFraming(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	reader, writer := &relayPacketConn{Conn: a}, &relayPacketConn{Conn: b}
	// A timeout without consuming a frame must permit a later read.
	a.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	if _, _, err := reader.ReadFrom(make([]byte, 1)); !os.IsTimeout(err) {
		t.Fatal(err)
	}
	a.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() {
		to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
		_, err := writer.WriteTo([]byte("truncated"), to)
		if err == nil {
			_, err = writer.WriteTo([]byte("next"), to)
		}
		done <- err
	}()
	for _, want := range []string{"tru", "next"} {
		buffer := make([]byte, len(want))
		n, peer, err := reader.ReadFrom(buffer)
		if err != nil || n != len(want) || string(buffer) != want || peer.String() != "127.0.0.1:1234" {
			t.Fatal(n, peer, err, string(buffer))
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { done <- writeAll(b, []byte{0, 1, 0}) }()
	if _, _, err := reader.ReadFrom(make([]byte, 1)); err == nil {
		t.Fatal("bad frame accepted")
	}
	<-done
	if _, err := b.Write([]byte("more")); err == nil {
		t.Fatal("malformed stream remains open")
	}
}

func TestRelayBindGOSTReference(t *testing.T) {
	for _, direction := range []string{"client", "server"} {
		t.Run(direction, func(t *testing.T) {
			if direction == "client" {
				address := portAddress("127.0.0.1", unusedPort(t))
				startGOST(t, "-L", "relay://client:private@"+address+"?bind=true&udpBufferSize=65535")
				waitPort(t, address)
				out := testOutbound(t, Inbound{Type: "relay"}, address)
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				exerciseRelayTCPBind(t, client)
				exerciseRelayUDPBind(t, client, []int{1, 511, 4096})
			} else {
				server, _ := relayBindPair(t, "")
				for _, network := range []string{"tcp", "udp"} {
					t.Run(network, func(t *testing.T) {
						bind := portAddress("127.0.0.1", unusedPort(t))
						target := echoUDP(t)
						kind := "rudp"
						if network == "tcp" {
							target = relayEchoTCP(t)
							kind = "rtcp"
						}
						startGOST(t, "-L", kind+"://"+bind+"/"+target+"?keepalive=true", "-F", "relay://client:private@"+server.Address("server"))
						if network == "tcp" {
							waitPort(t, bind)
							c, e := net.DialTimeout("tcp", bind, time.Second)
							if e != nil {
								t.Fatal(e)
							}
							defer c.Close()
							c.SetDeadline(time.Now().Add(3 * time.Second))
							p := bytes.Repeat([]byte("GOST remote bind"), 4096)
							if e = writeAll(c, p); e != nil {
								t.Fatal(e)
							}
							got := make([]byte, len(p))
							if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(p, got) {
								t.Fatal(e)
							}
						} else {
							time.Sleep(80 * time.Millisecond)
							direct := newTestRuntime(t, Config{})
							assertUDPAddress(t, direct, []int{1, 511, 4096}, bind)
						}
					})
				}
			}
		})
	}
}

func TestRelayBindDisabledAndLifecycle(t *testing.T) {
	for _, bind := range []bool{false, true} {
		t.Run(fmt.Sprint(bind), func(t *testing.T) {
			in := testInbound(t, "relay")
			in.Bind = bind
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l, e := client.ListenRelay(ctx, "proxy", "127.0.0.1:0")
			if !bind {
				if e == nil {
					l.Close()
					t.Fatal("disabled BIND accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			finished := make(chan error, 1)
			go func() { _, e := l.Accept(); finished <- e }()
			cancel()
			select {
			case e := <-finished:
				if e == nil {
					t.Fatal("cancel accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("cancel did not release Accept")
			}
		})
	}
	for _, address := range []string{"example.com:0", "[fe80::1%eth0]:1", "127.0.0.1:65536", "127.0.0.1:-1"} {
		if _, e := encodeRelayBind(address); e == nil {
			t.Fatal("invalid bind accepted", address)
		}
	}
}

func TestRelayForward(t *testing.T) {
	_, client := relayBindPair(t, "")
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			target := relayEchoTCP(t)
			if network == "udp" {
				target = echoUDP(t)
			}
			forward, err := client.ForwardRelay(context.Background(), "proxy", network, "127.0.0.1:0", target)
			if err != nil {
				t.Fatal(err)
			}
			defer forward.Close()
			if network == "udp" {
				direct := newTestRuntime(t, Config{})
				assertUDPAddress(t, direct, []int{0, 1, 511, 4096, 60000}, forward.Addr().String())
			} else {
				c, e := net.Dial("tcp", forward.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(2 * time.Second))
				p := bytes.Repeat([]byte("forward"), 10000)
				if e = writeAll(c, p); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, len(p))
				if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, p) {
					t.Fatal(e)
				}
			}
			if err = forward.Close(); err != nil {
				t.Fatal("close", err)
			}
		})
	}
}

func TestRelayBindAuthenticationAndPortConflict(t *testing.T) {
	server, client := relayBindPair(t, "")
	out := client.config.Outbounds[0]
	out.Password = "wrong"
	bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	if c, e := bad.ListenRelay(context.Background(), "proxy", "127.0.0.1:0"); e == nil {
		c.Close()
		t.Fatal("wrong password bound a port")
	}
	occupied, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer occupied.Close()
	if c, e := client.ListenRelay(context.Background(), "proxy", occupied.Addr().String()); e == nil {
		c.Close()
		t.Fatal("occupied port accepted")
	}
	if server.relayBinds.Load() != 0 {
		t.Fatal("failed bind retained capacity")
	}
	if _, e := Parse([]byte(`{"inbounds":[{"type":"relay","bind":true}]}`)); e == nil {
		t.Fatal("anonymous BIND accepted")
	}
	l, e := client.ListenRelay(context.Background(), "proxy", "[::1]:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	peer, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	accepted, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer accepted.Close()
	if accepted.RemoteAddr().String() != peer.LocalAddr().String() {
		t.Fatal("peer address lost", accepted.RemoteAddr(), peer.LocalAddr())
	}
}

type relayBindReplyBarrier struct {
	net.Conn
	entered chan struct{}
}

func (c *relayBindReplyBarrier) Write(b []byte) (int, error) {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Conn.Write(b)
}

func TestRelayBindFailureReleasesBeforeReply(t *testing.T) {
	for _, udp := range []bool{false, true} {
		t.Run(fmt.Sprint(udp), func(t *testing.T) {
			r := newTestRuntime(t, Config{})
			address := ""
			if udp {
				p, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				address = p.LocalAddr().String()
			} else {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				address = l.Addr().String()
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			right.SetDeadline(time.Now().Add(time.Second))
			barrier := &relayBindReplyBarrier{Conn: left, entered: make(chan struct{}, 1)}
			done := make(chan error, 1)
			go func() {
				done <- r.serveRelayBind(Inbound{Bind: true}, barrier, relayRequest{address: address, udp: udp})
			}()
			select {
			case <-barrier.entered:
			case <-time.After(time.Second):
				t.Fatal("failure response not reached")
			}
			if used := r.relayBinds.Load(); used != 0 {
				t.Fatalf("failed bind retained%dslots while reporting failure", used)
			}
			var reply [4]byte
			if _, err := io.ReadFull(right, reply[:]); err != nil || reply != [4]byte{1, 4, 0, 0} {
				t.Fatal(reply, err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("bind error hidden")
				}
			case <-time.After(time.Second):
				t.Fatal("failed bind handler stalled")
			}
			if used := r.relayBinds.Load(); used != 0 {
				t.Fatal("bind capacity double released", used)
			}
		})
	}
}

func TestRelayForwardUDPIsolationAndShutdown(t *testing.T) {
	server, client := relayBindPair(t, "")
	f, e := client.ForwardRelay(context.Background(), "proxy", "udp", "127.0.0.1:0", echoUDP(t))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	var workers sync.WaitGroup
	for i := range 12 {
		workers.Go(func() {
			c, e := net.Dial("udp", f.Addr().String())
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			for range 4 {
				p := bytes.Repeat([]byte{byte(i)}, 4096)
				if _, e = c.Write(p); e != nil {
					t.Error(e)
					return
				}
				got := make([]byte, len(p))
				if n, e := c.Read(got); e != nil || !bytes.Equal(got[:n], p) {
					t.Error("crossed UDP peers", i, e)
					return
				}
			}
		})
	}
	workers.Wait()
	server.Close()
	done := make(chan error, 1)
	go func() { done <- f.Wait() }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("unexpected server loss hidden")
		}
	case <-time.After(time.Second):
		t.Fatal("remote shutdown did not release forward")
	}
}

func relayEchoTCP(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			// Bulk-transfer clients allow 10-20 seconds; the echo must not close first.
			go func() { defer c.Close(); c.SetDeadline(time.Now().Add(30 * time.Second)); io.Copy(c, c) }()
		}
	}()
	return l.Addr().String()
}
