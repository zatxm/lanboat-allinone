package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func healthFrame(kind, flags byte, stream uint32, body []byte) []byte {
	b := make([]byte, 9+len(body))
	b[0], b[1], b[2], b[3], b[4] = byte(len(body)>>16), byte(len(body)>>8), byte(len(body)), kind, flags
	binary.BigEndian.PutUint32(b[5:], stream)
	copy(b[9:], body)
	return b
}

func healthReadFrame(c net.Conn) ([]byte, error) {
	var header [9]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return nil, err
	}
	n := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	b := make([]byte, 9+n)
	copy(b, header[:])
	_, err := io.ReadFull(c, b[9:])
	return b, err
}

func healthPipe(t *testing.T, transport Transport) (*httpHealthConn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	c := httpHealthConnection(a, transport).(*httpHealthConn)
	t.Cleanup(func() { c.Close(); b.Close() })
	readDone := make(chan struct{})
	go func() { io.Copy(io.Discard, c); close(readDone) }()
	t.Cleanup(func() {
		c.Close()
		select {
		case <-readDone:
		case <-time.After(time.Second):
			t.Error("health reader retained")
		}
	})
	preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	write := make(chan error, 1)
	go func() { write <- writeAll(c, preface) }()
	if _, err := io.ReadFull(b, make([]byte, len(preface))); err != nil {
		t.Fatal(err)
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
	return c, b
}

func healthSend(t *testing.T, c, peer net.Conn, frame []byte) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- writeAll(c, frame) }()
	got := make([]byte, len(frame))
	if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(frame, got) {
		t.Fatal("frame interrupted", err, got)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPKeepaliveFrames(t *testing.T) {
	for _, test := range []struct {
		name, kind     string
		permit, active bool
	}{
		{"http-idle", "http", false, false},
		{"grpc-active", "grpc", false, true},
		{"grpc-permit-idle", "grpc", true, false},
		{"grpc-suspend-idle", "grpc", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, peer := healthPipe(t, Transport{Type: test.kind, IdleTimeout: "20ms", PingTimeout: "200ms", PermitWithoutStream: test.permit})
			if test.active {
				healthSend(t, c, peer, healthFrame(1, 4, 1, []byte{0x82}))
			}
			if test.kind == "grpc" && !test.permit && !test.active {
				peer.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
				if _, err := healthReadFrame(peer); !os.IsTimeout(err) {
					t.Fatal("idle gRPC sent PING", err)
				}
				peer.SetReadDeadline(time.Time{})
				healthSend(t, c, peer, healthFrame(1, 4, 1, []byte{0x82}))
			}
			var previous []byte
			for range 3 {
				peer.SetReadDeadline(time.Now().Add(time.Second))
				ping, err := healthReadFrame(peer)
				if err != nil || len(ping) != 17 || ping[3] != 6 || ping[4] != 0 || bytes.Equal(ping, previous) {
					t.Fatal("PING", ping, err)
				}
				previous = bytes.Clone(ping)
				ping[4] = 1
				if err := writeAll(peer, ping); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHTTPKeepaliveTimeout(t *testing.T) {
	for _, mode := range []string{"missing-ack", "wrong-ack", "blocked-write"} {
		t.Run(mode, func(t *testing.T) {
			c, peer := healthPipe(t, Transport{Type: "http", IdleTimeout: "10ms", PingTimeout: "30ms"})
			if mode != "blocked-write" {
				peer.SetReadDeadline(time.Now().Add(time.Second))
				ping, err := healthReadFrame(peer)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "wrong-ack" {
					ping[4], ping[16] = 1, ping[16]^0xff
					if err := writeAll(peer, ping); err != nil {
						t.Fatal(err)
					}
				}
			}
			select {
			case <-c.done:
			case <-time.After(time.Second):
				t.Fatal("missing PING acknowledgement did not close connection")
			}
		})
	}
}

func TestHTTPKeepaliveFrameBoundaries(t *testing.T) {
	c, peer := healthPipe(t, Transport{Type: "http", IdleTimeout: "10ms", PingTimeout: "200ms"})
	frame := healthFrame(0, 0, 1, bytes.Repeat([]byte{6}, 20000))
	healthSend(t, c, peer, frame[:19])
	peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := healthReadFrame(peer); !os.IsTimeout(err) {
		t.Fatal("PING inserted inside DATA frame", err)
	}
	peer.SetReadDeadline(time.Time{})
	healthSend(t, c, peer, frame[19:])
	peer.SetReadDeadline(time.Now().Add(time.Second))
	ping, err := healthReadFrame(peer)
	if err != nil || ping[3] != 6 {
		t.Fatal("PING did not resume at frame boundary", err)
	}
}

func TestHTTPKeepaliveStreamLifetimes(t *testing.T) {
	c, peer := healthPipe(t, Transport{Type: "grpc", IdleTimeout: "200ms", PingTimeout: "200ms"})
	for _, frame := range [][]byte{healthFrame(1, 4, 1, nil), healthFrame(1, 5, 3, nil), healthFrame(0, 1, 1, nil)} {
		healthSend(t, c, peer, frame)
	}
	for _, frame := range [][]byte{healthFrame(1, 4, 1, nil), healthFrame(0, 1, 3, nil)} {
		if err := writeAll(peer, frame); err != nil {
			t.Fatal(err)
		}
	}
	// Only stream1 remains: closing a request body must not stop health checks
	// while the response body is still open.
	deadline := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		live := len(c.streams) == 1 && c.streams[1] == 3
		c.mu.Unlock()
		if live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream half-close accounting")
		}
		time.Sleep(time.Millisecond)
	}
	if err := writeAll(peer, healthFrame(3, 0, 1, make([]byte, 4))); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := healthReadFrame(peer); !os.IsTimeout(err) {
		t.Fatal("PING after last stream reset", err)
	}
}

func TestHTTPKeepaliveFinalStreamCancelsProbe(t *testing.T) {
	c, peer := healthPipe(t, Transport{Type: "grpc", IdleTimeout: "20ms", PingTimeout: "40ms"})
	healthSend(t, c, peer, healthFrame(1, 4, 1, nil))
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if ping, err := healthReadFrame(peer); err != nil || ping[3] != 6 {
		t.Fatal("missing active-stream probe", err)
	}
	if err := writeAll(peer, healthFrame(3, 0, 1, make([]byte, 4))); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err := healthReadFrame(peer); !os.IsTimeout(err) {
		t.Fatal("idle gRPC closed or pinged after final stream ended", err)
	}
	peer.SetReadDeadline(time.Time{})
	healthSend(t, c, peer, healthFrame(1, 4, 3, nil))
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if ping, err := healthReadFrame(peer); err != nil || ping[3] != 6 {
		t.Fatal("probe did not resume", err)
	}
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("resumed probe lost its timeout")
	}
}

func TestHTTPKeepaliveFinalStreamDuringBlockedProbe(t *testing.T) {
	c, peer := healthPipe(t, Transport{Type: "grpc", IdleTimeout: "20ms", PingTimeout: "100ms"})
	healthSend(t, c, peer, healthFrame(1, 4, 1, nil))
	peer.SetReadDeadline(time.Now().Add(time.Second))
	// Read the PING header, but leave its payload blocked in Write. An idle
	// pool cannot retain that partial frame indefinitely or use the socket.
	header := make([]byte, 9)
	if _, err := io.ReadFull(peer, header); err != nil || header[3] != 6 {
		t.Fatal("missing PING header", err)
	}
	if err := writeAll(peer, healthFrame(3, 0, 1, make([]byte, 4))); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("partial PING write retained connection after final stream closed")
	}
}

func TestHTTPKeepaliveConfig(t *testing.T) {
	for _, v := range []Transport{
		{Type: "ws", IdleTimeout: "1s"}, {Type: "httpupgrade", PingTimeout: "1s"},
		{Type: "grpc", IdleTimeout: "-1s"}, {Type: "http", PingTimeout: "tomorrow"},
		{Type: "http", PermitWithoutStream: true}, {IdleTimeout: "1s"},
	} {
		if v.validate() == nil {
			t.Fatal("accepted invalid keepalive", v)
		}
	}
	for _, v := range []Transport{{Type: "http", IdleTimeout: "0s", PingTimeout: "15s"}, {Type: "grpc", IdleTimeout: "30s", PermitWithoutStream: true}} {
		if err := v.validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPKeepaliveServerIdleGoAway(t *testing.T) {
	for _, idle := range []string{"0s", "60ms"} {
		t.Run(idle, func(t *testing.T) {
			in := testInbound(t, "vless")
			in.Transport = Transport{Type: "grpc", IdleTimeout: idle}
			r := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			c, err := net.Dial("tcp", r.Address("server"))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := writeAll(c, append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), healthFrame(4, 0, 0, nil)...)); err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			defer close(stop)
			go func() {
				ticker := time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-stop:
						return
					case <-ticker.C:
						if writeAll(c, healthFrame(6, 0, 0, make([]byte, 8))) != nil {
							return
						}
					}
				}
			}()
			c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			for {
				frame, err := healthReadFrame(c)
				if err != nil {
					if idle == "0s" && os.IsTimeout(err) {
						return
					}
					t.Fatal("missing GOAWAY", err)
				}
				if frame[3] == 7 {
					if idle == "0s" || len(frame) < 17 || binary.BigEndian.Uint32(frame[13:17]) != 0 {
						t.Fatal("unexpected GOAWAY", frame)
					}
					return
				}
			}
		})
	}
}

func FuzzHTTPHealthFrames(f *testing.F) {
	f.Add(healthFrame(6, 1, 0, make([]byte, 8)), uint8(1))
	f.Add(append(healthFrame(1, 4, 1, nil), healthFrame(0, 1, 1, []byte("payload"))...), uint8(11))
	f.Fuzz(func(t *testing.T, wire []byte, chunk uint8) {
		var whole, fragmented httpFrameObserver
		type frame struct {
			kind, flags byte
			id          uint32
			ping        uint64
		}
		var a, b []frame
		whole.feed(wire, func(k, f byte, id uint32, p uint64) { a = append(a, frame{k, f, id, p}) })
		n := int(chunk) + 1
		for len(wire) > 0 {
			size := min(n, len(wire))
			fragmented.feed(wire[:size], func(k, f byte, id uint32, p uint64) { b = append(b, frame{k, f, id, p}) })
			wire = wire[size:]
		}
		if len(a) != len(b) {
			t.Fatal("fragmented frame count")
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatal("fragmented frame content")
			}
		}
	})
}

func TestHTTPKeepaliveNativeAndReference(t *testing.T) {
	for _, transport := range []string{"http", "grpc", "grpc-clear", "grpc-default", "grpc-clear-default", "grpc-active-only"} {
		for _, side := range []string{"native", "client", "server"} {
			t.Run(transport+"/"+side, func(t *testing.T) {
				in := testInbound(t, "vless")
				in.Transport = Transport{Type: "http", IdleTimeout: "40ms", PingTimeout: "300ms"}
				if transport != "http" {
					in.Transport.Type = "grpc"
					if !strings.HasSuffix(transport, "-default") {
						in.Transport.ServiceName = "lanboat"
					}
					in.Transport.PermitWithoutStream = transport != "grpc-active-only"
				}
				if !strings.HasPrefix(transport, "grpc-clear") {
					in.TLS = certificate(t)
				}
				var client *Runtime
				if side == "client" {
					in.ListenPort = unusedPort(t)
					referenceRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					out.Transport = in.Transport
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address("server"))
					out.Transport = in.Transport
					if side == "native" {
						client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						out.Username, out.Password = "", ""
						local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
						referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
						front := testOutbound(t, local, portAddress(local.Listen, local.ListenPort))
						front.Username, front.Password, front.UUID = "", "", ""
						client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
					}
				}
				conn, err := client.Dial(context.Background(), "tcp", relayEchoTCP(t))
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				for range 3 {
					if err := writeAll(conn, []byte("warm")); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, 4)
					if _, err := io.ReadFull(conn, got); err != nil || string(got) != "warm" {
						t.Fatal("idle stream failed", err)
					}
					time.Sleep(100 * time.Millisecond)
				}
				conn.Close()
				// Reconnect after the server's idle GOAWAY, without disturbing the
				// preceding active stream despite its longer idle gaps.
				time.Sleep(150 * time.Millisecond)
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 4096})
			})
		}
	}
}
