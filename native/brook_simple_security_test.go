package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestBrookSimpleAuthentication(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, variant := range []string{"wss", "quic"} {
		for _, mode := range []string{"trusted", "mutual", "wrong-host", "untrusted", "wrong-password", "detour", "mode-mismatch"} {
			t.Run(variant+"/"+mode, func(t *testing.T) {
				in := brookSimpleInbound(t, variant)
				in.TLS = f.server()
				if mode != "mutual" {
					in.TLS.ClientAuthentication = ""
				}
				s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				o := brookOutbound(t, in, s.Address(in.Tag))
				o.TLS = f.client()
				switch mode {
				case "wrong-host":
					o.TLS.ServerName = "invalid.example"
				case "untrusted":
					o.TLS.Certificate = nil
				case "wrong-password":
					o.Password = "wrong"
				case "detour":
					o.Detour = "blocked"
				case "mode-mismatch":
					o.WithoutBrookProtocol = false
				}
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o, {Type: "block", Tag: "blocked"}}})
				if mode == "trusted" || mode == "mutual" {
					assertTCP(t, c)
					assertUDPSizes(t, c, []int{1, 511})
					return
				}
				for _, network := range []string{"tcp", "udp"} {
					ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
					defer cancel()
					conn, e := c.Dial(ctx, network, echoUDP(t))
					if e == nil {
						defer conn.Close()
						conn.SetDeadline(time.Now().Add(30 * time.Millisecond))
						_, e = conn.Write([]byte("must not forward"))
						if e == nil {
							_, e = conn.Read(make([]byte, 128))
						}
					}
					if e == nil {
						t.Fatal("authentication/transport failure bypassed proxy", network)
					}
				}
			})
		}
	}
}

func TestBrookSimpleHalfClose(t *testing.T) {
	for _, variant := range []string{"wss", "quic"} {
		t.Run(variant, func(t *testing.T) {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				conn, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				body, e := io.ReadAll(conn)
				if e == nil {
					e = writeAll(conn, body)
				}
				done <- e
			}()
			in := brookSimpleInbound(t, variant)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := brookOutbound(t, in, s.Address(in.Tag))
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			conn, e := c.Dial(context.Background(), "tcp", listener.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			want := bytes.Repeat([]byte("simple half-close"), 4000)
			if e = writeAll(conn, want); e != nil {
				t.Fatal(e)
			}
			if e = conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(conn)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal("lost half-close response", len(got), e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestBrookSimpleDatagramLifecycle(t *testing.T) {
	in := brookSimpleInbound(t, "quic")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := brookOutbound(t, in, s.Address(in.Tag))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	conn, e := c.Dial(context.Background(), "udp", echoUDP(t))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = conn.Write(make([]byte, 1155)); e == nil {
		t.Fatal("oversized simple datagram accepted")
	}
	conn.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, e = conn.Write([]byte("x")); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("expired write", e)
	}
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("1234"))
	if _, e = conn.Read(make([]byte, 1)); !errors.Is(e, io.ErrShortBuffer) {
		t.Fatal("short buffer", e)
	}
	conn.SetReadDeadline(time.Now().Add(-time.Second))
	if _, e = conn.Read(make([]byte, 4)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("expired read", e)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	conn.Write([]byte("ok"))
	b := make([]byte, 4)
	if n, e := conn.Read(b); e != nil || string(b[:n]) != "ok" {
		t.Fatal("deadline recovery", e)
	}
}

type brookWriteInterruption struct {
	memoryNetConn
	calls, failAt int
}

func (c *brookWriteInterruption) Write(b []byte) (int, error) {
	c.calls++
	if c.calls == c.failAt {
		return 0, os.ErrDeadlineExceeded
	}
	return c.memoryNetConn.Write(b[:1])
}

func TestBrookSimpleInterruptedWrite(t *testing.T) {
	for _, partial := range []bool{false, true} {
		var wire bytes.Buffer
		failAt := 1
		if partial {
			failAt = 2
		}
		raw := &brookWriteInterruption{memoryNetConn: memoryNetConn{bytes.NewReader(nil), &wire}, failAt: failAt}
		c := &brookSimplePacketConn{Conn: raw}
		if _, e := c.Write([]byte("x")); !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatal("missing write timeout", e)
		}
		_, e := c.Write([]byte("y"))
		if partial {
			if !errors.Is(e, os.ErrDeadlineExceeded) || wire.Len() != 1 {
				t.Fatal("retried partial frame", e)
			}
		} else if e != nil || !bytes.Equal(wire.Bytes(), []byte{0, 1, 'y'}) {
			t.Fatal("zero-progress timeout did not recover", e)
		}
	}
}

func TestBrookSimpleUDPRecordBound(t *testing.T) {
	for _, size := range []uint16{65506, 65535} {
		wire := binary.BigEndian.AppendUint16(nil, size)
		c := &brookSimplePacketConn{Conn: readerConn(wire)}
		if _, e := c.Read(make([]byte, 8)); e == nil {
			t.Fatal("oversize accepted")
		}
		if c.readBuffer != nil {
			t.Fatal("allocated untrusted oversized body")
		}
		if _, e := c.Read(make([]byte, 8)); e == nil {
			t.Fatal("invalid stream resumed")
		}
	}
}

func TestBrookSimpleUnauthenticatedDatagrams(t *testing.T) {
	r := newTestRuntime(t, Config{})
	in := brookSimpleInbound(t, "quic")
	flows := newUDPFlows(r)
	defer flows.Close()
	target, _ := encodeAddress(echoUDP(t))
	header := brookSimpleHeader("private", target, true)
	valid := append(append([]byte{}, header[:32]...), header[34:]...)
	wrong := append([]byte{}, valid...)
	wrong[0] ^= 1
	old := append([]byte{}, valid...)
	binary.BigEndian.PutUint32(old[32:], uint32(time.Now().Add(-time.Hour).Unix()))
	future := append([]byte{}, valid...)
	binary.BigEndian.PutUint32(future[32:], uint32(time.Now().Add(time.Hour).Unix()))
	address := append([]byte{}, valid[:36]...)
	address = append(address, 255, 0, 0, 0, 0, 0, 0)
	for _, packet := range [][]byte{nil, valid[:32], wrong, old, future, address} {
		r.brookDatagram(in, flows, packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, &net.UDPAddr{Port: 1080}, func([]byte) error { t.Error("unauthenticated packet produced a reply"); return nil })
	}
	flows.mu.Lock()
	count := len(flows.flows)
	flows.mu.Unlock()
	if count != 0 {
		t.Fatal("invalid packet allocated a UDP flow", count)
	}
}

func FuzzBrookSimple(f *testing.F) {
	target, _ := encodeAddress("a:443")
	valid := brookSimpleHeader("fuzz", target, true)
	f.Add(valid)
	f.Add(append(append([]byte{}, valid[:32]...), valid[34:]...))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65507 {
			return
		}
		network, address, e := brookReadSimpleHeader(bytes.NewReader(b), "fuzz")
		if e == nil {
			if network != "tcp" && network != "udp" {
				t.Fatal("invalid network")
			}
			if _, e = encodeAddress(address); e != nil {
				t.Fatal("invalid address", e)
			}
		}
		plain, e := brookOpenSimpleDatagram("fuzz", b)
		if e == nil && (len(plain) != len(b)-32 || brookSimpleTimestamp(plain) != nil) {
			t.Fatal("invalid authenticated datagram")
		}
	})
}
