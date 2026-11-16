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

func TestBrookQUICConfig(t *testing.T) {
	for _, fields := range []string{
		`"transport":{"type":"quic"}`,
		`"transport":{"type":"quic"},"tls":{"enabled":true,"max_version":"1.2"}`,
		`"transport":{"type":"quic"},"tls":{"enabled":true},"udp_over_tcp":true`,
		`"transport":{"type":"ws"},"udp_over_stream":true`,
		`"udp_over_stream":true`,
		`"transport":{"type":"quic","path":"/"},"tls":{"enabled":true}`,
		`"transport":{"type":"quic","max_early_data":1},"tls":{"enabled":true}`,
	} {
		if _, err := Parse([]byte(`{"outbounds":[{"type":"brook","tag":"proxy","server":"localhost","server_port":1,"password":"x",` + fields + `}]}`)); err == nil {
			t.Fatal("invalid Brook QUIC configuration accepted", fields)
		}
	}
	if _, err := Parse([]byte(`{"outbounds":[{"type":"direct","tag":"direct","udp_over_stream":true}]}`)); err == nil {
		t.Fatal("non-Brook UDP-over-stream accepted")
	}
	for _, options := range []BrookOptions{{UDPOverStream: true}, {UDPOverTCP: true}} {
		in := brookQUICInbound(t)
		in.BrookOptions = options
		if err := (Config{Inbounds: []Inbound{in}}).validate(); err == nil {
			t.Fatal("outbound-only option accepted on inbound")
		}
	}
}

func TestBrookQUICTLSAndAuthentication(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, mode := range []string{"trusted", "mutual", "wrong-host", "untrusted", "wrong-password", "detour"} {
		t.Run(mode, func(t *testing.T) {
			in := brookQUICInbound(t)
			in.TLS = f.server()
			if mode != "mutual" {
				in.TLS.ClientAuthentication = ""
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := brookOutbound(t, in, s.Address(in.Tag))
			out.TLS = f.client()
			switch mode {
			case "wrong-host":
				out.TLS.ServerName = "invalid.example"
			case "untrusted":
				out.TLS.Certificate = nil
			case "wrong-password":
				out.Password = "wrong"
			case "detour":
				out.Detour = "blocked"
			}
			config := Config{Outbounds: []Outbound{out, {Type: "block", Tag: "blocked"}}}
			c := newTestRuntime(t, config)
			if mode == "trusted" || mode == "mutual" {
				assertTCP(t, c)
				assertUDPSizes(t, c, []int{1, 511})
				return
			}
			for _, network := range []string{"tcp", "udp"} {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				conn, err := c.Dial(ctx, network, echoUDP(t))
				if err == nil {
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(30 * time.Millisecond))
					_, err = conn.Write([]byte("never forward with wrong credentials"))
					if err == nil {
						_, err = conn.Read(make([]byte, 100))
					}
				}
				if err == nil {
					t.Fatal("invalid credentials bypassed proxy", network)
				}
			}
		})
	}
}

func TestBrookQUICHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(3 * time.Second))
		body, err := io.ReadAll(raw)
		if err == nil {
			err = writeAll(raw, body)
		}
		done <- err
	}()
	in := brookQUICInbound(t)
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := brookOutbound(t, in, s.Address(in.Tag))
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	conn, err := c.Dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	want := bytes.Repeat([]byte("half-close"), 5000)
	if err = writeAll(conn, want); err != nil {
		t.Fatal(err)
	}
	if err = conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("half-close response", len(got), err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestBrookQUICWriteDeadlineUpdate(t *testing.T) {
	for _, queued := range []bool{false, true} {
		t.Run(map[bool]string{false: "queue-full", true: "pending"}[queued], func(t *testing.T) {
			// A stalled QUIC loop keeps the operation pending while the deadline changes.
			q := &quicConn{ctx: context.Background(), ops: make(chan *quicOperation, 1), done: make(chan struct{}), wake: make(chan struct{}, 1)}
			c := &brookQUICPacket{conn: q, readWake: make(chan struct{}), writeWake: make(chan struct{})}
			if !queued {
				q.ops <- newQUICOperation('d', nil)
			}
			done := make(chan error, 1)
			go func() { _, err := c.Write([]byte("pending")); done <- err }()
			var op *quicOperation
			if queued {
				op = <-q.ops
			}
			c.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
			select {
			case err := <-done:
				if !errors.Is(err, os.ErrDeadlineExceeded) || op != nil && !op.canceled.Load() {
					t.Fatal("pending write did not time out", err)
				}
			case <-time.After(time.Second):
				t.Fatal("deadline update did not interrupt write")
			}
		})
	}
}

func FuzzBrookDatagrams(f *testing.F) {
	address, _ := encodeAddress("127.0.0.1:80")
	valid := append(binary.BigEndian.AppendUint32(nil, uint32(time.Now().Unix())), address...)
	for _, plain := range [][]byte{nil, {0, 0, 0, 0}, []byte("not an address"), valid} {
		wire, err := brookSeal("fuzz", "", plain, &replayWindow{})
		if err != nil {
			f.Fatal(err)
		}
		f.Add(wire)
	}
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, packet []byte) {
		if len(packet) > 65508 {
			return
		}
		plain, err := brookOpen("fuzz", "", packet, &replayWindow{})
		if err == nil && brookTimestamp(plain) == nil {
			_, _ = readAddress(bytes.NewReader(plain[4:]))
		}
	})
}
