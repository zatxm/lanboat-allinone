package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

type visionPartialConn struct {
	*bytes.Reader
	fragment, failAt, received int
	failed, positive           bool
	closed                     bool
}

func (c *visionPartialConn) Read(b []byte) (int, error) {
	if c.failAt > 0 && c.received == c.failAt && !c.failed {
		c.failed = true
		return 0, os.ErrDeadlineExceeded
	}
	limit := min(len(b), c.fragment)
	if c.failAt > c.received && !c.failed {
		limit = min(limit, c.failAt-c.received)
	}
	n, e := c.Reader.Read(b[:limit])
	c.received += n
	if c.positive && c.received == c.failAt && !c.failed {
		c.failed = true
		return n, os.ErrDeadlineExceeded
	}
	return n, e
}
func (c *visionPartialConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *visionPartialConn) Close() error                     { c.closed = true; return nil }
func (c *visionPartialConn) LocalAddr() net.Addr              { return nil }
func (c *visionPartialConn) RemoteAddr() net.Addr             { return nil }
func (c *visionPartialConn) SetDeadline(time.Time) error      { return nil }
func (c *visionPartialConn) SetReadDeadline(time.Time) error  { return nil }
func (c *visionPartialConn) SetWriteDeadline(time.Time) error { return nil }
func visionTestFrame(id [16]byte, command byte, body []byte, padding int) []byte {
	b := append([]byte(nil), id[:]...)
	b = append(b, command)
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	b = binary.BigEndian.AppendUint16(b, uint16(padding))
	b = append(b, body...)
	return append(b, make([]byte, padding)...)
}
func TestVisionSplitFramesAndTimeoutRecovery(t *testing.T) {
	id, _ := parseUUID(testUUID)
	wire := visionTestFrame(id, 1, []byte("body"), 300)
	wire = append(wire, []byte("tail")...)
	for fragment := 1; fragment <= 23; fragment++ {
		for _, failAt := range []int{0, 5, 16, 20, 21, 23, 30} {
			for _, positive := range []bool{false, true} {
				input := &visionPartialConn{Reader: bytes.NewReader(wire), fragment: fragment, failAt: failAt, positive: positive}
				c := &visionConn{Conn: input, raw: &visionRecordConn{Conn: input}, id: id, firstRead: true}
				var got []byte
				var b [3]byte
				for range 500 {
					n, e := c.Read(b[:])
					got = append(got, b[:n]...)
					if errors.Is(e, os.ErrDeadlineExceeded) {
						continue
					}
					if e != nil {
						if e != io.EOF {
							t.Fatal(fragment, failAt, positive, e)
						}
						break
					}
				}
				if string(got) != "bodytail" {
					t.Fatal(fragment, failAt, positive, string(got))
				}
			}
		}
	}
}
func TestVisionMalformedFrames(t *testing.T) {
	id, _ := parseUUID(testUUID)
	for _, kind := range []string{"uuid", "command", "direct", "empty"} {
		t.Run(kind, func(t *testing.T) {
			body := visionTestFrame(id, 1, []byte("data"), 0)
			switch kind {
			case "uuid":
				body[0] ^= 1
			case "command":
				body[16] = 3
			case "direct":
				body[16] = 2
			case "empty":
				body = visionTestFrame(id, 0, nil, 0)
				body = append(body, bytes.Repeat([]byte{0, 0, 0, 0, 0}, 65)...)
			}
			input := &visionPartialConn{Reader: bytes.NewReader(body), fragment: 2}
			c := &visionConn{Conn: input, raw: &visionRecordConn{Conn: input}, id: id, firstRead: true}
			if _, e := io.ReadAll(c); e == nil || !input.closed {
				t.Fatal("malformed Vision accepted", e)
			}
		})
	}
}
func TestVisionRecordBoundary(t *testing.T) {
	first := []byte{23, 3, 3, 0, 3, 1, 2, 3}
	second := []byte{23, 3, 3, 0, 2, 4, 5}
	wire := append(bytes.Clone(first), second...)
	for size := 1; size < 24; size++ {
		input := readerConn(wire)
		c := &visionRecordConn{Conn: input}
		var got []byte
		b := make([]byte, size)
		for len(got) < len(first) {
			n, e := c.Read(b)
			if e != nil {
				t.Fatal(e)
			}
			got = append(got, b[:n]...)
			if len(got) > len(first) {
				t.Fatal("TLS record boundary crossed")
			}
		}
		if c.position != 0 || c.remaining != 0 || !bytes.Equal(got, first) {
			t.Fatal("record state")
		}
		c.direct.Store(true)
		rest, e := io.ReadAll(c)
		if e != nil || !bytes.Equal(rest, second) {
			t.Fatal(rest, e)
		}
	}
}
func TestVisionFlowAddons(t *testing.T) {
	valid := append([]byte{10, byte(len(visionFlow))}, visionFlow...)
	got, e := readVLESSFlow(bytes.NewReader(valid), byte(len(valid)))
	if e != nil || got != visionFlow {
		t.Fatal(got, e)
	}
	for _, bad := range [][]byte{{10, 255}, {0}, {8, 1}, {10, 1, 'x'}, append(bytes.Clone(valid), valid...)} {
		if _, e := readVLESSFlow(bytes.NewReader(bad), byte(len(bad))); e == nil {
			t.Fatal("invalid addon accepted", bad)
		}
	}
	unknown := append(bytes.Clone(valid), 0x19, 0, 0, 0, 0, 0, 0, 0, 0)
	if _, e := readVLESSFlow(bytes.NewReader(unknown), byte(len(unknown))); e != nil {
		t.Fatal(e)
	}
}
func TestVisionTLSFeatures(t *testing.T) {
	f := newMutualTLSFixture(t)
	for _, feature := range []string{"mtls", "pins", "ech", "fragment", "records", "combined"} {
		t.Run(feature, func(t *testing.T) {
			in := testInbound(t, "vless")
			in.Users[0].Flow = visionFlow
			in.TLS = f.server()
			outTLS := f.client()
			switch feature {
			case "pins":
				outTLS.Certificate = nil
				outTLS.CertificateSHA256 = []string{tlsPinFor(t, f.serverCert, false)}
			case "ech":
				config, key := testECHPair(t)
				in.TLS = testECHServer(t, f, key)
				outTLS = testECHClient(f, config)
			case "fragment":
				outTLS.Fragment = true
				outTLS.FragmentFallbackDelay = "1ms"
			case "records":
				outTLS.RecordFragment = true
			case "combined":
				outTLS.RecordFragment = true
				outTLS.Fragment = true
				outTLS.FragmentFallbackDelay = "1ms"
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address("server"))
			out.Flow = visionFlow
			out.TLS = outTLS
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			visionHTTPS(t, c, tls.VersionTLS13, true)
			assertUDPSizes(t, c, []int{1, 4096})
		})
	}
}
func TestVisionAccountPolicy(t *testing.T) {
	for _, kind := range []string{"missing-flow", "unexpected-flow", "wrong-uuid", "old-tls", "mux-tcp"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, "vless")
			in.TLS = certificate(t)
			in.Users[0].Flow = visionFlow
			if kind == "unexpected-flow" {
				in.Users[0].Flow = ""
			}
			if kind == "old-tls" {
				in.TLS.MaxVersion = "1.2"
				in.Users[0].Flow = ""
			}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, s.Address("server"))
			out.Flow = visionFlow
			if kind == "missing-flow" {
				out.Flow = ""
			}
			if kind == "wrong-uuid" {
				out.UUID = "3b2d59c9-a4e1-4efa-a694-12b6f063093c"
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			origin := masqueEcho(t, "tcp", "127.0.0.1:0")
			if kind == "mux-tcp" {
				conn, e := c.proxyMuxClients["proxy"].dial(ctx, "tcp", origin)
				if e != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				conn.Write([]byte("x"))
				if _, e = conn.Read(make([]byte, 1)); e == nil {
					t.Fatal("Vision allowed TCP multiplex")
				}
				return
			}
			conn, e := c.Dial(ctx, "tcp", origin)
			if e != nil {
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			conn.Write([]byte("x"))
			if _, e = conn.Read(make([]byte, 1)); e == nil {
				t.Fatal("Vision policy bypassed")
			}
		})
	}
}
func TestVisionConfig(t *testing.T) {
	for _, change := range []func(*Outbound){func(o *Outbound) { o.Flow = "unknown" }, func(o *Outbound) { o.Type = "vmess" }, func(o *Outbound) { o.TLS.Enabled = false }, func(o *Outbound) { o.TLS.MaxVersion = "1.2" }, func(o *Outbound) { o.Transport = Transport{Type: "ws"} }, func(o *Outbound) { o.Multiplex.Enabled = true }} {
		out := Outbound{Type: "vless", Tag: "proxy", Server: "127.0.0.1", ServerPort: 443, UUID: testUUID, Flow: visionFlow, TLS: TLSOptions{Enabled: true}}
		change(&out)
		raw, _ := json.Marshal(Config{Outbounds: []Outbound{out}})
		if _, e := Parse(raw); e == nil {
			t.Fatal("invalid Vision config accepted", out)
		}
	}
	in := testInbound(t, "vless")
	in.TLS = certificate(t)
	in.Users[0].Flow = visionFlow
	in.Users = append(in.Users, User{UUID: testUUID})
	raw, _ := json.Marshal(Config{Inbounds: []Inbound{in}})
	if _, e := Parse(raw); e == nil {
		t.Fatal("ambiguous account policy accepted")
	}
}
func TestVisionRuntimeClose(t *testing.T) {
	_, c := visionPair(t)
	conn, e := c.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "127.0.0.1:0"))
	if e != nil {
		t.Fatal(e)
	}
	var returned atomic.Bool
	done := make(chan struct{})
	go func() { conn.Read(make([]byte, 1)); returned.Store(true); close(done) }()
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("active Vision read survived runtime close")
	}
	conn.Close()
	if !returned.Load() {
		t.Fatal("read not released")
	}
}

func TestVisionResponseDeadlineRecovery(t *testing.T) {
	_, c := visionPair(t)
	conn, e := c.Dial(context.Background(), "tcp", masqueEcho(t, "tcp", "127.0.0.1:0"))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(-time.Second))
	if _, e = conn.Read(make([]byte, 1)); !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatal("expired read", e)
	}
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, e = conn.Write([]byte("retry")); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 5)
	if _, e = io.ReadFull(conn, got); e != nil || string(got) != "retry" {
		t.Fatal("response header did not resume", string(got), e)
	}
}

func TestVLESSResponseHeaderTimeoutRecovery(t *testing.T) {
	wire := []byte{0, 3, 10, 1, 0, 'o', 'k'}
	for position := 1; position <= 5; position++ {
		for _, positive := range []bool{false, true} {
			input := &visionPartialConn{Reader: bytes.NewReader(wire), fragment: 1, failAt: position, positive: positive}
			c := &vlessConn{Conn: input}
			var got []byte
			var b [2]byte
			for range 20 {
				n, e := c.Read(b[:])
				got = append(got, b[:n]...)
				if errors.Is(e, os.ErrDeadlineExceeded) {
					continue
				}
				if e != nil {
					if e != io.EOF {
						t.Fatal(e)
					}
					break
				}
			}
			if string(got) != "ok" {
				t.Fatal(position, positive, string(got))
			}
		}
	}
}

func TestVisionAuthenticatedRoute(t *testing.T) {
	in := testInbound(t, "vless")
	in.TLS = certificate(t)
	in.Users[0].Flow = visionFlow
	in.Users[0].Name = "alice"
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{AuthUser: []string{"alice"}, Outbound: "direct"}}}})
	out := testOutbound(t, in, s.Address("server"))
	out.Flow = visionFlow
	c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	visionHTTPS(t, c, tls.VersionTLS13, true)
	assertUDPSizes(t, c, []int{1, 4096})
}

func TestVisionMixedAccountsAndXUDP(t *testing.T) {
	in := testInbound(t, "vless")
	in.TLS = certificate(t)
	in.Users[0].Flow = visionFlow
	const plainID = "4b2d59c9-a4e1-4efa-a694-12b6f063093c"
	in.Users = append(in.Users, User{UUID: plainID})
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	for _, mode := range []string{"vision", "plain", "plain-xudp"} {
		t.Run(mode, func(t *testing.T) {
			out := testOutbound(t, in, s.Address("server"))
			switch mode {
			case "vision":
				out.Flow = visionFlow
			case "plain":
				out.UUID = plainID
			case "plain-xudp":
				out.Multiplex.Enabled = true
				out.Multiplex.Protocol = "mux.cool"
			}
			c := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			if mode != "plain-xudp" {
				assertTCP(t, c)
			}
			assertUDPSizes(t, c, []int{1, 4096})
			if mode == "vision" {
				for _, address := range []string{"127.0.0.1:443", "127.0.0.1:0443"} {
					if conn, e := c.Dial(context.Background(), "udp", address); e == nil {
						conn.Close()
						t.Fatal("UDP443 policy bypassed", address)
					}
				}
			}
		})
	}
}

func TestVisionHalfClose(t *testing.T) {
	_, c := visionPair(t)
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "tls13"}[secure], func(t *testing.T) {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			cfg, e := certificate(t).config(true, "")
			if e != nil {
				t.Fatal(e)
			}
			cfg.MinVersion = tls.VersionTLS13
			done := make(chan error, 1)
			go func() {
				raw, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer raw.Close()
				var peer net.Conn = raw
				if secure {
					peer = tls.Server(raw, cfg)
				}
				peer.SetDeadline(time.Now().Add(3 * time.Second))
				body, e := io.ReadAll(peer)
				if e == nil && string(body) != "request" {
					e = errors.New("half-close request mismatch")
				}
				if e == nil {
					_, e = peer.Write([]byte("response"))
				}
				if secure {
					peer.(*tls.Conn).CloseWrite()
				} else {
					raw.(*net.TCPConn).CloseWrite()
				}
				done <- e
			}()
			conn, e := c.Dial(context.Background(), "tcp", listener.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			var peer net.Conn = conn
			if secure {
				peer = tls.Client(conn, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, InsecureSkipVerify: true})
			}
			if _, e = peer.Write([]byte("request")); e != nil {
				t.Fatal(e)
			}
			if e = peer.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			body, e := io.ReadAll(peer)
			if e != nil || string(body) != "response" {
				t.Fatal(string(body), e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func FuzzVisionWire(f *testing.F) {
	id, _ := parseUUID(testUUID)
	f.Add(visionTestFrame(id, 1, []byte("hello"), 4))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var probe visionProbe
		var state visionState
		probe.observe(b, &state)
		_ = visionServerHello(b)
		if len(b) <= 255 {
			_, _ = readVLESSFlow(bytes.NewReader(b), byte(len(b)))
		}
		conn := readerConn(b)
		c := &visionConn{Conn: conn, raw: &visionRecordConn{Conn: conn}, id: id, firstRead: true}
		var buf [256]byte
		for range 256 {
			if _, e := c.Read(buf[:]); e != nil {
				break
			}
		}
	})
}
func BenchmarkVisionDirectWrite(b *testing.B) {
	c := &visionConn{raw: &visionRecordConn{Conn: memoryNetConn{bytes.NewReader(nil), io.Discard}}}
	c.writeDirect.Store(true)
	data := make([]byte, 1400)
	b.SetBytes(1400)
	b.ReportAllocs()
	for b.Loop() {
		if _, e := c.Write(data); e != nil {
			b.Fatal(e)
		}
	}
}
