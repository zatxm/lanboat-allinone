package native

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestQUICWireKeysAndTampering(t *testing.T) {
	cid, _ := hex.DecodeString("8394c8f03e515708")
	r, w, e := quicInitialKeys(cid, false)
	if e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(w.iv[:]) != "fa044b2f42a3fd3b46fb255c" || hex.EncodeToString(r.iv[:]) != "0ac1493ca1905853b0bba03e" {
		t.Fatal("RFC9001 initial IV mismatch")
	}
	peerCID := []byte("abcdefgh")
	packet := sealQUICPacket([]byte{6, 0, 3, 1, 2, 3}, cid, peerCID, nil, 0, 23, false, w)
	h, e := parseQUICHeader(packet)
	if e != nil {
		t.Fatal(e)
	}
	plain, pn, _, e := openQUICPacket(packet, h, w, -1)
	if e != nil || pn != 23 || !bytes.Equal(plain[:6], []byte{6, 0, 3, 1, 2, 3}) {
		t.Fatal(pn, e)
	}
	for _, i := range []int{0, len(packet) - 1, len(packet) / 2} {
		bad := bytes.Clone(packet)
		bad[i] ^= 4
		if _, _, _, e := openQUICPacket(bad, h, w, -1); e == nil {
			t.Fatal("accepted modified QUIC packet")
		}
	}
}
func TestQPACKCodec(t *testing.T) {
	b, _ := hex.DecodeString("f1e3c2e5f23a6ba0ab90f4ff")
	v, e := h3Huffman(b)
	if e != nil || v != "www.example.com" {
		t.Fatal(v, e)
	}
	for _, raw := range []string{"ffffffff", "00", "ff"} {
		b, _ := hex.DecodeString(raw)
		if _, e = h3Huffman(b); e == nil {
			t.Fatal("invalid Huffman padding accepted")
		}
	}
	want := [][2]string{{":method", "POST"}, {":path", "/auth"}, {"hysteria-auth", "password"}}
	h, e := h3Decode(h3Encode(want))
	if e != nil || h["hysteria-auth"] != "password" {
		t.Fatal(h, e)
	}
	if _, e = h3Decode([]byte{1, 0, 0x80}); e == nil {
		t.Fatal("unnegotiated dynamic QPACK accepted")
	}
}

type quicLossConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *quicLossConn) Write(b []byte) (int, error) {
	if c.writes.Add(1)%17 == 0 {
		return len(b), nil
	}
	return c.Conn.Write(b)
}
func TestQUICLossRecoveryAndReadDeadline(t *testing.T) {
	l := testQUICListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	raw, e := net.Dial("udp", l.packet.LocalAddr().String())
	if e != nil {
		t.Fatal(e)
	}
	cert := certificate(t)
	cert.Insecure = true
	cert.Certificate = nil
	cert.Key = nil
	cert.ALPN = []string{"lanboat-quic-test"}
	cfg, e := cert.config(false, "example.com")
	if e != nil {
		t.Fatal(e)
	}
	client, e := dialQUIC(ctx, context.Background(), &quicLossConn{Conn: raw}, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server, e := l.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		s, e := server.AcceptStream(ctx)
		if e == nil {
			defer s.Close()
			io.Copy(s, s)
			s.CloseWrite()
		}
	}()
	s, e := client.OpenStream(ctx, false)
	if e != nil {
		t.Fatal(e)
	}
	s.SetDeadline(time.Now().Add(12 * time.Second))
	want := bytes.Repeat([]byte("loss recovery"), 100000)
	written := make(chan error, 1)
	go func() {
		e := writeAll(s, want)
		if e == nil {
			e = s.CloseWrite()
		}
		written <- e
	}()
	got, e := io.ReadAll(s)
	if e != nil || !bytes.Equal(got, want) {
		t.Fatal(len(got), e)
	}
	if e = <-written; e != nil {
		t.Fatal(e)
	}
	s.Close()
	idle, e := client.OpenStream(ctx, false)
	if e != nil {
		t.Fatal(e)
	}
	defer idle.Close()
	idle.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e = idle.Read(make([]byte, 1)); e == nil {
		t.Fatal("missing deadline")
	}
}
func TestQUICProxyRejectsWrongPassword(t *testing.T) {
	for _, kind := range []string{"hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "correct"}}}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			out := testOutbound(t, in, server.Address("server"))
			out.Password = "wrong"
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, e := client.Dial(ctx, "tcp", "127.0.0.1:9")
			if e != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte("unauthorized"))
			if n, _ := c.Read(make([]byte, 1)); n > 0 {
				t.Fatal("unauthorized traffic accepted")
			}
		})
	}
}
func FuzzQUICWire(f *testing.F) {
	for _, b := range [][]byte{{}, {0xc0, 0, 0, 0, 1, 8}, {0x40}, {1, 0, 0xc0}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		parseQUICHeader(b)
		h3Decode(b)
		h3Huffman(b)
		s := newQUICProxySession(&quicConn{}, "hysteria2")
		s.decodePacket(b)
		s.kind = "tuic"
		s.decodePacket(b)
	})
}

func TestQUICCanceledOpenAndResetBeforeData(t *testing.T) {
	l := testQUICListener(t)
	client := testQUICDial(t, l.packet.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	server, e := l.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		for {
			s, e := server.AcceptStream(ctx)
			if e != nil {
				return
			}
			go func() { defer s.Close(); io.Copy(s, s); s.CloseWrite() }()
		}
	}()
	for range 600 {
		short, stop := context.WithTimeout(ctx, time.Microsecond)
		s, e := client.OpenStream(short, false)
		stop()
		if e == nil {
			s.Close()
		}
	}
	s, e := client.OpenStream(ctx, false)
	if e != nil {
		t.Fatal("canceled opens exhausted stream capacity", e)
	}
	defer s.Close()
	s.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = s.Write([]byte("still usable")); e != nil {
		t.Fatal(e)
	}
	s.CloseWrite()
	got, e := io.ReadAll(s)
	if e != nil || string(got) != "still usable" {
		t.Fatal(string(got), e)
	}
}
