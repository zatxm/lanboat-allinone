package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

func TestMKCPIndependent(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan", "shadowsocks", "relay"} {
		t.Run(kind, func(t *testing.T) {
			in := testInbound(t, kind)
			in.Transport = Transport{Type: "mkcp"}
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := testOutbound(t, in, s.Address("server"))
			o.Transport = in.Transport
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			if kind == "shadowsocks" {
				if conn, e := c.Dial(context.Background(), "udp", echoUDP(t)); e == nil {
					conn.Close()
					t.Fatal("SS native UDP must not bypass mKCP")
				}
			} else if kind == "vmess" {
				assertUDPSizes(t, c, []int{1, 4096})
			} else {
				assertUDP(t, c)
			}
			c.resetNetworkTransports()
			assertTCP(t, c)
		})
	}
}

func TestMKCPEnvelopes(t *testing.T) {
	for _, header := range []string{"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"} {
		for _, envelope := range []string{"legacy", "seed", "raw"} {
			t.Run(header+"/"+envelope, func(t *testing.T) {
				o := Transport{Type: "mkcp"}.mkcpOptions()
				o.Header.Type = header
				if envelope == "seed" {
					seed := "独立mKCP"
					o.Seed = &seed
				} else {
					o.PacketEncoding = envelope
				}
				c := newMKCPCodec(o)
				want := bytes.Repeat([]byte{2, 3, 5}, 330)
				wire := c.seal(want)
				got, e := newMKCPCodec(o).open(wire)
				if e != nil || !bytes.Equal(got, want) || len(wire) != len(want)+c.overhead() {
					t.Fatal("envelope roundtrip", e)
				}
				if envelope != "raw" {
					wire[len(wire)-1] ^= 1
					if _, e = c.open(wire); e == nil {
						t.Fatal("corruption accepted")
					}
				}
			})
		}
	}
}

func TestMKCPDeadlines(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	l, e := r.listenMKCP(Inbound{Transport: Transport{Type: "mkcp"}}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	host, port := splitTestAddress(t, l.Addr().String())
	c, e := r.dialMKCP(context.Background(), Outbound{Server: host, ServerPort: port, Transport: Transport{Type: "mkcp"}})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	s, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, e = c.Read(make([]byte, 1)); e == nil {
		t.Fatal("missing deadline")
	}
	c.SetReadDeadline(time.Time{})
	s.Write([]byte("ok"))
	var got [2]byte
	if _, e = io.ReadFull(c, got[:]); e != nil || string(got[:]) != "ok" {
		t.Fatal(e)
	}
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, e = c.Write([]byte("x")); e == nil {
		t.Fatal("expired write accepted")
	}
	c.SetWriteDeadline(time.Time{})
	c.Write([]byte("y"))
	s.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = s.Read(got[:1]); e != nil || got[0] != 'y' {
		t.Fatal(e)
	}
}

func FuzzMKCPPacket(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 1, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 2048 {
			return
		}
		frames, e := parseMKCP(b)
		if e != nil || len(frames) == 0 {
			return
		}
		for _, frame := range frames {
			if frame.cmd > 3 || len(frame.body) > 2048 || len(frame.acks) > 128 {
				t.Fatal("invalid parsed frame")
			}
		}
		for _, mode := range []string{"legacy", "raw"} {
			o := Transport{Type: "mkcp"}.mkcpOptions()
			o.PacketEncoding = mode
			c := newMKCPCodec(o)
			packet := c.seal(b)
			plain, e := c.open(packet)
			if len(packet) <= 2048 && (e != nil || !bytes.Equal(plain, b)) {
				t.Fatal("codec", e)
			}
		}
	})
}

func TestMKCPFrameBounds(t *testing.T) {
	b := make([]byte, 18)
	b[2] = 1
	binary.BigEndian.PutUint16(b[16:], 65535)
	if _, e := parseMKCP(b); e == nil {
		t.Fatal("oversized data accepted")
	}
	for _, bad := range [][]byte{{0, 1, 4, 0}, {0, 1, 3, 2}, []byte{0, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, e := parseMKCP(bad); e == nil {
			t.Fatal("invalid segment accepted")
		}
	}
}
