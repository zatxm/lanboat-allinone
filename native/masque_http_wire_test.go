package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestMasqueHPACK(t *testing.T) {
	// RFC7541 appendix C.4: three requests share a Huffman-coded dynamic table.
	d := masqueHPACK{limit: 4096}
	vectors := []struct {
		wire string
		want [][2]string
	}{
		{"828684418cf1e3c2e5f23a6ba0ab90f4ff", [][2]string{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}}},
		{"828684be5886a8eb10649cbf", [][2]string{{":method", "GET"}, {":scheme", "http"}, {":path", "/"}, {":authority", "www.example.com"}, {"cache-control", "no-cache"}}},
		{"828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf", [][2]string{{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"}, {":authority", "www.example.com"}, {"custom-key", "custom-value"}}},
	}
	for _, v := range vectors {
		b, _ := hex.DecodeString(v.wire)
		got, e := d.decode(b)
		if e != nil || !reflect.DeepEqual(got, v.want) {
			t.Fatal(got, e)
		}
	}
	for _, b := range [][]byte{{0x80}, {0xff}, {0x3f, 0xe2, 0x1f}, {0x82, 0x20}, {0, 0x81, 0xff, 0}, {0x40, 1, 'a', 0xff}} {
		d := masqueHPACK{limit: 4096}
		if _, e := d.decode(b); e == nil {
			t.Fatalf("accepted invalid HPACK: %x", b)
		}
	}
	d = masqueHPACK{limit: 4096}
	if _, e := d.decode([]byte{0x40, 1, 'a', 1, 'b', 0x40, 1, 'c', 1, 'd'}); e != nil {
		t.Fatal(e)
	}
	if _, e := d.decode([]byte{0x20}); e != nil || d.size != 0 || len(d.table) != 0 {
		t.Fatal("table shrink", e)
	}
	big := make([][2]string, 1025)
	for i := range big {
		big[i] = [2]string{"a", "b"}
	}
	block, _ := masqueLiteralHeaders(big)
	if _, e := d.decode(block); e == nil {
		t.Fatal("header field count unbounded")
	}
	block, _ = masqueLiteralHeaders([][2]string{{"a", strings.Repeat("x", 65536)}})
	if _, e := d.decode(block); e == nil {
		t.Fatal("header byte count unbounded")
	}
}
func TestMasqueHTTPRewrite(t *testing.T) {
	headers := [][2]string{{":method", "POST"}, {":authority", "example.com"}, {":scheme", "https"}, {":path", "/.well-known/masque/ip/*/*/"}, {masqueProtocolHeader, "connect-ip"}, {"authorization", "Basic Zm9vOmJhcg=="}}
	block, extended, e := masqueClientHeaders(headers)
	if e != nil || !extended {
		t.Fatal(e)
	}
	d := masqueHPACK{limit: 4096}
	wire, e := d.decode(block)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range wire {
		if v[0] == masqueProtocolHeader {
			t.Fatal("internal marker escaped on wire")
		}
	}
	rewritten, e := masqueRewriteHeaders(wire)
	if e != nil {
		t.Fatal(e)
	}
	got, e := d.decode(rewritten)
	if e != nil {
		t.Fatal(e)
	}
	fields := map[string]string{}
	for _, v := range got {
		fields[v[0]] = v[1]
	}
	if fields[":method"] != "POST" || fields[masqueProtocolHeader] != "connect-ip" {
		t.Fatal(fields)
	}
	spoof := [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "x"}, {":path", "/"}, {masqueProtocolHeader, "connect-ip"}}
	b, e := masqueRewriteHeaders(spoof)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := d.decode(b)
	for _, v := range f {
		if v[0] == masqueProtocolHeader {
			t.Fatal("regular header spoof")
		}
	}
	for _, v := range [][][2]string{
		{{":method", "GET"}, {":protocol", "connect-ip"}},
		{{":method", "CONNECT"}, {":protocol", ""}},
		{{"a", "b"}, {":method", "CONNECT"}},
		{{":method", "CONNECT"}, {":method", "CONNECT"}},
	} {
		if _, e := masqueRewriteHeaders(v); e == nil {
			t.Fatal("accepted invalid pseudo headers", v)
		}
	}
}
func TestMasqueHTTPContinuation(t *testing.T) {
	headers := [][2]string{{":method", "CONNECT"}, {":authority", "example.com"}, {":scheme", "http"}, {":path", "/"}, {":protocol", "connect-ip"}, {"long", strings.Repeat("x", 18000)}}
	block, e := masqueLiteralHeaders(headers)
	if e != nil {
		t.Fatal(e)
	}
	wire := masqueHeaderFrames(3, 1, block)
	c := &masqueHTTPWire{reader: bufio.NewReader(bytes.NewReader(wire)), decoder: masqueHPACK{limit: 4096}}
	first, e := c.frame()
	if e != nil {
		t.Fatal(e)
	}
	out, e := c.headers(first)
	if e != nil {
		t.Fatal(e)
	}
	if out[3] != 1 || out[4]&1 == 0 {
		t.Fatal("lost stream/flags")
	}
	var combined []byte
	for len(out) > 0 {
		n := int(out[0])<<16 | int(out[1])<<8 | int(out[2])
		combined = append(combined, out[9:9+n]...)
		out = out[9+n:]
	}
	d := masqueHPACK{limit: 4096}
	fields, e := d.decode(combined)
	if e != nil || len(fields) != 6 {
		t.Fatal(fields, e)
	}
	bad := masqueH2Frame(1, 0, 1, []byte{0x82})
	bad = append(bad, masqueH2Frame(0, 0, 1, nil)...)
	c = &masqueHTTPWire{reader: bufio.NewReader(bytes.NewReader(bad)), decoder: masqueHPACK{limit: 4096}}
	first, _ = c.frame()
	if _, e = c.headers(first); e == nil {
		t.Fatal("interleaved header accepted")
	}
	padded := masqueH2Frame(1, 8|32|4, 1, append([]byte{2, 0, 0, 0, 0, 0, 0x82}, 0, 0))
	f, e := masqueHeaderFragment(padded)
	if e != nil || !bytes.Equal(f, []byte{0x82}) {
		t.Fatal(f, e)
	}
	for _, p := range [][]byte{{}, {9}, {0, 1, 2}} {
		if _, e := masqueHeaderFragment(masqueH2Frame(1, 8|32, 1, p)); e == nil {
			t.Fatal("invalid padding/priority")
		}
	}
}
func TestMasqueHTTPSettings(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			c := newMasqueHTTP2Client(a, context.Background())
			defer c.Close()
			errors := make(chan error, 1)
			go func() {
				r := bufio.NewReader(b)
				prefix := make([]byte, 24)
				_, e := io.ReadFull(r, prefix)
				if e != nil {
					errors <- e
					return
				}
				payload := []byte{}
				if enabled {
					payload = binary.BigEndian.AppendUint16(payload, 8)
					payload = binary.BigEndian.AppendUint32(payload, 1)
				}
				if e = writeAll(b, masqueH2Frame(4, 0, 0, payload)); e != nil {
					errors <- e
					return
				}
				if enabled {
					frame := &masqueHTTPWire{reader: r}
					_, e = frame.frame()
				}
				errors <- e
			}()
			read := make(chan error, 1)
			go func() { _, e := c.Read(make([]byte, 64)); read <- e }()
			fields := [][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "x"}, {":path", "/"}, {masqueProtocolHeader, "connect-ip"}}
			block, _ := masqueLiteralHeaders(fields)
			_, e := c.Write(append([]byte(masqueH2Preface), masqueHeaderFrames(1, 0, block)...))
			if (e == nil) != enabled {
				t.Fatal(enabled, e)
			}
			if e = <-read; e != nil {
				t.Fatal(e)
			}
			if e = <-errors; e != nil {
				t.Fatal(e)
			}
		})
	}
}
func FuzzMasqueHTTPHeaders(f *testing.F) {
	for _, scheme := range []string{"http", "https"} {
		b, _ := masqueLiteralHeaders([][2]string{{":method", "CONNECT"}, {":protocol", "connect-ip"}, {":scheme", scheme}, {":authority", "vpn.test"}, {":path", "/vpn"}})
		f.Add(b)
	}
	for _, s := range []string{"828684418cf1e3c2e5f23a6ba0ab90f4ff", "82", "20", "ff", "0001610162"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 131072 {
			return
		}
		d := masqueHPACK{limit: 4096}
		fields, e := d.decode(b)
		if e != nil {
			return
		}
		_, _ = masqueRewriteHeaders(fields)
		_, _, _ = masqueClientHeaders(fields)
		_, _ = masqueLiteralHeaders(fields)
	})
}

func BenchmarkMasqueHTTP2Frames(b *testing.B) {
	for _, client := range []bool{false, true} {
		b.Run(map[bool]string{false: "server", true: "client"}[client], func(b *testing.B) {
			c := &masqueHTTPWire{Conn: memoryNetConn{bytes.NewReader(nil), io.Discard}, ctx: context.Background(), h2: true, client: client, prefaceSent: true}
			c.once.Do(func() {})
			frame := masqueH2Frame(0, 0, 1, make([]byte, 1400))
			c.Write(frame)
			b.SetBytes(1400)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, e := c.Write(frame); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
