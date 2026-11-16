package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func sniffTestHello(t *testing.T) []byte {
	t.Helper()
	h, err := newSTHello(&tls.Config{ServerName: "fragment.test"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := h.marshal("", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func sniffTestQUIC(t *testing.T, dcid []byte, pn, offset uint64, data []byte, before ...byte) []byte {
	t.Helper()
	_, key, err := quicInitialKeys(dcid, false)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), before...)
	frame = quicVar(append(frame, 6), offset)
	frame = append(quicVar(frame, uint64(len(data))), data...)
	return sealQUICPacket(frame, dcid, dcid, nil, 0, pn, false, key)
}
func TestSniffTLSReassembly(t *testing.T) {
	hello := sniffTestHello(t)
	for _, cut := range []int{1, 2, 3, 4, 39, len(hello) - 1} {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			wire := append(shadowFrame(22, hello[:cut]), shadowFrame(22, hello[cut:])...)
			for n := 1; n < len(wire); n++ {
				if !sniffNeedsMore("tcp", wire[:n], []string{"tls"}) {
					t.Fatal("premature decision", n)
				}
			}
			p, host := sniffPacket("tcp", wire, nil)
			if p != "tls" || host != "fragment.test" || sniffNeedsMore("tcp", wire, nil) {
				t.Fatal(p, host)
			}
		})
	}
	for _, b := range [][]byte{{22, 2}, {22, 3, 3, 0, 0}, shadowFrame(22, []byte{1, 255, 255, 255}), shadowFrame(23, hello)} {
		if sniffNeedsMore("tcp", b, []string{"tls"}) {
			t.Fatal("invalid record retained", b[:min(len(b), 9)])
		}
	}
	if sniffNeedsMore("tcp", shadowFrame(22, hello)[:10], []string{"http"}) {
		t.Fatal("disabled TLS waited")
	}
}
func TestSniffQUICReassembly(t *testing.T) {
	hello := sniffTestHello(t)
	id := []byte("12345678")
	cut := len(hello) / 2
	a := sniffTestQUIC(t, id, 0, 0, hello[:cut], 2, 0, 0, 0, 0)
	b := sniffTestQUIC(t, id, 1, uint64(cut), hello[cut:], 3, 0, 0, 0, 0, 0, 0, 0)
	for _, wire := range [][]byte{append(bytes.Clone(a), b...), append(bytes.Clone(b), a...), append(append(bytes.Clone(a), a...), b...)} {
		p, host := sniffPacket("udp", wire, nil)
		if p != "quic" || host != "fragment.test" || sniffNeedsMore("udp", wire, nil) {
			t.Fatal(p, host)
		}
	}
	if !sniffNeedsMore("udp", a, nil) || !sniffNeedsMore("udp", b, nil) {
		t.Fatal("fragment was not retained")
	}
	conflicting := sniffTestQUIC(t, id, 2, 0, bytes.Repeat([]byte{9}, cut))
	mixed := sniffTestQUIC(t, []byte("87654321"), 1, uint64(cut), hello[cut:])
	huge := sniffTestQUIC(t, id, 2, sniffLimit, []byte{1})
	badACK := sniffTestQUIC(t, id, 3, uint64(cut), hello[cut:], 2, 0, 0, 1, 0, 0, 0)
	tampered := bytes.Clone(b)
	tampered[len(tampered)-1] ^= 1
	for _, tail := range [][]byte{conflicting, mixed, huge, badACK, tampered} {
		wire := append(bytes.Clone(a), tail...)
		if _, ok, more := sniffQUICData(wire); ok || more {
			t.Fatal("invalid Initial accepted")
		}
	}
}

type sniffSplitConn struct{ net.Conn }

func (c sniffSplitConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n := min(17, len(b))
		written, err := c.Conn.Write(b[:n])
		total += written
		if err != nil {
			return total, err
		}
		if written != n {
			return total, io.ErrShortWrite
		}
		b = b[n:]
	}
	return total, nil
}
func TestSniffFragmentedTLSConnection(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "fragmented TLS routed") }))
	defer target.Close()
	host, port := splitTestAddress(t, target.Listener.Addr().String())
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "sniff", Sniffer: []string{"tls"}}, {Domain: []string{"fragment.test"}, Action: "route-options", OverrideAddress: host, OverridePort: port}, {Domain: []string{"fragment.test"}, Outbound: "direct"}, {Action: "reject"}}}})
	raw, err := r.Dial(context.Background(), "tcp", "192.0.2.9:443")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	c := tls.Client(sniffSplitConn{raw}, &tls.Config{ServerName: "fragment.test", InsecureSkipVerify: true})
	if err = c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(c, "GET / HTTP/1.1\r\nHost: fragment.test\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(c)
	if err != nil || !bytes.Contains(data, []byte("fragmented TLS routed")) {
		t.Fatal(err, string(data))
	}
}
func TestSniffFragmentedUDPRoute(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := packet.ReadFrom(b)
			if e != nil {
				return
			}
			packet.WriteTo(b[:n], a)
		}
	}()
	defer func() { packet.Close(); <-done }()
	host, port := splitTestAddress(t, packet.LocalAddr().String())
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "sniff", Sniffer: []string{"quic"}}, {Domain: []string{"fragment.test"}, Action: "route-options", OverrideAddress: host, OverridePort: port}, {Domain: []string{"fragment.test"}, Outbound: "direct"}, {Action: "reject"}}}})
	c, err := r.Dial(context.Background(), "udp", "192.0.2.9:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	hello := sniffTestHello(t)
	cut := len(hello) / 2
	id := []byte("12345678")
	packets := [][]byte{sniffTestQUIC(t, id, 1, uint64(cut), hello[cut:]), sniffTestQUIC(t, id, 1, uint64(cut), hello[cut:]), sniffTestQUIC(t, id, 0, 0, hello[:cut])}
	for _, b := range packets {
		if n, e := c.Write(b); e != nil || n != len(b) {
			t.Fatal(n, e)
		}
	}
	for _, want := range packets {
		got := make([]byte, 65535)
		n, e := c.Read(got)
		if e != nil || !bytes.Equal(got[:n], want) {
			t.Fatal("datagram boundaries changed", n, e)
		}
	}
}
func TestSniffPendingLifecycle(t *testing.T) {
	for _, mode := range []string{"timeout", "close-write", "large-write", "closed", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			echo := tcpEcho(t)
			r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "sniff", Timeout: "20ms"}}}})
			c, err := r.Dial(context.Background(), "tcp", echo)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			first := []byte("GET / ")
			if n, e := c.Write(first); e != nil || n != len(first) {
				t.Fatal(n, e)
			}
			switch mode {
			case "closed":
				c.Close()
				if _, e := c.Write(first); e == nil {
					t.Fatal("write after close")
				}
				return
			case "deadline":
				c.SetWriteDeadline(time.Now().Add(-time.Second))
				if _, e := c.Write(first); !os.IsTimeout(e) {
					t.Fatal(e)
				}
				return
			case "close-write":
				if e := c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
					t.Fatal(e)
				}
			case "large-write":
				rest := bytes.Repeat([]byte{'x'}, sniffLimit)
				if _, e := c.Write(rest); e != nil {
					t.Fatal(e)
				}
				first = append(first, rest...)
			}
			got := make([]byte, len(first))
			if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, first) {
				t.Fatal(e, len(got))
			}
		})
	}
}
func TestSniffFragmentedHTTPRoute(t *testing.T) {
	echo := tcpEcho(t)
	host, port := splitTestAddress(t, echo)
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "sniff", Sniffer: []string{"http"}}, {Domain: []string{"fragment.test"}, Action: "route-options", OverrideAddress: host, OverridePort: port}, {Domain: []string{"fragment.test"}, Outbound: "direct"}, {Action: "reject"}}}})
	c, e := r.Dial(context.Background(), "tcp", "192.0.2.9:80")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	parts := []string{"G", "ET / HTTP/1.1\r\nHo", "st: fragment.", "test\r\n\r\n"}
	var want []byte
	for _, p := range parts {
		if _, e = c.Write([]byte(p)); e != nil {
			t.Fatal(e)
		}
		want = append(want, p...)
	}
	got := make([]byte, len(want))
	if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, want) {
		t.Fatal(e)
	}
}
func FuzzSniffReassembly(f *testing.F) {
	h, err := newSTHello(&tls.Config{ServerName: "fuzz.test"})
	if err != nil {
		f.Fatal(err)
	}
	hello, err := h.marshal("", nil, false)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(shadowFrame(22, hello))
	id := []byte("12345678")
	_, key, err := quicInitialKeys(id, false)
	if err != nil {
		f.Fatal(err)
	}
	payload := append(quicVar([]byte{6, 0}, uint64(len(hello))), hello...)
	f.Add(sealQUICPacket(payload, id, id, nil, 0, 0, false, key))
	v2, err := os.ReadFile("testdata/quic-v2-client-initial.bin")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(v2)
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > sniffLimit {
			return
		}
		clientHelloSNI(b)
		r := quicReader(b)
		sniffQUICACK(&r, false)
		sniffTLS(b)
		sniffQUICData(b)
		sniffNeedsMore("tcp", b, nil)
		sniffNeedsMore("udp", b, nil)
		sniffPacket("tcp", b, nil)
		sniffPacket("udp", b, nil)
	})
}
func BenchmarkSniffCompleteTLS(b *testing.B) {
	h, _ := newSTHello(&tls.Config{ServerName: "benchmark.test"})
	hello, _ := h.marshal("", nil, false)
	wire := shadowFrame(22, hello)
	binary.BigEndian.PutUint16(wire[3:5], uint16(len(hello)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sniffPacket("tcp", wire, []string{"tls"})
	}
}

func TestSniffEarlyResponseDuplex(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	response := bytes.Repeat([]byte{'r'}, 2<<20)
	request := bytes.Repeat([]byte{'q'}, 2<<20)
	done := make(chan error, 1)
	go func() {
		c, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		e = writeAll(c, response)
		if e == nil {
			got := make([]byte, len(request))
			_, e = io.ReadFull(c, got)
			if e == nil && !bytes.Equal(got, request) {
				e = io.ErrUnexpectedEOF
			}
		}
		done <- e
	}()
	r := newTestRuntime(t, Config{Route: Route{Rules: []Rule{{Action: "sniff"}}}})
	c, e := r.Dial(context.Background(), "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	written := make(chan error, 1)
	go func() { written <- writeAll(c, request) }()
	got := make([]byte, len(response))
	if _, e = io.ReadFull(c, got); e != nil || !bytes.Equal(got, response) {
		t.Fatal(e)
	}
	if e = <-written; e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestSniffHTTPHeaderBoundary(t *testing.T) {
	for _, wire := range [][]byte{[]byte("POST / HTTP/1.1\r\nContent-Length: 22\r\n\r\nHost: forged.test\r\n"), []byte("GET / HTTP/1.1\r\n\r\nHost: forged.test\r\n")} {
		protocol, host := sniffPacket("tcp", wire, []string{"http"})
		if protocol != "http" || host != "" {
			t.Fatal(protocol, host)
		}
	}
}

type sniffZeroReader struct{}

func (sniffZeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }
func BenchmarkRouteReadyRead(b *testing.B) {
	ready := make(chan struct{})
	close(ready)
	c := &routeConn{ready: ready, conn: memoryNetConn{sniffZeroReader{}, &bytes.Buffer{}}}
	buffer := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c.Read(buffer)
	}
}
