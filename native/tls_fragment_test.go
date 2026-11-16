package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestTLSTCPFragmentProtocolsAndReference(t *testing.T) {
	testTLSFragmentProtocolsAndReference(t, true)
}
func TestTLSTCPFragmentPeerAuthentication(t *testing.T) { testTLSFragmentPeerAuthentication(t, true) }
func TestTLSTCPFragmentCancellation(t *testing.T)       { testTLSFragmentCancellation(t, true) }
func TestTLSTCPFragmentVersionsAndRetry(t *testing.T)   { testTLSFragmentVersionsAndRetry(t, true) }
func TestTLSTCPFragmentDNSAndDownloads(t *testing.T)    { testTLSFragmentDNSAndDownloads(t, true) }
func TestTLSTCPFragmentECHAndMutualTLS(t *testing.T)    { testTLSFragmentECHAndMutualTLS(t, true) }

type fragmentCapture struct {
	net.Conn
	mu    sync.Mutex
	parts [][]byte
	first chan struct{}
	once  sync.Once
	limit int
	fail  error
}

func (c *fragmentCapture) Write(p []byte) (int, error) {
	n := len(p)
	if c.limit > 0 {
		n = min(n, c.limit)
	}
	c.mu.Lock()
	c.parts = append(c.parts, bytes.Clone(p[:n]))
	c.mu.Unlock()
	c.once.Do(func() {
		if c.first != nil {
			close(c.first)
		}
	})
	return n, c.fail
}
func (c *fragmentCapture) SetDeadline(time.Time) error      { return nil }
func (c *fragmentCapture) SetWriteDeadline(time.Time) error { return nil }
func (c *fragmentCapture) Close() error                     { return nil }

func tcpFragmentHello() []byte {
	var capture bytes.Buffer
	c := tls.Client(memoryNetConn{bytes.NewReader(nil), &capture}, &tls.Config{ServerName: "tcp-fragment.example", InsecureSkipVerify: true})
	_ = c.Handshake()
	return bytes.Clone(capture.Bytes())
}

func TestTLSTCPFragmentWrites(t *testing.T) {
	hello := tcpFragmentHello()
	split, err := tlsFragmentSplit(hello)
	if err != nil || split <= 0 || bytes.Contains(hello[:split], []byte("tcp-fragment.example")) || bytes.Contains(hello[split:], []byte("tcp-fragment.example")) {
		t.Fatal(split, err)
	}
	for _, record := range []bool{false, true} {
		t.Run(strconv.FormatBool(record), func(t *testing.T) {
			wire := hello
			if record {
				wire, _, err = fragmentTLSRecords(hello, 0)
				if err != nil {
					t.Fatal(err)
				}
			}
			capture := &fragmentCapture{}
			c := newTLSFragmentConn(capture, time.Millisecond)
			if n, err := c.Write(wire); err != nil || n != len(wire) {
				t.Fatal(n, err)
			}
			if len(capture.parts) != 2 || !bytes.Equal(bytes.Join(capture.parts, nil), wire) {
				t.Fatal("changed transcript")
			}
			c.done.Store(true)
			capture.parts = nil
			if n, err := c.Write(wire); err != nil || n != len(wire) || len(capture.parts) != 1 {
				t.Fatal("post-handshake write split", n, err)
			}
		})
	}
	// A valid writer may consume a prefix only. Count failures without replaying it.
	short := &fragmentCapture{limit: 3}
	c := newTLSFragmentConn(short, time.Millisecond)
	if n, err := c.Write(hello); err != nil || n != len(hello) || !bytes.Equal(bytes.Join(short.parts, nil), hello) {
		t.Fatal(n, err)
	}
	broken := &fragmentCapture{limit: 3, fail: io.ErrClosedPipe}
	c = newTLSFragmentConn(broken, time.Millisecond)
	if n, err := c.Write(hello); n != 3 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal(n, err)
	}
	if n, err := c.Write(hello); n != 0 || !errors.Is(err, io.ErrClosedPipe) || len(broken.parts) != 1 {
		t.Fatal("replayed prefix", n, err)
	}
}

func TestTLSTCPFragmentCloseAndDeadlines(t *testing.T) {
	for _, mode := range []string{"close", "deadline", "expired", "extend"} {
		t.Run(mode, func(t *testing.T) {
			raw := &fragmentCapture{first: make(chan struct{})}
			c := newTLSFragmentConn(raw, 30*time.Millisecond)
			if mode == "extend" {
				if err := c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { _, err := c.Write(tcpFragmentHello()); done <- err }()
			<-raw.first
			switch mode {
			case "close":
				_ = c.Close()
			case "deadline":
				_ = c.SetWriteDeadline(time.Now().Add(time.Millisecond))
			case "expired":
				_ = c.SetDeadline(time.Now().Add(-time.Second))
			case "extend":
				_ = c.SetWriteDeadline(time.Time{})
			}
			select {
			case err := <-done:
				if mode == "close" && !errors.Is(err, net.ErrClosed) {
					t.Fatal(err)
				}
				if (mode == "deadline" || mode == "expired") && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal(err)
				}
				if mode == "extend" && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("wait did not stop")
			}
		})
	}
}

func TestTLSTCPFragmentConfigAndRTT(t *testing.T) {
	for _, o := range []TLSOptions{{Fragment: true}, {Enabled: true, Fragment: true, FragmentFallbackDelay: "-1s"}, {Enabled: true, Fragment: true, FragmentFallbackDelay: "0s"}, {Enabled: true, FragmentFallbackDelay: "1s"}} {
		if _, err := o.config(false, "example.com"); err == nil {
			t.Fatal("accepted", o)
		}
	}
	o := TLSOptions{Enabled: true, Fragment: true}
	if delay, err := o.fragmentDelay(); err != nil || delay != 500*time.Millisecond {
		t.Fatal(delay, err)
	}
	if _, err := o.config(true, ""); err == nil {
		t.Fatal("inbound fragment accepted")
	}
	if err := o.validateQUICVersion(); err == nil {
		t.Fatal("QUIC fragment accepted")
	}
	for _, kind := range []string{"udp", "tcp", "quic", "h3"} {
		if err := (DNSConfig{Servers: []DNSServer{{Type: kind, Tag: "d", Server: "127.0.0.1", TLS: o}}}).validate(); err == nil {
			t.Fatal("accepted ineffective DNS option", kind)
		}
	}
	for _, spec := range []struct {
		offset int
		unit   time.Duration
	}{{68, time.Microsecond}, {44, time.Millisecond}, {20, time.Microsecond}} {
		b := make([]byte, spec.offset+4)
		binary.NativeEndian.PutUint32(b[spec.offset:], 37)
		if got := tcpFragmentRTTValue(b, spec.offset, spec.unit); got != 37*spec.unit {
			t.Fatal(got, spec)
		}
		if got := tcpFragmentRTTValue(b[:len(b)-1], spec.offset, spec.unit); got != 0 {
			t.Fatal("short socket ABI accepted")
		}
	}
	raw := &fragmentCapture{}
	if rtt := tlsFragmentRTT(raw); rtt != 0 {
		t.Fatal(rtt)
	}
}

func FuzzTLSTCPFragmentSplit(f *testing.F) {
	f.Add(tcpFragmentHello())
	f.Add([]byte{22, 3, 3, 0, 4, 1, 0, 0, 0})
	f.Add([]byte{23, 3, 3, 0, 1, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		before := bytes.Clone(b)
		n, err := tlsFragmentSplit(b)
		if err == nil && (n < 0 || n >= len(b) && n != 0) {
			t.Fatal("invalid split", n, len(b))
		}
		if !bytes.Equal(before, b) {
			t.Fatal("modified input")
		}
	})
}

func BenchmarkTLSTCPFragmentData(b *testing.B) {
	c := newTLSFragmentConn(memoryNetConn{bytes.NewReader(nil), io.Discard}, time.Millisecond)
	c.done.Store(true)
	p := make([]byte, 16384)
	b.SetBytes(int64(len(p)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := c.Write(p); err != nil {
			b.Fatal(err)
		}
	}
}

func TestTLSTCPFragmentCancelDuringWait(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := clientTLS(a, &tls.Config{InsecureSkipVerify: true, ServerName: "cancel.example"}, TLSOptions{Fragment: true, FragmentFallbackDelay: "1h"})
	defer c.Close()
	done := make(chan error, 1)
	go func() { done <- c.HandshakeContext(ctx) }()
	first := make([]byte, 4096)
	if _, err := b.Read(first); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt fragment wait")
	}
}

func TestTLSTCPFragmentInvalidSNI(t *testing.T) {
	// Domain normalization can expand invalid UTF-8; wire offsets must stay bounded.
	name := bytes.Repeat([]byte{0xff}, 8)
	list := append([]byte{0, 0, 8}, name...)
	extension := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	extension = append(extension, list...)
	extensions := []byte{0, 0}
	extensions = binary.BigEndian.AppendUint16(extensions, uint16(len(extension)))
	extensions = append(extensions, extension...)
	body := make([]byte, 34)
	body = append(body, 0, 0, 2, 0x13, 1, 1, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions)))
	body = append(body, extensions...)
	hello := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hello = append(hello, body...)
	wire := binary.BigEndian.AppendUint16([]byte{22, 3, 3}, uint16(len(hello)))
	wire = append(wire, hello...)
	split, err := tlsFragmentSplit(wire)
	if err != nil || split <= 0 || split >= len(wire) {
		t.Fatal("out-of-range wire split", split, len(wire), err)
	}
	capture := &fragmentCapture{}
	c := newTLSFragmentConn(capture, time.Millisecond)
	if n, err := c.Write(wire); err != nil || n != len(wire) || !bytes.Equal(bytes.Join(capture.parts, nil), wire) {
		t.Fatal(n, err)
	}
}
