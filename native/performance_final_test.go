package native

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"
)

func BenchmarkSMUXControl(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &smuxSession{conn: readerConn(nil), ctx: ctx, cancel: cancel, version: 1, gate: make(chan struct{}, 1), space: make(chan struct{}, 1)}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := s.send(ctx, 3, 0, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkSMUXSmallQueue(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &smuxSession{ctx: ctx, cancel: cancel, version: 1, space: make(chan struct{}, 1)}
	c := s.newStream(1)
	payload := bytes.Repeat([]byte("x"), 128)
	buffer := make([]byte, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := c.push(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, buffer); err != nil {
			b.Fatal(err)
		}
	}
}

type readNotifyingConn struct {
	net.Conn
	once    sync.Once
	reading chan struct{}
}

func (c *readNotifyingConn) Read(p []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(p)
}
func BenchmarkSMUXIdleSession(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.ReportAllocs()
	for range b.N {
		a, peer := net.Pipe()
		c := &readNotifyingConn{Conn: a, reading: make(chan struct{})}
		s := newSMUXVersion(ctx, c, true, 1, 0)
		<-c.reading
		s.close(net.ErrClosed)
		peer.Close()
	}
}
func BenchmarkRelay(b *testing.B) {
	for _, size := range []int{128, 65536} {
		b.Run(map[int]string{128: "small", 65536: "bulk"}[size], func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &Runtime{ctx: ctx, logger: zap.NewNop()}
			payload := bytes.Repeat([]byte("x"), size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				left, input := net.Pipe()
				output, right := net.Pipe()
				done := make(chan struct{})
				go func() { r.relay(left, right); left.Close(); close(done) }()
				go func() { writeAll(input, payload); input.Close() }()
				io.Copy(io.Discard, output)
				output.Close()
				<-done
			}
		})
	}
}
func TestPerformanceBuffersPreserveData(t *testing.T) {
	for _, size := range []int{1, 1024, 16384, 65535} {
		ctx, cancel := context.WithCancel(context.Background())
		s := &smuxSession{ctx: ctx, cancel: cancel, version: 1, space: make(chan struct{}, 1)}
		c := s.newStream(1)
		want := bytes.Repeat([]byte{byte(size)}, size)
		if err := c.push(want); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, size)
		if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
			t.Fatal("queue data changed", size, err)
		}
		cancel()
	}
}

type shortRelayWriter struct{}

func (shortRelayWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

type finalRelayReader struct{ data []byte }

func (r *finalRelayReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}
func TestRelayAdaptiveBuffer(t *testing.T) {
	for _, size := range []int{0, 1, 2047, 2048, 2049, 65536, 3 << 20} {
		want := bytes.Repeat([]byte{byte(size)}, size)
		var got bytes.Buffer
		var count atomic.Int64
		if err := copyRelay(&got, &finalRelayReader{data: want}, &count); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got.Bytes()) || count.Load() != int64(size) {
			t.Fatal("relay data or accounting changed", size)
		}
	}
	var count atomic.Int64
	if err := copyRelay(shortRelayWriter{}, bytes.NewReader([]byte("01234567")), &count); err != io.ErrShortWrite || count.Load() != 4 {
		t.Fatal("short writes not preserved", err, count.Load())
	}
}
func TestGenericMuxQueuedCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		close(accepted)
		<-release
	}()
	in := Inbound{Type: "socks"}
	out := testOutbound(t, in, listener.Addr().String())
	out.Multiplex = MultiplexOptions{Enabled: true, Protocol: "smux"}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	leader, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := client.Dial(leader, "tcp", "example.com:80")
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	<-accepted
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	start := time.Now()
	c, err := client.Dial(ctx, "tcp", "example.com:80")
	if c != nil {
		c.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 300*time.Millisecond {
		t.Fatal("queued cancellation waited for another handshake", err, time.Since(start))
	}
	client.resetNetworkTransports()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("stale handshake survived reset")
		}
	case <-time.After(time.Second):
		t.Fatal("reset did not cancel pending handshake")
	}
}

func TestGenericMuxIdleReleasesBackingReference(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := net.Pipe()
	defer b.Close()
	s := newSMUXVersion(ctx, a, true, 1, 0)
	defer s.close(net.ErrClosed)
	e := &genericMuxEntry{session: genericSMUX{s}, active: 1}
	pool := &genericMuxClient{entries: []*genericMuxEntry{e}}
	pool.release(e)
	pool.mu.Lock()
	e.idle.Reset(0)
	pool.mu.Unlock()
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("idle session did not close")
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.entries) != 0 || pool.entries[:cap(pool.entries)][0] != nil {
		t.Fatal("idle pool retained the closed session")
	}
}

type blockedCloseConn struct {
	net.Conn
	closing, release chan struct{}
	once             sync.Once
}

func (c *blockedCloseConn) Close() error {
	c.once.Do(func() { close(c.closing); <-c.release })
	return c.Conn.Close()
}
func TestGenericMuxIdleCloseDoesNotBlockPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	a, b := net.Pipe()
	wire := &blockedCloseConn{Conn: a, closing: make(chan struct{}), release: make(chan struct{})}
	s := newSMUXVersion(ctx, wire, true, 1, 0)
	t.Cleanup(func() { close(wire.release); s.close(net.ErrClosed); b.Close(); cancel() })
	e := &genericMuxEntry{session: genericSMUX{s}, active: 1}
	p := &genericMuxClient{entries: []*genericMuxEntry{e}}
	p.release(e)
	p.mu.Lock()
	e.idle.Reset(0)
	p.mu.Unlock()
	select {
	case <-wire.closing:
	case <-time.After(time.Second):
		t.Fatal("idle close did not start")
	}
	done := make(chan struct{})
	go func() { p.reset(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("slow idle close held the pool lock")
	}
}
