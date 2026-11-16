package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func sudokuMuxRuntime(t *testing.T, method string, packed bool) *Runtime {
	t.Helper()
	o := sudokuTestOptions(method, "prefer_entropy", packed)
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Sudoku = o
	out.Multiplex.Enabled = true
	return newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}

func TestSudokuMuxRoundTrip(t *testing.T) {
	for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
		for _, packed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", method, packed), func(t *testing.T) {
				client := sudokuMuxRuntime(t, method, packed)
				assertTCP(t, client)
				pool := client.sudokuMuxClients["proxy"]
				first := pool.current
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{0, 1, 4096, 65507})
				assertTCP(t, client)
				if pool.current != first {
					t.Fatal("TCP/UDP changed the shared TCP session")
				}
				client.resetNetworkTransports()
				assertTCP(t, client)
				if pool.current == first {
					t.Fatal("network reset kept the old session")
				}
			})
		}
	}
}

func TestSudokuMuxOfficialReference(t *testing.T) {
	for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
		for _, variant := range []string{"entropy", "ascii", "directional", "packed", "custom", "custom-packed"} {
			for _, side := range []string{"client", "server"} {
				t.Run(method+"/"+variant+"/"+side, func(t *testing.T) {
					client := sudokuReferenceClient(t, method, variant, side, true)
					for range 3 {
						assertTCP(t, client)
					}
					assertUDPSizes(t, client, []int{1, 4096, 60000, 65497})
					assertTCP(t, client)
				})
			}
		}
	}
}

func TestSudokuMuxOfficialHalfClose(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			assertSudokuHalfClose(t, sudokuReferenceClient(t, "chacha20-poly1305", "packed", side, true))
		})
	}
}

func assertSudokuHalfClose(t *testing.T, client *Runtime) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		b, err := io.ReadAll(c)
		if err == nil {
			err = writeAll(c, append([]byte("response:"), b...))
		}
		done <- err
	}()
	c, err := client.Dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err = writeAll(c, []byte("request")); err == nil {
		err = c.(interface{ CloseWrite() error }).CloseWrite()
	}
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "response:request" {
		t.Fatalf("reference half close: %q %v", b, err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSudokuMuxOfficialIdleKeepalive(t *testing.T) {
	client := sudokuReferenceClient(t, "chacha20-poly1305", "packed", "client", true)
	assertTCP(t, client)
	pool := client.sudokuMuxClients["proxy"]
	session := pool.current
	started := time.Now()
	for time.Since(started) < 20*time.Second && session.lastRead.Load() < started.Add(10*time.Second).UnixNano() {
		time.Sleep(20 * time.Millisecond)
	}
	if session.lastRead.Load() < started.Add(10*time.Second).UnixNano() {
		t.Fatal("no keepalive from official peer")
	}
	assertTCP(t, client)
	if pool.current != session {
		t.Fatal("idle keepalive lost the authenticated session")
	}
}

func TestSudokuMuxConcurrentHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var servers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			servers.Go(func() {
				defer c.Close()
				b, err := io.ReadAll(c)
				if err == nil {
					_ = writeAll(c, b)
				}
			})
		}
	}()
	client := sudokuMuxRuntime(t, "chacha20-poly1305", true)
	var workers sync.WaitGroup
	for i := range 24 {
		workers.Go(func() {
			c, err := client.Dial(context.Background(), "tcp", listener.Addr().String())
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			// Race instrumentation slows this6MiB transfer through one shared encoder.
			c.SetDeadline(time.Now().Add(20 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 262144+i)
			if err = writeAll(c, want); err == nil {
				err = c.(interface{ CloseWrite() error }).CloseWrite()
			}
			if err != nil {
				t.Error(err)
				return
			}
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(want, got) {
				t.Errorf("stream %d got %d: %v", i, len(got), err)
			}
		})
	}
	workers.Wait()
	client.Close()
	listener.Close()
	<-accepted
	servers.Wait()
}

func sudokuMuxFrame(kind byte, id uint32, data []byte) []byte {
	b := make([]byte, 9+len(data))
	b[0] = kind
	binary.BigEndian.PutUint32(b[1:5], id)
	binary.BigEndian.PutUint32(b[5:9], uint32(len(data)))
	copy(b[9:], data)
	return b
}

func sudokuMuxWire(t *testing.T, client bool) (*smuxSession, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	s := newMuxConfigured(context.Background(), a, client, muxSudoku, 1, 0, false)
	b.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { b.Close(); s.close(net.ErrClosed) })
	return s, b
}

func sudokuReadMuxFrame(t *testing.T, c net.Conn) (byte, uint32, []byte) {
	t.Helper()
	var h [9]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(h[5:])
	if n > 256<<10 {
		t.Fatal("oversized test response")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(c, data); err != nil {
		t.Fatal(err)
	}
	return h[0], binary.BigEndian.Uint32(h[1:5]), data
}

func TestSudokuMuxControlAndEvenIDs(t *testing.T) {
	s, peer := sudokuMuxWire(t, false)
	if err := writeAll(peer, sudokuMuxFrame(5, 0, nil)); err != nil {
		t.Fatal(err)
	}
	kind, id, _ := sudokuReadMuxFrame(t, peer)
	if kind != 6 || id != 0 {
		t.Fatal("missing pong")
	}
	for _, id := range []uint32{1, 2, 3, 4} {
		target, _ := encodeAddress("example.test:443")
		if err := writeAll(peer, sudokuMuxFrame(1, id, target)); err != nil {
			t.Fatal(err)
		}
		var stream *smuxStream
		select {
		case stream = <-s.accept:
		case <-time.After(time.Second):
			t.Fatal("stream not accepted")
		}
		if stream.id != id || stream.address != "example.test:443" {
			t.Fatal("target or identifier changed")
		}
		if err := writeAll(peer, sudokuMuxFrame(3, id, nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("half close: %v", err)
		}
		written := make(chan error, 1)
		go func() { _, err := stream.Write([]byte("response")); written <- err }()
		kind, got, data := sudokuReadMuxFrame(t, peer)
		if kind != 2 || got != id || string(data) != "response" {
			t.Fatal("response after EOF lost")
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		if err := writeAll(peer, sudokuMuxFrame(4, id, []byte("reset"))); err != nil {
			t.Fatal(err)
		}
		select {
		case <-s.done:
			t.Fatal("stream reset closed session")
		default:
		}
	}
}

func TestSudokuMuxLargeFrame(t *testing.T) {
	for _, size := range []int{16384, 128 << 10, 256 << 10} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			s, peer := sudokuMuxWire(t, false)
			target, _ := encodeAddress("a:1")
			if err := writeAll(peer, sudokuMuxFrame(1, 2, target)); err != nil {
				t.Fatal(err)
			}
			stream := <-s.accept
			want := bytes.Repeat([]byte("L"), size)
			done := make(chan error, 1)
			go func() { done <- writeAll(peer, sudokuMuxFrame(2, 2, want)) }()
			got := make([]byte, size)
			if _, err := io.ReadFull(stream, got); err != nil || !bytes.Equal(got, want) {
				t.Fatal("large mux frame", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSudokuMuxSlowStreamIsolation(t *testing.T) {
	s, peer := sudokuMuxWire(t, false)
	target, _ := encodeAddress("a:1")
	if err := writeAll(peer, sudokuMuxFrame(1, 1, target)); err != nil {
		t.Fatal(err)
	}
	slow := <-s.accept
	for range 9 {
		if err := writeAll(peer, sudokuMuxFrame(2, 1, make([]byte, 128<<10))); err != nil {
			t.Fatal(err)
		}
	}
	kind, id, _ := sudokuReadMuxFrame(t, peer)
	if kind != 4 || id != 1 {
		t.Fatal("slow stream not reset")
	}
	if s.buffered.Load() != 0 {
		t.Fatal("reset leaked queued payload")
	}
	if _, err := slow.Read(make([]byte, 1)); err == nil {
		t.Fatal("slow stream still readable")
	}
	if err := writeAll(peer, sudokuMuxFrame(1, 2, target)); err != nil {
		t.Fatal(err)
	}
	fast := <-s.accept
	if err := writeAll(peer, sudokuMuxFrame(2, 2, []byte("fast"))); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(fast, b); err != nil || string(b) != "fast" {
		t.Fatal("other stream blocked", err)
	}
}

func TestSudokuMuxKeepalive(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := newMuxConfigured(ctx, a, true, muxSudoku, 1, 5*time.Millisecond, false)
	server := newMuxConfigured(ctx, b, false, muxSudoku, 1, 5*time.Millisecond, false)
	defer client.close(net.ErrClosed)
	defer server.close(net.ErrClosed)
	initial := client.lastRead.Load()
	deadline := time.Now().Add(time.Second)
	for client.lastRead.Load() == initial && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if client.lastRead.Load() == initial {
		t.Fatal("idle session did not exchange keepalives")
	}
}

func TestSudokuMuxRuntimeClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := listener.Accept()
		if err == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	client := sudokuMuxRuntime(t, "aes-128-gcm", false)
	c, err := client.Dial(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	read := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); read <- err }()
	client.Close()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("read survived runtime close")
		}
	case <-time.After(time.Second):
		t.Fatal("runtime close left blocked stream")
	}
	listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("origin connection leaked")
	}
}

func TestSudokuMuxBadTargetIsolation(t *testing.T) {
	s, peer := sudokuMuxWire(t, false)
	for _, target := range [][]byte{{9, 1, 2, 3, 4}, {3, 1, 'a', 0, 0}, {3, 1, 'a', 0, 1, 0}} {
		if err := writeAll(peer, sudokuMuxFrame(1, 1, target)); err != nil {
			t.Fatal(err)
		}
		kind, id, _ := sudokuReadMuxFrame(t, peer)
		if kind != 4 || id != 1 {
			t.Fatal("bad target not reset")
		}
	}
	target, _ := encodeAddress("a:1")
	if err := writeAll(peer, sudokuMuxFrame(1, 2, target)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-s.accept:
		if c.id != 2 {
			t.Fatal("wrong stream accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("bad target closed shared session")
	}
}

func TestSudokuMuxCapacity(t *testing.T) {
	s, peer := sudokuMuxWire(t, false)
	target, _ := encodeAddress("a:1")
	for id := uint32(1); id <= 128; id++ {
		if err := writeAll(peer, sudokuMuxFrame(1, id, target)); err != nil {
			t.Fatal(err)
		}
		<-s.accept
	}
	if err := writeAll(peer, sudokuMuxFrame(1, 129, target)); err != nil {
		t.Fatal(err)
	}
	kind, id, _ := sudokuReadMuxFrame(t, peer)
	if kind != 4 || id != 129 {
		t.Fatal("capacity not enforced")
	}
	select {
	case <-s.done:
		t.Fatal("capacity reset closed active streams")
	default:
	}
	if err := writeAll(peer, sudokuMuxFrame(4, 1, nil)); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(peer, sudokuMuxFrame(1, 130, target)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-s.accept:
		if c.id != 130 {
			t.Fatal("capacity not released")
		}
	case <-time.After(time.Second):
		t.Fatal("reset did not release capacity")
	}
}

func FuzzSudokuMuxWire(f *testing.F) {
	target, _ := encodeAddress("example.test:443")
	f.Add(sudokuMuxFrame(5, 0, nil))
	f.Add(append(sudokuMuxFrame(1, 1, target), sudokuMuxFrame(2, 1, []byte("payload"))...))
	f.Add([]byte{255})
	f.Fuzz(func(t *testing.T, data []byte) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s := &smuxSession{conn: &sudokuBufferConn{Buffer: bytes.NewBuffer(data)}, ctx: ctx, cancel: cancel, sudoku: true, version: 1, streams: map[uint32]*smuxStream{}, control: make(chan sudokuMuxControl, 128), gate: make(chan struct{}, 1), space: make(chan struct{}, 1), accept: make(chan *smuxStream, 128), done: make(chan struct{})}
		_ = s.receiveSudoku()
		s.close(net.ErrClosed)
		if s.buffered.Load() != 0 {
			t.Fatal("mux parser leaked receive budget")
		}
	})
}

func TestSudokuMuxBadFrames(t *testing.T) {
	for _, kind := range []string{"length", "unknown", "ping-target", "ping-body", "close-body", "zero-id", "reverse-open", "reused-id"} {
		t.Run(kind, func(t *testing.T) {
			s, peer := sudokuMuxWire(t, kind == "reverse-open")
			target, _ := encodeAddress("a:1")
			b := sudokuMuxFrame(2, 1, nil)
			switch kind {
			case "length":
				binary.BigEndian.PutUint32(b[5:], 256<<10+1)
			case "unknown":
				b[0] = 7
			case "ping-target":
				b = sudokuMuxFrame(5, 1, nil)
			case "ping-body":
				b = sudokuMuxFrame(5, 0, []byte("x"))
			case "close-body":
				b = sudokuMuxFrame(3, 1, []byte("x"))
			case "zero-id":
				b = sudokuMuxFrame(2, 0, nil)
			case "reverse-open":
				b = sudokuMuxFrame(1, 2, target)
			case "reused-id":
				b = sudokuMuxFrame(1, 1, target)
				if err := writeAll(peer, b); err != nil {
					t.Fatal(err)
				}
				<-s.accept
			}
			// Invalid headers may be rejected before their body is consumed.
			_ = writeAll(peer, b)
			select {
			case <-s.done:
			case <-time.After(time.Second):
				t.Fatal("malformed mux frame accepted")
			}
		})
	}
}
