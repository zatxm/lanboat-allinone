package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type naiveH2Capture struct {
	net.Conn
	mu   sync.Mutex
	wire []byte
}

func (c *naiveH2Capture) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.mu.Lock()
	c.wire = append(c.wire, b[:n]...)
	c.mu.Unlock()
	return n, err
}
func (c *naiveH2Capture) frames() ([][]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.wire
	if len(b) >= len(masqueH2Preface) && string(b[:len(masqueH2Preface)]) == masqueH2Preface {
		b = b[len(masqueH2Preface):]
	}
	var frames [][]byte
	for len(b) >= 9 {
		n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
		if len(b) < 9+n {
			return frames, nil
		}
		frames = append(frames, bytes.Clone(b[:9+n]))
		b = b[9+n:]
	}
	return frames, nil
}

func naiveH2Memory(t *testing.T) (*naiveH2Session, *bytes.Buffer) {
	t.Helper()
	var wire bytes.Buffer
	m := &naiveH2Session{conn: &memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}, streams: map[uint32]*naiveH2Stream{}, peerConcurrent: 128, peerWindow: 65535, send: 65535, receive: naiveH2ConnectionWindow, done: make(chan struct{}), space: make(chan struct{}, 1), control: make(chan *naiveH2Operation, 256), data: make(chan *naiveH2Operation, 32), decoder: masqueHPACK{limit: 4096}}
	m.settings = make(chan struct{})
	close(m.settings)
	m.haveSettings = true
	m.peerHeader = ^uint32(0)
	return m, &wire
}
func naiveH2Writer(t *testing.T, m *naiveH2Session) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); m.writeLoop() }()
	t.Cleanup(func() { m.fail(net.ErrClosed); <-done })
}
func naiveH2Barrier(t *testing.T, m *naiveH2Session) {
	t.Helper()
	op := &naiveH2Operation{wire: masqueH2Frame(6, 0, 0, make([]byte, 8)), result: make(chan error, 1)}
	m.queue(op)
	select {
	case err := <-op.result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("writer stalled")
	}
}

func TestNaiveH2ResetWire(t *testing.T) {
	for _, mode := range []string{"padded", "connection-tight", "stream-tight", "half-closed", "unopened"} {
		t.Run(mode, func(t *testing.T) {
			m, wire := naiveH2Memory(t)
			s, err := m.open(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			s.opened = true
			switch mode {
			case "connection-tight":
				m.send = 49
			case "stream-tight":
				s.send = 49
			case "half-closed":
				s.localEnd = true
			case "unopened":
				s.opened = false
			}
			before := m.send
			naiveH2Writer(t, m)
			for range 10 {
				s.close()
			}
			naiveH2Barrier(t, m)
			b := wire.Bytes()
			want := 13 + 17
			if mode == "padded" {
				n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
				combined := 9 + n + 13
				if combined < 48 || combined > 72 || b[3] != 0 || b[4] != 9 || binary.BigEndian.Uint32(b[5:9]) != s.id || int(b[9]) != n-1 || !bytes.Equal(b[10:9+n], make([]byte, n-1)) {
					t.Fatal("invalid padded reset vector", b)
				}
				m.mu.Lock()
				left := m.send
				m.mu.Unlock()
				if left != before-int64(n) {
					t.Fatal("padding was not charged", before, left, n)
				}
				b = b[9+n:]
				want = 30
			} else if mode == "unopened" {
				want = 17
			}
			if len(b) != want {
				t.Fatal("duplicate or missing reset", len(b), want, b)
			}
			if mode != "unopened" && (b[3] != 3 || b[2] != 4 || b[12] != 8) {
				t.Fatal("RST_STREAM changed", b)
			}
		})
	}
}

func TestNaiveH2ResetRealConnection(t *testing.T) {
	_, r := naivePair(t, false)
	client := r.trustClients["proxy"]
	dial := client.http.DialTLSContext
	var capture *naiveH2Capture
	client.http.DialTLSContext = func(ctx context.Context, n, a string) (net.Conn, error) {
		raw, err := dial(ctx, n, a)
		if err != nil {
			return nil, err
		}
		capture = &naiveH2Capture{Conn: raw}
		return capture, nil
	}
	target := tcpEcho(t)
	for range 96 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c, err := r.Dial(ctx, "tcp", target)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if err = writeAll(c, []byte("cancel-test")); err != nil {
			t.Fatal(err)
		}
		var reply [11]byte
		if _, err = io.ReadFull(c, reply[:]); err != nil || string(reply[:]) != "cancel-test" {
			t.Fatal(string(reply[:]), err)
		}
		c.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	resets, padded := 0, 0
	for time.Now().Before(deadline) {
		frames, _ := capture.frames()
		resets, padded = 0, 0
		for i, f := range frames {
			if f[3] == 3 {
				resets++
				if i > 0 && frames[i-1][3] == 0 && frames[i-1][4] == 9 {
					padded++
				}
			}
		}
		if resets >= 96 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if resets != 96 || padded == 0 {
		t.Fatal("real connection emitted no padded resets", resets, padded)
	}
	assertTCP(t, r)
	client.mu.Lock()
	sessions := len(client.naiveSessions)
	client.mu.Unlock()
	if sessions != 1 {
		t.Fatal("reset damaged multiplexed session", sessions)
	}
	t.Log("actual TLS-plaintext wire resets", resets, "padded", padded)
}

func TestNaiveH2CreditAndLifetime(t *testing.T) {
	t.Run("cancel-refunds-queued-data", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		old, _ := m.open(context.Background())
		next, _ := m.open(context.Background())
		old.opened, next.opened = true, true
		m.send, old.send = 0, 0
		old.closed = true
		delete(m.streams, old.id)
		op := &naiveH2Operation{wire: masqueH2Frame(0, 0, old.id, make([]byte, 16)), stream: old, kind: 0, count: 16, result: make(chan error, 1)}
		m.data <- op
		done := make(chan error, 1)
		go func() { _, err := next.Write([]byte("ok")); done <- err }()
		naiveH2Writer(t, m)
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("refunded credit did not wake another stream")
		}
		m.mu.Lock()
		left := m.send
		m.mu.Unlock()
		if left != 14 {
			t.Fatal("incorrect refunded connection credit", left)
		}
	})
	t.Run("cancel-before-enqueue", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		s, _ := m.open(context.Background())
		m.data = nil
		m.send = 0
		s.send = 0
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		op := &naiveH2Operation{stream: s, count: 42, result: make(chan error, 1)}
		if err := s.submit(ctx, op); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if m.send != 42 || s.send != 42 {
			t.Fatal("reserved credit leaked", m.send, s.send)
		}
	})
	t.Run("negative-window-and-recovery", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		s, _ := m.open(context.Background())
		s.send = 12
		if err := m.receiveFrame(4, 0, 0, []byte{0, 4, 0, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
		if s.send != 12-65535 {
			t.Fatal("SETTINGS window shrink lost debt", s.send)
		}
		if err := m.receiveFrame(8, 0, s.id, binary.BigEndian.AppendUint32(nil, 65535)); err != nil || s.send != 12 {
			t.Fatal("window recovery", s.send, err)
		}
	})
	t.Run("half-close-retires-wire-stream", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		s, _ := m.open(context.Background())
		s.localEnd, s.remoteEnd, s.ready = true, true, true
		s.buffer.WriteString("buffered")
		m.retire(s)
		if len(m.streams) != 0 {
			t.Fatal("completed stream retained a concurrency slot")
		}
		m.fail(io.EOF)
		got, err := io.ReadAll(s)
		if err != nil || string(got) != "buffered" {
			t.Fatal("connection EOF discarded completed response", string(got), err)
		}
	})
	t.Run("concurrent-zero-waits-for-settings", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		m.peerConcurrent = 0
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		if _, err := m.open(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	})
}

func TestNaiveH2InvalidFrames(t *testing.T) {
	for i, tc := range []struct {
		kind, flags byte
		id          uint32
		b           []byte
	}{
		{4, 0, 1, nil}, {4, 1, 0, []byte{0}}, {4, 0, 0, []byte{0, 4, 128, 0, 0, 0}}, {4, 0, 0, []byte{0, 5, 0, 0, 0, 1}},
		{8, 0, 0, []byte{0, 0, 0, 0}}, {8, 0, 0, []byte{0, 0, 0}}, {6, 0, 1, make([]byte, 8)}, {0, 8, 1, nil}, {0, 8, 1, []byte{1}},
		{0, 0, 3, []byte{1}}, {3, 0, 0, make([]byte, 4)}, {7, 0, 0, nil}, {9, 4, 1, nil}, {5, 0, 1, nil},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			m, _ := naiveH2Memory(t)
			m.open(context.Background())
			if err := m.receiveFrame(tc.kind, tc.flags, tc.id, tc.b); err == nil {
				t.Fatal("accepted malformed frame", tc)
			}
		})
	}
}

func TestNaiveH2ReceiveBuffers(t *testing.T) {
	t.Run("tiny-padded-frames", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		s, _ := m.open(context.Background())
		s.ready = true
		frame := make([]byte, 256)
		frame[0], frame[1] = 254, 'x'
		for range 4096 {
			if err := m.receiveFrame(0, 8, s.id, frame); err != nil {
				t.Fatal(err)
			}
		}
		if s.buffer.Len() != 4096 || s.buffer.Cap() > 8192 {
			t.Fatal("padding retained beyond receive byte budget", s.buffer.Len(), s.buffer.Cap())
		}
		frame[1] = 'y'
		if !bytes.Equal(s.buffer.Bytes(), bytes.Repeat([]byte("x"), 4096)) {
			t.Fatal("receive data aliases frame scratch")
		}
	})
	t.Run("completed-response-reset", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		s, _ := m.open(context.Background())
		s.ready = true
		if err := m.receiveFrame(0, 1, s.id, []byte("completed")); err != nil {
			t.Fatal(err)
		}
		if err := m.receiveFrame(3, 0, s.id, make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
		if len(m.streams) != 0 || !s.localEnd {
			t.Fatal("NO_ERROR did not retire completed stream")
		}
		got, err := io.ReadAll(s)
		if string(got) != "completed" || err != nil {
			t.Fatal("NO_ERROR discarded completed response", string(got), err)
		}
	})
	t.Run("reset-wakes-zero-credit-writer", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		s, _ := m.open(context.Background())
		s.ready, s.remoteEnd, s.send = true, true, 0
		done := make(chan error, 1)
		go func() { _, err := s.Write([]byte("x")); done <- err }()
		if err := m.receiveFrame(3, 0, s.id, make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("NO_ERROR left zero-credit writer blocked")
		}
	})
	t.Run("goaway-drains-old-stream", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		first, _ := m.open(context.Background())
		last, _ := m.open(context.Background())
		goaway := binary.BigEndian.AppendUint32(nil, first.id)
		goaway = binary.BigEndian.AppendUint32(goaway, 0)
		if err := m.receiveFrame(7, 0, 0, goaway); err != nil {
			t.Fatal(err)
		}
		if !last.closed || first.closed || len(m.streams) != 1 {
			t.Fatal("GOAWAY did not preserve accepted stream")
		}
		if _, err := m.open(context.Background()); !errors.Is(err, net.ErrClosed) {
			t.Fatal("GOAWAY accepted a new stream", err)
		}
		first.finish(io.EOF)
		select {
		case <-m.done:
		default:
			t.Fatal("drained connection not closed")
		}
	})
}

func TestNaiveH2IdleLifetime(t *testing.T) {
	t.Run("empty-session-closes", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		m.mu.Lock()
		m.idle = time.AfterFunc(time.Millisecond, m.closeIdle)
		m.mu.Unlock()
		select {
		case <-m.done:
		case <-time.After(time.Second):
			t.Fatal("idle session retained physical connection")
		}
	})
	t.Run("active-stream-survives-and-last-close-arms", func(t *testing.T) {
		m, _ := naiveH2Memory(t)
		s, _ := m.open(context.Background())
		m.closeIdle()
		if m.err != nil || m.draining {
			t.Fatal("idle callback closed active stream")
		}
		m.idle = time.AfterFunc(time.Hour, m.closeIdle)
		m.idle.Stop()
		s.finish(io.EOF)
		m.mu.Lock()
		armed := m.idle.Stop()
		m.mu.Unlock()
		if !armed {
			t.Fatal("last stream did not arm idle timer")
		}
		m.closeIdle()
		if m.err == nil {
			t.Fatal("finished session not evicted")
		}
	})
}

func FuzzNaiveH2Frame(f *testing.F) {
	f.Add(byte(4), byte(0), uint32(0), []byte{0, 4, 0, 0, 255, 255})
	f.Add(byte(0), byte(8), uint32(1), []byte{1, 0})
	f.Fuzz(func(t *testing.T, kind, flags byte, id uint32, b []byte) {
		m, _ := naiveH2Memory(t)
		m.open(context.Background())
		_ = m.receiveFrame(kind, flags, id, b[:min(len(b), 16384)])
	})
}
