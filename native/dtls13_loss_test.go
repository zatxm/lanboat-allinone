package native

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type dtls13TestConn struct {
	net.Conn
	owner     *ocDTLS
	mode      string
	mu        sync.Mutex
	changed   bool
	held      []byte
	sequences []uint64
}

func (c *dtls13TestConn) Write(wire []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kind, handshake := byte(0), byte(0)
	if len(wire) > 25 && wire[0] == 22 {
		kind, handshake = 22, wire[13]
	}
	if wire[0]&0xe0 == 0x20 {
		if k := c.owner.v13.writeKeys[uint64(wire[0]&3)]; k != nil {
			probe := *k
			probe.window = packetWindow{}
			content, data, seq, _, ok := probe.open(wire)
			if ok {
				kind = content
				if content == 22 && len(data) > 0 {
					handshake = data[0]
					c.sequences = append(c.sequences, seq)
				}
			}
		}
	}
	if !c.changed {
		drop := c.mode == "hello" && kind == 22 && handshake == 1 || c.mode == "server-hello" && kind == 22 && handshake == 2 || c.mode == "finished" && kind == 22 && handshake == 20 || c.mode == "ack" && kind == 26
		if drop {
			c.changed = true
			return len(wire), nil
		}
		if c.mode == "reorder" && kind == 22 && handshake == 8 {
			c.held = bytes.Clone(wire)
			return len(wire), nil
		}
	}
	n, err := c.Conn.Write(wire)
	if err == nil && len(c.held) > 0 && kind == 22 && handshake == 20 {
		_, err = c.Conn.Write(c.held)
		c.held = nil
		c.changed = true
	}
	return n, err
}

func TestDTLS13Loss(t *testing.T) {
	for _, mode := range []string{"hello", "server-hello", "finished", "ack", "reorder"} {
		t.Run(mode, func(t *testing.T) {
			c, s := dtls13Pair(t, 0x1301)
			target := c
			if mode == "server-hello" || mode == "reorder" || mode == "ack" {
				target = s
			}
			injector := &dtls13TestConn{Conn: target.conn, owner: target, mode: mode}
			target.conn = injector
			dtls13HandshakePair(t, c, s)
			if mode == "ack" {
				time.Sleep(1100 * time.Millisecond)
			}
			c.conn.SetDeadline(time.Now().Add(3 * time.Second))
			s.conn.SetDeadline(time.Now().Add(3 * time.Second))
			if err := c.write(3, []byte("alive")); err != nil {
				t.Fatal(err)
			}
			kind, p, err := s.read()
			if err != nil || kind != 3 || string(p) != "alive" {
				t.Fatal(kind, string(p), err)
			}
			if err = s.write(4, p); err != nil {
				t.Fatal(err)
			}
			kind, p, err = c.read()
			if err != nil || kind != 4 || string(p) != "alive" {
				t.Fatal(kind, string(p), err)
			}
			injector.mu.Lock()
			defer injector.mu.Unlock()
			if !injector.changed {
				t.Fatal("packet loss/reorder was not exercised")
			}
			if mode == "finished" && (len(injector.sequences) < 2 || injector.sequences[0] == injector.sequences[1]) {
				t.Fatal("retransmitted Finished reused record sequence", injector.sequences)
			}
		})
	}
}

func TestDTLS13KeyUpdateAckLoss(t *testing.T) {
	c, s := dtls13Pair(t, 0x1301)
	dtls13HandshakePair(t, c, s)
	exchange := func(sender, receiver *ocDTLS) {
		t.Helper()
		sender.conn.SetDeadline(time.Now().Add(3 * time.Second))
		receiver.conn.SetDeadline(time.Now().Add(3 * time.Second))
		if err := sender.write(3, []byte("alive")); err != nil {
			t.Fatal(err)
		}
		if kind, body, err := receiver.read(); err != nil || kind != 3 || string(body) != "alive" {
			t.Fatal(kind, string(body), err)
		}
	}
	exchange(c, s)
	exchange(s, c)
	loss := &dtls13TestConn{Conn: s.conn, owner: s, mode: "ack"}
	s.conn = loss
	c.writeMu.Lock()
	err := c.v13.keyUpdateLocked(false)
	c.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	exchange(c, s)
	exchange(s, c)
	if c.v13.writeEpoch != 3 {
		t.Fatal("missing ACK still advanced write epoch")
	}
	time.Sleep(1100 * time.Millisecond)
	exchange(c, s)
	exchange(s, c)
	if c.v13.writeEpoch != 4 || s.v13.readEpoch != 4 {
		t.Fatal("KeyUpdate ACK loss did not recover", c.v13.writeEpoch, s.v13.readEpoch)
	}
	exchange(c, s)
	if len(s.v13.readKeys) != 1 {
		t.Fatal("old keys retained after updated traffic")
	}
}

func TestDTLS13ConcurrentWrites(t *testing.T) {
	c, s := dtls13Pair(t, 0x1301)
	dtls13HandshakePair(t, c, s)
	c.conn.SetDeadline(time.Now().Add(3 * time.Second))
	s.conn.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() {
		seen := map[string]bool{}
		for range 160 {
			_, body, err := s.read()
			if err != nil {
				done <- err
				return
			}
			key := string(body)
			if seen[key] {
				done <- fmt.Errorf("duplicate %s", key)
				return
			}
			seen[key] = true
		}
		done <- nil
	}()
	var workers sync.WaitGroup
	for i := range 8 {
		workers.Go(func() {
			for j := range 20 {
				if err := c.write(0, fmt.Appendf(nil, "%d/%d", i, j)); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDTLS13ApplicationBeforeFinished(t *testing.T) {
	c, s := dtls13Pair(t, 0x1301)
	loss := &dtls13TestConn{Conn: c.conn, owner: c, mode: "finished"}
	c.conn = loss
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverDone := make(chan error, 1)
	go func() { serverDone <- s.handshake(ctx) }()
	if err := c.handshake(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c.ready.Store(false)
		s.ready.Store(false)
		c.writeMu.Lock()
		c.v13.clearFlight()
		c.writeMu.Unlock()
	})
	if err := c.write(3, []byte("early")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		t.Fatal("server stopped before Finished retransmission", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	s.conn.SetReadDeadline(time.Now().Add(time.Second))
	if err := c.write(3, []byte("after")); err != nil {
		t.Fatal(err)
	}
	kind, p, err := s.read()
	if err != nil || kind != 3 || string(p) != "after" {
		t.Fatal(kind, string(p), err)
	}
}
