package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type dtls12RekeyFault struct {
	net.Conn
	mode       string
	nth, calls int
	changed    bool
}

func (c *dtls12RekeyFault) Write(b []byte) (int, error) {
	c.calls++
	if c.changed || c.calls != c.nth {
		return c.Conn.Write(b)
	}
	c.changed = true
	if c.mode == "drop" {
		return len(b), nil
	}
	var records [][]byte
	for rest := b; len(rest) >= 13; {
		n := 13 + int(binary.BigEndian.Uint16(rest[11:]))
		if n > len(rest) {
			return 0, errors.New("bad test datagram")
		}
		records = append(records, rest[:n])
		rest = rest[n:]
	}
	if len(records) != 3 || records[0][0] != 22 || records[1][0] != 20 || records[2][0] != 22 {
		return 0, errors.New("test did not find CKE/CCS/Finished")
	}
	order := []int{1, 0, 2}
	if c.mode == "finished-first" {
		order = []int{2, 1, 0}
	}
	for _, i := range order {
		if _, err := c.Conn.Write(records[i]); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

func TestDTLS12RenegotiationLoss(t *testing.T) {
	for _, v := range []struct {
		name   string
		client bool
		nth    int
		mode   string
	}{
		{"client-hello", true, 1, "drop"},
		{"server-hello", false, 1, "drop"},
		{"client-finished", true, 2, "drop"},
		{"server-finished", false, 2, "drop"},
		{"ccs-before-cke", true, 2, "ccs-first"},
		{"finished-before-ccs", true, 2, "finished-first"},
	} {
		t.Run(v.name, func(t *testing.T) {
			c, s := dtls12Pair(t, 0xa8)
			target := s
			if v.client {
				target = c
			}
			fault := &dtls12RekeyFault{Conn: target.conn, nth: v.nth, mode: v.mode}
			target.conn = fault
			dtls12RekeyRound(t, c, s)
			if !fault.changed {
				t.Fatal("fault was not exercised")
			}
		})
	}
}

func TestDTLS12RenegotiationSimultaneous(t *testing.T) {
	c, s := dtls12Pair(t, 0xa9)
	for round := range 10 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		done := make(chan error, 2)
		start := make(chan struct{})
		for _, d := range []*ocDTLS{c, s} {
			go func() { <-start; done <- d.renegotiate(ctx, nil) }()
		}
		close(start)
		e1, e2 := <-done, <-done
		cancel()
		if e1 != nil || e2 != nil {
			t.Fatal(round, e1, e2)
		}
	}
	dtls12RekeyRound(t, c, s)
}

func TestDTLS12RenegotiationCancelled(t *testing.T) {
	c, _ := dtls12Pair(t, 0xa8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.renegotiate(ctx, nil) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil || c.ready.Load() || !bytes.Equal(c.secret[:], make([]byte, 32)) {
			t.Fatal("cancelled handshake remained live", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt handshake")
	}
}

func TestDTLS12RenegotiationConcurrentWrites(t *testing.T) {
	c, s := dtls12Pair(t, 0xccab)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var writers sync.WaitGroup
	done := make(chan error, 1)
	go func() {
		for count := 0; ; count++ {
			kind, body, err := s.read()
			if err != nil {
				done <- err
				return
			}
			if kind == 4 && count == 16 {
				done <- nil
				return
			}
			if kind != 3 || len(body) != 513 {
				done <- errors.New("bad concurrent payload")
				return
			}
		}
	}()
	for round := range 4 {
		for i := range 4 {
			writers.Add(1)
			go func() {
				defer writers.Done()
				if err := c.write(3, bytes.Repeat([]byte{byte(round + i)}, 513)); err != nil {
					t.Error(err)
				}
			}()
		}
		if err := c.renegotiate(ctx, nil); err != nil {
			t.Fatal(err)
		}
	}
	writers.Wait()
	if err := c.write(4, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("concurrent writes stalled")
	}
}
