package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

func TestSMUXConcurrentHalfClose(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, server := newSMUX(ctx, a, true), newSMUX(ctx, b, false)
	defer client.close(net.ErrClosed)
	defer server.close(net.ErrClosed)
	var handlers sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case c := <-server.accept:
				handlers.Go(func() { defer c.Close(); io.Copy(c, c); c.CloseWrite() })
			case <-server.done:
				return
			}
		}
	}()
	var workers sync.WaitGroup
	for i := range 24 {
		workers.Go(func() {
			c, err := client.open(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 1500000+i)
			written := make(chan error, 1)
			go func() {
				err := writeAll(c, want)
				if err == nil {
					err = c.CloseWrite()
				}
				written <- err
			}()
			got, err := io.ReadAll(c)
			if err != nil || !bytes.Equal(got, want) {
				t.Error("multiplex data or half-close", i, len(got), err)
			}
			if err = <-written; err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	client.close(net.ErrClosed)
	server.close(net.ErrClosed)
	<-done
	handlers.Wait()
}

func TestSMUXQueuedWriteDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	s := newSMUX(context.Background(), a, true)
	defer s.close(net.ErrClosed)
	c := s.newStream(1)
	s.gate <- struct{}{}
	done := make(chan error, 1)
	go func() { _, e := c.Write([]byte("queued")); done <- e }()
	c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	select {
	case e := <-done:
		if !os.IsTimeout(e) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("queued write ignored changed deadline")
	}
	<-s.gate
	if s.ctx.Err() != nil {
		t.Fatal("queued write timeout closed other streams")
	}
}

func TestSMUXStreamIDs(t *testing.T) {
	frame := func(cmd byte, id uint32) []byte {
		h := []byte{1, cmd, 0, 0}
		return binary.LittleEndian.AppendUint32(h, id)
	}
	for _, ids := range [][]uint32{{5, 1, 3}, {1, 3, 1}, {2}} {
		var wire []byte
		for _, id := range ids {
			wire = append(wire, frame(0, id)...)
		}
		s := &smuxSession{version: 1, conn: readerConn(wire), ctx: context.Background(), streams: map[uint32]*smuxStream{}, accept: make(chan *smuxStream, 128), space: make(chan struct{}, 1)}
		err := s.receive()
		if ids[0] == 5 {
			if err != io.EOF || len(s.streams) != 3 {
				t.Fatal("concurrent SYN order rejected", err)
			}
		} else if err == io.EOF {
			t.Fatal("reused or wrong-parity stream accepted")
		}
	}
}

func TestSMUXTinyFrames(t *testing.T) {
	wire := []byte{1, 0, 0, 0, 1, 0, 0, 0}
	for i := range 70000 {
		wire = append(wire, 1, 2, 1, 0, 1, 0, 0, 0, byte(i))
	}
	s := &smuxSession{version: 1, conn: readerConn(wire), ctx: context.Background(), streams: map[uint32]*smuxStream{}, accept: make(chan *smuxStream, 128), space: make(chan struct{}, 1)}
	if err := s.receive(); err != io.EOF {
		t.Fatal(err)
	}
	c := s.streams[1]
	if len(c.queue) > 8 || s.buffered.Load() != 70000 {
		t.Fatal("tiny frames consumed an unbounded number of chunks", len(c.queue), s.buffered.Load())
	}
	c.finish(io.EOF)
	got, err := io.ReadAll(c)
	if err != nil || len(got) != 70000 || s.buffered.Load() != 0 {
		t.Fatal(len(got), err, s.buffered.Load())
	}
	for i, b := range got {
		if b != byte(i) {
			t.Fatal("scratch buffer retained or frame order changed", i)
		}
	}
}

func FuzzRelayAndSMUX(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 0, 0, 0})
	f.Add([]byte{1, 2, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			return
		}
		_, _ = readRelayRequest(bytes.NewReader(data))
		_, _ = readRelayResponse(bytes.NewReader(data))
		s := &smuxSession{version: 1, conn: readerConn(data), ctx: context.Background(), streams: map[uint32]*smuxStream{}, accept: make(chan *smuxStream, 128), space: make(chan struct{}, 1)}
		_ = s.receive()
	})
}
