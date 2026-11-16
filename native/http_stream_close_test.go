package native

import (
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type closeTestWriter struct {
	started, unblock chan struct{}
	finished         atomic.Bool
}

func (w *closeTestWriter) Write([]byte) (int, error) {
	close(w.started)
	<-w.unblock
	w.finished.Store(true)
	return 0, net.ErrClosed
}
func TestHTTPStreamCloseSerializesWriters(t *testing.T) {
	writer := &closeTestWriter{started: make(chan struct{}), unblock: make(chan struct{})}
	var calls atomic.Int32
	c := &httpStreamConn{reader: io.NopCloser(strings.NewReader("")), writer: writer, readDeadline: func(time.Time) error { calls.Add(1); return nil }, writeDeadline: func(time.Time) error { calls.Add(1); return nil }}
	c.close = func() { close(writer.unblock) }
	done := make(chan struct{})
	go func() { c.Write([]byte("x")); close(done) }()
	<-writer.started
	c.Close()
	if !writer.finished.Load() {
		t.Fatal("Close returned before the active writer finished")
	}
	<-done
	if !errors.Is(c.SetReadDeadline(time.Now()), net.ErrClosed) || !errors.Is(c.SetWriteDeadline(time.Now()), net.ErrClosed) || calls.Load() != 0 {
		t.Fatal("accessed expired response controller")
	}
	if _, err := c.Write([]byte("y")); !errors.Is(err, net.ErrClosed) {
		t.Fatal("write after Close accepted")
	}
}
