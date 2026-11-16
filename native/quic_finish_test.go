package native

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestQUICFinishUniStop(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   uint64
		err  error
		ok   bool
	}{
		{"normal-fin", 2, nil, true},
		{"consumed-one-way", 2, &quicStreamStopError{code: 0}, true},
		{"nonzero-stop", 2, &quicStreamStopError{code: 7}, false},
		{"bidirectional-stop", 0, &quicStreamStopError{code: 0}, false},
		{"closed-connection", 2, net.ErrClosed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &quicConn{ctx: context.Background(), ops: make(chan *quicOperation), done: make(chan struct{})}
			s := newQUICStream(c, tc.id)
			done := make(chan struct{})
			go func() { defer close(done); op := <-c.ops; c.finish(op, quicResult{err: tc.err}) }()
			err := s.finishUni()
			<-done
			if (err == nil) != tc.ok {
				t.Fatalf("success=%v,want%v: %v", err == nil, tc.ok, err)
			}
			if !tc.ok && !errors.Is(err, tc.err) {
				t.Fatal("original error was lost")
			}
		})
	}
}

func TestQUICWriteStillReportsNormalStop(t *testing.T) {
	c := &quicConn{ctx: context.Background(), ops: make(chan *quicOperation), done: make(chan struct{})}
	s := newQUICStream(c, 2)
	stopped := &quicStreamStopError{code: 0}
	done := make(chan struct{})
	go func() { defer close(done); op := <-c.ops; c.finish(op, quicResult{err: stopped}) }()
	_, err := s.Write([]byte("message"))
	<-done
	if !errors.Is(err, stopped) {
		t.Fatal("Write suppressed the peer stop", err)
	}
}
