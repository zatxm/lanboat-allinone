package native

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"
)

func TestHY2AuthenticationEarlyReadStop(t *testing.T) {
	for _, code := range []uint64{0, 0x100, 0x101} {
		for _, status := range []string{"233", "404", ""} {
			t.Run(fmt.Sprintf("stop%x/status%s", code, status), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				c := &quicConn{ctx: ctx, ready: make(chan struct{}), done: make(chan struct{}), ops: make(chan *quicOperation), wake: make(chan struct{}, 1)}
				close(c.ready)
				var response bytes.Buffer
				if status != "" {
					if err := h3WriteFrame(&response, 1, h3Encode([][2]string{{":status", status}, {"hysteria-udp", "true"}, {"hysteria-cc-rx", "auto"}})); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					for {
						select {
						case op := <-c.ops:
							result := quicResult{}
							switch op.kind {
							case 'o':
								id := uint64(0)
								if op.n != 0 {
									id = 2
								}
								stream := newQUICStream(c, id)
								if id == 0 {
									stream.buffer.put(0, bytes.Clone(response.Bytes()))
									stream.finalKnown = true
									stream.final = uint64(response.Len())
								}
								result.stream = stream
							case 'w':
								result.n = len(op.data)
							case 'f':
								result.err = &quicStreamStopError{code: code}
							}
							c.finish(op, result)
						case <-ctx.Done():
							return
						}
					}
				}()
				s := newQUICProxySession(c, "hysteria2")
				err := s.authenticateHY2(ctx, Outbound{Password: "private"})
				cancel()
				<-done
				want := status == "233" && (code == 0 || code == 0x100)
				if (err == nil) != want {
					t.Fatalf("authenticated=%v,want%v:%v", err == nil, want, err)
				}
			})
		}
	}
}

func TestH3FinishConsumedRequest(t *testing.T) {
	for _, err := range []error{nil, &quicStreamStopError{code: 0x100}, &quicStreamStopError{code: 0}, &quicStreamStopError{code: 0x101}, io.ErrClosedPipe} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c := &quicConn{ctx: ctx, done: make(chan struct{}), ops: make(chan *quicOperation), wake: make(chan struct{}, 1)}
		s := newQUICStream(c, 0)
		go func() {
			select {
			case op := <-c.ops:
				c.finish(op, quicResult{err: err})
			case <-ctx.Done():
			}
		}()
		got := h3FinishRequest(s)
		cancel()
		want := err
		if stop, ok := err.(*quicStreamStopError); ok && (stop.code == 0 || stop.code == 0x100) {
			want = nil
		}
		if got != want {
			t.Fatal("request finish error", err, got, want)
		}
	}
}
