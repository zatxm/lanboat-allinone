package native

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestMuxCompletedControlDeadline(t *testing.T) {
	for _, protocol := range []muxProtocol{muxSMUX, muxCool, muxSudoku} {
		t.Run(string(rune('0'+protocol)), func(t *testing.T) {
			reader, writer := io.Pipe()
			conn := &httpStreamConn{reader: reader, writer: io.Discard, local: streamAddr("local"), remote: streamAddr("remote"), close: func() { reader.Close(); writer.Close() }}
			s := newMuxConfigured(context.Background(), conn, true, protocol, 1, 0, false)
			defer s.close(net.ErrClosed)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if err := s.send(ctx, 3, 0, nil, nil); err != nil {
				t.Fatal(err)
			}
			timer := time.NewTimer(60 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-s.done:
				t.Fatal("completed control deadline closed idle carrier")
			case <-timer.C:
			}
		})
	}
}
