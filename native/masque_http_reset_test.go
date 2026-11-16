package native

import (
	"context"
	"testing"
	"time"
)

func TestMasqueHTTPResetClosesPhysicalConnection(t *testing.T) {
	s, c := masqueHTTPPair(t, 2, "ip")
	for range 4 {
		conn, e := c.Dial(context.Background(), "udp", echoUDP(t))
		if e != nil {
			t.Fatal(e)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		if _, e = conn.Write([]byte{1}); e != nil {
			t.Fatal(e)
		}
		if _, e = conn.Read(make([]byte, 8)); e != nil {
			t.Fatal(e)
		}
		c.resetNetworkTransports()
		conn.Close()
		for until := time.Now().Add(300 * time.Millisecond); s.Stats().Connections != 0 && time.Now().Before(until); {
			time.Sleep(time.Millisecond)
		}
		if n := s.Stats().Connections; n != 0 {
			t.Fatalf("network reset retained %d physical connections", n)
		}
	}
}
