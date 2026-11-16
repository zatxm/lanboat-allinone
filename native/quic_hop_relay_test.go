package native

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHysteriaHopRelayReorderedPath(t *testing.T) {
	ports, _ := testHopRelays(t, echoUDP(t), false)
	old, err := net.Dial("udp", "127.0.0.1:"+strings.Split(ports[0], ":")[0])
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	next, err := net.Dial("udp", "127.0.0.1:"+strings.Split(ports[1], ":")[0])
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	for _, c := range []net.Conn{old, next} {
		c.SetDeadline(time.Now().Add(time.Second))
		if _, err = c.Write([]byte("path")); err != nil {
			t.Fatal(err)
		}
		if _, err = io.ReadFull(c, make([]byte, 4)); err != nil {
			t.Fatal(err)
		}
	}
	// A delayed old-path datagram must not revoke the newer NAT mapping.
	if _, err = old.Write([]byte("late")); err != nil {
		t.Fatal(err)
	}
	old.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, err = old.Read(make([]byte, 4)); err == nil {
		t.Fatal("reordered old packet made retired path active again")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
	if _, err = next.Write([]byte("live")); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(next, make([]byte, 4)); err != nil {
		t.Fatal("current path lost after reordered packet", err)
	}
}
