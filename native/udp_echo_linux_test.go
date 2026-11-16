package native

import (
	"bytes"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestUDPEchoBurst(t *testing.T) {
	// Keep the echo reader unscheduled while a concurrency-test-sized burst arrives.
	before := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(before)
	address := echoUDP(t)
	c, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = c.(*net.UDPConn).SetReadBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{42}, 8192)
	for range 16 {
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buffer := make([]byte, len(payload))
	for i := 0; i < 16; i++ {
		n, err := c.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("echo burst received %d/16: %v", i, err)
		}
	}
}
