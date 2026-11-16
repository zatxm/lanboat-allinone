package native

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestAnyTLSReuseMultiplexAndIdleCleanup(t *testing.T) {
	in := testInbound(t, "anytls")
	in.PaddingScheme = []string{"stop=3", "0=16-16", "1=128-128", "2=128-256"}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	minimum := 0
	out.MinIdleSession = &minimum
	out.IdleSessionTimeout = "30ms"
	out.IdleSessionCheckInterval = "10ms"
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	for range 3 {
		assertTCP(t, client)
	}
	pool := client.anyClients["proxy"]
	pool.mu.Lock()
	expected, _ := parseAnyPadding("stop=3\n0=16-16\n1=128-128\n2=128-256")
	if pool.padding.hash != expected.hash {
		pool.mu.Unlock()
		t.Fatal("server padding update was not retained")
	}
	if len(pool.sessions) != 1 {
		pool.mu.Unlock()
		t.Fatal("sequential connections did not reuse a session")
	}
	session := pool.sessions[0]
	pool.mu.Unlock()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var group sync.WaitGroup
	for i := range 20 {
		group.Add(1)
		go func() {
			defer group.Done()
			stream, err := session.open(echo.Addr().String(), "tcp")
			if err != nil {
				t.Error(err)
				return
			}
			defer stream.Close()
			_ = stream.SetDeadline(time.Now().Add(time.Second))
			want := []byte{byte(i), byte(i + 1), byte(i + 2)}
			if err := writeAll(stream, want); err != nil {
				t.Error(err)
				return
			}
			got := make([]byte, len(want))
			if _, err := io.ReadFull(stream, got); err != nil || string(got) != string(want) {
				t.Errorf("multiplex corruption: %x %v", got, err)
			}
		}()
	}
	group.Wait()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		pool.mu.Lock()
		count := len(pool.sessions)
		pool.mu.Unlock()
		if count == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("idle session was not released")
}

func TestAnyTLSPaddingUpdateAndInvalidSettings(t *testing.T) {
	for _, text := range []string{"stop=0\n0=1-2", "stop=1\n0=2-1", "stop=2\n0=c", "stop=2\n0=1-999999", "bad"} {
		if _, err := parseAnyPadding(text); err == nil {
			t.Fatal("invalid padding accepted", text)
		}
	}
	if _, err := parseAnyPadding(defaultAnyPadding + "\n"); err != nil {
		t.Fatal(err)
	}
	in := testInbound(t, "anytls")
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	pool := client.anyClients["proxy"]
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "udp", echoUDP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := c.Read(make([]byte, 8)); err == nil {
		t.Fatal("stream read deadline ignored")
	}
	pool.mu.Lock()
	session := pool.sessions[0]
	pool.mu.Unlock()
	session.close(io.EOF)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}
