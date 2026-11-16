package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

func dnsStreamFixture(t testing.TB) net.Conn {
	t.Helper()
	config := Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"a.test": {"192.0.2.1"}, strings.Repeat("a", 63) + ".test": {"192.0.2.1"}}}}}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(context.Background(), data, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); _ = r.serveDNSStream(server, "dns") }()
	t.Cleanup(func() { client.Close(); <-done; r.Close() })
	return client
}

func TestDNSStreamSequentialFrames(t *testing.T) {
	conn := dnsStreamFixture(t)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var header [2]byte
	for i := range 30 {
		name := "a.test"
		if i%3 == 1 {
			name = strings.Repeat("a", 63) + ".test"
		}
		query, _ := makeDNSQuery(name, 1)
		binary.BigEndian.PutUint16(query, uint16(i))
		binary.BigEndian.PutUint16(header[:], uint16(len(query)))
		if err := writeAll(conn, append(header[:], query...)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, binary.BigEndian.Uint16(header[:]))
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatal(err)
		}
		ips, _, err := parseDNSReply(query, reply)
		if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.1" {
			t.Fatal("DNS stream framing changed", i, ips, err)
		}
	}
}

func TestDNSListenerShutdownCancelsQuery(t *testing.T) {
	started, canceled := make(chan struct{}), make(chan struct{})
	upstream := dnsTestUpstream(t, "upstream", func(ctx context.Context, _ []byte) []byte {
		close(started)
		<-ctx.Done()
		close(canceled)
		return nil
	})
	r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: "127.0.0.1"}}, DNS: DNSConfig{Servers: []DNSServer{upstream}}})
	conn, err := net.Dial("udp", r.Address("dns"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query, _ := makeDNSQuery("shutdown.test", 1)
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("upstream query did not start")
	}
	done := make(chan struct{})
	go func() { r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for DNS timeout")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("upstream query survived shutdown")
	}
}

func BenchmarkDNSStream(b *testing.B) {
	conn := dnsStreamFixture(b)
	query, _ := makeDNSQuery("a.test", 1)
	var header [2]byte
	reply := make([]byte, 4096)
	exchange := func() {
		binary.BigEndian.PutUint16(header[:], uint16(len(query)))
		if err := writeAll(conn, header[:]); err != nil {
			b.Fatal(err)
		}
		if err := writeAll(conn, query); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, reply[:binary.BigEndian.Uint16(header[:])]); err != nil {
			b.Fatal(err)
		}
	}
	exchange()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		exchange()
	}
}
