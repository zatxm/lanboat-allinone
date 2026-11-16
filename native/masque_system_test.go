package native

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type masqueBlockedWriter struct {
	net.Conn
	entered chan struct{}
}

func TestMasqueSystemQueueIsolation(t *testing.T) {
	r := newTestRuntime(t, Config{})
	m := newMasqueHTTPSession(context.Background())
	s := &masqueSystemInterface{}
	var stacks []*wgIPStack
	defer func() {
		m.close()
		m.workers.Wait()
		for _, stack := range stacks {
			stack.close()
		}
	}()
	newPeer := func() (*masqueIP, *masqueBlockedWriter, net.Conn) {
		a, b := net.Pipe()
		t.Cleanup(func() { b.Close() })
		c := &masqueBlockedWriter{Conn: a, entered: make(chan struct{})}
		f, err := m.registerFlow(c, uint64(len(stacks)+1), c)
		if err != nil {
			t.Fatal(err)
		}
		p := newMasqueIP(r, f, "", true, 65535, []string{"10.44.0.2/32"}, []string{"10.44.0.1/24"}, "", nil)
		stacks = append(stacks, p.stack)
		return p, c, b
	}
	packet := makeUDPPacket(netip.MustParseAddr("10.44.0.1"), netip.MustParseAddr("10.44.0.2"), 1, 2, []byte("ready peer"))
	slow, blocked, _ := newPeer()
	slow.enqueueSystem(s, packet)
	<-blocked.entered
	fast, _, reader := newPeer()
	fast.enqueueSystem(s, packet)
	reader.SetReadDeadline(time.Now().Add(time.Second))
	kind, err := readQUICVar(reader)
	if err != nil || kind != 0 {
		t.Fatal("slow peer blocked another session", kind, err)
	}
	length, err := readQUICVar(reader)
	if err != nil || length != uint64(len(packet)+1) {
		t.Fatal(length, err)
	}
	got := make([]byte, length)
	if _, err = io.ReadFull(reader, got); err != nil || got[0] != 0 || !bytes.Equal(got[1:], packet) {
		t.Fatal("isolated session payload", err)
	}
	large := makeUDPPacket(netip.MustParseAddr("10.44.0.1"), netip.MustParseAddr("10.44.0.2"), 1, 2, bytes.Repeat([]byte{42}, 60000))
	for range 100 {
		slow.enqueueSystem(s, large)
	}
	slow.systemOutputMu.Lock()
	queued := slow.systemQueued
	slow.systemOutputMu.Unlock()
	if queued > 128<<10 || queued < 120000 {
		t.Fatal("per-session queue budget", queued)
	}
	if count := testing.AllocsPerRun(100, func() { slow.enqueueSystem(s, large) }); count != 0 {
		t.Fatal("dropping over-budget packets allocated memory", count)
	}
	for range 24 {
		p, _, _ := newPeer()
		for range 10 {
			p.enqueueSystem(s, large)
		}
	}
	if used := s.buffered.Load(); used > 2<<20 || used < 1<<20 {
		t.Fatal("shared queue budget", used)
	}
	m.close()
	m.workers.Wait()
	if used := s.buffered.Load(); used != 0 {
		t.Fatal("closed queues leaked shared capacity", used)
	}
}

func (c *masqueBlockedWriter) Write(b []byte) (int, error) {
	select {
	case <-c.entered:
	default:
		close(c.entered)
	}
	return c.Conn.Write(b)
}

func TestMasqueSystemCloseBlockedPeer(t *testing.T) {
	r := newTestRuntime(t, Config{})
	m := newMasqueHTTPSession(context.Background())
	defer m.close()
	a, b := net.Pipe()
	defer b.Close()
	c := &masqueBlockedWriter{Conn: a, entered: make(chan struct{})}
	f, err := m.registerFlow(c, 1, c)
	if err != nil {
		t.Fatal(err)
	}
	p := newMasqueIP(r, f, "", true, 1280, []string{"10.44.0.2/32"}, []string{"10.44.0.1/24"}, "", nil)
	defer p.stack.close()
	s := newMasqueServer(Inbound{})
	s.system = &masqueSystemInterface{tun: &tunTunnel{device: &packetDevice{}}}
	s.attach(f, p)
	s.system.jobs.Add(1)
	go func() {
		defer s.system.jobs.Done()
		_ = p.writePacket(makeUDPPacket(netip.MustParseAddr("10.44.0.1"), netip.MustParseAddr("10.44.0.2"), 1, 2, []byte("slow peer")))
	}()
	<-c.entered
	done := make(chan struct{})
	go func() { s.closeSystem(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		f.Close()
		<-done
		t.Fatal("system interface shutdown waited for a non-reading peer")
	}
	if _, err = s.allocate(f); err == nil {
		t.Fatal("server allocated an address while closing")
	}
	if peer := s.systemPeer(netip.MustParseAddr("10.44.0.2"), 17); peer != nil {
		t.Fatal("closed system interface still selected a peer")
	}
	late, err := m.registerFlow(c, 2, c)
	if err != nil {
		t.Fatal(err)
	}
	s.attach(late, p)
	if !late.isClosed() {
		t.Fatal("server accepted a late session while closing")
	}
}
