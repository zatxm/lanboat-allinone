package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type ocTestTLSExporter struct {
	net.Conn
	psk []byte
}

func (c *ocTestTLSExporter) ExportKeyingMaterial(_ string, _ []byte, _ int) ([]byte, error) {
	return bytes.Clone(c.psk), nil
}

func ocWaitDTLS(t *testing.T, tunnel *ocTunnel) *ocDTLS {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tunnel.dtlsMu.Lock()
		d := tunnel.dtls
		tunnel.dtlsMu.Unlock()
		if d != nil && d.ready.Load() {
			return d
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("DTLS did not become authenticated")
	return nil
}

func TestOpenConnectDTLS(t *testing.T) {
	_, c := ocPair(t)
	tunnel, err := c.ocClients["proxy"].session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d := ocWaitDTLS(t, tunnel)
	lateCSTP := makeUDPPacket(netip.MustParseAddr("127.0.0.1"), tunnel.local[0], 53, 65000, []byte{1})
	if !tunnel.handlePacket(0, lateCSTP, nil) || !tunnel.dtlsPath.Load() {
		t.Fatal("queued CSTP reply disabled an authenticated client DTLS channel")
	}
	probe, err := c.Dial(context.Background(), "tcp", relayEchoTCP(t))
	if err != nil {
		t.Fatal(err)
	}
	probe.SetDeadline(time.Now().Add(time.Second))
	if _, err = io.WriteString(probe, "hello"); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	if _, err = io.ReadFull(probe, got); err != nil || string(got) != "hello" {
		t.Fatal("tiny echo", string(got), err)
	}
	probe.Close()
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{0, 1, 511, 4096, 60000})
	assertUDPAddress(t, c, []int{1, 4096, 60000}, masqueEcho(t, "udp", "[::1]:0"))
	if d.sent.Load() == 0 || d.received.Load() == 0 {
		t.Fatal("traffic used CSTP instead of DTLS")
	}
	d.conn.Close()
	deadline := time.Now().Add(time.Second)
	for d.ready.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 4096})
	next := ocWaitDTLS(t, tunnel)
	if next == d {
		t.Fatal("DTLS channel did not renew")
	}
	assertTCP(t, c)
	assertUDPSizes(t, c, []int{1, 4096})
	if next.sent.Load() == 0 || next.received.Load() == 0 {
		t.Fatal("renewed DTLS channel did not carry traffic")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tunnel.finished:
	case <-time.After(time.Second):
		t.Fatal("tunnel workers leaked")
	}
}

func TestOpenConnectDTLSDisabled(t *testing.T) {
	s, c := ocPair(t)
	o := c.config.Outbounds[0]
	o.DisableDTLS = true
	disabled := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	assertTCP(t, disabled)
	tunnel := disabled.ocClients["proxy"].tunnel.Load()
	tunnel.dtlsMu.Lock()
	d := tunnel.dtls
	tunnel.dtlsMu.Unlock()
	if d != nil {
		t.Fatal("disabled DTLS was used")
	}
	s.ocServers["server"].dtls.mu.Lock()
	n := len(s.ocServers["server"].dtls.bindings)
	s.ocServers["server"].dtls.mu.Unlock()
	if n != 0 {
		t.Fatal("disabled client allocated server DTLS state")
	}
}

var _ net.Conn = (*ocDTLSPeer)(nil)

func TestOpenConnectDTLSRecords(t *testing.T) {
	for _, spec := range ocDTLSSuites {
		suite := spec.id
		client := &ocDTLS{client: true, suite: suite, psk: bytes.Repeat([]byte{7}, 32), writeEpoch: 1, ccs: true}
		server := &ocDTLS{suite: suite, psk: bytes.Repeat([]byte{7}, 32), writeEpoch: 1, ccs: true}
		if err := client.keys(); err != nil {
			t.Fatal(err)
		}
		if err := server.keys(); err != nil {
			t.Fatal(err)
		}
		for n := range 2000 {
			data := bytes.Repeat([]byte{byte(n)}, 1+n%1400)
			wire, err := client.record(23, data)
			if err != nil {
				t.Fatal(err)
			}
			for _, index := range []int{0, 5, len(wire) - 1} {
				bad := bytes.Clone(wire)
				bad[index] ^= 1
				if _, _, ok := server.open(bad); ok {
					t.Fatal("tampered record accepted", index)
				}
			}
			kind, got, ok := server.open(wire)
			if !ok || kind != 23 || !bytes.Equal(data, got) {
				t.Fatal("record mismatch", n, kind, len(got), ok)
			}
			if _, _, ok = server.open(wire); ok {
				t.Fatal("replay accepted")
			}
		}
	}
}

func TestOpenConnectDTLSPRF(t *testing.T) {
	// Independently obtained with OpenSSL's TLS1-PRF KDF (secret=010203, seed=040506).
	for _, vector := range []struct {
		hash func() hash.Hash
		want string
	}{{sha256.New, "fd78d759ca39f61855a94ca96740c48a"}, {sha512.New384, "cc6d6eff618bb7eb349a8d149ca9c1aa"}} {
		got := ocDTLSPRF(vector.hash, []byte{1, 2, 3}, "", []byte{4, 5, 6}, 16)
		if hex.EncodeToString(got) != vector.want {
			t.Fatal("TLS1.2 PRF differs from OpenSSL", hex.EncodeToString(got))
		}
	}
}

func TestOpenConnectDTLSFragments(t *testing.T) {
	body := append([]byte{0xfe, 0xfd}, make([]byte, 32)...)
	body = append(body, 0, 0, 0xa8, 0)
	fragment := func(offset, size int) []byte {
		b := ocDTLSHandshakeMessage(2, 0, body)
		putUint24(b[6:9], uint32(offset))
		putUint24(b[9:12], uint32(size))
		return append(b[:12:12], body[offset:offset+size]...)
	}
	d := &ocDTLS{client: true, fragments: map[uint16]*ocDTLSFragment{}}
	if err := d.handshakes(fragment(18, len(body)-18), 0); err != nil || d.stage != 0 {
		t.Fatal("out-of-order fragment", err)
	}
	if err := d.handshakes(fragment(0, 18), 0); err != nil || d.stage != 1 || d.suite != 0xa8 {
		t.Fatal("fragment reassembly", err)
	}
	d = &ocDTLS{client: true, fragments: map[uint16]*ocDTLSFragment{}}
	if err := d.handshakes(fragment(0, 18), 0); err != nil {
		t.Fatal(err)
	}
	conflict := fragment(10, 18)
	conflict[12] ^= 1
	if d.handshakes(conflict, 0) == nil {
		t.Fatal("conflicting fragments accepted")
	}
	for _, wire := range [][]byte{
		ocDTLSHandshakeMessage(20, 0, make([]byte, 12)),
		ocDTLSHandshakeMessage(2, 5, body),
		ocDTLSHandshakeMessage(2, 0, make([]byte, 8193)),
	} {
		d = &ocDTLS{client: true, fragments: map[uint16]*ocDTLSFragment{}}
		if d.handshakes(wire, 0) == nil {
			t.Fatal("invalid epoch, sequence or allocation limit accepted")
		}
	}
}

type ocDTLSTestPacket struct {
	net.PacketConn
	dropFinished atomic.Bool
}

func (p *ocDTLSTestPacket) WriteTo(b []byte, address net.Addr) (int, error) {
	if len(b) > 13 && b[0] == 20 && p.dropFinished.CompareAndSwap(true, false) {
		return len(b), nil
	}
	return p.PacketConn.WriteTo(b, address)
}

type ocDTLSTestConn struct {
	net.Conn
	mode    string
	changed bool
}

func (c *ocDTLSTestConn) Write(b []byte) (int, error) {
	if !c.changed && c.mode == "drop-hello" {
		c.changed = true
		return len(b), nil
	}
	if !c.changed && c.mode == "reorder-finished" {
		var records [][]byte
		for left := b; len(left) >= 13; {
			n := 13 + int(binary.BigEndian.Uint16(left[11:]))
			if n > len(left) {
				break
			}
			records = append(records, left[:n])
			left = left[n:]
		}
		if len(records) == 3 && records[1][0] == 20 {
			c.changed = true
			for _, record := range [][]byte{records[2], records[0], records[1]} {
				if _, err := c.Conn.Write(record); err != nil {
					return 0, err
				}
			}
			return len(b), nil
		}
	}
	return c.Conn.Write(b)
}

func TestOpenConnectDTLSLossAndAuthentication(t *testing.T) {
	for i, spec := range ocDTLSSuites {
		modes := []string{"wrong-secret"}
		if i == 0 {
			modes = []string{"drop-hello", "drop-finished", "reorder-finished", "wrong-secret"}
		}
		for _, mode := range modes {
			t.Run(spec.name+"/"+mode, func(t *testing.T) {
				r := newTestRuntime(t, Config{})
				raw, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				packet := &ocDTLSTestPacket{PacketConn: raw}
				packet.dropFinished.Store(mode == "drop-finished")
				listener := newOCDTLSListener(r, packet)
				listener.suites = []uint16{spec.id}
				left, right := net.Pipe()
				tunnel := newOCTunnel(r, left, "server", []netip.Addr{netip.MustParseAddr("10.44.0.2")}, 1280, "client", time.Hour)
				psk, id := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{8}, 32)
				tunnel.conn = &ocTestTLSExporter{Conn: left, psk: bytes.Clone(psk)}
				listener.bindings[string(id)] = &ocDTLSBinding{tunnel: tunnel}
				done := make(chan struct{})
				go func() { listener.run(); close(done) }()
				tunnel.start()
				t.Cleanup(func() { tunnel.close(); right.Close(); packet.Close(); <-done; <-tunnel.finished })
				conn, err := net.Dial("udp", raw.LocalAddr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				if mode == "wrong-secret" {
					psk[0] ^= 1
				}
				d := &ocDTLS{conn: &ocDTLSTestConn{Conn: conn, mode: mode}, client: true, psk: psk, appID: id, suites: []uint16{spec.id}}
				budget := 5 * time.Second
				if mode == "wrong-secret" {
					budget = 500 * time.Millisecond
				}
				ctx, cancel := context.WithTimeout(context.Background(), budget)
				defer cancel()
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				err = d.handshake(ctx)
				if mode == "wrong-secret" {
					if err == nil || d.ready.Load() {
						t.Fatal("wrong PSK authenticated")
					}
					tunnel.dtlsMu.Lock()
					installed := tunnel.dtls
					tunnel.dtlsMu.Unlock()
					if installed != nil {
						t.Fatal("unauthenticated channel installed")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if err = d.write(3, []byte("alive")); err != nil {
					t.Fatal(err)
				}
				kind, data, err := d.read()
				if err != nil || kind != 4 || string(data) != "alive" {
					t.Fatal(kind, string(data), err)
				}
			})
		}

	}
}

func TestOpenConnectDTLSQueuesAndDeadlines(t *testing.T) {
	p := &ocDTLSPeer{packets: make(chan []byte, 128), done: make(chan struct{}), wake: make(chan struct{}, 1)}
	for range 16 {
		if !p.queue(make([]byte, 16384)) {
			t.Fatal("queue prematurely full")
		}
	}
	if p.queue([]byte{1}) {
		t.Fatal("queue byte bound not enforced")
	}
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	if !p.queue([]byte{1}) {
		t.Fatal("queue accounting not released")
	}
	p.Close()
	if p.queuedBytes != 0 || p.queue([]byte{1}) {
		t.Fatal("close retained queue")
	}
	p = &ocDTLSPeer{packets: make(chan []byte, 128), done: make(chan struct{}), wake: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() { _, err := p.Read(make([]byte, 1)); done <- err }()
	p.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	select {
	case err := <-done:
		if !os.IsTimeout(err) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline did not wake read")
	}
	p.SetReadDeadline(time.Time{})
	if !p.queue([]byte{7}) {
		t.Fatal("queue closed after timeout")
	}
	b := make([]byte, 1)
	if _, err := p.Read(b); err != nil || b[0] != 7 {
		t.Fatal(err, b)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 100 {
				p.queue([]byte{1})
				p.SetReadDeadline(time.Time{})
			}
		})
	}
	workers.Go(func() { p.Close() })
	workers.Wait()
}

func FuzzOpenConnectDTLS(f *testing.F) {
	d := &ocDTLS{client: true, appID: bytes.Repeat([]byte{8}, 32)}
	f.Add(d.hello(nil))
	f.Add([]byte{22, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _, _, _, _ = ocDTLSClientHello(b)
		_, _ = ocDTLSExtensions(b)
		wire := &ocDTLS{client: true, suite: 0xa8, newHash: sha256.New, fragments: map[uint16]*ocDTLSFragment{}, recvNext: 10, stage: 99}
		_, _, _ = wire.open(b)
		_ = wire.handshakes(b, 0)
		_ = wire.handshakes(b, 1)
	})
}
