package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func testQUICListener(t *testing.T, options ...quicOptions) *quicEndpoint {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := certificate(t)
	cert.ALPN = []string{"lanboat-quic-test"}
	cfg, err := cert.config(true, "")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := listenQUIC(context.Background(), packet, cfg, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func TestQUICReceiveBurstBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &quicConn{ctx: ctx, packets: make(chan quicDatagram, quicInboxPackets)}
	packet := bytes.Repeat([]byte{7}, 1024)
	for i := range quicInboxPackets {
		if !c.queuePacket(packet, nil) {
			t.Fatal("burst dropped", i)
		}
	}
	if c.queuePacket(packet, nil) || c.packetBytes != quicInboxBytes {
		t.Fatal("queue exceeded bounds", c.packetBytes)
	}
	packet[0] = 9
	if (<-c.packets).data[0] != 7 {
		t.Fatal("queued data aliases caller")
	}
	// Simulate the owner consuming that packet before testing the independent byte cap.
	c.packetMu.Lock()
	c.packetBytes -= 1024
	c.packetMu.Unlock()
	c.discardPackets()
	large := make([]byte, 65535)
	for i := range 4 {
		if !c.queuePacket(large, nil) {
			t.Fatal(i)
		}
	}
	if c.queuePacket(large, nil) {
		t.Fatal("large datagrams bypassed byte limit")
	}
	cancel()
	c.discardPackets()
	if c.queuePacket(packet, nil) || c.packetBytes != 0 || len(c.packets) != 0 {
		t.Fatal("closed inbox retained data")
	}
}

func TestQUICReceiveFairBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, key, err := quicInitialKeys([]byte("12345678"), false)
	if err != nil {
		t.Fatal(err)
	}
	c := &quicConn{ctx: ctx, cid: []byte("abcdefgh"), established: true, confirmed: true, packets: make(chan quicDatagram, quicInboxPackets), datagrams: make(chan []byte, 128)}
	c.spaces[2] = quicSpace{read: key, largest: -1}
	for i := range 40 {
		wire := sealQUICPacket([]byte{49, 1, byte(i)}, c.cid, nil, nil, 2, uint64(i), false, key)
		if !c.queuePacket(wire, nil) {
			t.Fatal(i)
		}
	}
	if err := c.receiveBurst(); err != nil {
		t.Fatal(err)
	}
	if len(c.packets) != 8 || len(c.datagrams) != 32 || c.packetBytes == 0 {
		t.Fatal("receive batch starved other work", len(c.packets), len(c.datagrams))
	}
	if err := c.receiveBurst(); err != nil {
		t.Fatal(err)
	}
	if len(c.packets) != 0 || c.packetBytes != 0 || c.packetRemote != nil {
		t.Fatal("receive accounting leaked", c.packetBytes)
	}
	for i := range 40 {
		if b := <-c.datagrams; len(b) != 1 || b[0] != byte(i) {
			t.Fatal("data crossed packets", i, b)
		}
	}
}
func testQUICDial(t *testing.T, address string, options ...quicOptions) *quicConn {
	t.Helper()
	raw, err := net.Dial("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialQUIC(ctx, context.Background(), raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"lanboat-quic-test"}}, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}
func TestQUICIndependentStreamsAndDatagrams(t *testing.T) {
	listener := testQUICListener(t)
	client := testQUICDial(t, listener.packet.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			s, e := server.AcceptStream(ctx)
			if e != nil {
				return
			}
			go func() { defer s.Close(); io.Copy(s, s); s.CloseWrite() }()
		}
	}()
	var workers sync.WaitGroup
	for i := range 24 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s, e := client.OpenStream(ctx, false)
			if e != nil {
				t.Error(e)
				return
			}
			defer s.Close()
			s.SetDeadline(time.Now().Add(8 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 300000)
			written := make(chan error, 1)
			go func() {
				e := writeAll(s, want)
				if e == nil {
					e = s.CloseWrite()
				}
				written <- e
			}()
			got, e := io.ReadAll(s)
			if e != nil || !bytes.Equal(got, want) {
				t.Error("QUIC echo", len(got), e)
			}
			if e := <-written; e != nil {
				t.Error(e)
			}
		}()
	}
	workers.Wait()
	// QUIC DATAGRAM is unreliable; retry at the application layer under load.
	dataCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	for range 8 {
		attempt, cancel := context.WithTimeout(dataCtx, 300*time.Millisecond)
		if e := client.SendDatagram(attempt, []byte("native datagram")); e != nil {
			cancel()
			t.Fatal(e)
		}
		b, e := server.ReceiveDatagram(attempt)
		if e == nil && string(b) == "native datagram" {
			e = server.SendDatagram(attempt, b)
		}
		if e == nil {
			b, e = client.ReceiveDatagram(attempt)
		}
		cancel()
		if e == nil && string(b) == "native datagram" {
			return
		}
		if e != nil && !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal(e)
		}
	}
	t.Fatal("QUIC datagram round trip failed after bounded retries")
}

func TestQUICEndpointCloseNotifiesPeer(t *testing.T) {
	listener := testQUICListener(t)
	client := testQUICDial(t, listener.packet.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenStream(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeAll(stream, []byte("waiting")); err != nil {
		t.Fatal(err)
	}
	incoming, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var b [7]byte
	if _, err = io.ReadFull(incoming, b[:]); err != nil {
		t.Fatal(err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.done:
	case <-time.After(time.Second):
		t.Fatal("peer was not notified before UDP close")
	}
}

func TestQUICReference(t *testing.T) {
	for _, algorithm := range []string{"new_reno", "cubic", "bbr"} {
		t.Run(algorithm, func(t *testing.T) {
			testQUICReference(t, quicOptions{cubic: algorithm == "cubic", bbr: algorithm == "bbr"})
		})
	}
}
func testQUICReference(t *testing.T, options quicOptions) {
	reference := os.Getenv("LANBOAT_TEST_QUIC")
	if reference == "" {
		t.Skip("LANBOAT_TEST_QUIC not set")
	}
	t.Run("native-client", func(t *testing.T) {
		p, e := net.ListenPacket("udp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := p.LocalAddr().String()
		p.Close()
		cert := certificate(t)
		dir := t.TempDir()
		cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		os.WriteFile(cp, []byte(strings.Join(cert.Certificate, "\n")), 0600)
		os.WriteFile(kp, []byte(strings.Join(cert.Key, "\n")), 0600)
		cmd := exec.Command(reference, "server", address, cp, kp)
		pipe, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		cmd.Stderr = os.Stderr
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		defer func() { cmd.Process.Kill(); cmd.Wait() }()
		if !bufio.NewScanner(pipe).Scan() {
			t.Fatal("reference not ready")
		}
		c := testQUICDial(t, address, options)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for range 20 {
			s, e := c.OpenStream(ctx, false)
			if e != nil {
				t.Fatal(e)
			}
			s.SetDeadline(time.Now().Add(8 * time.Second))
			want := bytes.Repeat([]byte("q"), 300000)
			done := make(chan error, 1)
			go func() {
				e := writeAll(s, want)
				if e == nil {
					e = s.CloseWrite()
				}
				done <- e
			}()
			got, e := io.ReadAll(s)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal("echo", len(got), e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			s.Close()
		}
		if e := c.SendDatagram(ctx, []byte("oracle")); e != nil {
			t.Fatal(e)
		}
		got, e := c.ReceiveDatagram(ctx)
		if e != nil || string(got) != "oracle" {
			t.Fatal(string(got), e)
		}
	})
	t.Run("native-server", func(t *testing.T) {
		l := testQUICListener(t, options)
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			c, e := l.Accept(ctx)
			if e != nil {
				done <- e
				return
			}
			go func() {
				for {
					d, e := c.ReceiveDatagram(ctx)
					if e != nil {
						return
					}
					c.SendDatagram(ctx, d)
				}
			}()
			for {
				s, e := c.AcceptStream(ctx)
				if e != nil {
					done <- e
					return
				}
				go func() { defer s.Close(); io.Copy(s, s); s.CloseWrite() }()
			}
		}()
		cmd := exec.CommandContext(ctx, reference, "client", l.packet.LocalAddr().String())
		out, e := cmd.CombinedOutput()
		if e != nil || !strings.Contains(string(out), "PASS") {
			t.Fatal(string(out), e)
		}
	})
}

func TestQUICProxyIndependent(t *testing.T) {
	for _, mode := range []string{"hysteria", "hysteria-xplus", "hysteria2", "hysteria2-salamander", "tuic", "tuic-quic", "tuic4", "tuic4-quic"} {
		kind := strings.Split(mode, "-")[0]
		if kind == "tuic4" {
			kind = "tuic"
		}
		t.Run(mode, func(t *testing.T) {
			in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "private"}}}
			if mode == "hysteria2-salamander" {
				in.Obfs = Obfuscation(`{"type":"salamander","password":"mask-password"}`)
			}
			if strings.HasPrefix(mode, "tuic4") {
				in.Version = "4"
			}
			if mode == "hysteria-xplus" {
				in.Obfs = "mask-password"
			}
			in.TLS.ALPN = quicALPN(kind)
			if kind == "hysteria2" {
				in.Users[0].UUID = ""
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
			out := testOutbound(t, in, server.Address("server"))
			out.Obfs = in.Obfs
			out.Version = in.Version
			if mode == "tuic-quic" || mode == "tuic4-quic" {
				out.UDPRelayMode = "quic"
			}
			out.Username = ""
			out.TLS.ALPN = quicALPN(kind)
			if kind == "hysteria2" {
				out.UUID = ""
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			sizes := []int{1, 511, 4096}
			if mode == "tuic4" {
				sizes = []int{1, 511}
			}
			assertUDPSizes(t, client, sizes)
		})
	}
}
func TestQUICProxyReference(t *testing.T) {
	for _, mode := range []string{"hysteria", "hysteria-xplus", "hysteria2", "hysteria2-salamander", "tuic", "tuic-quic"} {
		kind := strings.Split(mode, "-")[0]
		for _, direction := range []string{"client", "server"} {
			t.Run(mode+"/"+direction, func(t *testing.T) {
				in := Inbound{Type: kind, Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{UUID: testUUID, Password: "private"}}}
				if mode == "hysteria2-salamander" {
					in.Obfs = Obfuscation(`{"type":"salamander","password":"mask-password"}`)
				}
				if mode == "hysteria-xplus" {
					in.Obfs = "mask-password"
				}
				in.TLS.ALPN = quicALPN(kind)
				if kind == "hysteria2" {
					in.Users[0].UUID = ""
				}
				var client *Runtime
				if direction == "client" {
					in.ListenPort = unusedPort(t)
					ready := Inbound{Type: "mixed", Tag: "ready", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{ready, in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, portAddress(in.Listen, in.ListenPort))
					if kind == "tuic" {
						out.UUID = testUUID
					}
					out.Obfs = in.Obfs
					if mode == "tuic-quic" {
						out.UDPRelayMode = "quic"
					}
					out.Username = ""
					out.TLS.ALPN = quicALPN(kind)
					if kind == "hysteria2" {
						out.UUID = ""
					}
					client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
					out := testOutbound(t, in, server.Address("server"))
					out.Obfs = in.Obfs
					if mode == "tuic-quic" {
						out.UDPRelayMode = "quic"
					}
					out.Username = ""
					out.TLS.ALPN = quicALPN(kind)
					if kind == "hysteria2" {
						out.UUID = ""
					}
					local := Inbound{Type: "mixed", Tag: "local", Listen: "127.0.0.1", ListenPort: unusedPort(t)}
					referenceRuntime(t, Config{Inbounds: []Inbound{local}, Outbounds: []Outbound{out}, Route: Route{Final: "proxy"}})
					front := testOutbound(t, local, portAddress(local.Listen, local.ListenPort))
					front.Username, front.Password, front.UUID = "", "", ""
					client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
				}
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096})
			})
		}
	}
}

func TestQUICBatchSegments(t *testing.T) {
	type send struct {
		data    []byte
		segment int
	}
	var sends []send
	fail := false
	b := &quicBatch{
		write: func(buffer, control []byte) error {
			if fail {
				return errors.New("offload rejected")
			}
			sends = append(sends, send{bytes.Clone(buffer), len(buffer)})
			return nil
		},
		single: func(p []byte) error { sends = append(sends, send{bytes.Clone(p), -1}); return nil },
	}
	packet := func(size int, fill byte) []byte { return bytes.Repeat([]byte{fill}, size) }
	// Equal packets coalesce; a shorter packet closes the batch as its last segment.
	for _, p := range [][]byte{packet(100, 1), packet(100, 2), packet(60, 3), packet(100, 4)} {
		if err := b.add(p); err != nil {
			t.Fatal(err)
		}
	}
	// A larger packet cannot follow smaller segments and starts a new batch.
	if err := b.add(packet(120, 5)); err != nil {
		t.Fatal(err)
	}
	if err := b.flush(); err != nil {
		t.Fatal(err)
	}
	want := [][]byte{append(append(packet(100, 1), packet(100, 2)...), packet(60, 3)...), packet(100, 4), packet(120, 5)}
	if len(sends) != len(want) || sends[0].segment != 260 || sends[1].segment != -1 || sends[2].segment != -1 {
		t.Fatalf("unexpected sends: %d", len(sends))
	}
	for i := range want {
		if !bytes.Equal(sends[i].data, want[i]) {
			t.Fatalf("send %d mismatch", i)
		}
	}
	// A rejected offload send falls back to individual packets permanently.
	sends, fail = nil, true
	for _, p := range [][]byte{packet(80, 6), packet(80, 7)} {
		if err := b.add(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.flush(); err != nil {
		t.Fatal(err)
	}
	fail = false
	if err := b.add(packet(80, 8)); err != nil {
		t.Fatal(err)
	}
	if !b.disabled || len(sends) != 3 || sends[0].segment != -1 || !bytes.Equal(sends[1].data, packet(80, 7)) || !bytes.Equal(sends[2].data, packet(80, 8)) {
		t.Fatalf("offload failure did not fall back: %d %v", len(sends), b.disabled)
	}
}

func TestQUICReceiveWindowOptions(t *testing.T) {
	for _, tc := range []struct {
		windows string
		ok      bool
	}{
		{`"stream_receive_window":"2MB","connection_receive_window":"8MiB"`, true},
		{`"stream_receive_window":524288`, true},
		{`"connection_receive_window":"512KB"`, false}, // below the 1MiB default stream window
		{`"stream_receive_window":"8MB"`, false},       // above the 4MiB default connection window
		{`"stream_receive_window":"8KB"`, false},
		{`"connection_receive_window":"65MB"`, false},
	} {
		raw := `{"outbounds":[{"type":"hysteria2","tag":"proxy","server":"127.0.0.1","server_port":443,"password":"p","tls":{"enabled":true,"insecure":true},` + tc.windows + `}]}`
		r, err := New(context.Background(), []byte(raw), zap.NewNop())
		if r != nil {
			r.Close()
		}
		if (err == nil) != tc.ok {
			t.Fatalf("%s: %v", tc.windows, err)
		}
	}
	in := Inbound{Type: "hysteria2", Tag: "server", Listen: "127.0.0.1", TLS: certificate(t), Users: []User{{Password: "private"}}}
	in.QUICReceiveWindows = QUICReceiveWindows{StreamReceiveWindow: 2 << 20, ConnectionReceiveWindow: 8 << 20}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.QUICReceiveWindows = QUICReceiveWindows{StreamReceiveWindow: 512 << 10, ConnectionReceiveWindow: 2 << 20}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	assertTCP(t, client)
	s, err := client.quicClients["proxy"].session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := s.conn
	if c.streamWindow != 512<<10 || c.connectionWindow != 2<<20 || c.peer.bidiRemote != 2<<20 || c.peer.maxData < 8<<20 {
		t.Fatal("receive windows not applied", c.streamWindow, c.connectionWindow, c.peer.bidiRemote, c.peer.maxData)
	}
}
