package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func dtls13Pair(t *testing.T, suite uint16) (*ocDTLS, *ocDTLS) {
	t.Helper()
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	// Bind the server to the client's address without consuming its first flight.
	serverAddress := listener.LocalAddr().(*net.UDPAddr)
	listener.Close()
	server, err := net.DialUDP("udp4", serverAddress, client.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	psk := bytes.Repeat([]byte{9}, 32)
	makePeer := func(c net.Conn, isClient bool) *ocDTLS {
		return &ocDTLS{conn: c, client: isClient, psk: bytes.Clone(psk), suites: []uint16{suite}, v13: &dtls13{identity: []byte("lanboat-test")}}
	}
	return makePeer(client, true), makePeer(server, false)
}

func dtls13HandshakePair(t *testing.T, c, s *ocDTLS) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.handshake(ctx) }()
	ce := c.handshake(ctx)
	se := <-done
	if ce != nil || se != nil {
		t.Fatalf("client=%v server=%v", ce, se)
	}
	t.Cleanup(func() {
		c.ready.Store(false)
		s.ready.Store(false)
		c.writeMu.Lock()
		c.v13.clearFlight()
		c.writeMu.Unlock()
		s.writeMu.Lock()
		s.v13.clearFlight()
		s.writeMu.Unlock()
	})
}

func TestDTLS13Handshake(t *testing.T) {
	for _, suite := range []uint16{0x1301, 0x1302, 0x1303} {
		t.Run(fmt.Sprintf("%04x", suite), func(t *testing.T) {
			c, s := dtls13Pair(t, suite)
			dtls13HandshakePair(t, c, s)
			for _, n := range []int{0, 1, 513, 1200} {
				payload := bytes.Repeat([]byte{7}, n)
				if err := c.write(0, payload); err != nil {
					t.Fatal(err)
				}
				s.conn.SetReadDeadline(time.Now().Add(time.Second))
				kind, got, err := s.read()
				if err != nil || kind != 0 || !bytes.Equal(got, payload) {
					t.Fatal("server", kind, len(got), err)
				}
				if err = s.write(0, got); err != nil {
					t.Fatal(err)
				}
				c.conn.SetReadDeadline(time.Now().Add(time.Second))
				kind, got, err = c.read()
				if err != nil || kind != 0 || !bytes.Equal(got, payload) {
					t.Fatal("client", kind, len(got), err)
				}
			}
		})
	}
}

func TestDTLS13WolfSSL(t *testing.T) {
	ref := os.Getenv("LANBOAT_TEST_DTLS13")
	if ref == "" {
		t.Skip("set LANBOAT_TEST_DTLS13 to the external wolfSSL5.8.2 reference")
	}
	for _, v := range []struct {
		id   uint16
		name string
	}{{0x1301, "TLS13-AES128-GCM-SHA256"}, {0x1302, "TLS13-AES256-GCM-SHA384"}, {0x1303, "TLS13-CHACHA20-POLY1305-SHA256"}} {
		for _, role := range []string{"client", "server"} {
			t.Run(fmt.Sprintf("%s-%04x", role, v.id), func(t *testing.T) {
				socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err != nil {
					t.Fatal(err)
				}
				port := socket.LocalAddr().(*net.UDPAddr).Port
				psk := bytes.Repeat([]byte{9}, 32)
				referenceRole := "client"
				if role == "client" {
					referenceRole = "server"
					socket.Close()
				}
				processCtx, processCancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer processCancel()
				cmd := exec.CommandContext(processCtx, ref, referenceRole, fmt.Sprint(port), "lanboat-test", hex.EncodeToString(psk), v.name, "psk-dhe-ku")
				var logs bytes.Buffer
				stdout, pipeErr := cmd.StdoutPipe()
				if pipeErr != nil {
					t.Fatal(pipeErr)
				}
				output := bufio.NewReader(stdout)
				cmd.Stderr = &logs
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { cmd.Process.Kill() })
				var raw net.Conn
				if role == "client" {
					line, e := output.ReadString('\n')
					if e != nil || line != "READY\n" {
						cmd.Process.Kill()
						cmd.Wait()
						t.Fatal("reference not ready", line, e, logs.String())
					}
					raw, err = net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
				} else {
					socket.SetReadDeadline(time.Now().Add(3 * time.Second))
					b := make([]byte, 18432)
					n, from, e := socket.ReadFrom(b)
					if e != nil {
						t.Fatal(e)
					}
					l := newOCDTLSListener(nil, socket)
					peer := &ocDTLSPeer{l: l, remote: from, packets: make(chan []byte, 128), done: make(chan struct{}), wake: make(chan struct{}, 1)}
					peer.queue(b[:n])
					raw = peer
				}
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				defer socket.Close()
				d := &ocDTLS{conn: raw, client: role == "client", psk: psk, suites: []uint16{v.id}, v13: &dtls13{identity: []byte("lanboat-test")}}
				if role == "server" {
					peer := raw.(*ocDTLSPeer)
					go func() {
						b := make([]byte, 18432)
						for {
							n, _, e := socket.ReadFrom(b)
							if e != nil {
								return
							}
							peer.queue(b[:n])
						}
					}()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				if err = d.handshake(ctx); err != nil {
					cmd.Process.Kill()
					cmd.Wait()
					t.Fatalf("handshake %v\n%s", err, logs.String())
				}
				defer func() { d.ready.Store(false); d.writeMu.Lock(); d.v13.clearFlight(); d.writeMu.Unlock() }()
				for i, n := range []int{1, 513, 1200} {
					data := make([]byte, n)
					for j := range data {
						data[j] = byte(j + i)
					}
					raw.SetReadDeadline(time.Now().Add(3 * time.Second))
					// wolfSSL speaks raw DTLS application data, OpenConnect adds one type byte.
					if role == "client" {
						d.writeMu.Lock()
						_, err = d.v13.writeRecord(d.v13.writeEpoch, 23, data)
						d.writeMu.Unlock()
						if err != nil {
							t.Fatal(err)
						}
					}
					kind, got, e := d.read()
					if e != nil {
						cmd.Process.Kill()
						cmd.Wait()
						t.Fatalf("read %v\n%s", e, logs.String())
					}
					received := append([]byte{kind}, got...)
					if !bytes.Equal(received, data) {
						t.Fatal("echo mismatch", len(received), n)
					}
					if role == "server" {
						d.writeMu.Lock()
						_, err = d.v13.writeRecord(d.v13.writeEpoch, 23, received)
						d.writeMu.Unlock()
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				remaining, readErr := io.ReadAll(output)
				if err = cmd.Wait(); err != nil || readErr != nil {
					t.Fatal(err, readErr, logs.String())
				}
				if !bytes.Contains(remaining, []byte("PASS")) {
					t.Fatal(string(remaining), logs.String())
				}
				if d.v13.readEpoch != 4 || d.v13.writeEpoch != 4 {
					t.Fatal("external KeyUpdate was not exercised", d.v13.readEpoch, d.v13.writeEpoch)
				}
			})
		}
	}
}

func TestDTLS13KeyUpdates(t *testing.T) {
	for _, suite := range []uint16{0x1301, 0x1302, 0x1303} {
		t.Run(fmt.Sprintf("%04x", suite), func(t *testing.T) {
			c, s := dtls13Pair(t, suite)
			dtls13HandshakePair(t, c, s)
			exchange := func(sender, receiver *ocDTLS) {
				t.Helper()
				sender.conn.SetDeadline(time.Now().Add(2 * time.Second))
				receiver.conn.SetDeadline(time.Now().Add(2 * time.Second))
				if err := sender.write(3, []byte("alive")); err != nil {
					t.Fatal(err)
				}
				kind, p, err := receiver.read()
				if err != nil || kind != 3 || string(p) != "alive" {
					t.Fatal(kind, string(p), err)
				}
			}
			exchange(c, s)
			exchange(s, c) // Process the last Finished ACK.
			for i := range 12 {
				sender, receiver := c, s
				if i%2 != 0 {
					sender, receiver = s, c
				}
				sender.writeMu.Lock()
				old := sender.v13.writeEpoch
				err := sender.v13.keyUpdateLocked(false)
				sender.writeMu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
				// New traffic keys cannot be used until the peer's authenticated ACK arrives.
				if sender.v13.writeEpoch != old {
					t.Fatal("write epoch changed before ACK")
				}
				exchange(sender, receiver)
				exchange(receiver, sender)
				if sender.v13.writeEpoch != old+1 || receiver.v13.readEpoch != old+1 {
					t.Fatal("KeyUpdate was not acknowledged")
				}
				exchange(sender, receiver)
				if len(receiver.v13.readKeys) != 1 || len(sender.v13.writeKeys) != 1 {
					t.Fatal("old epochs retained", len(receiver.v13.readKeys), len(sender.v13.writeKeys))
				}
			}
		})
	}
}

func TestDTLS13WrongPSK(t *testing.T) {
	c, s := dtls13Pair(t, 0x1301)
	s.psk[0] ^= 1
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.handshake(ctx) }()
	ce := c.handshake(ctx)
	se := <-done
	if ce == nil || se == nil || c.ready.Load() || s.ready.Load() {
		t.Fatal("wrong PSK authenticated", ce, se)
	}
}

func TestDTLS13Fragments(t *testing.T) {
	s, _ := stSuite(0x1301)
	d := new(dtls13)
	d.init(&ocDTLS{client: true})
	d.owner.ready.Store(true)
	d.suite = s
	d.readEpoch = 3
	d.sendNext = 1
	d.readKeys[3], _ = newDTLS13Epoch(s, bytes.Repeat([]byte{9}, 32), 3)
	body := []byte{0}
	fragment := func(offset, n int) []byte {
		b := ocDTLSHandshakeMessage(24, 0, body)
		putUint24(b[6:], uint32(offset))
		putUint24(b[9:], uint32(n))
		return append(b[:12:12], body[offset:offset+n]...)
	}
	if err := d.handshakes(fragment(0, 0), 3); err != nil || d.readEpoch != 3 {
		t.Fatal(err)
	}
	if err := d.handshakes(fragment(0, 1), 3); err != nil || d.readEpoch != 4 {
		t.Fatal(err, d.readEpoch)
	}
	// A ticket can arrive in out-of-order fragments; overlapping bytes must agree.
	ticket := append(make([]byte, 9), 0, 1, 1, 0, 0)
	msg := ocDTLSHandshakeMessage(4, 1, ticket)
	head := bytes.Clone(msg[:12])
	putUint24(head[9:], 5)
	if err := d.handshakes(append(head, ticket[:5]...), 4); err != nil {
		t.Fatal(err)
	}
	tail := bytes.Clone(msg[:12])
	putUint24(tail[6:], 5)
	putUint24(tail[9:], uint32(len(ticket)-5))
	if err := d.handshakes(append(tail, ticket[5:]...), 4); err != nil || d.recvNext != 2 {
		t.Fatal("ticket reassembly", err, d.recvNext)
	}
	binary.BigEndian.PutUint16(head[4:], 2)
	if err := d.handshakes(append(bytes.Clone(head), ticket[:5]...), 4); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Clone(head)
	putUint24(bad[6:], 2)
	bad = append(bad, ticket[2:7]...)
	bad[12] ^= 1
	if d.handshakes(bad, 4) == nil {
		t.Fatal("conflicting fragment accepted")
	}
	for _, wire := range [][]byte{ocDTLSHandshakeMessage(24, 2, make([]byte, 16385)), ocDTLSHandshakeMessage(24, 100, body)} {
		if d.handshakes(wire, 4) == nil {
			t.Fatal("handshake allocation bound ignored")
		}
	}
}

func FuzzDTLS13Record(f *testing.F) {
	s, _ := stSuite(0x1301)
	sender, _ := newDTLS13Epoch(s, bytes.Repeat([]byte{9}, 32), 3)
	wire, _ := sender.seal(23, []byte("data"))
	f.Add(wire)
	f.Add([]byte{})
	f.Add([]byte{0x20, 1})
	f.Fuzz(func(t *testing.T, wire []byte) {
		n := dtls13RecordSize(wire)
		if n == 0 {
			return
		}
		if wire[0]&0xe0 == 0x20 {
			receiver, _ := newDTLS13Epoch(s, bytes.Repeat([]byte{9}, 32), 3)
			receiver.open(wire[:n])
		}
	})
}

func TestDTLS13RejectInvalidHelloParameters(t *testing.T) {
	owner := &ocDTLS{client: true, psk: bytes.Repeat([]byte{7}, 32), suites: []uint16{0x1301}}
	d := new(dtls13)
	d.init(owner)
	d.identity = []byte("lanboat")
	hello, err := d.clientHello(nil)
	if err != nil {
		t.Fatal(err)
	}
	d.transcript = stMessage(1, hello)
	retry := dtls13ServerHello(stRetryRandom, nil, 0x1301, nil, 0, 0, []byte{1})
	extensions := stExtension(bytes.Clone(retry[40:]), 51, []byte{0, 29})
	retry = append(retry[:38:38], stVector(extensions, 2)...)
	if d.clientServerHello(retry) == nil {
		t.Fatal("retry requested an already offered share")
	}
	p := stCursor{data: hello}
	p.take(34)
	p.vector(1)
	p.vector(1)
	p.vector(2)
	p.vector(1)
	for ext := p.vector(2); len(ext) > 0; {
		kind, n := binary.BigEndian.Uint16(ext), int(binary.BigEndian.Uint16(ext[2:]))
		if kind == 10 {
			ext[7] = 23
			break
		}
		ext = ext[4+n:]
	}
	if _, err = parseDTLS13Hello(hello); err == nil {
		t.Fatal("key share absent from supported groups accepted")
	}
}
