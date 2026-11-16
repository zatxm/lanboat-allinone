package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func brookSimpleInbound(t *testing.T, variant string) Inbound {
	t.Helper()
	in := brookInbound(t, variant)
	in.WithoutBrookProtocol = true
	if strings.HasPrefix(variant, "quic") {
		in.Transport = Transport{Type: "quic"}
		in.TLS = certificate(t)
	}
	return in
}

func TestBrookSimpleIndependent(t *testing.T) {
	for _, variant := range []string{"ws", "wss", "quic", "quic-stream"} {
		t.Run(variant, func(t *testing.T) {
			in := brookSimpleInbound(t, variant)
			s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := brookOutbound(t, in, s.Address(in.Tag))
			o.UDPOverStream = variant == "quic-stream"
			c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			assertTCP(t, c)
			sizes := []int{0, 1, 511, 1154}
			v6 := []int{0, 1, 511, 1142}
			if variant != "quic" {
				sizes = append(sizes, 4096, 60000, 65505)
				v6 = append(v6, 4096, 60000)
			}
			assertUDPSizes(t, c, sizes)
			assertUDPAddress(t, c, v6, masqueEcho(t, "udp", "[::1]:0"))
			c.resetNetworkTransports()
			assertTCP(t, c)
			assertUDPSizes(t, c, []int{1, 511})
		})
	}
}

func TestBrookSimpleReference(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_BROOK_SIMPLE")
	if reference == "" {
		t.Fatal("LANBOAT_TEST_BROOK_SIMPLE required: pinned upstream revision with simple protocol")
	}
	t.Setenv("LANBOAT_TEST_BROOK", reference)
	for _, variant := range []string{"ws", "wss", "quic", "quic-stream"} {
		for _, side := range []string{"client", "server"} {
			t.Run(variant+"/"+side, func(t *testing.T) {
				in := brookSimpleInbound(t, variant)
				stream := variant == "quic-stream"
				quic := strings.HasPrefix(variant, "quic")
				sizes := []int{1, 511, 1154}
				if variant != "quic" {
					sizes = append(sizes, 4096, 60000)
				}
				if side == "server" {
					s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					kind := variant + "server"
					if quic {
						kind = "quicserver"
					}
					uri := strings.TrimSuffix(kind, "server") + "://" + s.Address(in.Tag)
					if !quic {
						uri += in.Transport.Path
					}
					q := url.Values{kind: {uri}, "password": {in.Password}, "withoutBrookProtocol": {"true"}, "insecure": {"true"}}
					if stream {
						q.Set("udpoverstream", "true")
					}
					link := "brook://" + kind + "?" + q.Encode()
					assertBrookReferenceServer(t, link, sizes...)
					front := portAddress("127.0.0.1", unusedPort(t))
					startBrookReference(t, "relayoverbrook", "--link", link, "--from", front, "--to", masqueEcho(t, "udp", "[::1]:0"))
					waitPort(t, front)
					assertUDPAddress(t, newTestRuntime(t, Config{}), []int{1, 511, 1142}, front)
					return
				}
				in.ListenPort = unusedPort(t)
				address := portAddress(in.Listen, in.ListenPort)
				args := []string{"wsserver", "--listen", address, "--path", in.Transport.Path}
				if in.TLS.Enabled {
					kind := "wssserver"
					if quic {
						kind = "quicserver"
					}
					dir := t.TempDir()
					cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
					if e := os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600); e != nil {
						t.Fatal(e)
					}
					if e := os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600); e != nil {
						t.Fatal(e)
					}
					args = []string{kind, "--domainaddress", address, "--cert", cert, "--certkey", key}
					if !quic {
						args = append(args, "--path", in.Transport.Path)
					}
				}
				startBrookReference(t, append(args, "--password", in.Password, "--withoutBrookProtocol")...)
				if quic {
					waitPacketPort(t, address)
				} else {
					waitPort(t, address)
				}
				o := brookOutbound(t, in, address)
				o.UDPOverStream = stream
				c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
				assertTCP(t, c)
				assertUDPSizes(t, c, sizes)
				assertUDPAddress(t, c, []int{1, 511, 1142}, masqueEcho(t, "udp", "[::1]:0"))
			})
		}
	}
}

func TestBrookSimpleHeader(t *testing.T) {
	for _, address := range []string{"a:443", "127.0.0.1:443", "[::1]:443", strings.Repeat("a", 255) + ":443"} {
		for _, udp := range []bool{false, true} {
			target, e := encodeAddress(address)
			if e != nil {
				t.Fatal(e)
			}
			b := brookSimpleHeader("private", target, udp)
			network, got, e := brookReadSimpleHeader(bytes.NewReader(b), "private")
			if e != nil || got != address || (network == "udp") != udp {
				t.Fatal(address, network, got, e)
			}
			if _, _, e = brookReadSimpleHeader(bytes.NewReader(b), "wrong"); e == nil {
				t.Fatal("wrong password accepted")
			}
			for _, stamp := range []uint32{uint32(time.Now().Add(-time.Hour).Unix()), uint32(time.Now().Add(time.Hour).Unix())} {
				binary.BigEndian.PutUint32(b[34:], stamp)
				if _, _, e = brookReadSimpleHeader(bytes.NewReader(b), "private"); e == nil {
					t.Fatal("expired/future timestamp accepted")
				}
			}
		}
	}
	for _, size := range []uint16{0, 8, 264, 65535} {
		b := make([]byte, 34)
		h := sha256.Sum256([]byte("private"))
		copy(b, h[:])
		binary.BigEndian.PutUint16(b[32:], size)
		if _, _, e := brookReadSimpleHeader(bytes.NewReader(b), "private"); e == nil {
			t.Fatal("invalid length accepted", size)
		}
	}
}

func TestBrookSimpleConfig(t *testing.T) {
	for _, tr := range []string{"ws", "quic"} {
		o := BrookOptions{WithoutBrookProtocol: true}
		if e := o.validate("brook", "private", Transport{Type: tr}, true); e != nil {
			t.Fatal(e)
		}
		for _, bad := range []BrookOptions{{WithoutBrookProtocol: true, ClientHKDFInfo: "x"}, {WithoutBrookProtocol: true, ServerHKDFInfo: "x"}} {
			if bad.validate("brook", "private", Transport{Type: tr}, true) == nil {
				t.Fatal("ignored HKDF")
			}
		}
	}
	for _, kind := range []string{"socks", "vmess", "naive"} {
		if (BrookOptions{WithoutBrookProtocol: true}).validate(kind, "private", Transport{Type: "ws"}, false) == nil {
			t.Fatal("wrong protocol", kind)
		}
	}
	if (BrookOptions{WithoutBrookProtocol: true}).validate("brook", "private", Transport{}, false) == nil {
		t.Fatal("plain TCP accepted")
	}
	in := brookSimpleInbound(t, "wss")
	out := brookOutbound(t, in, "127.0.0.1:443")
	data, e := json.Marshal(Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{out}})
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := Parse(data)
	if e != nil || !cfg.Inbounds[0].WithoutBrookProtocol || !cfg.Outbounds[0].WithoutBrookProtocol {
		t.Fatal("option lost after serialization", e)
	}
}

type brookPartialConn struct {
	memoryNetConn
	calls, failAt int
}

func (c *brookPartialConn) Read(b []byte) (int, error) {
	c.calls++
	if c.calls == c.failAt {
		return 0, os.ErrDeadlineExceeded
	}
	return c.memoryNetConn.Read(b[:min(1, len(b))])
}

func TestBrookSimplePacketRecords(t *testing.T) {
	var wire bytes.Buffer
	w := &brookSimplePacketConn{Conn: memoryNetConn{bytes.NewReader(nil), &wire}}
	for _, data := range [][]byte{nil, []byte("abc"), bytes.Repeat([]byte("z"), 65505)} {
		if n, e := w.Write(data); e != nil || n != len(data) {
			t.Fatal(n, e)
		}
	}
	if _, e := w.Write(make([]byte, 65506)); e == nil {
		t.Fatal("oversized record accepted")
	}
	for _, failAt := range []int{1, 2, 3, 4, 5, 6} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			conn := &brookPartialConn{memoryNetConn: memoryNetConn{bytes.NewReader(wire.Bytes()), io.Discard}, failAt: failAt}
			r := &brookSimplePacketConn{Conn: conn}
			for _, size := range []int{0, 3, 65505} {
				b := make([]byte, size)
				n, e := r.Read(b)
				if errors.Is(e, os.ErrDeadlineExceeded) {
					n, e = r.Read(b)
				}
				if e != nil || n != size {
					t.Fatal("record deadline recovery", size, n, e)
				}
			}
		})
	}
	r := &brookSimplePacketConn{Conn: readerConn(wire.Bytes())}
	r.Read(nil)
	if _, e := r.Read(make([]byte, 1)); !errors.Is(e, io.ErrShortBuffer) {
		t.Fatal("short buffer", e)
	}
	if n, e := r.Read(make([]byte, 65505)); e != nil || n != 65505 {
		t.Fatal("short buffer corrupted next packet", n, e)
	}
}

func TestBrookSimpleConcurrent(t *testing.T) {
	in := brookSimpleInbound(t, "quic-stream")
	s := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	o := brookOutbound(t, in, s.Address(in.Tag))
	o.UDPOverStream = true
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	target := relayEchoTCP(t)
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Go(func() {
			conn, e := c.Dial(context.Background(), "tcp", target)
			if e != nil {
				t.Error(e)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte{byte(i)}, 35000)
			if e = writeAll(conn, want); e != nil {
				t.Error(e)
				return
			}
			got := make([]byte, len(want))
			if _, e = io.ReadFull(conn, got); e != nil || !bytes.Equal(got, want) {
				t.Error("crossed streams", e)
			}
		})
	}
	workers.Wait()
	conn, e := c.Dial(context.Background(), "tcp", target)
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := conn.Read(make([]byte, 1)); done <- e }()
	c.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("closed read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not unblock reader")
	}
}
