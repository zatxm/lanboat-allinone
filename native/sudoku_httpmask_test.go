package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSudokuHTTPMaskRoundTrip(t *testing.T) {
	for _, mask := range []string{"legacy", "ws", "stream", "poll", "auto"} {
		for _, cipher := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
			for _, packed := range []bool{false, true} {
				for _, mux := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/packed=%v/mux=%v", mask, cipher, packed, mux), func(t *testing.T) {
						o := sudokuTestOptions(cipher, "up_ascii_down_entropy", packed)
						o.HTTPMask = &SudokuHTTPMask{Mode: mask, Host: "cover.example", PathRoot: "assets"}
						in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						out := testOutbound(t, in, server.Address("server"))
						out.Sudoku, out.Multiplex.Enabled = o, mux
						client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						assertTCP(t, client)
						assertTCP(t, client)
						assertUDPSizes(t, client, []int{0, 1, 4096, 65507})
						client.resetNetworkTransports()
						assertTCP(t, client)
					})
				}
			}
		}
	}
}

func TestSudokuHTTPMaskOfficialReference(t *testing.T) {
	for _, mask := range []string{"legacy", "ws", "stream", "poll", "auto"} {
		for _, cipher := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
			for _, variant := range []string{"entropy", "custom-packed"} {
				for _, side := range []string{"client", "server"} {
					for _, mux := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s/%s/%s/mux=%v", mask, cipher, variant, side, mux), func(t *testing.T) {
							client := sudokuMaskedReferenceClient(t, cipher, variant, side, mux, mask)
							for range 3 {
								assertTCP(t, client)
								assertUDPSizes(t, client, []int{1, 4096, 60000})
							}
						})
					}
				}
			}
		}
	}
}

func TestSudokuHTTPMaskOfficialHalfClose(t *testing.T) {
	for _, mask := range []string{"legacy", "ws", "stream", "poll", "auto"} {
		for _, side := range []string{"client", "server"} {
			t.Run(mask+"/"+side, func(t *testing.T) {
				assertSudokuHalfClose(t, sudokuMaskedReferenceClient(t, "chacha20-poly1305", "packed", side, true, mask))
			})
		}
	}
}

func TestSudokuHTTPMaskTLS(t *testing.T) {
	for _, mask := range []string{"legacy", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			o := sudokuTestOptions("chacha20-poly1305", "prefer_entropy", true)
			o.HTTPMask = &SudokuHTTPMask{Mode: mask}
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o, TLS: certificate(t)}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Sudoku, out.Multiplex.Enabled = o, true
			out.TLS.Insecure, out.TLS.Certificate = false, in.TLS.Certificate
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 65507})
			out.Tag, out.TLS.Certificate = "untrusted", nil
			bad := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			if c, err := bad.Dial(context.Background(), "tcp", "127.0.0.1:80"); err == nil {
				c.Close()
				t.Fatal("untrusted certificate accepted")
			}
		})
	}
}

func TestSudokuHTTPMaskHandshakeCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	in := Inbound{Type: "sudoku"}
	out := testOutbound(t, in, listener.Addr().String())
	out.Sudoku = sudokuTestOptions("chacha20-poly1305", "", false)
	out.Sudoku.HTTPMask = &SudokuHTTPMask{Mode: "ws"}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		c, err := client.Dial(ctx, "tcp", "127.0.0.1:80")
		if c != nil {
			c.Close()
		}
		result <- err
	}()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(time.Second))
	var header [1]byte
	if _, err = io.ReadFull(peer, header[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err = <-result:
		if err == nil {
			t.Fatal("cancelled upgrade accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled HTTP upgrade blocked")
	}
}

func sudokuHTTPHelloPayload(t testing.TB, o *SudokuOptions, identity ...[]byte) []byte {
	t.Helper()
	if err := o.prepare(); err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, 68)
	binary.BigEndian.PutUint64(hello, uint64(time.Now().Unix()))
	rand.Read(hello[8:32])
	if len(identity) > 0 {
		copy(hello[8:16], identity[0])
	}
	copy(hello[32:64], key.PublicKey().Bytes())
	binary.BigEndian.PutUint32(hello[64:], 7)
	var wire bytes.Buffer
	if err = sudokuMessage(o.codec(&sudokuBufferConn{Buffer: &wire}, true), 1, hello); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func TestSudokuHTTPMaskEarlyAuthentication(t *testing.T) {
	o := sudokuTestOptions("chacha20-poly1305", "", true)
	o.HTTPMask = &SudokuHTTPMask{Mode: "ws"}
	hello := sudokuHTTPHelloPayload(t, o)
	token := sudokuWSAuth(o.Key, time.Now().Unix())
	core := new(Runtime)
	for _, name := range []string{"valid", "replay", "truncated", "tampered"} {
		t.Run(name, func(t *testing.T) {
			payload := bytes.Clone(hello)
			if name == "truncated" {
				payload = payload[:len(payload)/2]
			}
			if name == "tampered" {
				payload[len(payload)/2] ^= 0xff
			}
			request := "GET /ws?auth=" + token + "&ed=" + base64.RawURLEncoding.EncodeToString(payload) + " HTTP/1.1\r\nHost: cover.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
			wire := &sudokuBufferConn{Buffer: bytes.NewBufferString(request)}
			stream, prepared, features, err := core.acceptSudokuHTTPMask(o, wire)
			if name == "valid" {
				if err != nil || prepared == nil || features != 7 || !strings.Contains(wire.String(), "X-Sudoku-Early: ") {
					t.Fatal("early handshake rejected", err, features)
				}
				stream.Close()
			} else if err == nil {
				t.Fatal("invalid early handshake accepted")
			}
		})
	}
}

func TestSudokuHTTPMaskAuth(t *testing.T) {
	const stamp = int64(1700000000)
	token := sudokuWSAuth("golden-key", stamp)
	if token != "AAAAAGVT8QAJHu_Fuwf5lL-TIBqcSaOL" {
		t.Fatal("WebSocket authentication envelope mismatch", token)
	}
	for _, tc := range []struct {
		key, token string
		now        int64
		want       bool
	}{
		{"golden-key", token, stamp, true},
		{"golden-key", "bEaReR " + token, stamp + 60, true},
		{"golden-key", token, stamp - 60, true},
		{"golden-key", token, stamp + 61, false},
		{"golden-key", token, stamp - 61, false},
		{"wrong", token, stamp, false},
		{"golden-key", token[:31], stamp, false},
		{"golden-key", strings.Repeat("_", 32), stamp, false},
		{"golden-key", "", stamp, false},
	} {
		if got := sudokuWSAuthorized(tc.key, tc.token, tc.now); got != tc.want {
			t.Fatal("unexpected authorization", tc.want, got)
		}
	}
}

func TestSudokuHTTPMaskConfig(t *testing.T) {
	for _, m := range []*SudokuHTTPMask{{Mode: "invalid"}, {Host: "bad\r\nHost: injected"}, {PathRoot: "../"}, {PathRoot: "x/y"}, {PathRoot: "x?y"}, {PathRoot: strings.Repeat("x", 129)}} {
		o := sudokuTestOptions("none", "", false)
		o.HTTPMask = m
		b, _ := json.Marshal(Config{Outbounds: []Outbound{{Type: "sudoku", Tag: "proxy", Server: "localhost", ServerPort: 1, Sudoku: o}}})
		if _, err := Parse(b); err == nil {
			t.Fatal("invalid mask accepted", m)
		}
	}
}

func TestSudokuHTTPMaskReject(t *testing.T) {
	token := sudokuWSAuth(sudokuTestKey, time.Now().Unix())
	for _, tc := range []struct{ name, path, headers string }{
		{"missing-auth", "/ws", ""},
		{"wrong-auth", "/ws?auth=bad", ""},
		{"wrong-path", "/other?auth=" + token, ""},
		{"bad-early", "/ws?auth=" + token + "&ed=***", ""},
		{"oversized-early", "/ws?auth=" + token + "&ed=" + base64.RawURLEncoding.EncodeToString(make([]byte, 16385)), ""},
		{"body", "/ws?auth=" + token, "Content-Length: 1\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			o := sudokuTestOptions("none", "", false)
			o.HTTPMask = &SudokuHTTPMask{Mode: "ws"}
			result := make(chan error, 1)
			go func() { _, _, _, err := new(Runtime).acceptSudokuHTTPMask(o, b); result <- err }()
			a.SetDeadline(time.Now().Add(time.Second))
			wire := "GET " + tc.path + " HTTP/1.1\r\nHost: cover.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" + tc.headers + "\r\n"
			if _, err := a.Write([]byte(wire)); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err == nil {
				t.Fatal("invalid mask accepted")
			}
		})
	}
}

func FuzzSudokuHTTPMask(f *testing.F) {
	f.Add([]byte("GET /ws HTTP/1.1\r\nHost: test\r\n\r\n"), true)
	f.Add([]byte("POST / HTTP/1.1\r\nHost: test\r\n\r\n"), false)
	f.Add([]byte{0, 1, 2, 3}, true)
	base := sudokuTestOptions("chacha20-poly1305", "", true)
	hello := sudokuHTTPHelloPayload(f, base)
	request := "GET /ws?auth=" + sudokuWSAuth(base.Key, time.Now().Unix()) + "&ed=" + base64.RawURLEncoding.EncodeToString(hello) + " HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	f.Add([]byte(request), true)
	f.Fuzz(func(t *testing.T, b []byte, ws bool) {
		if len(b) > 65536 {
			return
		}
		options := *base
		o := &options
		o.HTTPMask = &SudokuHTTPMask{Mode: "legacy"}
		if ws {
			o.HTTPMask.Mode = "ws"
		}
		_, _, _, _ = new(Runtime).acceptSudokuHTTPMask(o, &sudokuBufferConn{Buffer: bytes.NewBuffer(b)})
	})
}
