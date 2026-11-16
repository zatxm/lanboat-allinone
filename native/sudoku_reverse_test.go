package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func sudokuReverseOptions(mask, method string, down bool) *SudokuOptions {
	o := sudokuTablesOptions("up_ascii_down_entropy", mask, down)
	o.AEAD = method
	return o
}

func sudokuReverseTarget(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(15 * time.Second))
				io.Copy(c, c)
				c.Write([]byte("reverse-eof"))
			}()
		}
	}()
	return l.Addr().String()
}

func waitSudokuReverse(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			c.SetDeadline(time.Now().Add(300 * time.Millisecond))
			want := []byte("rev!ready")
			err = writeAll(c, want)
			b := make([]byte, len(want))
			if err == nil {
				_, err = io.ReadFull(c, b)
			}
			c.Close()
			if err == nil && bytes.Equal(b, want) {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reverse publication did not become usable")
}

func sudokuReverseTransfer(address string) error {
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	want := bytes.Repeat([]byte("rev!payload\x00\xff"), 8192)
	write := make(chan error, 1)
	go func() { write <- writeAll(c, want) }()
	b := make([]byte, len(want))
	_, err = io.ReadFull(c, b)
	if err != nil {
		return err
	}
	if err = <-write; err != nil {
		return err
	}
	if !bytes.Equal(b, want) {
		return fmt.Errorf("reverse payload mismatch")
	}
	if err = c.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	tail, err := io.ReadAll(c)
	if err != nil {
		return err
	}
	if string(tail) != "reverse-eof" {
		return fmt.Errorf("reverse half-close lost response")
	}
	return nil
}

func nativeSudokuReverse(t *testing.T, mask, method string, down bool, tls bool) (*Runtime, *Runtime, string) {
	t.Helper()
	so := sudokuReverseOptions(mask, method, down)
	so.Key = sudokuPublicVector
	so.Reverse = &SudokuReverse{Listen: "127.0.0.1:0"}
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: so}
	if tls {
		in.TLS = certificate(t)
	}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	co := sudokuReverseOptions(mask, method, down)
	co.Key, co.PrivateKey = "", sudokuSplitVector
	co.Reverse = &SudokuReverse{ClientID: "native-publisher", Routes: []SudokuReverseRoute{{Target: sudokuReverseTarget(t)}}}
	out := testOutbound(t, in, server.Address("server"))
	out.Sudoku = co
	out.Multiplex.Enabled = true
	if tls {
		out.TLS.Insecure, out.TLS.Certificate = false, in.TLS.Certificate
	}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	address := server.SudokuReverseAddress("server")
	if address == "" {
		t.Fatal("missing reverse address")
	}
	waitSudokuReverse(t, address)
	return server, client, address
}

func TestSudokuReverseRoundTrip(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
			for _, down := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/packed-down=%v", mask, method, down), func(t *testing.T) {
					server, client, address := nativeSudokuReverse(t, mask, method, down, false)
					if err := sudokuReverseTransfer(address); err != nil {
						t.Fatal(err)
					}
					// The publication and ordinary client requests share credentials,
					// not physical links or uplink modes.
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{0, 65507})
					client.resetNetworkTransports()
					waitSudokuReverse(t, address)
					if err := sudokuReverseTransfer(address); err != nil {
						t.Fatal(err)
					}
					client.Close()
					server.Close()
				})
			}
		}
	}
}

func TestSudokuReverseOfficialReference(t *testing.T) {
	for mi, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
			for _, side := range []string{"client", "server"} {
				t.Run(mask+"/"+method+"/"+side, func(t *testing.T) {
					down := mi%2 == 0
					target := sudokuReverseTarget(t)
					so := sudokuReverseOptions(mask, method, down)
					so.Key = sudokuPublicVector
					cfg := map[string]any{"mode": "server", "transport": "tcp", "key": sudokuPublicVector, "aead": method, "ascii": so.ASCII, "custom_tables": sudokuTestPatterns,
						"padding_min": 5, "padding_max": 15, "enable_pure_downlink": !down, "multiplex": "off", "httpmask": map[string]any{"disable": true}}
					if mask != "raw" {
						cfg["httpmask"] = map[string]any{"mode": mask, "path_root": "assets-v2"}
					}
					in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: so}
					var address string
					if side == "client" {
						in.ListenPort = unusedPort(t)
						cfg["local_port"] = in.ListenPort
						address = portAddress("127.0.0.1", unusedPort(t))
						cfg["reverse"] = map[string]any{"listen": address}
						startSudokuReference(t, cfg)
						waitPort(t, portAddress("127.0.0.1", in.ListenPort))
						co := sudokuReverseOptions(mask, method, down)
						co.Key, co.PrivateKey = "", sudokuSplitVector
						co.Reverse = &SudokuReverse{Routes: []SudokuReverseRoute{{Target: target}}}
						out := testOutbound(t, in, portAddress("127.0.0.1", in.ListenPort))
						out.Sudoku = co
						newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					} else {
						so.Reverse = &SudokuReverse{Listen: "127.0.0.1:0"}
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						address = server.SudokuReverseAddress("server")
						cfg["mode"], cfg["local_port"], cfg["server_address"], cfg["proxy_mode"], cfg["key"] = "client", unusedPort(t), server.Address("server"), "global", sudokuSplitVector
						cfg["reverse"] = map[string]any{"client_id": "reference-publisher", "routes": []map[string]any{{"path": "", "target": target}}}
						startSudokuReference(t, cfg)
					}
					waitSudokuReverse(t, address)
					if err := sudokuReverseTransfer(address); err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

func TestSudokuReverseTLSConcurrent(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			server, client, address := nativeSudokuReverse(t, mask, "chacha20-poly1305", true, true)
			var workers sync.WaitGroup
			for range 16 {
				workers.Go(func() {
					if err := sudokuReverseTransfer(address); err != nil {
						t.Error(err)
					}
				})
			}
			workers.Wait()
			client.Close()
			server.Close()
		})
	}
}

func TestSudokuReverseConfig(t *testing.T) {
	for _, raw := range []string{`{}`, `{"routes":[]}`, `{"routes":[{"path":"/http","target":"127.0.0.1:80"},{"path":"http/","target":"127.0.0.1:81"}]}`, `{"routes":[{"target":"bad"}]}`, `{"routes":[{"target":"127.0.0.1:80"},{"target":"127.0.0.1:81"}]}`, `{"listen":"127.0.0.1:80","routes":[{"target":"127.0.0.1:80"}]}`, `{"routes":[{"target":"127.0.0.1:80"}],"unknown":true}`, `{"routes":[{"target":"127.0.0.1:80"}]} {}`} {
		if _, err := parseSudokuReverse([]byte(raw)); err == nil {
			t.Fatal("bad registration accepted", raw)
		}
	}
	for _, address := range []string{"", ":80", "127.0.0.1:65536", "127.0.0.1:-1", "bad"} {
		if err := (&SudokuReverse{Listen: address}).validate(false); err == nil {
			t.Fatal("bad listener accepted")
		}
	}
	if err := (&SudokuReverse{Listen: "[::1]:0"}).validate(false); err != nil {
		t.Fatal(err)
	}
	if err := (&SudokuReverse{ClientID: strings.Repeat("x", 129), Routes: []SudokuReverseRoute{{Target: "127.0.0.1:80"}}}).validate(true); err == nil {
		t.Fatal("oversized id")
	}
}

func FuzzSudokuReverseRegistration(f *testing.F) {
	for _, seed := range []string{`{}`, `{"client_id":"a","routes":[{"path":"","target":"127.0.0.1:80"}]}`, `null`, `{"routes":[{"target":"[::1]:443"}]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > sudokuReverseMaxRegistration {
			return
		}
		p, err := parseSudokuReverse([]byte(input))
		if err == nil {
			b, _ := json.Marshal(p)
			if _, err = parseSudokuReverse(b); err != nil {
				t.Fatal(err)
			}
		}
	})
}

// A close during an unresponsive handshake must not wait for its network deadline.
func TestSudokuReverseClosePending(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	o := testOutbound(t, Inbound{Type: "sudoku"}, l.Addr().String())
	o.Sudoku = sudokuReverseOptions("raw", "aes-128-gcm", true)
	o.Sudoku.Reverse = &SudokuReverse{Routes: []SudokuReverseRoute{{Target: "127.0.0.1:80"}}}
	c := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
	l.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
	raw, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pending reverse handshake blocked Close")
	}
	if err := c.ctx.Err(); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestSudokuReverseLifecycle(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			server, client, address := nativeSudokuReverse(t, mask, "chacha20-poly1305", true, false)
			owner := server.sudokuReverseServers["server"]
			owner.mu.Lock()
			original := owner.current
			owner.mu.Unlock()
			// A second authenticated publisher must not replace the active route.
			out := client.outbounds["proxy"]
			second := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			time.Sleep(400 * time.Millisecond)
			owner.mu.Lock()
			if owner.current != original {
				owner.mu.Unlock()
				t.Fatal("duplicate publisher replaced route")
			}
			owner.mu.Unlock()
			second.Close()
			if err := sudokuReverseTransfer(address); err != nil {
				t.Fatal(err)
			}
			client.Close()
			deadline := time.Now().Add(3 * time.Second)
			for {
				owner.mu.Lock()
				empty := owner.current == nil
				owner.mu.Unlock()
				if empty {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("closed publisher retained route")
				}
				time.Sleep(10 * time.Millisecond)
			}
			replacement := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			waitSudokuReverse(t, address)
			if err := sudokuReverseTransfer(address); err != nil {
				t.Fatal(err)
			}
			replacement.Close()
			server.Close()
		})
	}
}

func TestSudokuReverseTargetGuard(t *testing.T) {
	for _, mask := range []string{"raw", "ws", "poll"} {
		t.Run(mask, func(t *testing.T) {
			server, client, address := nativeSudokuReverse(t, mask, "aes-128-gcm", true, false)
			spy, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer spy.Close()
			owner := server.sudokuReverseServers["server"]
			owner.mu.Lock()
			s := owner.current
			owner.mu.Unlock()
			payload, _ := encodeAddress(spy.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			stream, err := s.openPayload(ctx, payload)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			stream.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, err = stream.Read(b[:]); err == nil {
				t.Fatal("unpublished target accepted")
			}
			spy.(*net.TCPListener).SetDeadline(time.Now().Add(100 * time.Millisecond))
			if c, err := spy.Accept(); err == nil {
				c.Close()
				t.Fatal("server made client dial unpublished target")
			}
			if err := sudokuReverseTransfer(address); err != nil {
				t.Fatal(err)
			}
			client.Close()
			server.Close()
		})
	}
}

func TestSudokuReverseIdleKeepalive(t *testing.T) {
	server, client, address := nativeSudokuReverse(t, "auto", "chacha20-poly1305", true, false)
	owner := server.sudokuReverseServers["server"]
	owner.mu.Lock()
	original := owner.current
	owner.mu.Unlock()
	time.Sleep(46 * time.Second)
	owner.mu.Lock()
	same := owner.current == original
	owner.mu.Unlock()
	if !same {
		original.mu.Lock()
		err := original.err
		original.mu.Unlock()
		t.Fatal("idle reverse publication was recycled", err)
	}
	if err := sudokuReverseTransfer(address); err != nil {
		t.Fatal(err)
	}
	client.Close()
	server.Close()
}

func TestSudokuReverseNegotiation(t *testing.T) {
	for _, name := range []string{"classic", "unnegotiated", "disabled", "bad-json", "too-large"} {
		t.Run(name, func(t *testing.T) {
			so := sudokuReverseOptions("raw", "aes-128-gcm", true)
			if name != "disabled" {
				so.Reverse = &SudokuReverse{Listen: "127.0.0.1:0"}
			}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: so}}})
			co := sudokuReverseOptions("raw", "aes-128-gcm", true)
			if err := co.prepareClient(); err != nil {
				t.Fatal(err)
			}
			co.packedUplink = name != "classic" && name != "disabled"
			for _, v := range co.tables {
				v.packedUplink = co.packedUplink
			}
			wire, err := net.DialTimeout("tcp", server.Address("server"), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer wire.Close()
			wire.SetDeadline(time.Now().Add(time.Second))
			features := uint32(15)
			if name == "unnegotiated" {
				features = 7
			}
			c, selected, err := sudokuHandshake(wire, co, features)
			if err != nil {
				t.Fatal(err)
			}
			if name == "disabled" && selected&8 != 0 {
				t.Fatal("disabled reverse negotiated")
			}
			body := []byte(`{"routes":[{"path":"","target":"127.0.0.1:80"}]}`)
			if name == "bad-json" {
				body = []byte(`{"routes":[]}`)
			}
			if name == "too-large" {
				body = bytes.Repeat([]byte("x"), sudokuReverseMaxRegistration+1)
			}
			if err = sudokuMessage(c, 0x13, body); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if _, err = c.Read(b[:]); err == nil {
				t.Fatal("invalid reverse registration accepted")
			}
			if p := server.sudokuReverseServers["server"]; p != nil {
				p.mu.Lock()
				active := p.current != nil
				p.mu.Unlock()
				if active {
					t.Fatal("rejected client published route")
				}
			}
		})
	}
}
