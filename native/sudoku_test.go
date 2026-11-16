package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sudokuTestKey = "lanboat-sudoku-test-secret-32bytes"

func sudokuTestOptions(method, mode string, packed bool) *SudokuOptions {
	pure := !packed
	return &SudokuOptions{Key: sudokuTestKey, AEAD: method, ASCII: mode, PaddingMin: 5, PaddingMax: 15, PureDownlink: &pure}
}

func TestSudokuRoundTrip(t *testing.T) {
	for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
		for _, mode := range []string{"prefer_entropy", "prefer_ascii", "up_ascii_down_entropy", "up_entropy_down_ascii"} {
			for _, packed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/packed=%v", method, mode, packed), func(t *testing.T) {
					o := sudokuTestOptions(method, mode, packed)
					in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					out := testOutbound(t, in, server.Address("server"))
					out.Sudoku = o
					client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{0, 1, 511, 4096, 60000, 65507})
				})
			}
		}
	}
}

func TestSudokuCustomAndPadding(t *testing.T) {
	for _, pattern := range []string{"xpxvvpvv", "ppxvvxvv", "vvpxxvvp"} {
		for _, packed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%v", pattern, packed), func(t *testing.T) {
				o := sudokuTestOptions("chacha20-poly1305", "up_ascii_down_entropy", packed)
				o.CustomTable = pattern
				o.PaddingMin, o.PaddingMax = 100, 100
				in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				out := testOutbound(t, in, server.Address("server"))
				out.Sudoku = o
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{0, 1, 4096, 65507})
			})
		}
	}
}

func startSudokuReference(t *testing.T, config map[string]any) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_SUDOKU")
	if binary == "" {
		t.Skip("set LANBOAT_TEST_SUDOKU for official Sudoku interoperability")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	b, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	log, e := os.Create(filepath.Join(dir, "reference.log"))
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "-c", path)
	cmd.Env = append(os.Environ(), "NO_PROXY=*", "no_proxy=*")
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	})
}

func sudokuReferenceClient(t *testing.T, method, variant, side string, mux bool) *Runtime {
	return sudokuMaskedReferenceClient(t, method, variant, side, mux, "")
}

func sudokuMaskedReferenceClient(t *testing.T, method, variant, side string, mux bool, mask string) *Runtime {
	t.Helper()
	mode := "prefer_entropy"
	if variant == "ascii" {
		mode = "prefer_ascii"
	}
	if variant == "directional" {
		mode = "up_ascii_down_entropy"
	}
	o := sudokuTestOptions(method, mode, strings.Contains(variant, "packed"))
	if strings.Contains(variant, "custom") {
		o.CustomTable = "xpxvvpvv"
	}
	cfg := map[string]any{"mode": "server", "transport": "tcp", "key": o.Key, "aead": method, "ascii": mode, "padding_min": 5, "padding_max": 15, "enable_pure_downlink": *o.PureDownlink, "multiplex": "off", "httpmask": map[string]any{"disable": true}, "custom_table": o.CustomTable}
	if mask != "" {
		o.HTTPMask = &SudokuHTTPMask{Mode: mask, PathRoot: "assets-v1"}
		cfg["httpmask"] = map[string]any{"mode": mask, "path_root": "assets-v1"}
		if mask != "legacy" {
			o.HTTPMask.Host = "cover.example"
			cfg["httpmask"].(map[string]any)["host"] = "cover.example"
		}
	}
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
	if mux {
		cfg["multiplex"] = "on"
	}
	var client *Runtime
	if side == "client" {
		in.ListenPort = unusedPort(t)
		cfg["local_port"] = in.ListenPort
		startSudokuReference(t, cfg)
		addr := portAddress("127.0.0.1", in.ListenPort)
		waitPort(t, addr)
		out := testOutbound(t, in, addr)
		out.Sudoku = o
		out.Multiplex.Enabled = mux
		client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	} else {
		server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		port := unusedPort(t)
		cfg["mode"], cfg["local_port"], cfg["server_address"], cfg["proxy_mode"] = "client", port, server.Address("server"), "global"
		startSudokuReference(t, cfg)
		addr := portAddress("127.0.0.1", port)
		waitPort(t, addr)
		out := testOutbound(t, Inbound{Type: "socks"}, addr)
		out.Username, out.Password = "", ""
		client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	}
	return client
}

func TestSudokuOfficialReference(t *testing.T) {
	for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
		for _, variant := range []string{"entropy", "ascii", "directional", "packed", "custom", "custom-packed"} {
			for _, side := range []string{"client", "server"} {
				t.Run(method+"/"+variant+"/"+side, func(t *testing.T) {
					client := sudokuReferenceClient(t, method, variant, side, false)
					assertTCP(t, client)
					sizes := []int{1, 511, 4096, 60000, 65507}
					if side == "server" {
						sizes[len(sizes)-1] = 65497
					} // SOCKS UDP adds 10 bytes.
					assertUDPSizes(t, client, sizes)
				})
			}
		}
	}
}

func TestSudokuConfigValidation(t *testing.T) {
	for _, o := range []*SudokuOptions{nil, {}, {Key: "short"}, {Key: sudokuTestKey, AEAD: "invalid"}, {Key: sudokuTestKey, ASCII: "invalid"}, {Key: sudokuTestKey, PaddingMin: -1}, {Key: sudokuTestKey, PaddingMax: 101}, {Key: sudokuTestKey, PaddingMin: 3, PaddingMax: 2}, {Key: sudokuTestKey, CustomTable: "xxppppvv"}} {
		cfg := Config{Outbounds: []Outbound{{Type: "sudoku", Tag: "proxy", Server: "127.0.0.1", ServerPort: 1, Sudoku: o}}}
		b, _ := json.Marshal(cfg)
		if _, e := Parse(b); e == nil {
			t.Fatalf("accepted invalid Sudoku options: %+v", o)
		}
	}
}

func TestSudokuRecordAuthentication(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305"} {
		for _, failure := range []string{"tamper", "replay", "wrong-key", "short"} {
			t.Run(method+"/"+failure, func(t *testing.T) {
				send, receive := sudokuBases(sudokuTestKey, nil, nil)
				var wire bytes.Buffer
				writer := newSudokuRecord(&sudokuBufferConn{Buffer: &wire}, method, send, receive)
				if _, e := writer.Write([]byte("secret")); e != nil {
					t.Fatal(e)
				}
				if failure == "tamper" {
					wire.Bytes()[wire.Len()-1] ^= 1
				}
				if failure == "short" {
					wire.Reset()
					wire.Write([]byte{0, 12})
				}
				if failure == "replay" {
					wire.Write(bytes.Clone(wire.Bytes()))
				}
				if failure == "wrong-key" {
					send = make([]byte, 32)
				}
				reader := newSudokuRecord(&sudokuBufferConn{Buffer: &wire}, method, receive, send)
				b := make([]byte, 32)
				if failure == "replay" {
					if _, e := reader.Read(b); e != nil {
						t.Fatal(e)
					}
				}
				if _, e := reader.Read(b); e == nil {
					t.Fatal("accepted invalid record")
				}
				if _, e := reader.Read(b); e == nil {
					t.Fatal("record failure did not persist")
				}
			})
		}
	}
}

type sudokuBufferConn struct {
	net.Conn
	*bytes.Buffer
}

func (c *sudokuBufferConn) Read(p []byte) (int, error)     { return c.Buffer.Read(p) }
func (c *sudokuBufferConn) Write(p []byte) (int, error)    { return c.Buffer.Write(p) }
func (*sudokuBufferConn) Close() error                     { return nil }
func (*sudokuBufferConn) SetDeadline(time.Time) error      { return nil }
func (*sudokuBufferConn) SetReadDeadline(time.Time) error  { return nil }
func (*sudokuBufferConn) SetWriteDeadline(time.Time) error { return nil }

type sudokuBatchCounter struct {
	*sudokuBufferConn
	writes   int
	maxWrite int
}

func (c *sudokuBatchCounter) Write(p []byte) (int, error) {
	c.writes++
	c.maxWrite = max(c.maxWrite, len(p))
	return c.sudokuBufferConn.Write(p)
}

func TestSudokuCodecWriteBatch(t *testing.T) {
	for _, packed := range []bool{false, true} {
		for _, padding := range []int{0, 100} {
			t.Run(fmt.Sprintf("packed=%v/padding=%d", packed, padding), func(t *testing.T) {
				o := sudokuTestOptions("none", "prefer_ascii", packed)
				o.PaddingMin, o.PaddingMax = padding, padding
				if err := o.prepare(); err != nil {
					t.Fatal(err)
				}
				var wire bytes.Buffer
				counter := &sudokuBatchCounter{sudokuBufferConn: &sudokuBufferConn{Buffer: &wire}}
				writer := o.codec(counter, false).Conn
				want := make([]byte, 20000)
				for i := range want {
					want[i] = byte(i)
				}
				if n, err := writer.Write(want); err != nil || n != len(want) {
					t.Fatal(n, err)
				}
				if counter.maxWrite > 65535 {
					t.Fatal("pooled write buffer exceeded", counter.maxWrite)
				}
				if packed && padding == 0 && counter.writes != 1 {
					t.Fatal("packed record was split into synchronous uploads", counter.writes)
				}
				if packed && padding == 100 && counter.writes > 2 {
					t.Fatal("padded packed record was not batched", counter.writes)
				}
				reader := o.codec(&sudokuBufferConn{Buffer: &wire}, true).Conn
				got, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("batched wire roundtrip", len(got), err)
				}
			})
		}
	}
}

func TestSudokuRecordKeyUpdate(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			var wire bytes.Buffer
			a, b := sudokuBases(sudokuTestKey, nil, nil)
			writer := newSudokuRecord(&sudokuBufferConn{Buffer: &wire}, method, a, b)
			writer.rotateAfter = 64
			payload := bytes.Repeat([]byte("K"), 73)
			for range 10 {
				if _, e := writer.Write(payload); e != nil {
					t.Fatal(e)
				}
			}
			reader := newSudokuRecord(&sudokuBufferConn{Buffer: &wire}, method, b, a)
			got, e := io.ReadAll(reader)
			if e != nil || !bytes.Equal(got, bytes.Repeat(payload, 10)) {
				t.Fatalf("key update: %d %v", len(got), e)
			}
		})
	}
}

func TestSudokuUDPShortBufferAndAddresses(t *testing.T) {
	var wire bytes.Buffer
	w := &sudokuPackets{Conn: &sudokuBufferConn{Buffer: &wire}}
	for _, a := range []string{"127.0.0.1:53", "[::1]:54", "domain.test:55", "a:1", "aa:2"} {
		if _, e := w.writePacket([]byte("payload"), a); e != nil {
			t.Fatal(e)
		}
	}
	r := &sudokuPackets{Conn: &sudokuBufferConn{Buffer: &wire}}
	if _, _, e := r.readPacket(make([]byte, 1)); !errors.Is(e, io.ErrShortBuffer) {
		t.Fatal(e)
	}
	for _, a := range []string{"[::1]:54", "domain.test:55", "a:1", "aa:2"} {
		b := make([]byte, 7)
		n, got, e := r.readPacket(b)
		if e != nil || n != 7 || got != a || string(b) != "payload" {
			t.Fatalf("packet %s %s %v", a, got, e)
		}
	}
}

func TestSudokuRejectsHandshakeReplay(t *testing.T) {
	o := sudokuTestOptions("aes-128-gcm", "prefer_entropy", false)
	if e := o.prepare(); e != nil {
		t.Fatal(e)
	}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}}})
	hello := make([]byte, 68)
	binary.BigEndian.PutUint64(hello, uint64(time.Now().Unix()))
	// X25519's base point is a valid peer public value.
	hello[32] = 9
	binary.BigEndian.PutUint32(hello[64:], 5)
	for i := range 2 {
		raw, e := net.Dial("tcp", server.Address("server"))
		if e != nil {
			t.Fatal(e)
		}
		c := o.codec(raw, true)
		c.SetDeadline(time.Now().Add(time.Second))
		if e = sudokuMessage(c, 1, hello); e != nil {
			t.Fatal(e)
		}
		kind, _, e := sudokuReadMessage(c)
		c.Close()
		if i == 0 && (e != nil || kind != 2) {
			t.Fatal(e)
		}
		if i == 1 && e == nil {
			t.Fatal("replayed hello accepted")
		}
	}
}

func TestSudokuRuntimeCancellation(t *testing.T) {
	o := sudokuTestOptions("chacha20-poly1305", "prefer_entropy", false)
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}}})
	in := Inbound{Type: "sudoku"}
	out := testOutbound(t, in, server.Address("server"))
	out.Sudoku = o
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	c, e := client.Dial(context.Background(), "udp", echoUDP(t))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, e := c.Read(make([]byte, 32)); done <- e }()
	client.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("read survived runtime closure")
		}
	case <-time.After(time.Second):
		t.Fatal("runtime close did not interrupt UDP")
	}
}

func TestSudokuTCPHalfClose(t *testing.T) {
	for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			listener, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			done := make(chan error, 1)
			go func() {
				c, e := listener.Accept()
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				b, e := io.ReadAll(c)
				if e == nil && string(b) != "request" {
					e = errors.New("bad half-close request")
				}
				if e == nil {
					e = writeAll(c, []byte("response after EOF"))
				}
				done <- e
			}()
			o := sudokuTestOptions(method, "prefer_entropy", true)
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Sudoku = o
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			c, e := client.Dial(context.Background(), "tcp", listener.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = c.Write([]byte("request")); e != nil {
				t.Fatal(e)
			}
			if e = c.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
				t.Fatal(e)
			}
			b, e := io.ReadAll(c)
			if e != nil || string(b) != "response after EOF" {
				t.Fatalf("half close: %q %v", b, e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestSudokuUDPAssociation(t *testing.T) {
	o := sudokuTestOptions("chacha20-poly1305", "prefer_entropy", true)
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Sudoku = o
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	a, b := echoUDP(t), echoUDP(t)
	c, e := client.Dial(context.Background(), "udp", a)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	carrier := udpCarrier(c)
	if carrier == nil || !multiTargetUDP(out) {
		t.Fatal("multi-destination carrier missing")
	}
	for _, address := range []string{a, b, a, b} {
		if _, e = carrier.writePacket([]byte(address), address); e != nil {
			t.Fatal(e)
		}
		buffer := make([]byte, 128)
		n, from, e := carrier.readPacket(buffer)
		if e != nil || from != address || string(buffer[:n]) != address {
			t.Fatalf("target %s: %s %q %v", address, from, buffer[:n], e)
		}
	}
}

func TestSudokuCodecFragmentation(t *testing.T) {
	o := sudokuTestOptions("none", "prefer_ascii", true)
	if e := o.prepare(); e != nil {
		t.Fatal(e)
	}
	for _, packed := range []bool{false, true} {
		for _, size := range []int{1, 2, 3, 14, 15, 256, 4097} {
			t.Run(fmt.Sprintf("%v/%d", packed, size), func(t *testing.T) {
				var wire bytes.Buffer
				w := o.codec(&sudokuBufferConn{Buffer: &wire}, false).Conn.(*sudokuCodec)
				w.writePacked = packed
				if packed {
					w.writePadding = nil
					for _, b := range w.writeLayout.padding {
						if b != w.writeLayout.marker {
							w.writePadding = append(w.writePadding, b)
						}
					}
				}
				want := make([]byte, size)
				for i := range want {
					want[i] = byte(i)
				}
				for i := 0; i < len(want); i += 17 {
					if _, e := w.Write(want[i:min(i+17, len(want))]); e != nil {
						t.Fatal(e)
					}
				}
				r := o.codec(&sudokuBufferConn{Buffer: &wire}, true).Conn.(*sudokuCodec)
				r.readPacked = packed
				r.reader = bufio.NewReaderSize(&sudokuFragmentReader{Reader: &wire}, 16)
				got, e := io.ReadAll(r)
				if e != nil || !bytes.Equal(got, want) {
					t.Fatalf("fragmented decode: %d %v", len(got), e)
				}
			})
		}
	}
}

type sudokuFragmentReader struct{ io.Reader }

func (r *sudokuFragmentReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:min(len(p), 3)]) }

func TestSudokuTrailingPaddingDoesNotBlock(t *testing.T) {
	for _, packed := range []bool{false, true} {
		t.Run(fmt.Sprint(packed), func(t *testing.T) {
			o := sudokuTestOptions("none", "prefer_entropy", packed)
			o.PaddingMin, o.PaddingMax = 0, 0
			if e := o.prepare(); e != nil {
				t.Fatal(e)
			}
			var wire bytes.Buffer
			encoder := o.codec(&sudokuBufferConn{Buffer: &wire}, false)
			encoder.Write([]byte("one"))
			first := bytes.Clone(wire.Bytes())
			wire.Reset()
			encoder.Write([]byte("two"))
			second := bytes.Clone(wire.Bytes())
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			left.SetDeadline(time.Now().Add(time.Second))
			right.SetDeadline(time.Now().Add(time.Second))
			proceed := make(chan struct{})
			done := make(chan error, 1)
			go func() {
				head := append(first, o.downlink.padding[1])
				head = append(head, second[:2]...)
				e := writeAll(right, head)
				if e == nil {
					<-proceed
					e = writeAll(right, second[2:])
				}
				done <- e
			}()
			reader := o.codec(left, true)
			buf := make([]byte, 6)
			n, e := reader.Read(buf)
			close(proceed)
			if e != nil || n < 3 || string(buf[:3]) != "one" {
				t.Fatalf("buffered payload blocked: %d %v", n, e)
			}
			if _, e = io.ReadFull(reader, buf[n:]); e != nil || string(buf) != "onetwo" {
				t.Fatalf("lost partial clues/bits: %q %v", buf, e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestSudokuRejectsBadClientHello(t *testing.T) {
	for _, kind := range []string{"stale", "future", "invalid-key", "unknown-table", "bad-length", "command"} {
		t.Run(kind, func(t *testing.T) {
			o := sudokuTestOptions("aes-128-gcm", "prefer_entropy", false)
			if e := o.prepare(); e != nil {
				t.Fatal(e)
			}
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			raw, e := net.Dial("tcp", server.Address("server"))
			if e != nil {
				t.Fatal(e)
			}
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(time.Second))
			c := o.codec(raw, true)
			hello := make([]byte, 68)
			binary.BigEndian.PutUint64(hello, uint64(time.Now().Unix()))
			hello[32] = 9
			switch kind {
			case "stale":
				binary.BigEndian.PutUint64(hello, uint64(time.Now().Unix()-61))
			case "future":
				binary.BigEndian.PutUint64(hello, uint64(time.Now().Unix()+61))
			case "invalid-key":
				hello[32] = 0
			case "unknown-table":
				hello = binary.BigEndian.AppendUint32(hello, o.hint^1)
			case "bad-length":
				hello = hello[:60]
			}
			command := byte(1)
			if kind == "command" {
				command = 0x13
			}
			if e = sudokuMessage(c, command, hello); e != nil {
				t.Fatal(e)
			}
			if _, _, e = sudokuReadMessage(c); e == nil {
				t.Fatal("invalid handshake accepted")
			}
		})
	}
}

func FuzzSudokuDecoder(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3})
	f.Add([]byte{128, 0, 32, 64, 96, 1, 33, 65, 97})
	table := newSudokuTable(sudokuTestKey)
	layout, _ := newSudokuLayout(false, "")
	f.Fuzz(func(t *testing.T, b []byte) {
		c := &sudokuCodec{Conn: &sudokuBufferConn{Buffer: bytes.NewBuffer(b)}, table: table, reader: bufio.NewReader(bytes.NewReader(b)), readLayout: layout}
		_, _ = io.ReadAll(io.LimitReader(c, 4096))
	})
}
