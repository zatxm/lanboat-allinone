package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

var sudokuTestPatterns = []string{"xpxvvpvv", "ppxvvxvv", "vvpxxvvp"}

func sudokuTablesOptions(mode, mask string, packed bool) *SudokuOptions {
	o := sudokuTestOptions("chacha20-poly1305", mode, packed)
	o.CustomTables = append([]string(nil), sudokuTestPatterns...)
	if mask != "raw" {
		o.HTTPMask = &SudokuHTTPMask{Mode: mask, PathRoot: "assets-v2"}
	}
	return o
}

func TestSudokuTablesConfig(t *testing.T) {
	for _, mode := range []string{"prefer_entropy", "prefer_ascii", "up_ascii_down_entropy", "up_entropy_down_ascii"} {
		t.Run(mode, func(t *testing.T) {
			o := sudokuTablesOptions(mode, "raw", false)
			if err := o.prepare(); err != nil {
				t.Fatal(err)
			}
			count := 3
			if mode == "prefer_ascii" {
				count = 1
			}
			if len(o.tables) != count {
				t.Fatal("distinct layouts", len(o.tables), count)
			}
			for _, variant := range o.acceptTables {
				if variant.table != o.table {
					t.Fatal("grid permutation copied per layout")
				}
			}
			if mode == "prefer_entropy" || mode == "up_entropy_down_ascii" {
				if len(o.acceptTables) != 4 || o.acceptTables[0].CustomTable != "" {
					t.Fatal("missing legacy default table")
				}
			}
		})
	}
	for _, name := range []string{"conflict", "invalid", "too-many", "duplicate", "empty"} {
		t.Run(name, func(t *testing.T) {
			o := sudokuTablesOptions("prefer_entropy", "raw", false)
			switch name {
			case "conflict":
				o.CustomTable = sudokuTestPatterns[0]
			case "invalid":
				o.CustomTables[1] = "xxppppvv"
			case "too-many":
				o.CustomTables = make([]string, 17)
			case "duplicate":
				o.CustomTables = []string{" XPXVVPVV ", "xpxvvpvv"}
			case "empty":
				o.CustomTables = []string{"", sudokuTestPatterns[0]}
			}
			err := o.prepare()
			if name == "duplicate" || name == "empty" {
				if err != nil {
					t.Fatal(err)
				}
				want := 1
				if name == "empty" {
					want = 2
				}
				if len(o.tables) != want {
					t.Fatal("deduplication", len(o.tables))
				}
			} else if err == nil {
				t.Fatal("invalid table list accepted")
			}
		})
	}
}

func TestSudokuTablesRoundTrip(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for _, mode := range []string{"prefer_entropy", "prefer_ascii", "up_ascii_down_entropy", "up_entropy_down_ascii"} {
			for _, mux := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/mux=%v", mask, mode, mux), func(t *testing.T) {
					options := sudokuTablesOptions(mode, mask, mux)
					in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: options}
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					for _, pattern := range sudokuTestPatterns {
						o := *options
						o.CustomTables = []string{pattern}
						out := testOutbound(t, in, server.Address("server"))
						out.Sudoku = &o
						out.Multiplex.Enabled = mux
						client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						assertTCP(t, client)
						assertUDPSizes(t, client, []int{0, 4096, 65507})
						if mask != "ws" || mux {
							assertSudokuHalfClose(t, client)
						}
						client.resetNetworkTransports()
						assertTCP(t, client)
						client.Close()
					}
				})
			}
		}
	}
}

func TestSudokuTablesOfficialReference(t *testing.T) {
	for mi, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for ai, mode := range []string{"prefer_entropy", "prefer_ascii", "up_ascii_down_entropy", "up_entropy_down_ascii"} {
			for _, side := range []string{"client", "server"} {
				t.Run(mask+"/"+mode+"/"+side, func(t *testing.T) {
					method := []string{"none", "aes-128-gcm", "chacha20-poly1305"}[mi%3]
					mux := ai%2 == 0
					packed := mi%2 == 0
					for _, pattern := range sudokuTestPatterns {
						o := sudokuTablesOptions(mode, mask, packed)
						o.AEAD = method
						cfg := map[string]any{"mode": "server", "transport": "tcp", "key": o.Key, "aead": method, "ascii": mode, "custom_tables": sudokuTestPatterns,
							"padding_min": 5, "padding_max": 15, "enable_pure_downlink": !packed, "multiplex": "off", "httpmask": map[string]any{"disable": true}}
						if mask != "raw" {
							cfg["httpmask"] = map[string]any{"mode": mask, "path_root": "assets-v2"}
						}
						if mux {
							cfg["multiplex"] = "on"
						}
						in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
						var client *Runtime
						if side == "client" {
							in.ListenPort = unusedPort(t)
							cfg["local_port"] = in.ListenPort
							startSudokuReference(t, cfg)
							address := portAddress("127.0.0.1", in.ListenPort)
							waitPort(t, address)
							o.CustomTables = []string{pattern}
							out := testOutbound(t, in, address)
							out.Sudoku = o
							out.Multiplex.Enabled = mux
							client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						} else {
							server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
							port := unusedPort(t)
							cfg["mode"], cfg["local_port"], cfg["server_address"], cfg["proxy_mode"] = "client", port, server.Address("server"), "global"
							// Two identical entries force an explicit KIP table hint in the reference.
							cfg["custom_tables"] = []string{pattern, pattern}
							startSudokuReference(t, cfg)
							address := portAddress("127.0.0.1", port)
							waitPort(t, address)
							out := testOutbound(t, Inbound{Type: "socks"}, address)
							out.Username, out.Password = "", ""
							client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						}
						assertTCP(t, client)
						assertUDPSizes(t, client, []int{1, 4096, 60000})
						if mux || mask != "ws" {
							assertSudokuHalfClose(t, client)
						}
						client.Close()
					}
				})
			}
		}
	}
}

func TestSudokuTablesRotation(t *testing.T) {
	o := sudokuTablesOptions("up_ascii_down_entropy", "raw", true)
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	if err := o.prepare(); err != nil {
		t.Fatal(err)
	}
	seen := map[uint32]bool{}
	for range 128 {
		wire, err := net.DialTimeout("tcp", server.Address("server"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		wire.SetDeadline(time.Now().Add(3 * time.Second))
		c, _, err := sudokuHandshake(wire, o, 1)
		wire.Close()
		if err != nil {
			t.Fatal(err)
		}
		seen[c.options.hint] = true
	}
	if len(seen) != len(o.tables) {
		t.Fatal("connections did not rotate among all configured layouts", len(seen))
	}
}

func TestSudokuTablesTLSConcurrent(t *testing.T) {
	for _, mask := range []string{"raw", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			options := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: options, TLS: certificate(t)}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			o := *options
			o.CustomTables = append([]string(nil), options.CustomTables...)
			out := testOutbound(t, in, server.Address("server"))
			out.Sudoku = &o
			out.TLS.Insecure, out.TLS.Certificate = false, in.TLS.Certificate
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			target := sudokuTCPEcho(t)
			var workers sync.WaitGroup
			for i := range 12 {
				workers.Go(func() {
					c, err := client.Dial(context.Background(), "tcp", target)
					if err != nil {
						t.Error(err)
						return
					}
					defer c.Close()
					c.SetDeadline(time.Now().Add(10 * time.Second))
					data := bytes.Repeat([]byte{byte(i)}, 4096)
					if err := writeAll(c, data); err != nil {
						t.Error(err)
						return
					}
					read := make([]byte, len(data))
					if _, err := io.ReadFull(c, read); err != nil || !bytes.Equal(read, data) {
						t.Error("concurrent payload", err)
					}
				})
			}
			workers.Wait()
			assertUDPSizes(t, client, []int{0, 65507})
			client.Close()
			server.Close()
		})
	}
}

// The probe must retain every byte, including a command coalesced with Hello.
func TestSudokuTablesProbe(t *testing.T) {
	for _, mode := range []string{"prefer_entropy", "up_ascii_down_entropy"} {
		t.Run(mode, func(t *testing.T) {
			o := sudokuTablesOptions(mode, "raw", false)
			if err := o.prepare(); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"coalesced", "fragmented", "no-hint", "unknown-hint", "expired", "tamper", "padding-limit", "truncated", "bad-command"} {
				t.Run(name, func(t *testing.T) {
					variant := o.tables[2]
					hello := make([]byte, 72)
					binary.BigEndian.PutUint64(hello, uint64(time.Now().Unix()))
					binary.BigEndian.PutUint32(hello[68:], variant.hint)
					if name == "no-hint" {
						variant = o.tables[0]
						hello = hello[:68]
					}
					if name == "unknown-hint" {
						binary.BigEndian.PutUint32(hello[68:], 0x12345678)
					}
					if name == "expired" {
						binary.BigEndian.PutUint64(hello, 1)
					}
					var wire bytes.Buffer
					record := variant.codec(&sudokuBufferConn{Buffer: &wire}, true)
					kind := byte(1)
					if name == "bad-command" {
						kind = 0x10
					}
					if err := sudokuMessage(record, kind, hello); err != nil {
						t.Fatal(err)
					}
					if err := sudokuMessage(record, 0x10, []byte("retained")); err != nil {
						t.Fatal(err)
					}
					data := bytes.Clone(wire.Bytes())
					if name == "tamper" {
						var encrypted bytes.Buffer
						send, receive := sudokuBases(o.Key, nil, nil)
						if err := sudokuMessage(newSudokuRecord(&sudokuBufferConn{Buffer: &encrypted}, o.AEAD, send, receive), 1, hello); err != nil {
							t.Fatal(err)
						}
						encrypted.Bytes()[encrypted.Len()-1] ^= 1
						wire.Reset()
						if err := writeAll(variant.codec(&sudokuBufferConn{Buffer: &wire}, true).Conn, encrypted.Bytes()); err != nil {
							t.Fatal(err)
						}
						data = bytes.Clone(wire.Bytes())
					}
					if name == "padding-limit" {
						data = bytes.Repeat([]byte{variant.uplink.padding[0]}, 65537)
					}
					if name == "truncated" {
						data = data[:len(data)/2]
					}
					reader := io.Reader(bytes.NewReader(data))
					if name == "fragmented" {
						reader = &sudokuSingleByteReader{reader}
					}
					c, err := o.acceptCodec(&bufferedConn{Conn: &sudokuBufferConn{Buffer: new(bytes.Buffer)}, reader: bufio.NewReaderSize(reader, 16)})
					valid := name == "coalesced" || name == "fragmented" || name == "no-hint"
					if !valid {
						if err == nil {
							t.Fatal("invalid table handshake accepted")
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if c.options.hint != variant.hint {
						t.Fatal("wrong downlink selected")
					}
					if _, _, err := sudokuReadMessage(c); err != nil {
						t.Fatal(err)
					}
					kind, body, err := sudokuReadMessage(c)
					if err != nil || kind != 0x10 || string(body) != "retained" {
						t.Fatal("probe lost pipelined bytes", err)
					}
				})
			}
		})
	}
}

type sudokuSingleByteReader struct{ io.Reader }

func (r *sudokuSingleByteReader) Read(p []byte) (int, error) {
	return r.Reader.Read(p[:min(1, len(p))])
}

func FuzzSudokuTablesProbe(f *testing.F) {
	o := sudokuTablesOptions("up_ascii_down_entropy", "raw", false)
	if err := o.prepare(); err != nil {
		f.Fatal(err)
	}
	valid := sudokuHTTPHelloPayload(f, o.tables[1])
	f.Add(valid)
	f.Add([]byte("GET /"))
	f.Add(bytes.Repeat([]byte("\x20"), 4096))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65537 {
			t.Skip()
		}
		conn := &bufferedConn{Conn: &sudokuBufferConn{Buffer: new(bytes.Buffer)}, reader: bufio.NewReader(strings.NewReader(string(wire)))}
		record, err := o.acceptCodec(conn)
		if err == nil {
			kind, hello, err := sudokuReadMessage(record)
			if err != nil || kind != 1 || (len(hello) != 68 && len(hello) != 72) {
				t.Fatal("probe accepted an invalid hello", err)
			}
		}
	})
}

func TestSudokuTablesHandshake(t *testing.T) {
	for _, pattern := range sudokuTestPatterns {
		t.Run(pattern, func(t *testing.T) {
			server := sudokuTablesOptions("prefer_entropy", "raw", false)
			if err := server.prepare(); err != nil {
				t.Fatal(err)
			}
			client := sudokuTablesOptions("prefer_entropy", "raw", false)
			client.CustomTables = []string{pattern}
			if err := client.prepare(); err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			a.SetDeadline(time.Now().Add(time.Second))
			b.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() {
				c, err := server.acceptCodec(b)
				if err == nil {
					_, err = new(Runtime).sudokuServerHello(server, c)
				}
				done <- err
			}()
			_, _, err := sudokuHandshake(a, client, 1)
			if err != nil {
				t.Error("client", err)
			}
			if err := <-done; err != nil {
				t.Error("server", err)
			}
		})
	}
}

func TestSudokuTablesDefaultFallback(t *testing.T) {
	for _, mode := range []string{"prefer_entropy", "up_entropy_down_ascii"} {
		t.Run(mode, func(t *testing.T) {
			options := sudokuTablesOptions(mode, "raw", false)
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: options}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Sudoku = sudokuTestOptions("chacha20-poly1305", mode, false)
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 60000})
		})
	}
}

func TestSudokuTablesEarlyReplay(t *testing.T) {
	options := sudokuTablesOptions("prefer_entropy", "raw", false)
	if err := options.prepare(); err != nil {
		t.Fatal(err)
	}
	payload := sudokuHTTPHelloPayload(t, options.tables[2])
	runtime := new(Runtime)
	for attempt := range 2 {
		raw := &sudokuHTTPHello{input: bytes.NewReader(payload)}
		record, err := options.acceptCodec(raw)
		if err != nil {
			t.Fatal(err)
		}
		_, err = runtime.sudokuServerHello(options, record)
		if attempt == 0 && err != nil {
			t.Fatal("probe consumed replay nonce", err)
		}
		if attempt == 1 && (err == nil || !strings.Contains(err.Error(), "replay")) {
			t.Fatal("replay was not rejected", err)
		}
	}
}

func TestSudokuTablesProbeCancellation(t *testing.T) {
	for _, closeConn := range []bool{false, true} {
		t.Run(fmt.Sprint(closeConn), func(t *testing.T) {
			options := sudokuTablesOptions("prefer_entropy", "raw", false)
			if err := options.prepare(); err != nil {
				t.Fatal(err)
			}
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			done := make(chan error, 1)
			go func() { _, err := options.acceptCodec(b); done <- err }()
			if err := writeAll(a, []byte{options.tables[0].uplink.padding[0]}); err != nil {
				t.Fatal(err)
			}
			if closeConn {
				b.Close()
			} else {
				b.SetReadDeadline(time.Now().Add(-time.Second))
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled probe succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("probe outlived cancellation")
			}
		})
	}
}

func TestSudokuTablesStandardHint(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for _, side := range []string{"native", "official"} {
			t.Run(mask+"/"+side, func(t *testing.T) {
				options := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
				options.CustomTables = []string{sudokuTestPatterns[0], ""}
				in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: options}
				var address string
				if side == "native" {
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					address = server.Address("server")
				} else {
					in.ListenPort = unusedPort(t)
					address = portAddress("127.0.0.1", in.ListenPort)
					cfg := map[string]any{"mode": "server", "local_port": in.ListenPort, "transport": "tcp", "key": options.Key, "aead": options.AEAD, "ascii": options.ASCII, "enable_pure_downlink": false, "multiplex": "off", "httpmask": map[string]any{"disable": true}}
					if mask != "raw" {
						cfg["httpmask"] = map[string]any{"mode": mask, "path_root": "assets-v2"}
					}
					startSudokuReference(t, cfg)
					waitPort(t, address)
				}
				for _, mux := range []bool{false, true} {
					o := *options
					o.CustomTables = []string{""}
					out := testOutbound(t, in, address)
					out.Sudoku = &o
					out.Multiplex.Enabled = mux
					client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{0, 4096})
					client.Close()
				}
			})
		}
	}
}
