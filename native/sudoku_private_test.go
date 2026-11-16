package native

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func sudokuPrivateOptions(key, mask, method string) *SudokuOptions {
	o := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
	o.Key, o.PrivateKey, o.AEAD = "", key, method
	return o
}

func TestSudokuPrivateConfig(t *testing.T) {
	for _, key := range []string{sudokuMasterVector, sudokuSplitVector} {
		o := sudokuPrivateOptions(key, "ws", "chacha20-poly1305")
		for range 2 {
			if err := o.prepareClient(); err != nil {
				t.Fatal(err)
			}
			if o.Key != "" || o.PrivateKey != key || o.wireKey() != sudokuPublicVector {
				t.Fatal("private config mutated")
			}
			b, _ := hex.DecodeString(key)
			h := sha256.Sum256(b)
			if o.clientHash != [8]byte(h[:8]) {
				t.Fatal("private client identifier")
			}
			for _, variant := range o.tables {
				if variant.wireKey() != sudokuPublicVector || variant.clientHash != o.clientHash {
					t.Fatal("table variant lost identity")
				}
			}
		}
		if err := o.prepare(); err == nil {
			t.Fatal("private key accepted as server key")
		}
		o.Key = sudokuPublicVector
		if err := o.prepareClient(); err == nil {
			t.Fatal("conflicting credentials accepted")
		}
	}
	for _, key := range []string{"bad-private", strings.Repeat("00", 32), strings.Repeat("ff", 32)} {
		if err := sudokuPrivateOptions(key, "raw", "aes-128-gcm").prepareClient(); err == nil {
			t.Fatal("invalid connection credential")
		}
	}
	// Existing64/128-character PSKs are never silently interpreted as scalars.
	for _, key := range []string{sudokuMasterVector, sudokuSplitVector} {
		o := &SudokuOptions{Key: key}
		if err := o.prepareClient(); err != nil || o.wireKey() != key {
			t.Fatal("PSK compatibility", err)
		}
	}
}

func TestSudokuPrivateRoundTrip(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for ki, key := range []string{sudokuMasterVector, sudokuSplitVector} {
			for _, mux := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/key=%d/mux=%v", mask, ki, mux), func(t *testing.T) {
					for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
						so := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
						so.Key, so.AEAD = sudokuPublicVector, method
						in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: so}
						server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
						out := testOutbound(t, in, server.Address("server"))
						out.Sudoku = sudokuPrivateOptions(key, mask, method)
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
						server.Close()
					}
				})
			}
		}
	}
}

func TestSudokuPrivateOfficialReference(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for ki, key := range []string{sudokuMasterVector, sudokuSplitVector} {
			for _, side := range []string{"client", "server"} {
				t.Run(fmt.Sprintf("%s/key=%d/%s", mask, ki, side), func(t *testing.T) {
					for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
						so := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
						so.Key, so.AEAD = sudokuPublicVector, method
						cfg := map[string]any{"mode": "server", "transport": "tcp", "key": sudokuPublicVector, "aead": method, "ascii": so.ASCII,
							"custom_tables": sudokuTestPatterns, "padding_min": 5, "padding_max": 15, "enable_pure_downlink": false, "multiplex": "on", "httpmask": map[string]any{"disable": true}}
						if mask != "raw" {
							cfg["httpmask"] = map[string]any{"mode": mask, "path_root": "assets-v2"}
						}
						in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: so}
						var client *Runtime
						if side == "client" {
							in.ListenPort = unusedPort(t)
							cfg["local_port"] = in.ListenPort
							startSudokuReference(t, cfg)
							address := portAddress("127.0.0.1", in.ListenPort)
							waitPort(t, address)
							out := testOutbound(t, in, address)
							out.Sudoku = sudokuPrivateOptions(key, mask, method)
							out.Multiplex.Enabled = true
							client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						} else {
							server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
							port := unusedPort(t)
							cfg["mode"], cfg["local_port"], cfg["server_address"], cfg["proxy_mode"], cfg["key"] = "client", port, server.Address("server"), "global", key
							startSudokuReference(t, cfg)
							address := portAddress("127.0.0.1", port)
							waitPort(t, address)
							out := testOutbound(t, Inbound{Type: "socks"}, address)
							out.Username, out.Password = "", ""
							client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
						}
						assertTCP(t, client)
						assertUDPSizes(t, client, []int{0, 4096, 60000})
						assertSudokuHalfClose(t, client)
						client.Close()
					}
				})
			}
		}
	}
}

func TestSudokuPrivateTLS(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			o := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
			o.Key = sudokuPublicVector
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o, TLS: certificate(t)}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Sudoku = sudokuPrivateOptions(sudokuSplitVector, mask, "chacha20-poly1305")
			out.TLS.Insecure, out.TLS.Certificate = false, in.TLS.Certificate
			out.Multiplex.Enabled = true
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 65507})
			assertSudokuHalfClose(t, client)
			client.Close()
			// httptest reuses one static certificate; clear the explicit CA to
			// exercise actual trust failure rather than loading the same CA again.
			out.TLS.Certificate = nil
			untrusted := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if c, err := untrusted.Dial(ctx, "tcp", sudokuTCPEcho(t)); err == nil {
				c.Close()
				t.Fatal("untrusted TLS accepted")
			}
		})
	}
}

func TestSudokuPrivateHelloIdentity(t *testing.T) {
	for _, key := range []string{sudokuMasterVector, sudokuSplitVector} {
		client := sudokuPrivateOptions(key, "raw", "aes-128-gcm")
		if err := client.prepareClient(); err != nil {
			t.Fatal(err)
		}
		server := *client
		server.PrivateKey = ""
		server.Key = sudokuPublicVector
		if err := server.prepare(); err != nil {
			t.Fatal(err)
		}
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		a.SetDeadline(time.Now().Add(time.Second))
		b.SetDeadline(time.Now().Add(time.Second))
		done := make(chan error, 1)
		go func() { _, _, err := sudokuHandshake(a, client, 1); done <- err }()
		c, err := server.acceptCodec(b)
		if err != nil {
			t.Fatal(err)
		}
		kind, hello, err := sudokuReadMessage(c)
		if err != nil || kind != 1 || len(hello) != 72 {
			t.Fatal("hello", err)
		}
		raw, _ := hex.DecodeString(key)
		h := sha256.Sum256(raw)
		if [8]byte(hello[8:16]) != [8]byte(h[:8]) {
			t.Fatal("wire user hash")
		}
		b.Close()
		<-done
	}
}

func TestSudokuPrivateWrongKey(t *testing.T) {
	for _, mask := range []string{"raw", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			o := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
			o.Key = sudokuPublicVector
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
			server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
			out := testOutbound(t, in, server.Address("server"))
			out.Sudoku = sudokuPrivateOptions("01"+strings.Repeat("00", 31), mask, "chacha20-poly1305")
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if c, err := client.Dial(ctx, "tcp", sudokuTCPEcho(t)); err == nil {
				c.Close()
				t.Fatal("mismatched private key accepted")
			}
		})
	}
}

func BenchmarkSudokuPublicRecovery(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := RecoverSudokuPublicKey(sudokuSplitVector); err != nil {
			b.Fatal(err)
		}
	}
}

func FuzzSudokuPrivateKey(f *testing.F) {
	for _, seed := range []string{sudokuMasterVector, sudokuSplitVector, "", strings.Repeat("ff", 64)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, key string) {
		s, b, err := sudokuParsePrivate(key)
		if err != nil {
			return
		}
		if len(b) != 32 && len(b) != 64 {
			t.Fatal("unexpected key size")
		}
		if _, below := s.reduce(); below != 1 {
			t.Fatal("noncanonical recovered scalar")
		}
	})
}
