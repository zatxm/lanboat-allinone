package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sudokuUserServer(t *testing.T, mask string, users []SudokuUserOptions) Config {
	t.Helper()
	o := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
	o.Key = sudokuPublicVector
	o.Users = users
	o.UsagePath = filepath.Join(t.TempDir(), "usage.json")
	return Config{Log: LogOptions{Disabled: true}, ExternalController: "127.0.0.1:0", Inbounds: []Inbound{{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}}}
}

func sudokuUserClient(t *testing.T, server *Runtime, key, mask, method string, mux bool) *Runtime {
	t.Helper()
	in := server.config.Inbounds[0]
	out := testOutbound(t, in, server.Address(in.Tag))
	out.Sudoku = sudokuPrivateOptions(key, mask, method)
	out.Multiplex.Enabled = mux
	return newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{out}})
}

func waitSudokuUser(t *testing.T, u *sudokuUser, predicate func(SudokuUserStat) bool) SudokuUserStat {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for {
		s := u.stat()
		if predicate(s) {
			return s
		}
		if time.Now().After(until) {
			t.Fatalf("user state did not settle: %+v", s)
		}
		time.Sleep(time.Millisecond * 5)
	}
}

func TestSudokuUsersConfig(t *testing.T) {
	hash, err := sudokuUserHash(sudokuSplitVector)
	if err != nil || len(hash) != 16 {
		t.Fatal(hash, err)
	}
	for _, key := range []string{hash, strings.ToUpper(hash[:9]), sudokuSplitVector, sudokuMasterVector} {
		if _, err := sudokuUserHash(key); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"", hash[:7], hash + "0", strings.Repeat("z", 16), strings.Repeat("0", 64), strings.Repeat("f", 64)} {
		if _, err := sudokuUserHash(key); err == nil {
			t.Fatal("invalid user key accepted")
		}
	}
	for _, name := range []string{"valid", "bad-key", "duplicate", "bandwidth-count", "negative-rate", "tiny-rate", "nan-rate", "huge-data", "nan-data", "fractional-byte", "missing-store", "long-alias", "client", "orphan-store"} {
		t.Run(name, func(t *testing.T) {
			o := &SudokuOptions{Key: sudokuPublicVector, UsagePath: "usage.json", Users: []SudokuUserOptions{{Key: sudokuSplitVector, Bandwidth: []float64{20, 5}, Data: 1}}}
			client := false
			switch name {
			case "bad-key":
				o.Users[0].Key = "bad"
			case "duplicate":
				o.Users = append(o.Users, SudokuUserOptions{Key: hash})
			case "bandwidth-count":
				o.Users[0].Bandwidth = []float64{1}
			case "negative-rate":
				o.Users[0].Bandwidth[0] = -1
			case "tiny-rate":
				o.Users[0].Bandwidth[0] = 1e-9
			case "nan-rate":
				o.Users[0].Bandwidth[0] = math.NaN()
			case "huge-data":
				o.Users[0].Data = math.MaxFloat64
			case "nan-data":
				o.Users[0].Data = math.NaN()
			case "fractional-byte":
				o.Users[0].Data = 1e-12
			case "missing-store":
				o.UsagePath = ""
			case "long-alias":
				o.Users[0].Alias = strings.Repeat("x", 257)
			case "client":
				client = true
			case "orphan-store":
				o.Users = nil
			}
			err := o.validateUsers(client)
			if (err == nil) != (name == "valid") {
				t.Fatal("validation", err)
			}
		})
	}
	for _, name := range []string{"duplicate-store", "bad-store"} {
		t.Run(name, func(t *testing.T) {
			cfg := sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: hash}})
			if name == "duplicate-store" {
				in := cfg.Inbounds[0]
				in.Tag = "second"
				cfg.Inbounds = append(cfg.Inbounds, in)
			} else if err := os.WriteFile(cfg.Inbounds[0].Sudoku.UsagePath, []byte("broken"), 0600); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(cfg)
			if r, err := New(context.Background(), raw, nil); err == nil {
				r.Close()
				t.Fatal("invalid usage storage accepted")
			}
		})
	}
}

func TestSudokuUsersRoundTrip(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for _, mux := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/mux=%v", mask, mux), func(t *testing.T) {
				prefix, _ := sudokuUserHash(sudokuMasterVector)
				cfg := sudokuUserServer(t, mask, []SudokuUserOptions{{Key: sudokuSplitVector, Alias: "alice"}, {Key: prefix[:9], Alias: "bob"}})
				server := newTestRuntime(t, cfg)
				for _, key := range []string{sudokuSplitVector, sudokuMasterVector} {
					client := sudokuUserClient(t, server, key, mask, "chacha20-poly1305", mux)
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{0, 4096, 60000})
					if mask != "ws" || mux {
						assertSudokuHalfClose(t, client)
					}
					client.resetNetworkTransports()
					for _, u := range server.sudokuUsers[0].all {
						waitSudokuUser(t, u, func(s SudokuUserStat) bool { return s.Conns == 0 })
					}
					client.Close()
				}
				for _, u := range server.sudokuUsers[0].all {
					stat := waitSudokuUser(t, u, func(s SudokuUserStat) bool { return s.Conns == 0 })
					if stat.UpTotal == 0 || stat.DownTotal == 0 || stat.Used != stat.UpTotal+stat.DownTotal {
						t.Fatalf("wire accounting: %+v", stat)
					}
				}
				raw := controllerCall(t, server, "GET", "/users", "", 200)
				obj := controllerObject(t, raw)
				if obj["count"] != float64(2) || obj["active"] != float64(0) {
					t.Fatalf("users: %s", raw)
				}
				for _, secret := range []string{sudokuSplitVector, sudokuMasterVector, sudokuPublicVector} {
					if bytes.Contains(raw, []byte(secret)) {
						t.Fatal("credential disclosed")
					}
				}
				if err := server.Close(); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(cfg.Inbounds[0].Sudoku.UsagePath)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("private usage file", err)
				}
				restored := newTestRuntime(t, cfg)
				for i, u := range restored.sudokuUsers[0].all {
					if u.stat().Used != server.sudokuUsers[0].all[i].stat().Used {
						t.Fatal("usage lost on restart")
					}
				}
			})
		}
	}
}

func TestSudokuUsersAEAD(t *testing.T) {
	for _, method := range []string{"none", "aes-128-gcm", "chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			cfg := sudokuUserServer(t, "ws", []SudokuUserOptions{{Key: sudokuSplitVector}})
			cfg.Inbounds[0].Sudoku.AEAD = method
			cfg.Inbounds[0].TLS = certificate(t)
			r := newTestRuntime(t, cfg)
			client := sudokuUserClient(t, r, sudokuSplitVector, "ws", method, true)
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 4096})
		})
	}
}

func TestSudokuUsersModuleWithoutController(t *testing.T) {
	cfg := sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector, Alias: "module-user"}})
	cfg.ExternalController = ""
	r := newTestRuntime(t, cfg)
	client := sudokuUserClient(t, r, sudokuSplitVector, "raw", "chacha20-poly1305", false)
	assertTCP(t, client)
	stats := r.SudokuUserStats()
	if r.controller != nil || len(stats) != 1 || stats[0].Name != "module-user" || stats[0].Used == 0 {
		t.Fatal("module requires HTTP controller", stats)
	}
}

func assertSudokuDenied(t *testing.T, client *Runtime, target string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "tcp", target)
	if err == nil {
		defer c.Close()
		c.SetDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Write([]byte("not authorized"))
		if err == nil {
			var b [14]byte
			_, err = io.ReadFull(c, b[:])
		}
	}
	if err == nil {
		t.Fatal("unauthorized transfer succeeded")
	}
}

func TestSudokuUsersWhitelist(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			cfg := sudokuUserServer(t, mask, []SudokuUserOptions{{Key: sudokuSplitVector}, {Key: sudokuMasterVector, Blocked: true}})
			server := newTestRuntime(t, cfg)
			good := sudokuUserClient(t, server, sudokuSplitVector, mask, "chacha20-poly1305", true)
			assertTCP(t, good)
			unknown, err := SplitSudokuPrivateKey(sudokuMasterVector)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{sudokuMasterVector, unknown} {
				client := sudokuUserClient(t, server, key, mask, "chacha20-poly1305", true)
				assertSudokuDenied(t, client, sudokuTCPEcho(t))
			}
			assertTCP(t, good)
			if s := server.sudokuUsers[0].all[1].stat(); s.Used != 0 || s.Conns != 0 {
				t.Fatal("rejected user was admitted", s)
			}
		})
	}
}

func TestSudokuUsersQuota(t *testing.T) {
	for _, mask := range []string{"raw", "ws", "stream", "poll"} {
		t.Run(mask, func(t *testing.T) {
			cfg := sudokuUserServer(t, mask, []SudokuUserOptions{{Key: sudokuSplitVector, Data: 0.0002}, {Key: sudokuMasterVector}})
			server := newTestRuntime(t, cfg)
			client := sudokuUserClient(t, server, sudokuSplitVector, mask, "chacha20-poly1305", false)
			target := sudokuTCPEcho(t)
			idle, err := client.Dial(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer idle.Close()
			active, err := client.Dial(context.Background(), "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer active.Close()
			u := server.sudokuUsers[0].all[0]
			waitSudokuUser(t, u, func(s SudokuUserStat) bool { return s.Conns == 2 })
			active.SetDeadline(time.Now().Add(5 * time.Second))
			writeDone := make(chan error, 1)
			go func() { _, err := active.Write(make([]byte, 1<<20)); writeDone <- err }()
			_, readErr := io.CopyN(io.Discard, active, 1<<20)
			if readErr == nil {
				t.Fatal("quota did not interrupt transfer")
			}
			active.Close()
			<-writeDone
			stat := waitSudokuUser(t, u, func(s SudokuUserStat) bool { return s.Exceeded && s.Conns == 0 })
			idle.SetDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err = idle.Read(one[:]); err == nil {
				t.Fatal("another active session survived quota")
			}
			assertSudokuDenied(t, client, target)
			other := sudokuUserClient(t, server, sudokuMasterVector, mask, "chacha20-poly1305", false)
			assertTCP(t, other)
			other.Close()
			client.Close()
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			restarted := newTestRuntime(t, cfg)
			if s := restarted.sudokuUsers[0].all[0].stat(); !s.Exceeded || s.Used < stat.Used {
				t.Fatal("quota reset at restart", s)
			}
			again := sudokuUserClient(t, restarted, sudokuSplitVector, mask, "chacha20-poly1305", false)
			assertSudokuDenied(t, again, target)
		})
	}
}

func TestSudokuUsersSharedBandwidth(t *testing.T) {
	server := newTestRuntime(t, sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector, Bandwidth: []float64{1, 1}}}))
	client := sudokuUserClient(t, server, sudokuSplitVector, "raw", "chacha20-poly1305", false)
	target := sudokuTCPEcho(t)
	var group sync.WaitGroup
	errors := make(chan error, 2)
	start := time.Now()
	for range 2 {
		group.Go(func() {
			c, err := client.Dial(context.Background(), "tcp", target)
			if err != nil {
				errors <- err
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			payload := bytes.Repeat([]byte{0x45}, 65536)
			done := make(chan error, 1)
			go func() { done <- writeAll(c, payload) }()
			got := make([]byte, len(payload))
			_, err = io.ReadFull(c, got)
			if err == nil && !bytes.Equal(got, payload) {
				err = fmt.Errorf("payload mismatch")
			}
			c.Close()
			if e := <-done; err == nil {
				err = e
			}
			errors <- err
		})
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 850*time.Millisecond || elapsed > 10*time.Second {
		t.Fatal("aggregate bandwidth not applied", elapsed)
	}
}

func TestSudokuUsersBandwidthCancellation(t *testing.T) {
	for _, name := range []string{"cancel", "close", "deadline", "change-deadline"} {
		t.Run(name, func(t *testing.T) {
			r := newTestRuntime(t, sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector, Bandwidth: []float64{0.001, 0.001}}}))
			a := newSudokuAccount()
			defer a.Close()
			if err := a.bind(r.sudokuUsers[0].all[0]); err != nil {
				t.Fatal(err)
			}
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newSudokuPayload(ctx, left, a)
			if name == "deadline" {
				p.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
			}
			done := make(chan error, 1)
			go func() { done <- p.wait(1, 65536) }()
			switch name {
			case "cancel":
				cancel()
			case "close":
				p.Close()
			case "change-deadline":
				p.SetWriteDeadline(time.Now().Add(-time.Second))
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("blocked rate wait succeeded")
				}
				if strings.Contains(name, "deadline") && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("rate wait did not unblock")
			}
		})
	}
}
