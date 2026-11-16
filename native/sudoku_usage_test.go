package native

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSudokuUsersUsageStorage(t *testing.T) {
	hash, _ := sudokuUserHash(sudokuSplitVector)
	for _, name := range []string{"current", "old", "corrupt", "empty", "future", "wrong-version", "too-large", "overflow", "unknown-field"} {
		t.Run(name, func(t *testing.T) {
			cfg := sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector, Data: 0.000001}})
			path := cfg.Inbounds[0].Sudoku.UsagePath
			saved := sudokuSavedUsage{Version: 1, Users: map[string]sudokuMonthlyUsage{hash: {time.Now().Format("2006-01"), 2000}}}
			switch name {
			case "old":
				saved.Users[hash] = sudokuMonthlyUsage{"2000-01", 2000}
			case "future":
				saved.Users[hash] = sudokuMonthlyUsage{"9999-01", 2000}
			case "wrong-version":
				saved.Version = 2
			case "overflow":
				saved.Users[hash] = sudokuMonthlyUsage{time.Now().Format("2006-01"), ^uint64(0)}
			}
			b, _ := json.Marshal(saved)
			switch name {
			case "corrupt":
				b = []byte("{")
			case "empty":
				b = nil
			case "too-large":
				b = bytes.Repeat([]byte("x"), sudokuUsageMax+1)
			case "unknown-field":
				b = append(b[:len(b)-1], []byte(`,"unexpected":true}`)...)
			}
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(cfg)
			r, err := New(context.Background(), raw, nil)
			if name != "current" && name != "old" {
				if err == nil {
					r.Close()
					t.Fatal("invalid usage accepted")
				}
				got, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(got, b) {
					t.Fatal("invalid usage was overwritten", e)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			s := r.sudokuUsers[0].all[0].stat()
			if name == "current" && (!s.Exceeded || s.Used != 2000) {
				t.Fatal(s)
			}
			if name == "old" && (s.Exceeded || s.Used != 0) {
				t.Fatal(s)
			}
		})
	}
}

func TestSudokuUsersUsageLockAndWriteFailure(t *testing.T) {
	cfg := sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector}})
	r := newTestRuntime(t, cfg)
	raw, _ := json.Marshal(cfg)
	if second, err := New(context.Background(), raw, nil); err == nil {
		second.Close()
		t.Fatal("two writers accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = newTestRuntime(t, cfg)
	u := r.sudokuUsers[0].all[0]
	if err := u.record(10, 20); err != nil {
		t.Fatal(err)
	}
	path := cfg.Inbounds[0].Sudoku.UsagePath
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A failed temporary-file creation must retain the last valid snapshot.
	r.sudokuUsers[0].path = filepath.Join(path, "cannot-create.json")
	if err := r.sudokuUsers[0].save(); err == nil {
		t.Fatal("write failure swallowed")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(old, got) {
		t.Fatal("saved snapshot damaged", err)
	}
	r.sudokuUsers[0].path = path
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r = newTestRuntime(t, cfg)
	if s := r.sudokuUsers[0].all[0].stat(); s.Used != 30 {
		t.Fatal("final snapshot was not persisted", s)
	}
}

func TestSudokuUsersMonthAndPrefixPrecedence(t *testing.T) {
	hash, _ := sudokuUserHash(sudokuSplitVector)
	cfg := sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: hash[:8], Alias: "broad", Blocked: true}, {Key: sudokuSplitVector, Alias: "exact", Data: 0.000001}})
	r := newTestRuntime(t, cfg)
	registry := r.sudokuUsers[0]
	u := registry.all[1]
	u.mu.Lock()
	u.month = "2000-01"
	u.resetAt = 0
	u.used = u.limit
	u.mu.Unlock()
	a := newSudokuAccount()
	defer a.Close()
	decoded, _ := hex.DecodeString(hash)
	if err := registry.authorize(a, decoded); err != nil {
		t.Fatal("exact key failed or month failed to reset", err)
	}
	if s := u.stat(); s.Exceeded || s.Used != 0 || s.Conns != 1 {
		t.Fatal(s)
	}
	if a.user.name != "exact" {
		t.Fatal("prefix overrode exact user")
	}
}

func TestSudokuUsersConcurrentAccounting(t *testing.T) {
	r := newTestRuntime(t, sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector}}))
	u := r.sudokuUsers[0].all[0]
	a := newSudokuAccount()
	defer a.Close()
	if err := a.add(17, 19); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			part := newSudokuAccount()
			part.add(7, 11)
			if err := part.join(a); err != nil {
				t.Error(err)
				return
			}
			for range 100 {
				if err := part.add(13, 23); err != nil {
					t.Error(err)
				}
			}
		})
	}
	if err := a.bind(u); err != nil {
		t.Fatal(err)
	}
	workers.Wait()
	if err := r.sudokuUsers[0].save(); err != nil {
		t.Fatal(err)
	}
	s := u.stat()
	if s.UpTotal != 17+16*(7+1300) || s.DownTotal != 19+16*(11+2300) || s.Used != s.UpTotal+s.DownTotal {
		t.Fatal("concurrent count lost", s)
	}
	b, err := os.ReadFile(r.sudokuUsers[0].path)
	if err != nil || strings.Contains(string(b), sudokuSplitVector) {
		t.Fatal("invalid usage file", err)
	}
}

func TestSudokuUsersStorageFailureStopsQuotaSessions(t *testing.T) {
	r := newTestRuntime(t, sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector, Data: 1}}))
	s := r.sudokuUsers[0]
	a := newSudokuAccount()
	defer a.Close()
	hash, _ := sudokuUserHash(sudokuSplitVector)
	identity, _ := hex.DecodeString(hash)
	if err := s.authorize(a, identity); err != nil {
		t.Fatal(err)
	}
	if err := a.add(100, 100); err != nil {
		t.Fatal(err)
	}
	path := s.path
	s.path = filepath.Join(path, "invalid")
	if err := s.persist(); err == nil {
		t.Fatal("storage error ignored")
	}
	select {
	case <-a.done:
	default:
		t.Fatal("quota session survived storage loss")
	}
	other := newSudokuAccount()
	defer other.Close()
	if err := s.authorize(other, identity); err == nil {
		t.Fatal("quota admission ignored storage loss")
	}
	s.path = path
	if err := s.persist(); err != nil {
		t.Fatal(err)
	}
	if err := s.authorize(other, identity); err != nil {
		t.Fatal("storage recovery did not resume admissions", err)
	}
}

func BenchmarkSudokuUserWireAccounting(b *testing.B) {
	registry := &sudokuUsers{flush: make(chan struct{}, 1)}
	u := &sudokuUser{registry: registry, resetAt: time.Now().Add(24 * time.Hour).Unix(), sessions: map[*sudokuAccount]struct{}{}}
	registry.all = []*sudokuUser{u}
	b.ReportAllocs()
	for b.Loop() {
		if err := u.record(16384, 0); err != nil {
			b.Fatal(fmt.Errorf("accounting: %w", err))
		}
	}
}

func FuzzSudokuUserHash(f *testing.F) {
	for _, key := range []string{"", sudokuMasterVector, sudokuSplitVector, "aabbccdd", "AABBCCDDEEFF0011", strings.Repeat("f", 64)} {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		hash, err := sudokuUserHash(key)
		if err != nil {
			return
		}
		if len(hash) < 8 || len(hash) > 16 || hash != strings.ToLower(hash) {
			t.Fatal("noncanonical hash")
		}
		for _, c := range hash {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				t.Fatal("invalid hash alphabet")
			}
		}
	})
}
