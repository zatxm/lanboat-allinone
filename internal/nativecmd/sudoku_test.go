package nativecmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zatxm/lanboat-allinone/v26/native"
)

func TestSudokuForwardCommand(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "cli:"+r.URL.Path) }))
	defer origin.Close()
	newRuntime := func(config native.Config) *native.Runtime {
		t.Helper()
		raw, _ := json.Marshal(config)
		r, err := native.New(context.Background(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { r.Close() })
		if err = r.Start(); err != nil {
			t.Fatal(err)
		}
		return r
	}
	key := "lanboat-sudoku-cli-test-secret-32"
	server := newRuntime(native.Config{Inbounds: []native.Inbound{{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: &native.SudokuOptions{Key: key, Reverse: &native.SudokuReverse{Listen: "127.0.0.1:0"}}}}})
	host, port, _ := net.SplitHostPort(server.Address("server"))
	var serverPort uint16
	fmt.Sscan(port, &serverPort)
	newRuntime(native.Config{Outbounds: []native.Outbound{{Type: "sudoku", Tag: "proxy", Server: host, ServerPort: serverPort, Sudoku: &native.SudokuOptions{Key: key, Reverse: &native.SudokuReverse{Routes: []native.SudokuReverseRoute{{Path: "/app", Target: strings.TrimPrefix(origin.URL, "http://")}}}}}}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(relayReadyWriter, 1)
	done := make(chan error, 1)
	go func() {
		done <- Execute(ctx, []string{"sudoku-forward", "-url", "ws://" + server.SudokuReverseAddress("server") + "/app"}, ready)
	}()
	var address string
	select {
	case address = <-ready:
	case err := <-done:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("CLI forwarder did not report local port")
	}
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	defer client.CloseIdleConnections()
	until := time.Now().Add(10 * time.Second)
	ok := false
	for time.Now().Before(until) {
		resp, err := client.Get("http://" + address + "/command")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(b) == "cli:/command" {
				ok = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("CLI did not forward actual HTTP bytes")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CLI shutdown blocked")
	}
	for _, args := range [][]string{{"sudoku-forward"}, {"sudoku-forward", "-url"}, {"sudoku-forward", "-url", "http://example.com"}, {"sudoku-forward", "-url", "ws://example.com", "extra"}} {
		if err := Execute(context.Background(), args, io.Discard); err == nil {
			t.Fatal("invalid command accepted", args)
		}
	}
}

func TestGenerateSudoku(t *testing.T) {
	var b bytes.Buffer
	if err := Execute(context.Background(), []string{"generate", "sudoku-keypair"}, &b); err != nil {
		t.Fatal(err)
	}
	var pair native.SudokuKeyPair
	if err := json.Unmarshal(b.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private.txt")
	for _, key := range []string{pair.PrivateKey, pair.SplitKey} {
		if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"sudoku-split", "sudoku-public"} {
			b.Reset()
			if err := Execute(context.Background(), []string{"generate", command, "-key-file", path}, &b); err != nil {
				t.Fatal(err)
			}
			var result map[string]string
			if err := json.Unmarshal(b.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if command == "sudoku-public" {
				if result["public_key"] != pair.PublicKey {
					t.Fatal("public key mismatch")
				}
			} else if public, err := native.RecoverSudokuPublicKey(result["private_key"]); err != nil || public != pair.PublicKey {
				t.Fatal("split mismatch", err)
			}
		}
	}
	for _, args := range [][]string{{"generate", "sudoku-keypair", "extra"}, {"generate", "sudoku-split"}, {"generate", "sudoku-public", "-key-file", path, "extra"}, {"generate", "sudoku-public", "-unknown"}} {
		if err := Execute(context.Background(), args, &b); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
	for _, key := range []string{"secret-that-is-not-a-scalar", strings.Repeat("a", 513)} {
		os.WriteFile(path, []byte(key), 0600)
		b.Reset()
		err := Execute(context.Background(), []string{"generate", "sudoku-public", "-key-file", path}, &b)
		if err == nil || b.Len() != 0 || strings.Contains(err.Error(), key) {
			t.Fatal("invalid key handling or secret disclosure")
		}
	}
}
