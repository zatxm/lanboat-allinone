package native

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSudokuUsersEarlyHTTP(t *testing.T) {
	for _, mask := range []string{"ws", "stream", "poll"} {
		for _, blocked := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/blocked=%v", mask, blocked), func(t *testing.T) {
				cfg := sudokuUserServer(t, mask, []SudokuUserOptions{{Key: sudokuSplitVector, Blocked: blocked}})
				r := newTestRuntime(t, cfg)
				o := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
				o.Key = sudokuPublicVector
				hash, _ := sudokuUserHash(sudokuSplitVector)
				identity, _ := hex.DecodeString(hash)
				early := base64.RawURLEncoding.EncodeToString(sudokuHTTPHelloPayload(t, o, identity))
				c, err := net.Dial("tcp", r.Address("server"))
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				request := "GET /assets-v2/session?ed=" + early + " HTTP/1.1\r\nHost: test\r\nX-Sudoku-Tunnel: " + mask + "\r\n\r\n"
				if mask == "ws" {
					request = "GET /assets-v2/ws?auth=" + sudokuWSAuth(sudokuPublicVector, time.Now().Unix()) + "&ed=" + early + " HTTP/1.1\r\nHost: test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n"
				}
				if err := writeAll(c, []byte(request)); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(c), nil)
				if blocked {
					if err == nil && response.StatusCode != 403 {
						response.Body.Close()
						t.Fatal("blocked early user accepted", response.StatusCode)
					}
					if s := r.sudokuUsers[0].all[0].stat(); s.Used != 0 || s.Conns != 0 {
						t.Fatal(s)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				want := 200
				if mask == "ws" {
					want = 101
				}
				if response.StatusCode != want {
					b, _ := io.ReadAll(response.Body)
					t.Fatalf("early status%d: %s", response.StatusCode, b)
				}
				if s := r.sudokuUsers[0].all[0].stat(); s.Conns != 1 || s.Used == 0 {
					t.Fatal("early accounting missing", s)
				}
			})
		}
	}
}

func TestSudokuUsersReverseQuota(t *testing.T) {
	for _, mask := range []string{"raw", "poll"} {
		t.Run(mask, func(t *testing.T) {
			cfg := sudokuUserServer(t, mask, []SudokuUserOptions{{Key: sudokuSplitVector, Data: 1}})
			cfg.Inbounds[0].Sudoku.Reverse = &SudokuReverse{Listen: "127.0.0.1:0"}
			r := newTestRuntime(t, cfg)
			out := testOutbound(t, cfg.Inbounds[0], r.Address("server"))
			out.Sudoku = sudokuPrivateOptions(sudokuSplitVector, mask, "chacha20-poly1305")
			out.Sudoku.Reverse = &SudokuReverse{ClientID: "quota-publisher", Routes: []SudokuReverseRoute{{Target: sudokuReverseTarget(t)}}}
			out.Multiplex.Enabled = true
			newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{out}})
			address := r.SudokuReverseAddress("server")
			waitSudokuReverse(t, address)
			if err := sudokuReverseTransfer(address); err != nil {
				t.Fatal(err)
			}
			u := r.sudokuUsers[0].all[0]
			u.mu.Lock()
			u.limit = u.used + 1
			u.mu.Unlock()
			if err := u.record(1, 0); err != errSudokuQuota {
				t.Fatal(err)
			}
			waitSudokuUser(t, u, func(s SudokuUserStat) bool { return s.Exceeded && s.Conns == 0 })
			until := time.Now().Add(3 * time.Second)
			for {
				p := r.sudokuReverseServers["server"]
				p.mu.Lock()
				left := p.sessions
				p.mu.Unlock()
				if left == 0 {
					break
				}
				if time.Now().After(until) {
					t.Fatal("quota left reverse publication active")
				}
				time.Sleep(time.Millisecond * 5)
			}
		})
	}
}
