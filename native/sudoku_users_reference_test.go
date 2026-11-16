package native

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSudokuUsersOfficialReference(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for _, side := range []string{"client", "server"} {
			t.Run(mask+"/"+side, func(t *testing.T) {
				for _, prefix := range []bool{false, true} {
					hash, _ := sudokuUserHash(sudokuSplitVector)
					userKey := sudokuSplitVector
					if prefix {
						userKey = hash[:9]
					}
					inOptions := sudokuTablesOptions("up_ascii_down_entropy", mask, true)
					inOptions.Key = sudokuPublicVector
					ref := map[string]any{"mode": "server", "transport": "tcp", "key": sudokuPublicVector, "aead": "chacha20-poly1305", "ascii": inOptions.ASCII, "padding_min": 5, "padding_max": 15, "enable_pure_downlink": false, "multiplex": "on", "custom_tables": sudokuTestPatterns, "httpmask": map[string]any{"disable": true}}
					if mask != "raw" {
						ref["httpmask"] = map[string]any{"mode": mask, "path_root": inOptions.HTTPMask.PathRoot}
					}
					var client *Runtime
					if side == "client" {
						port := unusedPort(t)
						ref["local_port"] = port
						ref["users"] = []SudokuUserOptions{{Key: userKey, Alias: "official-allowed"}, {Key: sudokuMasterVector, Blocked: true}}
						startSudokuReference(t, ref)
						address := portAddress("127.0.0.1", port)
						waitPort(t, address)
						out := testOutbound(t, Inbound{Type: "sudoku"}, address)
						out.Sudoku = sudokuPrivateOptions(sudokuSplitVector, mask, "chacha20-poly1305")
						out.Multiplex.Enabled = true
						client = newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{out}})
						blocked := out
						blocked.Sudoku = sudokuPrivateOptions(sudokuMasterVector, mask, "chacha20-poly1305")
						assertSudokuDenied(t, newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{blocked}}), sudokuTCPEcho(t))
					} else {
						cfg := sudokuUserServer(t, mask, []SudokuUserOptions{{Key: userKey, Alias: "native-allowed"}, {Key: sudokuMasterVector, Blocked: true}})
						server := newTestRuntime(t, cfg)
						port := unusedPort(t)
						ref["mode"], ref["local_port"], ref["server_address"], ref["proxy_mode"], ref["key"] = "client", port, server.Address("server"), "global", sudokuSplitVector
						startSudokuReference(t, ref)
						address := portAddress("127.0.0.1", port)
						waitPort(t, address)
						out := testOutbound(t, Inbound{Type: "socks"}, address)
						out.Username, out.Password = "", ""
						client = newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{out}})
						// A second upstream client holds the correct PSK but a blocked user label.
						badPort := unusedPort(t)
						bad := map[string]any{}
						for k, v := range ref {
							bad[k] = v
						}
						bad["local_port"], bad["key"] = badPort, sudokuMasterVector
						startSudokuReference(t, bad)
						badAddress := portAddress("127.0.0.1", badPort)
						waitPort(t, badAddress)
						blocked := testOutbound(t, Inbound{Type: "socks"}, badAddress)
						blocked.Username, blocked.Password = "", ""
						assertSudokuDenied(t, newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{blocked}}), sudokuTCPEcho(t))
					}
					assertTCP(t, client)
					assertUDPSizes(t, client, []int{1, 4096, 60000})
					assertSudokuHalfClose(t, client)
					client.resetNetworkTransports()
					client.Close()
				}
			})
		}
	}
}

func TestSudokuUsersControllerStream(t *testing.T) {
	r := newTestRuntime(t, sudokuUserServer(t, "raw", []SudokuUserOptions{{Key: sudokuSplitVector, Alias: "alice"}, {Key: sudokuMasterVector, Alias: "bob", Blocked: true}}))
	client := sudokuUserClient(t, r, sudokuSplitVector, "raw", "chacha20-poly1305", true)
	conn, err := client.Dial(context.Background(), "tcp", sudokuTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitSudokuUser(t, r.sudokuUsers[0].all[0], func(s SudokuUserStat) bool { return s.Conns == 1 })
	up, down := r.controller.totals()
	var sumUp, sumDown uint64
	for _, u := range r.sudokuUsers[0].all {
		sumUp += u.up.Load()
		sumDown += u.down.Load()
	}
	if up != int64(sumUp) || down != int64(sumDown) {
		t.Fatal("controller totals differ from users")
	}
	raw, err := net.Dial("tcp", r.ControllerAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(raw, "GET /users?interval=100 HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n", r.ControllerAddress())
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(raw)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != 101 {
		t.Fatal(response, err)
	}
	ws := &websocketConn{Conn: &bufferedConn{Conn: raw, reader: reader}, client: true, legacyText: true}
	var snapshot struct {
		Count  int              `json:"count"`
		Active int              `json:"active"`
		Users  []SudokuUserStat `json:"users"`
	}
	if err := json.NewDecoder(ws).Decode(&snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Count != 2 || snapshot.Active != 1 || snapshot.Users[0].Name != "alice" || !snapshot.Users[1].Blocked {
		t.Fatal(snapshot)
	}
	encoded, _ := json.Marshal(snapshot)
	if strings.Contains(string(encoded), sudokuSplitVector) {
		t.Fatal("private key exposed")
	}
}
