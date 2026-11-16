package native

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func sudokuReverseOrigin(t *testing.T) string {
	t.Helper()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			c, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: app-echo\r\n\r\n", websocketAccept(r.Header.Get("Sec-WebSocket-Key")))
			rw.Flush()
			ws := &websocketConn{Conn: &bufferedConn{Conn: c, reader: rw.Reader}}
			io.Copy(ws, ws)
			return
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/login?q=1")
			w.Header().Add("Set-Cookie", "token=secret; Path=/; HttpOnly")
			w.WriteHeader(302)
			return
		}
		if r.URL.Path == "/page" {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<img src="/asset"><script>const untouched="/script";</script><style>a{background:url(/background)}</style>`)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "%s|%s|%s|%s|%s", r.URL.RequestURI(), r.Host, r.Header.Get("X-Forwarded-Prefix"), r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Forwarded-Host"))
	}))
	t.Cleanup(origin.Close)
	return strings.TrimPrefix(origin.URL, "http://")
}

func sudokuReverseHTTPGet(address, path string, headers http.Header) (int, http.Header, string, error) {
	c := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer c.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "http://"+address+path, nil)
	if headers != nil {
		req.Header = headers
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b), err
}

func waitSudokuReverseHTTP(t *testing.T, address, path string) {
	t.Helper()
	until := time.Now().Add(12 * time.Second)
	for time.Now().Before(until) {
		status, _, _, err := sudokuReverseHTTPGet(address, path, nil)
		if err == nil && status == 200 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("HTTP publication did not become usable", path)
}

func dialSudokuReverseWS(address, path, protocol, origin string) (net.Conn, int, error) {
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		return nil, 0, err
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	key := "MDEyMzQ1Njc4OWFiY2RlZg=="
	request := "GET " + path + " HTTP/1.1\r\nHost: " + address + "\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: " + protocol + "\r\n"
	if origin != "" {
		request += "Origin: " + origin + "\r\n"
	}
	if err = writeAll(c, []byte(request+"\r\n")); err != nil {
		c.Close()
		return nil, 0, err
	}
	reader := bufio.NewReader(c)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		c.Close()
		return nil, 0, err
	}
	if resp.StatusCode != 101 {
		resp.Body.Close()
		c.Close()
		return nil, resp.StatusCode, nil
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != websocketAccept(key) || resp.Header.Get("Sec-WebSocket-Protocol") != protocol {
		c.Close()
		return nil, 101, fmt.Errorf("invalid WebSocket upgrade response")
	}
	return &websocketConn{Conn: &bufferedConn{Conn: c, reader: reader}, client: true}, 101, nil
}

func checkSudokuReverseHTTP(t *testing.T, address string) {
	t.Helper()
	status, headers, _, err := sudokuReverseHTTPGet(address, "/app?q=1", nil)
	if err != nil || status != 308 || headers.Get("Location") != "/app/?q=1" {
		t.Fatal(status, headers, err)
	}
	status, _, body, err := sudokuReverseHTTPGet(address, "/app/hello?x=1", http.Header{"X-Forwarded-For": {"forged"}, "X-Forwarded-Host": {"forged"}})
	if err != nil || status != 200 || !strings.HasPrefix(body, "/hello?x=1|backend.example|/app|") {
		t.Fatal(status, body, err)
	}
	// Only our endpoint promises sanitized forwarding headers;the pinned upstream
	// deliberately preserves them and is checked separately below.
	status, _, body, err = sudokuReverseHTTPGet(address, "/keep/hello", nil)
	if err != nil || status != 200 || !strings.HasPrefix(body, "/keep/hello|") {
		t.Fatal(status, body, err)
	}
	status, _, _, err = sudokuReverseHTTPGet(address, "/application/hello", nil)
	if err != nil || status != 404 {
		t.Fatal(status, err)
	}
	status, headers, body, err = sudokuReverseHTTPGet(address, "/app/page", nil)
	if err != nil || status != 200 || !strings.Contains(body, `src="/app/asset"`) || !strings.Contains(body, `untouched="/script"`) || !strings.Contains(body, `url(/app/background)`) {
		t.Fatal(status, body, err)
	}
	status, headers, _, err = sudokuReverseHTTPGet(address, "/app/redirect", nil)
	if err != nil || status != 302 || headers.Get("Location") != "/app/login?q=1" || !strings.Contains(strings.Join(headers.Values("Set-Cookie"), ";"), "Path=/app/") {
		t.Fatal(status, headers, err)
	}
	for _, h := range []http.Header{{"Referer": {"http://" + address + "/app/page"}}, {"Cookie": {sudokuReverseCookie + "=%2Fapp"}}} {
		status, _, body, err = sudokuReverseHTTPGet(address, "/assets", h)
		if err != nil || status != 200 || !strings.HasPrefix(body, "/assets|") {
			t.Fatal(status, body, err)
		}
	}
	ws, status, err := dialSudokuReverseWS(address, "/app", sudokuTCPSubprotocol, "")
	if err != nil || status != 101 {
		t.Fatal(status, err)
	}
	defer ws.Close()
	if err = writeAll(ws, []byte("GET /over-websocket HTTP/1.1\r\nHost: through-ws\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(ws), &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !strings.HasPrefix(string(b), "/over-websocket|through-ws|") {
		t.Fatal(resp.StatusCode, string(b), err)
	}
	app, status, err := dialSudokuReverseWS(address, "/app/ws", "app-echo", "")
	if err != nil || status != 101 {
		t.Fatal(status, err)
	}
	defer app.Close()
	payload := bytes.Repeat([]byte("app-websocket\x00\xff"), 8192)
	done := make(chan error, 1)
	go func() { done <- writeAll(app, payload) }()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(app, got)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil || !bytes.Equal(payload, got) {
		t.Fatal("application WebSocket mismatch", err)
	}
}

func sudokuReverseHTTPRoutes(target string) []SudokuReverseRoute {
	keep := false
	return []SudokuReverseRoute{{Path: "/app", Target: target, HostHeader: "backend.example"}, {Path: "/keep", Target: target, StripPrefix: &keep}}
}

func nativeSudokuReverseHTTP(t *testing.T, mask string, routes []SudokuReverseRoute, tls bool) (*Runtime, *Runtime, string) {
	t.Helper()
	so := sudokuReverseOptions(mask, "chacha20-poly1305", true)
	so.Reverse = &SudokuReverse{Listen: "127.0.0.1:0"}
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: so}
	if tls {
		in.TLS = certificate(t)
	}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	co := sudokuReverseOptions(mask, "chacha20-poly1305", true)
	co.Reverse = &SudokuReverse{Routes: routes}
	out := testOutbound(t, in, server.Address("server"))
	out.Sudoku = co
	if tls {
		out.TLS.Insecure = false
		out.TLS.Certificate = in.TLS.Certificate
	}
	client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	return server, client, server.SudokuReverseAddress("server")
}

func TestSudokuReverseHTTP(t *testing.T) {
	for _, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		t.Run(mask, func(t *testing.T) {
			target := sudokuReverseOrigin(t)
			routes := sudokuReverseHTTPRoutes(target)
			routes = append(routes, SudokuReverseRoute{Target: sudokuReverseTarget(t)})
			server, client, address := nativeSudokuReverseHTTP(t, mask, routes, true)
			waitSudokuReverseHTTP(t, address, "/app/ready")
			checkSudokuReverseHTTP(t, address)
			if err := sudokuReverseTransfer(address); err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			for range 16 {
				workers.Go(func() {
					status, _, body, err := sudokuReverseHTTPGet(address, "/app/concurrent", nil)
					if err != nil || status != 200 || !strings.HasPrefix(body, "/concurrent|") {
						t.Error(status, body, err)
					}
				})
			}
			workers.Wait()
			client.resetNetworkTransports()
			waitSudokuReverseHTTP(t, address, "/app/ready")
			checkSudokuReverseHTTP(t, address)
			client.Close()
			server.Close()
		})
	}
}

func TestSudokuReverseHTTPOfficial(t *testing.T) {
	for i, mask := range []string{"raw", "legacy", "ws", "stream", "poll", "auto"} {
		for _, side := range []string{"client", "server"} {
			t.Run(mask+"/"+side, func(t *testing.T) {
				target := sudokuReverseOrigin(t)
				method := []string{"none", "aes-128-gcm", "chacha20-poly1305"}[i%3]
				so := sudokuReverseOptions(mask, method, true)
				cfg := map[string]any{"mode": "server", "transport": "tcp", "key": sudokuTestKey, "aead": method, "ascii": so.ASCII, "custom_tables": sudokuTestPatterns, "padding_min": 5, "padding_max": 15, "enable_pure_downlink": false, "multiplex": "off", "httpmask": map[string]any{"disable": true}}
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
					co := sudokuReverseOptions(mask, method, true)
					co.Reverse = &SudokuReverse{Routes: sudokuReverseHTTPRoutes(target)}
					out := testOutbound(t, in, portAddress("127.0.0.1", in.ListenPort))
					out.Sudoku = co
					newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				} else {
					so.Reverse = &SudokuReverse{Listen: "127.0.0.1:0"}
					server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
					address = server.SudokuReverseAddress("server")
					cfg["mode"], cfg["local_port"], cfg["server_address"], cfg["proxy_mode"] = "client", unusedPort(t), server.Address("server"), "global"
					cfg["reverse"] = map[string]any{"routes": sudokuReverseHTTPRoutes(target)}
					startSudokuReference(t, cfg)
				}
				waitSudokuReverseHTTP(t, address, "/app/ready")
				checkSudokuReverseHTTP(t, address)
			})
		}
	}
}

func TestSudokuReverseHTTPPublishers(t *testing.T) {
	for _, mask := range []string{"raw", "ws", "poll"} {
		t.Run(mask, func(t *testing.T) {
			target := sudokuReverseOrigin(t)
			server, first, address := nativeSudokuReverseHTTP(t, mask, sudokuReverseHTTPRoutes(target), false)
			waitSudokuReverseHTTP(t, address, "/app/ready")
			publish := func(routes []SudokuReverseRoute) *Runtime {
				out := first.outbounds["proxy"]
				options := *out.Sudoku
				options.Reverse = &SudokuReverse{Routes: routes}
				out.Sudoku = &options
				return newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			}
			second := publish([]SudokuReverseRoute{{Path: "/app/nested", Target: target, HostHeader: "nested.example"}})
			until := time.Now().Add(12 * time.Second)
			for time.Now().Before(until) {
				server.sudokuReverseServers["server"].mu.Lock()
				published := server.sudokuReverseServers["server"].routes["/app/nested"] != nil
				server.sudokuReverseServers["server"].mu.Unlock()
				if published {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			status, _, body, err := sudokuReverseHTTPGet(address, "/app/nested/longest", nil)
			if err != nil || status != 200 || !strings.HasPrefix(body, "/longest|nested.example|") {
				t.Fatal(status, body, err)
			}
			duplicate := publish([]SudokuReverseRoute{{Path: "/app", Target: target}, {Path: "/uncommitted", Target: target}})
			time.Sleep(400 * time.Millisecond)
			status, _, _, err = sudokuReverseHTTPGet(address, "/uncommitted/ready", nil)
			if err != nil || status != 404 {
				t.Fatal("conflict partially published routes", status, err)
			}
			duplicate.Close()
			status, _, body, err = sudokuReverseHTTPGet(address, "/app/ready", http.Header{"X-Forwarded-For": {"forged"}, "X-Forwarded-Host": {"forged"}})
			if err != nil || status != 200 || strings.Contains(body, "forged") {
				t.Fatal("untrusted forwarding headers", status, body, err)
			}
			for _, origin := range []string{"https://untrusted.example", "null"} {
				c, code, err := dialSudokuReverseWS(address, "/app", sudokuTCPSubprotocol, origin)
				if c != nil {
					c.Close()
				}
				if err != nil || code != 403 {
					t.Fatal("cross-origin WebSocket accepted", code, err)
				}
			}
			status, _, _, err = sudokuReverseHTTPGet(address, "/assets", http.Header{"Referer": {"https://untrusted.example/app/"}})
			if err != nil || status != 404 {
				t.Fatal("cross-origin routing fallback accepted", status, err)
			}
			first.Close()
			until = time.Now().Add(3 * time.Second)
			for time.Now().Before(until) {
				status, _, _, err = sudokuReverseHTTPGet(address, "/app/ready", nil)
				if err == nil && status == 404 {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil || status != 404 {
				t.Fatal("closed publisher retained route", status, err)
			}
			waitSudokuReverseHTTP(t, address, "/app/nested/ready")
			replacement := publish(sudokuReverseHTTPRoutes(target))
			waitSudokuReverseHTTP(t, address, "/app/ready")
			replacement.Close()
			second.Close()
			server.Close()
		})
	}
}
