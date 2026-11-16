package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
)

func controllerCall(t *testing.T, r *Runtime, method, path, body string, status int) []byte {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+r.ControllerAddress()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+r.controller.o.Secret)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != status {
		t.Fatalf("%s %s: status%d want%d: %s", method, path, resp.StatusCode, status, raw)
	}
	return raw
}

func controllerObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}
func controllerBase() Config {
	return Config{ExternalController: "127.0.0.1:0", Secret: "controller-test-secret", Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "blocked"}}, Route: Route{Final: "direct"}}
}

func TestControllerConfiguration(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		r := newTestRuntime(t, Config{})
		if r.controller != nil || r.ControllerAddress() != "" {
			t.Fatal("controller unexpectedly enabled")
		}
		assertTCP(t, r)
	})
	for _, raw := range []string{
		`{"external_controller":"0.0.0.0:0"}`, `{"external_controller":":9090"}`, `{"external_controller":"example.com:9090","secret":"x"}`,
		`{"external_controller":"127.0.0.1:65536"}`, `{"external_controller":"127.0.0.1:-1"}`, `{"secret":"x"}`,
		`{"external_controller":"127.0.0.1:0","experimental":{"clash_api":{"external_controller":"127.0.0.1:0"}}}`,
		`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:0","default_mode":"bad"}}}`,
		`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:0","access_control_allow_origin":["*"]}}}`,
		`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:0","access_control_allow_origin":["https://panel.example/path"]}}}`,
		`{"experimental":{"clash_api":{"external_controller":"127.0.0.1:0","unknown":1}}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("invalid controller accepted")
			}
		})
	}
	t.Run("experimental", func(t *testing.T) {
		cfg := controllerBase()
		cfg.ExternalController, cfg.Secret = "", ""
		cfg.Experimental.ClashAPI = &ControllerOptions{ExternalController: "127.0.0.1:0", DefaultMode: "direct"}
		r := newTestRuntime(t, cfg)
		if r.controller.modeName() != "direct" {
			t.Fatal("default mode ignored")
		}
		controllerCall(t, r, "GET", "/version", "", 200)
	})
	t.Run("bind-failure", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		cfg := controllerBase()
		cfg.ExternalController = l.Addr().String()
		raw, _ := json.Marshal(cfg)
		r, err := New(context.Background(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		if r.Start() == nil {
			t.Fatal("occupied controller port accepted")
		}
	})
}

func TestControllerAuthAndCORS(t *testing.T) {
	for _, secret := range []string{"", "secret"} {
		t.Run("secret="+secret, func(t *testing.T) {
			cfg := controllerBase()
			cfg.Secret = secret
			r := newTestRuntime(t, cfg)
			for _, test := range []struct {
				name, token, origin, host, query string
				want                             int
			}{
				{"valid", secret, "", "", "", 200},
				{"wrong", "wrong", "", "", "", map[bool]int{true: 200, false: 401}[secret == ""]},
				{"query", "", "", "", "?token=secret", map[bool]int{true: 200, false: 401}[secret == ""]},
				{"cross-origin", secret, "https://evil.example", "", "", map[bool]int{true: 403, false: 200}[secret == ""]},
				{"rebinding", secret, "", "evil.example", "", map[bool]int{true: 403, false: 200}[secret == ""]},
				{"null-origin", secret, "null", "", "", 403},
			} {
				t.Run(test.name, func(t *testing.T) {
					req, _ := http.NewRequest("GET", "http://"+r.ControllerAddress()+"/version"+test.query, nil)
					if test.token != "" {
						req.Header.Set("Authorization", "Bearer "+test.token)
					}
					req.Header.Set("Origin", test.origin)
					if test.host != "" {
						req.Host = test.host
					}
					resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					if resp.StatusCode != test.want {
						t.Fatalf("status%d want%d", resp.StatusCode, test.want)
					}
					if test.origin != "" && test.want == 200 && resp.Header.Get("Access-Control-Allow-Origin") != test.origin {
						t.Fatal("CORS reflection absent")
					}
				})
			}
			if secret != "" {
				req, _ := http.NewRequest("OPTIONS", "http://"+r.ControllerAddress()+"/configs", nil)
				req.Header.Set("Origin", "https://panel.example")
				req.Header.Set("Access-Control-Request-Private-Network", "true")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != 204 || resp.Header.Get("Access-Control-Allow-Private-Network") != "true" {
					t.Fatal("preflight rejected")
				}
			}
		})
	}
	t.Run("allowlist", func(t *testing.T) {
		cfg := controllerBase()
		cfg.ExternalController, cfg.Secret = "", ""
		cfg.Experimental.ClashAPI = &ControllerOptions{ExternalController: "127.0.0.1:0", Secret: "x", AccessControlAllowOrigin: []string{"https://panel.example"}}
		r := newTestRuntime(t, cfg)
		req := httptest.NewRequest("GET", "http://localhost/version", nil)
		req.Header.Set("Authorization", "Bearer x")
		req.Header.Set("Origin", "https://other.example")
		rec := httptest.NewRecorder()
		r.controller.serve(rec, req)
		if rec.Code != 403 {
			t.Fatal(rec.Code)
		}
	})
}

func controllerEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("controller-payload")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(payload, got) {
		t.Fatal(string(got), err)
	}
}
func controllerRows(t *testing.T, r *Runtime) []any {
	t.Helper()
	return controllerObject(t, controllerCall(t, r, "GET", "/connections", "", 200))["connections"].([]any)
}

func TestControllerSudokuRoutingAndConnections(t *testing.T) {
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: sudokuTestOptions("chacha20-poly1305", "prefer_entropy", true)}
	serverCfg := Config{Inbounds: []Inbound{in}, ExternalController: "127.0.0.1:0", Secret: "server-secret"}
	server := newTestRuntime(t, serverCfg)
	out := testOutbound(t, in, server.Address("server"))
	out.Tag = "node"
	out.Sudoku = in.Sudoku
	cfg := controllerBase()
	cfg.Outbounds = append(cfg.Outbounds, out, Outbound{Type: "selector", Tag: "主/组", Outbounds: []string{"node", "blocked", "direct"}, Default: "node"})
	cfg.Route.Final = "主/组"
	cfg.Route.Rules = []Rule{{Domain: []string{"blocked.invalid"}, Action: "reject"}, {Domain: []string{"direct.invalid"}, Outbound: "direct"}}
	r := newTestRuntime(t, cfg)
	target := sudokuTCPEcho(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, err := r.Dial(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	controllerEcho(t, conn)
	rows := controllerRows(t, r)
	if len(rows) != 1 {
		t.Fatal(rows)
	}
	row := rows[0].(map[string]any)
	if fmt.Sprint(row["chains"]) != "[node 主/组 PROXY]" {
		t.Fatal(row)
	}
	if row["upload"] != float64(len("controller-payload")) || row["download"] != row["upload"] {
		t.Fatal(row)
	}
	controllerCall(t, r, "PUT", "/proxies/"+url.PathEscape("主/组"), `{"name":"blocked"}`, 204)
	controllerEcho(t, conn)
	if c, e := r.Dial(ctx, "tcp", target); e == nil {
		c.Close()
		t.Fatal("selector change ignored")
	}
	controllerCall(t, r, "PATCH", "/configs", `{"mode":"GLOBAL","ignored":true}`, 204)
	controllerCall(t, r, "PUT", "/proxies/GLOBAL", `{"name":"DIRECT"}`, 204)
	direct, err := r.Dial(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	controllerEcho(t, direct)
	defer direct.Close()
	if c, e := r.Dial(ctx, "tcp", "blocked.invalid:80"); e == nil {
		c.Close()
		t.Fatal("global mode bypassed reject")
	}
	controllerCall(t, r, "PATCH", "/configs", `{"mode":"direct"}`, 204)
	if c, e := r.Dial(ctx, "tcp", "blocked.invalid:80"); e == nil {
		c.Close()
		t.Fatal("direct mode bypassed reject")
	}
	q, tag, err := r.routeTarget(ctx, request{network: "tcp", address: target})
	if err != nil || tag != r.controller.directTag || fmt.Sprint(q.controllerTrace.chain) != "[DIRECT]" {
		t.Fatal(tag, q, err)
	}
	controllerCall(t, r, "DELETE", "/connections/"+row["id"].(string), "", 204)
	if _, err := conn.Write([]byte("closed")); err == nil {
		t.Fatal("deleted connection still writable")
	}
	if len(controllerRows(t, r)) != 1 {
		t.Fatal("deleted unrelated connection")
	}
	controllerCall(t, r, "DELETE", "/connections", "", 204)
	if len(controllerRows(t, r)) != 0 {
		t.Fatal("connections not cleared")
	}
	controllerCall(t, r, "GET", "/version", "", 200)
	if !server.controller.readOnly {
		t.Fatal("server not read-only")
	}
	controllerCall(t, server, "GET", "/configs", "", 404)
	users := controllerObject(t, controllerCall(t, server, "GET", "/users", "", 200))
	if users["count"] != float64(0) {
		t.Fatal(users)
	}
	if server.controller.wireUp.Load() == 0 || server.controller.wireDown.Load() == 0 {
		t.Fatal("server wire traffic not counted")
	}
	proxies := controllerCall(t, r, "GET", "/proxies", "", 200)
	for _, secret := range []string{sudokuTestKey, cfg.Secret, "server-secret"} {
		if bytes.Contains(proxies, []byte(secret)) {
			t.Fatal("proxy response leaked secret")
		}
	}
}

func TestControllerGroupsAndValidation(t *testing.T) {
	cfg := controllerBase()
	cfg.Outbounds = append(cfg.Outbounds, Outbound{Type: "selector", Tag: "PROXY", Outbounds: []string{"direct", "blocked"}, Default: "direct", InterruptExistConnections: true}, Outbound{Type: "selector", Tag: "outer", Outbounds: []string{"PROXY"}, Default: "PROXY"})
	cfg.Route.Final = "outer"
	r := newTestRuntime(t, cfg)
	conn, err := r.Dial(context.Background(), "tcp", sudokuTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	controllerEcho(t, conn)
	controllerCall(t, r, "PUT", "/proxies/PROXY", `{"name":"blocked"}`, 204)
	if len(controllerRows(t, r)) != 0 {
		t.Fatal("interrupted group still tracked")
	}
	for _, test := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/group", "", 200}, {"GET", "/group/PROXY", "", 200}, {"GET", "/providers/proxies", "", 200}, {"GET", "/rules", "", 200},
		{"PUT", "/proxies/direct", `{"name":"direct"}`, 400}, {"PUT", "/proxies/PROXY", `{"name":"unknown"}`, 400}, {"GET", "/proxies/missing", "", 404},
		{"PATCH", "/configs", `{"mode":"bad"}`, 400}, {"PATCH", "/configs", `null`, 400}, {"PATCH", "/configs", `{} {}`, 400}, {"PATCH", "/configs", `{"mode":7}`, 400},
		{"PATCH", "/configs", `{"padding":"` + strings.Repeat("a", 65<<10) + `"}`, 400}, {"POST", "/version", "", 405}, {"GET", "/no-such-api", "", 404},
	} {
		t.Run(test.method+test.path+fmt.Sprint(test.want), func(t *testing.T) { controllerCall(t, r, test.method, test.path, test.body, test.want) })
	}
}

func TestControllerDelay(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "HEAD" {
			t.Errorf("delay used%s", req.Method)
		}
		if req.URL.Path == "/slow" {
			select {
			case <-req.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
		if req.URL.Path == "/redirect" {
			w.Header().Set("Location", "/ok")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(204)
	}))
	defer origin.Close()
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: sudokuTestOptions("aes-128-gcm", "prefer_ascii", true)}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Tag = "node"
	out.Sudoku = in.Sudoku
	cfg := controllerBase()
	cfg.Outbounds = append(cfg.Outbounds, out)
	r := newTestRuntime(t, cfg)
	for _, test := range []struct {
		name, path, expected, timeout string
		status                        int
	}{
		{"node", "/ok", "204", "1000", 200}, {"direct", "/redirect", "302", "1000", 200}, {"direct", "/redirect", "200-299", "1000", 503},
		{"blocked", "/ok", "*", "1000", 503}, {"direct", "/slow", "204", "20", 504},
		{"direct", "/ok", "200-", "1000", 400}, {"direct", "/ok", "204", "0", 400},
	} {
		t.Run(test.name+test.path+test.expected+test.timeout, func(t *testing.T) {
			path := "/proxies/" + test.name + "/delay?" + url.Values{"url": {origin.URL + test.path}, "timeout": {test.timeout}, "expected": {test.expected}}.Encode()
			controllerCall(t, r, "GET", path, "", test.status)
		})
	}
	query := "?" + url.Values{"url": {origin.URL}, "timeout": {"1000"}, "expected": {"200/204/301-302"}}.Encode()
	results := controllerObject(t, controllerCall(t, r, "GET", "/group/PROXY/delay"+query, "", 200))
	if results["node"] == nil || results["direct"] == nil || results["blocked"] != nil {
		t.Fatal(results)
	}
	info := controllerObject(t, controllerCall(t, r, "GET", "/proxies/node", "", 200))
	if len(info["history"].([]any)) != 2 {
		t.Fatal(info)
	}
	for i := range 20 {
		r.controller.recordDelay("node", fmt.Sprintf("http://example.com/%d", i), uint16(i+1))
	}
	h := r.controller.history["node"]
	if len(h.entries) != 10 || len(h.urls) != 8 {
		t.Fatal("history unbounded")
	}
	for i := range 300 {
		r.controller.recordDelay(fmt.Sprint(i), "http://example.com", 1)
	}
	if len(r.controller.history) != 256 {
		t.Fatal("node history unbounded")
	}
}

func controllerStream(t *testing.T, r *Runtime, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://"+r.ControllerAddress()+path, nil)
	req.Header.Set("Authorization", "Bearer "+r.controller.o.Secret)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		t.Fatal(resp.Status)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}
func TestControllerStreamsAndLogs(t *testing.T) {
	r := newTestRuntime(t, controllerBase())
	for _, path := range []string{"/traffic", "/memory"} {
		t.Run(path, func(t *testing.T) {
			resp := controllerStream(t, r, path+"?interval=100")
			defer resp.Body.Close()
			dec := json.NewDecoder(resp.Body)
			for range 2 {
				var v map[string]any
				if err := dec.Decode(&v); err != nil {
					t.Fatal(err)
				}
				if path == "/memory" && v["inuse"].(float64) <= 0 {
					t.Fatal(v)
				}
			}
		})
	}
	for _, format := range []string{"plain", "structured"} {
		t.Run(format, func(t *testing.T) {
			resp := controllerStream(t, r, "/logs?level=warning&format="+format)
			defer resp.Body.Close()
			r.logger.Info("filtered")
			r.logger.With(zap.String("password", "do-not-publish")).Warn("\x1b[31mvisible\x1b[0m")
			var line map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&line); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(line)
			if bytes.Contains(raw, []byte("password")) || bytes.Contains(raw, []byte("do-not-publish")) || bytes.Contains(raw, []byte("\\u001b")) {
				t.Fatal(string(raw))
			}
			if format == "plain" && line["payload"] != "visible" || format == "structured" && line["message"] != "visible" {
				t.Fatal(line)
			}
		})
	}
	controllerCall(t, r, "GET", "/logs?level=invalid", "", 400)
	controllerCall(t, r, "GET", "/traffic?interval=-1", "", 400)
	deadline := time.Now().Add(2 * time.Second)
	for {
		r.controller.mu.Lock()
		active := r.controller.streams
		r.controller.mu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed streams were not released")
		}
		time.Sleep(time.Millisecond)
	}
	var responses []*http.Response
	for range 16 {
		responses = append(responses, controllerStream(t, r, "/traffic?interval=100"))
	}
	controllerCall(t, r, "GET", "/memory", "", 503)
	for _, resp := range responses {
		resp.Body.Close()
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if r.controller.logReaders.Load() != 0 {
		t.Fatal("log subscriber leaked")
	}
}

func TestControllerWebSocket(t *testing.T) {
	r := newTestRuntime(t, controllerBase())
	raw, err := net.Dial("tcp", r.ControllerAddress())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(raw, "GET /traffic?token=%s&interval=100 HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n", r.controller.o.Secret, r.ControllerAddress())
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(raw)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil || resp.StatusCode != 101 {
		t.Fatal(resp, err)
	}
	client := &websocketConn{Conn: &bufferedConn{Conn: raw, reader: reader}, client: true, legacyText: true}
	var v map[string]any
	if err := json.NewDecoder(client).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v["upTotal"] == nil {
		t.Fatal(v)
	}
	if err := client.writeFrame(9, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	pong := false
	for range 4 {
		var h [2]byte
		if _, err := io.ReadFull(reader, h[:]); err != nil {
			t.Fatal(err)
		}
		n := int(h[1] & 127)
		if n == 126 {
			var extended [2]byte
			_, _ = io.ReadFull(reader, extended[:])
			n = int(binary.BigEndian.Uint16(extended[:]))
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(reader, p); err != nil {
			t.Fatal(err)
		}
		if h[0]&15 == 10 {
			pong = string(p) == "ping"
			break
		}
	}
	if !pong {
		t.Fatal("no WebSocket pong")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("WebSocket not closed by runtime")
	}
}

func TestControllerRulesAndDNSMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"version":3,"rules":[{"domain":["a.test"]}]}`)
	cfg := controllerBase()
	cfg.Route.RuleSet = []RuleSet{{Type: "local", Tag: "local/规则", Path: path, Format: "source"}}
	cfg.Route.Rules = []Rule{{RuleSet: []string{"local/规则"}, Action: "reject"}}
	cfg.DNS = DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "a", Predefined: map[string][]string{"mode.test": {"192.0.2.1"}}}, {Type: "hosts", Tag: "b", Predefined: map[string][]string{"mode.test": {"192.0.2.2"}}}}, Final: "a", Rules: []DNSRule{{Rule: Rule{ClashMode: "direct"}, Server: "b"}}}
	r := newTestRuntime(t, cfg)
	provider := controllerObject(t, controllerCall(t, r, "GET", "/providers/rules/"+url.PathEscape("local/规则"), "", 200))
	if provider["ruleCount"] != float64(1) || provider["updatedAt"] == "0001-01-01T00:00:00Z" {
		t.Fatal(provider)
	}
	write(`{"version":3,"rules":[{"domain":["b.test"]},{"domain_suffix":["other.test"]}]}`)
	controllerCall(t, r, "PUT", "/providers/rules/"+url.PathEscape("local/规则"), "", 204)
	if _, _, err := r.routeTarget(context.Background(), request{network: "tcp", address: "b.test:80"}); err == nil {
		t.Fatal("rule refresh not applied")
	}
	write(`{bad`)
	controllerCall(t, r, "PUT", "/providers/rules/"+url.PathEscape("local/规则"), "", 500)
	if _, _, err := r.routeTarget(context.Background(), request{network: "tcp", address: "b.test:80"}); err == nil {
		t.Fatal("failed reload discarded previous rules")
	}
	for _, mode := range []string{"rule", "direct", "rule"} {
		controllerCall(t, r, "PATCH", "/configs", `{"mode":"`+mode+`"}`, 204)
		ips, err := r.resolver.lookupReal(context.Background(), "mode.test")
		want := netip.MustParseAddr("192.0.2.1")
		if mode == "direct" {
			want = netip.MustParseAddr("192.0.2.2")
		}
		if err != nil || len(ips) != 1 || ips[0] != want {
			t.Fatal(mode, ips, err)
		}
	}
}

func FuzzControllerDelayOptions(f *testing.F) {
	for _, s := range []string{"timeout=1000", "timeout=1&expected=200-299", "timeout=2&expected=200-", "timeout=100&url=http%3A%2F%2Flocalhost"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 8192 {
			return
		}
		req := &http.Request{URL: &url.URL{RawQuery: query}}
		duration, _, accept, err := controllerDelayOptions(req)
		if err == nil {
			if duration <= 0 || duration > time.Minute {
				t.Fatal(duration)
			}
			for status := 0; status < 700; status++ {
				_ = accept(status)
			}
		}
	})
}

func TestControllerConcurrentSwitchAndClose(t *testing.T) {
	r := newTestRuntime(t, controllerBase())
	target := sudokuTCPEcho(t)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 10 {
				conn, err := r.Dial(context.Background(), "tcp", target)
				if err == nil {
					conn.Close()
				}
				r.controller.setMode("direct")
				r.controller.setMode("rule")
				r.controller.connections()
			}
		})
	}
	workers.Go(func() {
		for range 30 {
			r.controller.closeConnections("")
		}
	})
	workers.Wait()
	r.Close()
	if len(r.controller.flows) != 0 {
		t.Fatal("connections leaked after shutdown")
	}
}

func TestControllerUDPPacketsAndHalfClose(t *testing.T) {
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: sudokuTestOptions("chacha20-poly1305", "prefer_entropy", true)}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Sudoku = in.Sudoku
	cfg := controllerBase()
	cfg.Outbounds = append(cfg.Outbounds, out)
	cfg.Route.Final = out.Tag
	r := newTestRuntime(t, cfg)
	target, other := echoUDP(t), echoUDP(t)
	conn, err := r.Dial(context.Background(), "udp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	packet := udpCarrier(conn)
	if packet == nil {
		t.Fatal("controller hid addressed UDP carrier")
	}
	total := 0
	for i, address := range []string{target, other, target, other} {
		p := bytes.Repeat([]byte{byte(i)}, i*511)
		if _, err := packet.writePacket(p, address); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, got, err := packet.readPacket(buf)
		if err != nil || got != address || !bytes.Equal(p, buf[:n]) {
			t.Fatal(n, got, err)
		}
		total += len(p)
	}
	up, down := r.controller.totals()
	if up != int64(total) || down != int64(total) {
		t.Fatalf("packet payload counted incorrectly:%d/%d want%d", up, down, total)
	}
	conn.Close()
	if len(controllerRows(t, r)) != 0 {
		t.Fatal("UDP flow leaked")
	}
	stream, err := r.Dial(context.Background(), "tcp", sudokuTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = stream.Write([]byte("half-close"))
	if err := stream.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	p, err := io.ReadAll(stream)
	if err != nil || string(p) != "half-close" {
		t.Fatal(string(p), err)
	}
}

func TestControllerCapacityDoesNotBlockProxy(t *testing.T) {
	r := newTestRuntime(t, controllerBase())
	c := r.controller
	c.mu.Lock()
	for i := range 4096 {
		c.flows[fmt.Sprint(i)] = &controllerConn{}
	}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); clear(c.flows); c.mu.Unlock() }()
	conn, err := r.Dial(context.Background(), "tcp", sudokuTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	controllerEcho(t, conn)
	if r.controller.up.Load() == 0 {
		t.Fatal("unlisted traffic not counted")
	}
	c.mu.Lock()
	size := len(c.flows)
	c.mu.Unlock()
	if size != 4096 {
		t.Fatal("inventory limit ignored")
	}
}

func TestControllerOfficialAPI(t *testing.T) {
	for _, side := range []string{"client", "server"} {
		t.Run(side, func(t *testing.T) {
			in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: sudokuTestOptions("chacha20-poly1305", "prefer_entropy", true)}
			nativeServer := newTestRuntime(t, Config{Inbounds: []Inbound{in}, ExternalController: "127.0.0.1:0", Secret: "api-reference-secret"})
			apiPort := unusedPort(t)
			refAddress := portAddress("127.0.0.1", apiPort)
			reference := map[string]any{"mode": side, "name": "node", "transport": "tcp", "key": sudokuTestKey, "aead": "chacha20-poly1305", "ascii": "prefer_entropy", "padding_min": 5, "padding_max": 15, "enable_pure_downlink": false, "multiplex": "off", "httpmask": map[string]any{"disable": true}, "external_controller": refAddress, "secret": "api-reference-secret", "local_port": unusedPort(t)}
			var ours *Runtime
			if side == "client" {
				reference["server_address"], reference["proxy_mode"] = nativeServer.Address("server"), "global"
				out := testOutbound(t, in, nativeServer.Address("server"))
				out.Sudoku = in.Sudoku
				out.Tag = "node"
				cfg := controllerBase()
				cfg.Secret = "api-reference-secret"
				cfg.Outbounds = append(cfg.Outbounds, out)
				cfg.Route.Final = "node"
				ours = newTestRuntime(t, cfg)
			} else {
				ours = nativeServer
			}
			startSudokuReference(t, reference)
			waitPort(t, refAddress)
			call := func(address, method, path, body string, status int) []byte {
				t.Helper()
				req, _ := http.NewRequest(method, "http://"+address+path, strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer api-reference-secret")
				resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				raw, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != status {
					t.Fatalf("%s%s status%d:%s", method, path, resp.StatusCode, raw)
				}
				return raw
			}
			for _, path := range []string{"/", "/version"} {
				a := controllerObject(t, call(ours.ControllerAddress(), "GET", path, "", 200))
				b := controllerObject(t, call(refAddress, "GET", path, "", 200))
				if path == "/" && fmt.Sprint(a) != fmt.Sprint(b) || path == "/version" && a["meta"] != b["meta"] {
					t.Fatal(a, b)
				}
			}
			if side == "server" {
				for _, address := range []string{ours.ControllerAddress(), refAddress} {
					v := controllerObject(t, call(address, "GET", "/users", "", 200))
					if v["count"] != float64(0) || len(v["users"].([]any)) != 0 {
						t.Fatal(v)
					}
					call(address, "GET", "/proxies", "", 404)
				}
				return
			}
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(204) }))
			defer origin.Close()
			for _, address := range []string{ours.ControllerAddress(), refAddress} {
				for _, mode := range []string{"rule", "proxy", "DIRECT"} {
					call(address, "PATCH", "/configs", `{"mode":"`+mode+`"}`, 204)
					v := controllerObject(t, call(address, "GET", "/configs", "", 200))
					want := strings.ToLower(mode)
					if want == "proxy" {
						want = "global"
					}
					if v["mode"] != want {
						t.Fatal(v)
					}
				}
				call(address, "PATCH", "/configs", `{"mode":"invalid"}`, 400)
				call(address, "GET", "/proxies/missing", "", 404)
				call(address, "DELETE", "/proxies/PROXY", "", 400)
				nodes := controllerObject(t, call(address, "GET", "/proxies", "", 200))["proxies"].(map[string]any)
				name := ""
				for key, raw := range nodes {
					v := raw.(map[string]any)
					if v["type"] == "Sudoku" {
						name = key
						if !v["udp"].(bool) || !v["uot"].(bool) {
							t.Fatal(v)
						}
						break
					}
				}
				if name == "" {
					t.Fatal("Sudoku node missing")
				}
				path := "/proxies/" + url.PathEscape(name) + "/delay?" + url.Values{"url": {origin.URL}, "timeout": {"2000"}, "expected": {"204"}}.Encode()
				v := controllerObject(t, call(address, "GET", path, "", 200))
				if v["delay"].(float64) < 1 {
					t.Fatal(v)
				}
			}
		})
	}
}

func TestControllerBoundedLogQueue(t *testing.T) {
	r := newTestRuntime(t, controllerBase())
	c := r.controller
	ch := make(chan controllerLog, 256)
	c.mu.Lock()
	c.logs[ch] = struct{}{}
	c.logReaders.Add(1)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.logs, ch); c.logReaders.Add(-1); c.mu.Unlock() }()
	for range 300 {
		r.logger.Info("queue test")
	}
	if len(ch) != 256 {
		t.Fatal("log queue did not keep its bound")
	}
}
func TestControllerHeadlessModeRejected(t *testing.T) {
	for _, rules := range [][]Rule{{{ClashMode: "direct"}}, {{Type: "logical", Mode: "or", Rules: []Rule{{ClashMode: "global"}, {Domain: []string{"example.com"}}}}}} {
		if _, err := compileRuleSet(rules); err == nil {
			t.Fatal("controller mode accepted as a headless condition")
		}
	}
}

func TestControllerWebSocketIdleControlDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	_ = a.SetWriteDeadline(time.Now().Add(-time.Second))
	server := &websocketConn{Conn: &controllerWriteDeadlineConn{Conn: a}}
	done := make(chan error, 1)
	go func() { _, err := server.Read(make([]byte, 1)); done <- err }()
	client := &websocketConn{Conn: b, client: true}
	if err := client.writeFrame(9, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	var frame [6]byte
	if _, err := io.ReadFull(b, frame[:]); err != nil {
		t.Fatal(err)
	}
	if frame[0] != 0x8a || frame[1] != 4 || string(frame[2:]) != "ping" {
		t.Fatal(frame)
	}
	if err := client.writeFrame(8, nil); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != io.EOF {
		t.Fatal(err)
	}
}

func TestControllerQueryTokenRequiresStream(t *testing.T) {
	r := newTestRuntime(t, controllerBase())
	req := httptest.NewRequest("GET", "http://localhost/version?token="+r.controller.o.Secret, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	rec := httptest.NewRecorder()
	r.controller.serve(rec, req)
	if rec.Code != 401 {
		t.Fatal("query token authenticated non-stream endpoint", rec.Code)
	}
}
