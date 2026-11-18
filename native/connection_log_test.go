package native

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// withoutConnectionLog removes the close-tracking wrapper that debug logging
// adds to routed connections.
func withoutConnectionLog(c net.Conn) net.Conn {
	if v, ok := c.(*connectionLogConn); ok {
		return v.Conn
	}
	return c
}

func loggingRuntime(t *testing.T, cfg Config) (*Runtime, *observer.ObservedLogs) {
	t.Helper()
	core, logs := observer.New(zap.DebugLevel)
	raw, _ := json.Marshal(cfg)
	r, err := New(context.Background(), raw, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r, logs
}

func TestConnectionLogHTTPPrivacy(t *testing.T) {
	for _, https := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[https], func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body, _ := io.ReadAll(req.Body)
				if req.URL.RequestURI() != "/search?q=sing-box&token=query-secret" || req.Header.Get("Authorization") != "Bearer header-secret" || string(body) != "body-secret" {
					t.Error("request changed while proxying")
				}
				_, _ = w.Write([]byte("ok"))
			})
			origin := httptest.NewUnstartedServer(handler)
			if https {
				origin.StartTLS()
			} else {
				origin.Start()
			}
			defer origin.Close()
			cfg := Config{Log: LogOptions{Level: "debug"}, Inbounds: []Inbound{{Type: "mixed", Tag: "local", Listen: "127.0.0.1"}}, DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"www.google.com": {"127.0.0.1"}}}}, Final: "hosts"}}
			r, logs := loggingRuntime(t, cfg)
			proxy, _ := url.Parse("http://" + r.Address("local"))
			_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			scheme := "http"
			if https {
				scheme = "https"
			}
			req, _ := http.NewRequest("POST", scheme+"://www.google.com:"+port+"/search?q=sing-box&token=query-secret", strings.NewReader("body-secret"))
			req.Header.Set("Authorization", "Bearer header-secret")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "ok" {
				t.Fatal(string(body), err)
			}
			from := logs.FilterMessageSnippet("inbound/mixed[local]: inbound connection from 127.0.0.1:").All()
			in := logs.FilterMessageSnippet("inbound/mixed[local]: inbound connection to www.google.com:" + port).All()
			out := logs.FilterMessageSnippet("outbound/direct[direct]: outbound connection to www.google.com:" + port).All()
			if len(from) != 1 || len(in) != 1 || len(out) != 1 {
				t.Fatal(logs.All())
			}
			if id := logEntryID(t, in[0].Message); logEntryID(t, from[0].Message) != id || logEntryID(t, out[0].Message) != id {
				t.Fatal("connection entries do not share an ID", from[0].Message, in[0].Message, out[0].Message)
			}
			raw, _ := json.Marshal(logs.All())
			for _, secret := range []string{"/search", "sing-box", "query-secret", "header-secret", "body-secret", "Authorization"} {
				if bytes.Contains(raw, []byte(secret)) {
					t.Fatalf("request content appeared in log:%s", secret)
				}
			}
		})
	}
}

func TestConnectionLogLevelsAndFailures(t *testing.T) {
	for _, level := range []string{"info", "debug", "warn", "error", "disabled"} {
		t.Run(level, func(t *testing.T) {
			cfg := Config{Log: LogOptions{Level: level}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct", Rules: []Rule{{Domain: []string{"reject.test"}, Action: "reject"}}}}
			if level == "disabled" {
				cfg.Log = LogOptions{Disabled: true}
			}
			r, logs := loggingRuntime(t, cfg)
			conn, err := r.Dial(context.Background(), "tcp", sudokuTCPEcho(t))
			if err != nil {
				t.Fatal(err)
			}
			controllerEcho(t, conn)
			conn.Close()
			if c, err := r.Dial(context.Background(), "tcp", "reject.test:443"); !errors.Is(err, ErrRejected) {
				if c != nil {
					c.Close()
				}
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			target := listener.Addr().String()
			listener.Close()
			if c, err := r.Dial(context.Background(), "tcp", target); err == nil {
				c.Close()
				t.Fatal("closed target unexpectedly accepted connection")
			}
			if level == "disabled" {
				if logs.Len() != 0 {
					t.Fatal(logs.All())
				}
				return
			}
			if logs.FilterLevelExact(zapcore.ErrorLevel).Len() != 1 {
				t.Fatal(logs.All())
			}
			if (level == "warn" || level == "error") && logs.FilterLevelExact(zapcore.InfoLevel).Len() != 0 {
				t.Fatal("info escaped configured level")
			}
			if level == "info" && logs.FilterLevelExact(zapcore.DebugLevel).Len() != 0 {
				t.Fatal("debug escaped info level")
			}
			if level == "debug" && logs.FilterMessageSnippet("] router: match[0] domain=reject.test => reject").Len() != 1 {
				t.Fatal("missing rule match")
			}
		})
	}
}

func TestConnectionLogUDPAndSelector(t *testing.T) {
	cfg := Config{Outbounds: []Outbound{{Type: "direct", Tag: "one"}, {Type: "selector", Tag: "pick", Outbounds: []string{"one"}, Default: "one"}}, Route: Route{Final: "pick"}}
	r, logs := loggingRuntime(t, cfg)
	target := echoUDP(t)
	c, err := r.Dial(context.Background(), "udp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	for range 4 {
		p := []byte("udp-body-secret")
		if _, err := c.Write(p); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		if _, err := c.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	if logs.FilterMessageSnippet("outbound/direct[one]: outbound packet connection to "+target).Len() != 1 || logs.FilterMessageSnippet("outbound/").Len() != 1 {
		t.Fatal("UDP logged per packet instead of per session", logs.All())
	}
	// Do not embed the HTTP transport's URL (query may contain credentials).
	r.logConnection(request{address: target}, "pick", nil, &url.Error{Op: "Get", URL: "https://private.test/path?secret=secret", Err: errors.New("transport failed")}, false)
	raw, _ := json.Marshal(logs.All())
	if bytes.Contains(raw, []byte("?secret")) || bytes.Contains(raw, []byte("udp-body-secret")) {
		t.Fatal("request payload leaked")
	}
}

func TestConnectionLogFile(t *testing.T) {
	for _, timestamp := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "connection.log")
		cfg := Config{Log: LogOptions{Level: "info", Output: path, Timestamp: timestamp}}
		raw, _ := json.Marshal(cfg)
		r, err := New(context.Background(), raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Start(); err != nil {
			t.Fatal(err)
		}
		target := sudokuTCPEcho(t)
		c, err := r.Dial(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		r.Close()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		prefix := `^INFO `
		if timestamp {
			prefix = `^[+-]\d{4} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} INFO `
		}
		want := regexp.MustCompile(prefix + `\[1 \d+ms\] (inbound: inbound|outbound/direct\[direct\]: outbound) connection to ` + regexp.QuoteMeta(target) + `$`)
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 2 {
			t.Fatal(string(data))
		}
		for _, line := range lines {
			if !want.MatchString(line) {
				t.Fatal(line)
			}
		}
	}
}

// logEntryID returns the connection ID of a "[id elapsed] ..." message.
func logEntryID(t *testing.T, message string) string {
	t.Helper()
	id, _, ok := strings.Cut(strings.TrimPrefix(message, "["), " ")
	if !ok || !strings.HasPrefix(message, "[") {
		t.Fatal("missing connection prefix", message)
	}
	return id
}

func TestConnectionLoggerEvents(t *testing.T) {
	cfg := Config{Log: LogOptions{Level: "debug"}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct", Rules: []Rule{{Domain: []string{"reject.test"}, Action: "reject"}, {IPCIDR: []string{"127.0.0.1/32"}, Outbound: "direct"}}}}
	r, logs := loggingRuntime(t, cfg)
	var events []ConnectionLog
	r.SetConnectionLogger(func(e ConnectionLog) { events = append(events, e) }, true)
	target := sudokuTCPEcho(t)
	conn, err := r.Dial(context.Background(), "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	controllerEcho(t, conn)
	conn.Close()
	conn.Close()
	if c, err := r.Dial(context.Background(), "tcp", "reject.test:443"); !errors.Is(err, ErrRejected) {
		if c != nil {
			c.Close()
		}
		t.Fatal(err)
	}
	r.Close()
	if len(events) != 3 {
		t.Fatal(events)
	}
	opened, closed, rejected := events[0], events[1], events[2]
	if opened.Event != ConnectionOpened || closed.Event != ConnectionClosed || rejected.Event != ConnectionFailed {
		t.Fatal(events)
	}
	if opened.ID == 0 || closed.ID != opened.ID || opened.Destination != target || opened.Rule != "ip_cidr=127.0.0.1/32" || opened.Outbound != "direct" {
		t.Fatal(opened, closed)
	}
	if closed.Upload == 0 || closed.Upload != closed.Download || closed.Elapsed < opened.Elapsed || closed.Error != nil {
		t.Fatal(closed)
	}
	if rejected.Outbound != "REJECT" || rejected.Rule != "domain=reject.test" || !errors.Is(rejected.Error, ErrRejected) {
		t.Fatal(rejected)
	}
	entries := logs.FilterMessageSnippet("] connection: connection closed (upload ").All()
	if len(entries) != 1 || entries[0].Level != zapcore.DebugLevel || logEntryID(t, entries[0].Message) != strconv.FormatUint(closed.ID, 10) {
		t.Fatal(entries)
	}
}

func TestConnectionLoggerWithoutZapOrCloseEvents(t *testing.T) {
	cfg := Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct"}}
	r, logs := loggingRuntime(t, cfg)
	var events []ConnectionLog
	r.SetConnectionLogger(func(e ConnectionLog) { events = append(events, e) }, false)
	conn, err := r.Dial(context.Background(), "tcp", sudokuTCPEcho(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := conn.(*connectionLogConn); ok {
		t.Fatal("close tracking without a consumer")
	}
	conn.Close()
	r.Close()
	if logs.Len() != 0 || len(events) != 1 || events[0].Event != ConnectionOpened || events[0].ID == 0 || events[0].Rule != "final" {
		t.Fatal(events, logs.All())
	}
}

func TestLogFormat(t *testing.T) {
	for d, want := range map[time.Duration]string{38 * time.Millisecond: "38ms", 1050 * time.Millisecond: "1.05s", 75 * time.Second: "1m15s"} {
		if got := formatLogDuration(d); got != want {
			t.Fatal(d, got)
		}
	}
	rule := Rule{Type: "logical", Mode: "or", Invert: true, Action: "route", Outbound: "proxy", Rules: []Rule{{DomainSuffix: []string{"a.test", "b.test"}}, {Port: []uint16{443}, IPIsPrivate: true}}}
	if got := newRuleLogs([]Rule{rule})[0].match; got != "match[0] !((domain_suffix=[a.test b.test] || port=443 ip_is_private)) => route(proxy)" {
		t.Fatal(got)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.FixedZone("", 8*3600))
	entry := zapcore.Entry{Level: zapcore.WarnLevel, Time: at, Message: "[42 5ms] router: lookup failed"}
	for _, c := range []struct {
		encoder *logEncoder
		want    string
	}{
		{newLogEncoder(true, true, false), "+0800 2026-01-02 03:04:05 WARN [42 5ms] router: lookup failed\n"},
		{newLogEncoder(false, true, false), "WARN [42 5ms] router: lookup failed\n"},
		{&logEncoder{Encoder: newLogEncoder(false, false, false).Encoder, start: at.Add(-12 * time.Second)}, "WARN[0012] [42 5ms] router: lookup failed\n"},
	} {
		line, err := c.encoder.EncodeEntry(entry, nil)
		if err != nil || line.String() != c.want {
			t.Fatalf("%q %v", line.String(), err)
		}
	}
	named := entry
	named.LoggerName, named.Message = "http2", "TLS handshake error"
	line, _ := newLogEncoder(false, true, false).EncodeEntry(named, []zapcore.Field{zap.Int("extra", 1)})
	if line.String() != "WARN http2: TLS handshake error {\"extra\":1}\n" {
		t.Fatal(line.String())
	}
	if got := colorLogID("[42 5ms] x"); got != "[\x1b[38;5;189m42\x1b[0m 5ms] x" {
		t.Fatalf("%q", got)
	}
}

func BenchmarkConnectionLogDisabled(b *testing.B) {
	r := &Runtime{logger: zap.NewNop()}
	q := request{network: "tcp", address: "example.com:443"}
	b.ReportAllocs()
	for b.Loop() {
		r.logInbound(&q)
		r.logConnection(q, "direct", nil, nil, true)
	}
}
