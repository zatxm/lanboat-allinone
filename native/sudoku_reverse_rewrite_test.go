package native

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSudokuReverseRewrite(t *testing.T) {
	for _, v := range []struct{ name, ct, input, want string }{
		{"html", "text/html", `<a href="/login?q=1">/text</a><img src=/image><iframe src="//external/x">`, `<a href="/app/login?q=1">/text</a><img src=/app/image><iframe src="//external/x">`},
		{"scripts", "text/html", `<SCRIPT src="/code.js">x="/do-not-change"</SCRIPT><textarea>/text<img src="/literal"></textarea><!-- <img src="/comment"> -->`, `<SCRIPT src="/app/code.js">x="/do-not-change"</SCRIPT><textarea>/text<img src="/literal"></textarea><!-- <img src="/comment"> -->`},
		{"styles", "text/html", `<style>a{background:url(/a)}</style><img style="background:url('/b')">`, `<style>a{background:url(/app/a)}</style><img style="background:url('/app/b')">`},
		{"srcset", "text/html", `<img srcset="/a 1x, /b 2x, //cdn/c 3x, /app/d 4x">`, `<img srcset="/app/a 1x, /app/b 2x, //cdn/c 3x, /app/d 4x">`},
		{"svg", "image/svg+xml", `<use xlink:href="/icons.svg#id"/><text>/literal</text>`, `<use xlink:href="/app/icons.svg#id"/><text>/literal</text>`},
		{"css", "text/css", `a{background:URL( "/a")}b{src:url(/app/b)}c{src:url(//cdn/c)}`, `a{background:URL( "/app/a")}b{src:url(/app/b)}c{src:url(//cdn/c)}`},
		{"json", "application/json", `{"asset":"/file","root":"/","url":"https://external/file","quoted":"x\"/literal"}`, `{"asset":"/app/file","root":"/app/","url":"https://external/file","quoted":"x\"/literal"}`},
		{"already-prefixed", "text/html", `<a href="/app?x=1"><img src="/app/ok">`, `<a href="/app?x=1"><img src="/app/ok">`},
	} {
		t.Run(v.name, func(t *testing.T) {
			got := sudokuRewriteText([]byte(v.input), "/app", v.ct)
			if string(got) != v.want {
				t.Fatalf("got %s,want %s", got, v.want)
			}
			if again := sudokuRewriteText(got, "/app", v.ct); !bytes.Equal(again, got) {
				t.Fatal("not idempotent", string(again))
			}
		})
	}
}

func TestSudokuReverseBody(t *testing.T) {
	for _, name := range []string{"plain", "gzip", "over-limit", "unknown-size", "gzip-bomb", "bad-gzip", "brotli", "javascript", "event-stream", "partial", "head", "expansion-limit"} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`<img src="/asset">`)
			resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}, "ETag": {"stale"}}, Request: &http.Request{Method: "GET", URL: &url.URL{Scheme: "http", Host: "origin", Path: "/page"}}}
			prefix := "/app"
			unchanged := false
			switch name {
			case "over-limit", "unknown-size":
				raw = bytes.Repeat(raw, sudokuReverseBodyLimit/len(raw)+1)
				unchanged = true
			case "gzip-bomb":
				raw = bytes.Repeat(raw, sudokuReverseBodyLimit/len(raw)+1)
				unchanged = true
			case "bad-gzip":
				resp.Header.Set("Content-Encoding", "gzip")
				unchanged = true
			case "brotli":
				resp.Header.Set("Content-Encoding", "br")
				unchanged = true
			case "javascript":
				resp.Request.URL.Path = "/code.js"
				unchanged = true
			case "event-stream":
				resp.Header.Set("Content-Type", "text/event-stream")
				unchanged = true
			case "partial":
				resp.StatusCode = 206
				unchanged = true
			case "head":
				resp.Request.Method = "HEAD"
				unchanged = true
			case "expansion-limit":
				raw = bytes.Repeat(raw, 40000)
				prefix = "/" + strings.Repeat("x", 255)
				unchanged = true
			}
			if name == "gzip" || name == "gzip-bomb" {
				var b bytes.Buffer
				g := gzip.NewWriter(&b)
				g.Write(raw)
				g.Close()
				raw = b.Bytes()
				resp.Header.Set("Content-Encoding", "gzip")
			}
			resp.ContentLength = int64(len(raw))
			if name == "unknown-size" {
				resp.ContentLength = -1
			}
			resp.Body = io.NopCloser(bytes.NewReader(raw))
			if err := sudokuReverseBody(resp, prefix); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if unchanged {
				if !bytes.Equal(got, raw) {
					t.Fatal("opaque body changed")
				}
				return
			}
			if string(got) != `<img src="/app/asset">` || resp.Header.Get("ETag") != "" || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength != int64(len(got)) {
				t.Fatal(string(got), resp.Header, resp.ContentLength)
			}
		})
	}
}

func TestSudokuReverseRouteValidation(t *testing.T) {
	canonical, err := parseSudokuReverse([]byte(`{"routes":[{"path":"/v6","target":"[0:0:0:0:0:0:0:1]:80"}]}`))
	if err != nil || canonical.Routes[0].Target != "[::1]:80" {
		t.Fatal("published IPv6 target does not match the wire address", canonical, err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "v6:"+r.URL.Path) }))
	origin.Listener.Close()
	origin.Listener, err = net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	origin.Start()
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	server, client, entry := nativeSudokuReverseHTTP(t, "raw", []SudokuReverseRoute{{Path: "/v6", Target: "[0:0:0:0:0:0:0:1]:" + port}}, false)
	waitSudokuReverseHTTP(t, entry, "/v6/ready")
	code, _, body, err := sudokuReverseHTTPGet(entry, "/v6/echo", nil)
	if err != nil || code != 200 || body != "v6:/echo" {
		t.Fatal(code, body, err)
	}
	client.Close()
	server.Close()
	for _, raw := range []string{
		`{"routes":[{"path":"/x","target":"127.0.0.1:80","host_header":"bad\r\nInjected:yes"}]}`,
		`{"routes":[{"path":"/a/../x","target":"127.0.0.1:80"},{"path":"x/","target":"127.0.0.1:81"}]}`,
		`{"routes":[{"path":"/x?query","target":"127.0.0.1:80"}]}`,
		`{"routes":[{"path":"/x","target":"127.0.0.1:80","strip_prefix":"yes"}]}`,
	} {
		if _, err := parseSudokuReverse([]byte(raw)); err == nil {
			t.Fatal("bad route accepted", raw)
		}
	}
	valid := SudokuReverse{ClientID: "many", Routes: make([]SudokuReverseRoute, 64)}
	for i := range valid.Routes {
		valid.Routes[i] = SudokuReverseRoute{Path: fmt.Sprintf("/route-%d", i), Target: "127.0.0.1:80"}
	}
	b, _ := json.Marshal(valid)
	if len(b) <= 1024 {
		t.Fatal("fixture must exceed old limit")
	}
	p, err := parseSudokuReverse(b)
	if err != nil || len(p.Routes) != 64 {
		t.Fatal(err)
	}
	valid.Routes = append(valid.Routes, SudokuReverseRoute{Path: "/too-many", Target: "127.0.0.1:80"})
	b, _ = json.Marshal(valid)
	if _, err = parseSudokuReverse(b); err == nil {
		t.Fatal("route limit ignored")
	}
	if _, err = parseSudokuReverse(bytes.Repeat([]byte{' '}, sudokuReverseMaxRegistration+1)); err == nil {
		t.Fatal("body limit ignored")
	}
}

func TestSudokuReverseHeaders(t *testing.T) {
	for _, v := range []struct{ input, want string }{
		{"/login?q=1#x", "/app/login?q=1#x"},
		{"/app?x=1", "/app?x=1"},
		{"https://backend.example/login", "/app/login"},
		{"https://external.example/login", "https://external.example/login"},
		{"//external.example/login", "//external.example/login"},
		{"relative", "relative"},
	} {
		t.Run(v.input, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{"Location": {v.input}, "Set-Cookie": {"a=1; Path=/; Secure", "b=2; Path=/app/x; HttpOnly"}}, Request: &http.Request{Host: "backend.example"}}
			sudokuReverseHeaders(resp, "/app")
			if resp.Header.Get("Location") != v.want {
				t.Fatal(resp.Header)
			}
			cookies := resp.Cookies()
			if len(cookies) != 3 || cookies[0].Path != "/app/" || cookies[1].Path != "/app/x" || cookies[2].Name != sudokuReverseCookie || !cookies[2].HttpOnly {
				t.Fatal(cookies)
			}
		})
	}
}

func TestSudokuReverseResponseBuffers(t *testing.T) {
	r := newTestRuntime(t, Config{})
	p := &sudokuReverseServer{r: r, bodySlots: make(chan struct{}, 4)}
	proxy := p.newHTTPRoute(SudokuReverseRoute{Path: "/app", Target: "127.0.0.1:80"}, nil).proxy
	response := func(ctx context.Context) *http.Response {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://backend/page", nil)
		return &http.Response{StatusCode: 200, Request: req, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(`<img src="/asset">`)), ContentLength: 18}
	}
	held := make([]*http.Response, 0, 4)
	for range 4 {
		resp := response(context.Background())
		if err := proxy.ModifyResponse(resp); err != nil {
			t.Fatal(err)
		}
		held = append(held, resp)
	}
	if len(p.bodySlots) != 4 {
		t.Fatal("buffer slots released before body close")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	blocked := response(ctx)
	if err := proxy.ModifyResponse(blocked); err != context.DeadlineExceeded {
		t.Fatal("buffer limit not cancellable", err)
	}
	blocked.Body.Close()
	held[0].Body.Close()
	held[0].Body.Close()
	if len(p.bodySlots) != 3 {
		t.Fatal("body close did not release exactly one slot")
	}
	next := response(context.Background())
	if err := proxy.ModifyResponse(next); err != nil {
		t.Fatal(err)
	}
	next.Body.Close()
	for _, resp := range held[1:] {
		resp.Body.Close()
	}
	stream := response(context.Background())
	stream.Header.Set("Content-Type", "text/event-stream")
	if err := proxy.ModifyResponse(stream); err != nil {
		t.Fatal(err)
	}
	stream.Body.Close()
	if len(p.bodySlots) != 0 {
		t.Fatal("retained slot or streaming body buffered")
	}
}

func FuzzSudokuReverseText(f *testing.F) {
	for _, seed := range []string{`<img src="/a"><script>x="/b";</script>`, `<img srcset="/a 1x, /b 2x">`, `a{background:url(/a)}`, `{"file":"/x"}`, `<img src=`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 65536 {
			return
		}
		for _, ct := range []string{"text/html", "text/css", "application/json"} {
			got := sudokuRewriteText([]byte(s), "/app", ct)
			if len(got) > 2*sudokuReverseBodyLimit {
				t.Fatal("output limit")
			}
		}
	})
}
