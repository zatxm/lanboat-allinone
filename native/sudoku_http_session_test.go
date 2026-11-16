package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func sudokuTCPEcho(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String()
}

func sudokuSplitRuntime(t *testing.T, mode string, mux bool) (*Runtime, *Runtime) {
	t.Helper()
	o := sudokuTestOptions("chacha20-poly1305", "up_ascii_down_entropy", true)
	o.HTTPMask = &SudokuHTTPMask{Mode: mode, PathRoot: "assets"}
	in := Inbound{Type: "sudoku", Tag: "server", Listen: "127.0.0.1", Sudoku: o}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	out := testOutbound(t, in, server.Address("server"))
	out.Sudoku, out.Multiplex.Enabled = o, mux
	return server, newTestRuntime(t, Config{Outbounds: []Outbound{out}})
}

func TestSudokuHTTPSplitHalfClose(t *testing.T) {
	for _, mode := range []string{"stream", "poll", "auto"} {
		t.Run(mode, func(t *testing.T) {
			_, client := sudokuSplitRuntime(t, mode, false)
			assertSudokuHalfClose(t, client)
		})
	}
}

func TestSudokuHTTPSplitConcurrent(t *testing.T) {
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server, client := sudokuSplitRuntime(t, mode, true)
			target := sudokuTCPEcho(t)
			var workers sync.WaitGroup
			for i := range 20 {
				workers.Go(func() {
					conn, err := client.Dial(context.Background(), "tcp", target)
					if err != nil {
						t.Error(err)
						return
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					payload := bytes.Repeat([]byte{byte(i)}, 70000)
					read := make([]byte, len(payload))
					go func() { _, _ = conn.Write(payload) }()
					if _, err = io.ReadFull(conn, read); err != nil || !bytes.Equal(payload, read) {
						t.Errorf("concurrent stream: %v", err)
					}
				})
			}
			workers.Wait()
			client.Close()
			server.Close()
			server.mu.Lock()
			left := len(server.sudokuHTTPSessions)
			server.mu.Unlock()
			if left != 0 {
				t.Fatal("sessions survived runtime shutdown", left)
			}
		})
	}
}

func TestSudokuHTTPSplitAutoFallback(t *testing.T) {
	for _, stall := range []bool{false, true} {
		t.Run(fmt.Sprintf("stall=%v", stall), func(t *testing.T) {
			server, _ := sudokuSplitRuntime(t, "auto", false)
			target, _ := url.Parse("http://" + server.Address("server"))
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.FlushInterval = -1
			proxy.Transport = &http.Transport{Proxy: nil}
			defer proxy.Transport.(*http.Transport).CloseIdleConnections()
			var stream, poll atomic.Int32
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Header.Get("X-Sudoku-Tunnel") == "stream" {
					stream.Add(1)
					if !stall {
						w.WriteHeader(404)
						return
					}
					if req.URL.Path == "/assets/stream" {
						select {
						case <-req.Context().Done():
						case <-time.After(5 * time.Second):
						}
						return
					}
				} else {
					poll.Add(1)
				}
				proxy.ServeHTTP(w, req)
			}))
			defer front.Close()
			out := testOutbound(t, Inbound{Type: "sudoku"}, front.Listener.Addr().String())
			out.Sudoku = server.config.Inbounds[0].Sudoku
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{0, 65507})
			if stream.Load() == 0 || poll.Load() == 0 {
				t.Fatal("auto did not try both carriers")
			}
		})
	}
}

func TestSudokuHTTPSplitCancellation(t *testing.T) {
	for _, mode := range []string{"stream", "poll", "auto"} {
		t.Run(mode, func(t *testing.T) {
			server, client := sudokuSplitRuntime(t, mode, false)
			conn, err := client.Dial(context.Background(), "udp", echoUDP(t))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			done := make(chan error, 1)
			go func() { _, err := conn.Read(make([]byte, 16)); done <- err }()
			server.Close()
			client.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("read survived shutdown")
				}
			case <-time.After(time.Second):
				t.Fatal("shutdown blocked")
			}
		})
	}
}

func TestSudokuHTTPSplitDialCancellation(t *testing.T) {
	for _, mode := range []string{"stream", "poll", "auto"} {
		for _, runtimeClose := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/runtime=%v", mode, runtimeClose), func(t *testing.T) {
				started := make(chan struct{}, 1)
				front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					select {
					case started <- struct{}{}:
					default:
					}
					<-req.Context().Done()
				}))
				defer front.Close()
				out := testOutbound(t, Inbound{Type: "sudoku"}, front.Listener.Addr().String())
				out.Sudoku = sudokuTestOptions("chacha20-poly1305", "", false)
				out.Sudoku.HTTPMask = &SudokuHTTPMask{Mode: mode}
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					c, err := client.Dial(ctx, "tcp", "127.0.0.1:80")
					if c != nil {
						c.Close()
					}
					done <- err
				}()
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("request did not start")
				}
				if runtimeClose {
					client.Close()
				} else {
					cancel()
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("cancelled session accepted")
					}
				case <-time.After(time.Second):
					t.Fatal("cancelled HTTP session blocked")
				}
			})
		}
	}
}

func TestSudokuHTTPSplitUploadRetry(t *testing.T) {
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server, _ := sudokuSplitRuntime(t, mode, false)
			target, _ := url.Parse("http://" + server.Address("server"))
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.FlushInterval = -1
			proxy.Transport = &http.Transport{Proxy: nil}
			defer proxy.Transport.(*http.Transport).CloseIdleConnections()
			var replaced atomic.Bool
			proxy.ModifyResponse = func(response *http.Response) error {
				if response.Request.URL.Query().Get("seq") == "1" && replaced.CompareAndSwap(false, true) {
					response.StatusCode, response.Status = 503, "503 Service Unavailable"
				}
				return nil
			}
			front := httptest.NewServer(proxy)
			defer front.Close()
			out := testOutbound(t, Inbound{Type: "sudoku"}, front.Listener.Addr().String())
			out.Sudoku = server.config.Inbounds[0].Sudoku
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			if !replaced.Load() {
				t.Fatal("upload retry was not exercised")
			}
		})
	}
}

func TestSudokuHTTPSplitTLSDialCancellation(t *testing.T) {
	for _, mode := range []string{"stream", "poll", "auto"} {
		for _, runtimeClose := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/runtime=%v", mode, runtimeClose), func(t *testing.T) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				out := testOutbound(t, Inbound{Type: "sudoku"}, listener.Addr().String())
				out.TLS = TLSOptions{Enabled: true, Insecure: true, ServerName: "localhost"}
				out.Sudoku = sudokuTestOptions("chacha20-poly1305", "", false)
				out.Sudoku.HTTPMask = &SudokuHTTPMask{Mode: mode}
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() {
					conn, err := client.Dial(ctx, "tcp", "127.0.0.1:80")
					if conn != nil {
						conn.Close()
					}
					done <- err
				}()
				listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
				peer, err := listener.Accept()
				if err != nil {
					t.Fatal(err)
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(time.Second))
				if _, err = io.ReadFull(peer, make([]byte, 1)); err != nil {
					t.Fatal(err)
				}
				if runtimeClose {
					client.Close()
				} else {
					cancel()
				}
				if _, err = io.Copy(io.Discard, peer); err != nil {
					t.Fatal("TLS socket remained open after cancel", err)
				}
				select {
				case err := <-done:
					if err == nil {
						t.Fatal("cancelled TLS dial accepted")
					}
				case <-time.After(time.Second):
					t.Fatal("TLS dial remained blocked")
				}
			})
		}
	}
}

func TestSudokuHTTPSplitUploadSequence(t *testing.T) {
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server, _ := sudokuSplitRuntime(t, mode, false)
			o := server.config.Inbounds[0].Sudoku
			app, up, down := sudokuHTTPPipe(streamAddr("test"), streamAddr("test"))
			p := &sudokuHTTPSession{r: server, options: o, token: "test-token", mode: mode, app: app, up: up, down: down, next: 1}
			p.timer = time.AfterFunc(time.Minute, func() { p.Close() })
			p.stop = func() bool { return true }
			server.mu.Lock()
			server.sudokuHTTPSessions[p.token] = p
			server.mu.Unlock()
			defer p.Close()
			got := make(chan []byte, 1)
			go func() { b, _ := io.ReadAll(app); got <- b }()
			transport := &http.Transport{Proxy: nil}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			request := func(query, payload string) int {
				t.Helper()
				req, _ := http.NewRequest("POST", "http://"+server.Address("server")+"/assets/api/v1/upload?token="+p.token+query, strings.NewReader(payload))
				req.Header.Set("X-Sudoku-Tunnel", mode)
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				io.Copy(io.Discard, response.Body)
				return response.StatusCode
			}
			payload := func(s string) string {
				if mode == "poll" {
					return base64.StdEncoding.EncodeToString([]byte(s)) + "\n"
				}
				return s
			}
			if request("&seq=0", payload("bad")) != 400 {
				t.Fatal("zero sequence accepted")
			}
			if request("&seq=2", payload("bad")) != 409 {
				t.Fatal("gap accepted")
			}
			if request("&seq=1", payload("first")) != 200 {
				t.Fatal("upload rejected")
			}
			if request("&seq=1", payload("duplicate")) != 200 {
				t.Fatal("retry not acknowledged")
			}
			if mode == "poll" && request("&seq=2", "!!!!") != 400 {
				t.Fatal("bad base64 accepted")
			}
			if request("&seq=2", strings.Repeat("a", sudokuHTTPMaxUpload+1)) != 413 {
				t.Fatal("oversize upload accepted")
			}
			if request("&seq=2", payload("second")) != 200 {
				t.Fatal("upload rejected")
			}
			if request("&fin=1", "") != 200 {
				t.Fatal("FIN rejected")
			}
			if b := <-got; string(b) != "firstsecond" {
				t.Fatalf("duplicated or missing upload %q", b)
			}
			if request("&close=1", "") != 200 {
				t.Fatal("close rejected")
			}
			if request("&seq=3", payload("gone")) != 403 {
				t.Fatal("closed session accepted")
			}
		})
	}
}

func TestSudokuHTTPSplitEarlyAuthentication(t *testing.T) {
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server, _ := sudokuSplitRuntime(t, mode, false)
			o := server.config.Inbounds[0].Sudoku
			hello := sudokuHTTPHelloPayload(t, o)
			for _, name := range []string{"valid", "replay", "tampered", "oversized"} {
				t.Run(name, func(t *testing.T) {
					payload := bytes.Clone(hello)
					if name == "tampered" {
						payload[len(payload)/2] ^= 0xff
					}
					if name == "oversized" {
						payload = make([]byte, 16385)
					}
					req, _ := http.NewRequest("GET", "http://"+server.Address("server")+"/assets/session?ed="+base64.RawURLEncoding.EncodeToString(payload), nil)
					req.Header.Set("X-Sudoku-Tunnel", mode)
					response, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					b, _ := io.ReadAll(response.Body)
					if name == "valid" {
						if response.StatusCode != 200 || !bytes.Contains(b, []byte("\ned=")) {
							t.Fatal("early handshake rejected", response.StatusCode)
						}
					} else if response.StatusCode == 200 {
						t.Fatal("invalid early handshake accepted")
					}
				})
			}
		})
	}
}

func TestSudokuHTTPSplitPollLines(t *testing.T) {
	got, err := sudokuHTTPLines([]byte("YQ==\n\n Yg== \r\n"))
	if err != nil || string(got) != "ab" {
		t.Fatal("base64 framing", string(got), err)
	}
	if _, err = sudokuHTTPLines([]byte("YQ==\n!!!!\n")); err == nil {
		t.Fatal("invalid framing accepted")
	}
}

func TestSudokuHTTPSplitDownloadRecovery(t *testing.T) {
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			r := &Runtime{sudokuHTTPSessions: map[string]*sudokuHTTPSession{}}
			app, up, down := sudokuHTTPPipe(streamAddr("test"), streamAddr("test"))
			p := &sudokuHTTPSession{r: r, token: "test-token", mode: mode, app: app, up: up, down: down}
			p.timer, p.stop = time.AfterFunc(time.Minute, func() { p.Close() }), func() bool { return true }
			r.sudokuHTTPSessions[p.token] = p
			defer p.Close()
			dial := func() (net.Conn, *http.Response, <-chan error) {
				t.Helper()
				a, b := net.Pipe()
				t.Cleanup(func() { a.Close(); b.Close() })
				a.SetDeadline(time.Now().Add(3 * time.Second))
				done := make(chan error, 1)
				go func() { done <- p.download(b) }()
				response, err := http.ReadResponse(bufio.NewReader(a), &http.Request{Method: "GET"})
				if err != nil {
					t.Fatal(err)
				}
				return a, response, done
			}
			first, _, failed := dial()
			first.Close()
			payload := bytes.Repeat([]byte("retry-downlink"), 100)
			if err := writeAll(app, payload); err != nil {
				t.Fatal(err)
			}
			if err := <-failed; err == nil {
				t.Fatal("broken download accepted")
			}
			app.(interface{ CloseWrite() error }).CloseWrite()
			_, response, done := dial()
			got, err := io.ReadAll(response.Body)
			if mode == "poll" && err == nil {
				got, err = sudokuHTTPLines(got)
			}
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("pending downlink lost", len(got), err)
			}
			if response.Trailer.Get("X-Sudoku-Stream-EOF") != "1" {
				t.Fatal("FIN trailer missing")
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if len(r.sudokuHTTPSessions) != 0 {
				t.Fatal("finished session retained")
			}
		})
	}
}

func TestSudokuHTTPSplitSessionLimit(t *testing.T) {
	server, _ := sudokuSplitRuntime(t, "stream", false)
	server.mu.Lock()
	for i := range 512 {
		server.sudokuHTTPSessions[fmt.Sprint(i)] = nil
	}
	server.mu.Unlock()
	req, _ := http.NewRequest("GET", "http://"+server.Address("server")+"/assets/session", nil)
	req.Header.Set("X-Sudoku-Tunnel", "stream")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	io.Copy(io.Discard, response.Body)
	if response.StatusCode != 503 {
		t.Fatal("unbounded session allocation", response.StatusCode)
	}
	server.mu.Lock()
	clear(server.sudokuHTTPSessions)
	server.mu.Unlock()
}

func TestSudokuHTTPSplitStreamOne(t *testing.T) {
	server, _ := sudokuSplitRuntime(t, "stream", false)
	o := server.config.Inbounds[0].Sudoku
	raw, err := net.Dial("tcp", server.Address("server"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	request := "POST /assets/stream HTTP/1.1\r\nHost: test\r\nX-Sudoku-Tunnel: stream\r\nTransfer-Encoding: chunked\r\n\r\n"
	if err = writeAll(raw, []byte(request)); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "POST"})
	if err != nil || response.StatusCode != 200 {
		t.Fatal("stream-one rejected", err)
	}
	writer := httputil.NewChunkedWriter(raw)
	conn := &httpStreamConn{reader: response.Body, writer: writer, local: raw.LocalAddr(), remote: raw.RemoteAddr(), readDeadline: raw.SetReadDeadline, writeDeadline: raw.SetWriteDeadline, close: func() { raw.Close() }}
	client, err := sudokuClient(conn, o, sudokuTCPEcho(t), false)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("stream-one"), 1000)
	go func() { _, _ = client.Write(payload) }()
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(client, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("stream-one data", err)
	}
}

func FuzzSudokuHTTPSplit(f *testing.F) {
	f.Add([]byte("GET /session HTTP/1.1\r\nHost: test\r\nX-Sudoku-Tunnel: stream\r\n\r\n"), false)
	f.Add([]byte("POST /api/v1/upload?token=unknown&seq=1 HTTP/1.1\r\nHost: test\r\nX-Sudoku-Tunnel: poll\r\nContent-Length: 4\r\n\r\n!!!!"), true)
	f.Add([]byte("GET /stream?token=unknown HTTP/1.1\r\nHost: test\r\nX-Sudoku-Tunnel: stream\r\n\r\n"), false)
	base := sudokuTestOptions("chacha20-poly1305", "", true)
	if err := base.prepare(); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, wire []byte, poll bool) {
		if len(wire) > 65536 {
			return
		}
		o := *base
		o.HTTPMask = &SudokuHTTPMask{Mode: "stream"}
		if poll {
			o.HTTPMask.Mode = "poll"
		}
		r := &Runtime{ctx: context.Background(), sudokuHTTPSessions: map[string]*sudokuHTTPSession{}, sudokuHTTPUploads: make(chan struct{}, 8)}
		conn, _, _, _ := r.acceptSudokuHTTPMask(&o, &sudokuHTTPFuzzConn{sudokuBufferConn{Buffer: bytes.NewBuffer(wire)}})
		if conn != nil {
			conn.Close()
		}
		for _, session := range r.sudokuHTTPSessions {
			session.Close()
		}
	})
}

type sudokuHTTPFuzzConn struct{ sudokuBufferConn }

func (*sudokuHTTPFuzzConn) LocalAddr() net.Addr  { return streamAddr("fuzz-local") }
func (*sudokuHTTPFuzzConn) RemoteAddr() net.Addr { return streamAddr("fuzz-remote") }

type sudokuHTTPReadProbe struct {
	net.Conn
	reading chan struct{}
}

func (c *sudokuHTTPReadProbe) Read(b []byte) (int, error) {
	select {
	case c.reading <- struct{}{}:
	default:
	}
	return c.Conn.Read(b)
}

func TestSudokuHTTPSplitIdleRotation(t *testing.T) {
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			r := &Runtime{sudokuHTTPSessions: map[string]*sudokuHTTPSession{}}
			app, up, down := sudokuHTTPPipe(streamAddr("test"), streamAddr("test"))
			probe := &sudokuHTTPReadProbe{Conn: down, reading: make(chan struct{}, 1)}
			p := &sudokuHTTPSession{r: r, token: "idle", mode: mode, app: app, up: up, down: probe}
			p.timer, p.stop = time.AfterFunc(time.Minute, func() { p.Close() }), func() bool { return true }
			r.sudokuHTTPSessions[p.token] = p
			defer p.Close()
			dial := func() (net.Conn, *http.Response, <-chan error) {
				t.Helper()
				a, b := net.Pipe()
				t.Cleanup(func() { a.Close(); b.Close() })
				a.SetDeadline(time.Now().Add(3 * time.Second))
				done := make(chan error, 1)
				go func() { defer b.Close(); done <- p.download(b) }()
				response, err := http.ReadResponse(bufio.NewReader(a), &http.Request{Method: "GET"})
				if err != nil {
					t.Fatal(err)
				}
				return b, response, done
			}
			first, response, done := dial()
			<-probe.reading
			// Simulate the old payload write deadline expiring before the longer idle read timeout.
			first.SetWriteDeadline(time.Now().Add(-time.Second))
			down.SetReadDeadline(time.Now())
			body, err := io.ReadAll(response.Body)
			if err != nil || len(body) != 0 || response.Trailer.Get("X-Sudoku-Stream-EOF") == "1" {
				t.Fatal("idle pull did not end cleanly", err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			go func() { _ = writeAll(app, []byte("after idle")); app.(interface{ CloseWrite() error }).CloseWrite() }()
			_, response, done = dial()
			body, err = io.ReadAll(response.Body)
			if mode == "poll" && err == nil {
				body, err = sudokuHTTPLines(body)
			}
			if err != nil || string(body) != "after idle" || response.Trailer.Get("X-Sudoku-Stream-EOF") != "1" {
				t.Fatal("idle session could not resume", string(body), err)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSudokuHTTPSplitEmptyPull(t *testing.T) {
	for _, mode := range []string{"stream", "poll"} {
		t.Run(mode, func(t *testing.T) {
			server, _ := sudokuSplitRuntime(t, mode, false)
			target, _ := url.Parse("http://" + server.Address("server"))
			proxy := httputil.NewSingleHostReverseProxy(target)
			proxy.FlushInterval = -1
			proxy.Transport = &http.Transport{Proxy: nil}
			defer proxy.Transport.(*http.Transport).CloseIdleConnections()
			var empty atomic.Bool
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/assets/stream" && empty.CompareAndSwap(false, true) {
					w.Header().Set("Trailer", "X-Sudoku-Stream-EOF")
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					return
				}
				proxy.ServeHTTP(w, req)
			}))
			defer front.Close()
			out := testOutbound(t, Inbound{Type: "sudoku"}, front.Listener.Addr().String())
			out.Sudoku = server.config.Inbounds[0].Sudoku
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			assertUDPSizes(t, client, []int{1, 65507})
			if !empty.Load() {
				t.Fatal("empty pull not exercised")
			}
		})
	}
}
