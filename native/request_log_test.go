package native

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type requestLogSink struct {
	net.Conn
	wire bytes.Buffer
}

func (c *requestLogSink) Write(p []byte) (int, error) { return c.wire.Write(p) }
func (c *requestLogSink) Close() error                { return nil }
func observedLogConn(t *testing.T, full bool) (*Runtime, net.Conn, chan RequestLog, *requestLogSink) {
	t.Helper()
	r := &Runtime{}
	entries := make(chan RequestLog, 20)
	r.SetRequestLogger(func(e RequestLog) { entries <- e }, full)
	sink := &requestLogSink{}
	conn := r.observeRequests(sink, request{network: "tcp", address: "origin.test:80"})
	t.Cleanup(func() { conn.Close() })
	return r, conn, entries, sink
}
func readRequestEntry(t *testing.T, ch <-chan RequestLog) RequestLog {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(time.Second):
		t.Fatal("request log blocked")
		return RequestLog{}
	}
}
func TestRequestLoggingPlaintextBoundedAndDefault(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "full"}[full], func(t *testing.T) {
			_, conn, entries, sink := observedLogConn(t, full)
			body := strings.Repeat("b", 100000)
			wire := "POST /path?query=kept HTTP/1.1\r\nHost: origin.test\r\nProxy-Authorization: Basic private\r\nX-Test: detail\r\nContent-Length: 100000\r\n\r\n" + body
			for start := 0; start < len(wire); start += 613 {
				end := min(len(wire), start+613)
				if _, err := conn.Write([]byte(wire[start:end])); err != nil {
					t.Fatal(err)
				}
			}
			e := readRequestEntry(t, entries)
			if e.URL != "http://origin.test/path?query=kept" || e.Method != "POST" || sink.wire.String() != wire {
				t.Fatal("request or forwarding changed")
			}
			if full {
				if len(e.Body) != RequestBodyLogLimit || !e.BodyTruncated || e.Headers.Get("X-Test") != "detail" || e.Headers.Get("Proxy-Authorization") != "" {
					t.Fatal("full log incorrect")
				}
			} else if len(e.Body) > 0 || len(e.Headers) > 0 {
				t.Fatal("details leaked in default mode")
			}
		})
	}
}
func TestRequestLoggingChunkedPipelineAndRuntimeToggle(t *testing.T) {
	r, conn, entries, _ := observedLogConn(t, true)
	wire := "POST /chunk HTTP/1.1\r\nHost: origin.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: origin.test\r\n\r\n"
	io.WriteString(conn, wire)
	first, second := readRequestEntry(t, entries), readRequestEntry(t, entries)
	if string(first.Body) != "data" || second.Method != "GET" || second.URL != "http://origin.test/next" {
		t.Fatal("chunking or keepalive parsing lost bytes")
	}
	r.SetRequestLogger(func(e RequestLog) { entries <- e }, false)
	io.WriteString(conn, "GET /private HTTP/1.1\r\nHost: origin.test\r\nAuthorization: hidden\r\n\r\n")
	if e := readRequestEntry(t, entries); len(e.Headers) > 0 {
		t.Fatal("toggle retained headers")
	}
}
func TestRequestLoggingEncryptedAndIncomplete(t *testing.T) {
	_, conn, entries, sink := observedLogConn(t, true)
	wire := []byte{22, 3, 3, 0, 3, 1, 2, 3}
	conn.Write(wire)
	conn.Close()
	if !bytes.Equal(sink.wire.Bytes(), wire) {
		t.Fatal("TLS bytes changed")
	}
	if conn.(*requestLogConn).pipe != nil {
		t.Fatal("encrypted stream started the HTTP parser")
	}
	select {
	case <-entries:
		t.Fatal("fabricated encrypted HTTP request")
	default:
	}
	_, conn, entries, _ = observedLogConn(t, true)
	io.WriteString(conn, "POST / HTTP/1.1\r\nHost: origin.test\r\nContent-Length: 9\r\n\r\nshort")
	conn.Close()
	if e := readRequestEntry(t, entries); !e.Incomplete || string(e.Body) != "short" {
		t.Fatal("partial request not identified")
	}
}
func TestRequestLoggingDisabledHasNoWrapper(t *testing.T) {
	r := &Runtime{}
	c := &requestLogSink{}
	if got := r.observeRequests(c, request{network: "tcp"}); got != c {
		t.Fatal("disabled logger allocated a wrapper")
	}
}
func TestRequestLoggingSlowCallbackDoesNotBlockTraffic(t *testing.T) {
	r := &Runtime{}
	release := make(chan struct{})
	var got []string
	r.SetRequestLogger(func(e RequestLog) { <-release; got = append(got, e.URL) }, false)
	conn := r.observeRequests(&requestLogSink{}, request{network: "tcp", address: "origin.test:80"})
	const total = logQueueSize + 200
	written := make(chan struct{})
	go func() {
		defer close(written)
		for i := range total {
			io.WriteString(conn, "GET /"+strings.Repeat("x", i%7)+"?n="+string(rune('a'+i%26))+" HTTP/1.1\r\nHost: origin.test\r\n\r\n")
		}
		conn.Close()
	}()
	select {
	case <-written:
	case <-time.After(5 * time.Second):
		t.Fatal("slow request log callback blocked proxied writes")
	}
	requests, _ := r.LogDrops()
	if requests == 0 {
		t.Fatal("overflow was not counted")
	}
	close(release)
	r.closeLogQueues()
	if uint64(len(got))+requests != total || got[0] != "http://origin.test/?n=a" || got[1] != "http://origin.test/x?n=b" {
		t.Fatal("records lost, reordered or not drained", len(got), requests)
	}
	r.SetRequestLogger(func(RequestLog) {}, false)
	if r.requestLogger.Load() != nil {
		t.Fatal("logger restarted after close")
	}
}
func TestDNSLoggingCopiesExchange(t *testing.T) {
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"logged.test": {"192.0.2.9"}}}}, Final: "hosts"}})
	var logged []DNSLog
	r.SetDNSLogger(func(e DNSLog) { logged = append(logged, e) })
	q, err := makeDNSQuery("logged.test", 1)
	if err != nil {
		t.Fatal(err)
	}
	query := bytes.Clone(q)
	reply, err := r.resolver.exchangePolicy(context.Background(), q, false)
	if err != nil {
		t.Fatal(err)
	}
	response := bytes.Clone(reply)
	// The exchange's buffers belong to the caller once it returns.
	clear(q)
	clear(reply)
	r.closeLogQueues()
	if len(logged) != 1 || !bytes.Equal(logged[0].Query, query) || !bytes.Equal(logged[0].Response, response) || logged[0].Error != nil {
		t.Fatal("DNS log did not keep its own copy", len(logged))
	}
}
