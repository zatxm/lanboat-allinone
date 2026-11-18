package native

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const RequestBodyLogLimit = 64 << 10

type RequestLog struct {
	URL           string      `json:"url"`
	Method        string      `json:"method"`
	Destination   string      `json:"destination"`
	Inbound       string      `json:"inbound,omitempty"`
	Headers       http.Header `json:"headers,omitempty"`
	Body          []byte      `json:"body,omitempty"`
	BodyTruncated bool        `json:"body_truncated,omitempty"`
	Incomplete    bool        `json:"incomplete,omitempty"`
}

// logQueueSize bounds records waiting for a slow callback; beyond it new
// records are dropped and counted rather than slowing proxied traffic.
const logQueueSize = 1024

// logQueue delivers records to a callback in order on its own goroutine, so
// callbacks never run on, or block, the proxy data path.
type logQueue[T any] struct {
	record  func(T)
	queue   chan T
	stop    chan struct{}
	once    sync.Once
	dropped *atomic.Uint64
}

func startLogQueue[T any](r *Runtime, record func(T), dropped *atomic.Uint64) *logQueue[T] {
	q := &logQueue[T]{record: record, queue: make(chan T, logQueueSize), stop: make(chan struct{}), dropped: dropped}
	r.logQueues.Add(1)
	go func() {
		defer r.logQueues.Done()
		for {
			select {
			case v := <-q.queue:
				q.record(v)
			case <-q.stop:
				// Deliver what was accepted before stopping.
				for {
					select {
					case v := <-q.queue:
						q.record(v)
					default:
						return
					}
				}
			}
		}
	}()
	return q
}

func (q *logQueue[T]) push(v T) {
	select {
	case <-q.stop:
		q.dropped.Add(1)
		return
	default:
	}
	select {
	case q.queue <- v:
	default:
		q.dropped.Add(1)
	}
}

// close stops accepting records; queued ones are still delivered.
func (q *logQueue[T]) close() {
	if q != nil {
		q.once.Do(func() { close(q.stop) })
	}
}

type requestLogger struct {
	full bool
	*logQueue[RequestLog]
}

// SetRequestLogger observes plaintext HTTP. It never decrypts HTTPS or stores proxy authentication.
// A nil callback disables parsing and allocation for subsequent connections.
// The callback runs on a dedicated goroutine in record order, so a slow callback
// delays logging but not traffic; when 1024 records are waiting, newer ones are
// dropped and counted by LogDrops. Replacing the callback lets the previous one
// finish its queued records; Close waits for them.
func (r *Runtime) SetRequestLogger(record func(RequestLog), full bool) {
	r.logQueueMu.Lock()
	defer r.logQueueMu.Unlock()
	var next *requestLogger
	if record != nil && !r.logQueuesClosed {
		next = &requestLogger{full: full, logQueue: startLogQueue(r, record, &r.requestLogDrops)}
	}
	if old := r.requestLogger.Swap(next); old != nil {
		old.close()
	}
}

// LogDrops reports request and DNS log records dropped because callbacks fell behind.
func (r *Runtime) LogDrops() (requests, dns uint64) {
	return r.requestLogDrops.Load(), r.dnsLogDrops.Load()
}

// closeLogQueues stops the log callbacks and waits for queued records.
func (r *Runtime) closeLogQueues() {
	r.logQueueMu.Lock()
	r.logQueuesClosed = true
	if old := r.requestLogger.Swap(nil); old != nil {
		old.close()
	}
	if old := r.dnsLogger.Swap(nil); old != nil {
		old.close()
	}
	if old := r.connectionLogger.Swap(nil); old != nil {
		old.close()
	}
	r.logQueueMu.Unlock()
	r.logQueues.Wait()
}

type requestLogConn struct {
	net.Conn
	runtime *Runtime
	request request
	writeMu sync.Mutex
	// observing is guarded by writeMu: 0 undecided, 1 parsing, 2 stopped.
	observing int
	// pipe and closed are guarded by pipeMu so Close can stop a parser that
	// a concurrent first Write is starting.
	pipeMu sync.Mutex
	pipe   *io.PipeWriter
	closed bool
	done   chan struct{}
	once   sync.Once
}

func (r *Runtime) observeRequests(conn net.Conn, q request) net.Conn {
	if r.requestLogger.Load() == nil || q.network != "tcp" {
		return conn
	}
	return &requestLogConn{Conn: conn, runtime: r, request: q}
}

// start launches the parser only for traffic that can be HTTP/1, so TLS and
// other binary streams never pay for the pipe, goroutine or read buffer.
func (c *requestLogConn) start(first byte) bool {
	if first < 'A' || first > 'Z' {
		return false
	}
	c.pipeMu.Lock()
	defer c.pipeMu.Unlock()
	if c.closed {
		return false
	}
	reader, writer := io.Pipe()
	c.pipe, c.done = writer, make(chan struct{})
	go func() { defer close(c.done); defer reader.Close(); c.parse(bufio.NewReaderSize(reader, 64<<10)) }()
	return true
}
func (c *requestLogConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	n, err := c.Conn.Write(p)
	if n > 0 {
		if c.observing == 0 {
			c.observing = 2
			if c.start(p[0]) {
				c.observing = 1
			}
		}
		// The parser closes its end once it stops observing.
		if c.observing == 1 {
			if _, e := c.pipe.Write(p[:n]); e != nil {
				c.observing = 2
			}
		}
	}
	return n, err
}
func (c *requestLogConn) stopParser() {
	c.pipeMu.Lock()
	c.closed = true
	pipe, done := c.pipe, c.done
	c.pipeMu.Unlock()
	if pipe != nil {
		pipe.Close()
		<-done
	}
}
func (c *requestLogConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.stopParser)
	return err
}
func (c *requestLogConn) CloseWrite() error {
	c.pipeMu.Lock()
	c.closed = true
	if c.pipe != nil {
		c.pipe.Close()
	}
	c.pipeMu.Unlock()
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
func (c *requestLogConn) parse(reader *bufio.Reader) {
	for {
		// TLS and other binary protocols stop observation immediately.
		first, err := reader.Peek(1)
		if err != nil || first[0] < 'A' || first[0] > 'Z' {
			return
		}
		scanned := 0
		for {
			buffered, _ := reader.Peek(reader.Buffered())
			if bytes.Contains(buffered[max(0, scanned-3):], []byte("\r\n\r\n")) {
				break
			}
			scanned = len(buffered)
			if reader.Buffered() >= 64<<10 {
				return
			}
			if _, err = reader.Peek(reader.Buffered() + 1); err != nil {
				return
			}
		}
		req, err := http.ReadRequest(reader)
		if err != nil || req.ProtoMajor != 1 {
			return
		}
		cfg := c.runtime.requestLogger.Load()
		if cfg == nil {
			return
		}
		target := req.URL.String()
		if !req.URL.IsAbs() {
			target = "http://" + req.Host + req.URL.RequestURI()
		}
		entry := RequestLog{URL: target, Method: req.Method, Destination: c.request.address, Inbound: c.request.inbound}
		if cfg.full {
			entry.Headers = req.Header.Clone()
			entry.Headers.Del("Proxy-Authorization")
			entry.Headers.Set("Host", req.Host)
		}
		// Stream the entire request onward; only the log copy has a size cap.
		capture := &requestBodyCapture{enabled: cfg.full}
		if req.Body != nil {
			buffer := buffers.Get().(*[32 * 1024]byte)
			_, err = io.CopyBuffer(capture, req.Body, buffer[:])
			buffers.Put(buffer)
			req.Body.Close()
		}
		entry.Body, entry.BodyTruncated, entry.Incomplete = capture.body, capture.truncated, err != nil
		if current := c.runtime.requestLogger.Load(); current != nil {
			if !current.full {
				entry.Headers = nil
				entry.Body = nil
				entry.BodyTruncated = false
			}
			current.push(entry)
		}
		if err != nil || req.Method == http.MethodConnect || strings.EqualFold(req.Header.Get("Upgrade"), "websocket") {
			return
		}
	}
}

type requestBodyCapture struct {
	enabled   bool
	body      []byte
	truncated bool
}

func (c *requestBodyCapture) Write(p []byte) (int, error) {
	n := len(p)
	if !c.enabled {
		return n, nil
	}
	remain := RequestBodyLogLimit - len(c.body)
	c.body = append(c.body, p[:min(n, remain)]...)
	c.truncated = c.truncated || n > remain
	return n, nil
}

type DNSLog struct {
	Query, Response []byte
	Duration        time.Duration
	Error           error
}
type dnsLogger struct{ *logQueue[DNSLog] }

// SetDNSLogger observes DNS exchanges. Like SetRequestLogger, the callback runs
// asynchronously in order and receives copies of the query and response.
func (r *Runtime) SetDNSLogger(record func(DNSLog)) {
	r.logQueueMu.Lock()
	defer r.logQueueMu.Unlock()
	var next *dnsLogger
	if record != nil && !r.logQueuesClosed {
		next = &dnsLogger{startLogQueue(r, record, &r.dnsLogDrops)}
	}
	if old := r.dnsLogger.Swap(next); old != nil {
		old.close()
	}
}
