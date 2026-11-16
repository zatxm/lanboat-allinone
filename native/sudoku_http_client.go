package native

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sudokuHTTPReady struct {
	net.Conn
	record   *sudokuRecord
	features uint32
}

type sudokuHTTPClient struct {
	*httpStreamConn
	r                *Runtime
	ctx              context.Context
	cancel           context.CancelFunc
	transport        *http.Transport
	base             Outbound
	withdrawn        chan struct{}
	url, host, mode  string
	rmu, wmu         sync.Mutex
	meta             sync.RWMutex
	response         *http.Response
	lines            *bufio.Scanner
	pending          []byte
	seq              uint64
	eof, writeClosed bool
}

type sudokuHTTPReader struct{ c *sudokuHTTPClient }
type sudokuHTTPWriter struct{ c *sudokuHTTPClient }

func (p sudokuHTTPReader) Read(b []byte) (int, error)  { return p.c.read(b) }
func (p sudokuHTTPWriter) Write(b []byte) (int, error) { return p.c.write(b) }

func (r *Runtime) dialSudokuHTTP(ctx context.Context, o Outbound) (net.Conn, error) {
	mode := o.Sudoku.HTTPMask.Mode
	if mode != "auto" {
		return r.dialSudokuHTTPMode(ctx, o, mode)
	}
	first, cancel := context.WithTimeout(ctx, 3*time.Second)
	c, err := r.dialSudokuHTTPMode(first, o, "stream")
	cancel()
	if err == nil {
		return c, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c, next := r.dialSudokuHTTPMode(ctx, o, "poll")
	if next != nil {
		return nil, fmt.Errorf("Sudoku HTTP auto: stream: %v; poll: %w", err, next)
	}
	return c, nil
}

func (r *Runtime) dialSudokuHTTPMode(ctx context.Context, o Outbound, mode string) (net.Conn, error) {
	base := o
	options := *o.Sudoku
	options.HTTPMask = nil
	base.Sudoku = &options
	child, cancel := context.WithCancel(r.ctx)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		// HTTP pools detach request cancellation while dialing; the session still owns this socket.
		dialCtx, cancelDial := context.WithCancel(ctx)
		stop := context.AfterFunc(child, cancelDial)
		defer stop()
		defer cancelDial()
		conn, err := r.dialProxyTransportRaw(dialCtx, base)
		if err == nil {
			conn.SetDeadline(time.Time{})
		}
		return conn, err
	}
	transport := &http.Transport{
		Protocols: protocols, DialContext: dial, DialTLSContext: dial,
		MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4,
		IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: handshakeTimeout,
		MaxResponseHeaderBytes: 65536, DisableCompression: true,
	}
	host := portAddress(o.Server, o.ServerPort)
	if o.Sudoku.HTTPMask.Host != "" {
		host = o.Sudoku.HTTPMask.Host
	}
	scheme := "http"
	if o.TLS.Enabled {
		scheme = "https"
	}
	c := &sudokuHTTPClient{r: r, ctx: child, cancel: cancel, transport: transport, base: base, withdrawn: make(chan struct{}), url: scheme + "://" + portAddress(o.Server, o.ServerPort) + o.Sudoku.HTTPMask.path(), host: host, mode: mode, seq: 1}
	c.httpStreamConn = &httpStreamConn{
		reader: io.NopCloser(sudokuHTTPReader{c}), writer: sudokuHTTPWriter{c},
		local: streamAddr("sudoku-http-client"), remote: streamAddr(portAddress(o.Server, o.ServerPort)),
		close: c.shutdown, closeWrite: c.finish,
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	ok := false
	defer func() {
		if !ok {
			c.Close()
		}
	}()
	response, err := c.request(c.ctx, "GET", "/session", nil)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	response.Body.Close()
	if err != nil || len(body) > 4096 || response.StatusCode != 200 {
		return nil, errors.New("Sudoku HTTP session authorization failed")
	}
	var token string
	capable := false
	for _, line := range strings.Split(string(body), "\n") {
		if v, ok := strings.CutPrefix(line, "token="); ok {
			token = v
		}
		capable = capable || line == "cap=upload-seq"
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(value) < 16 || len(value) > 64 || !capable {
		return nil, errors.New("invalid Sudoku HTTP session token or capability")
	}
	c.meta.Lock()
	c.url += "?token=" + token
	c.meta.Unlock()
	// Complete authentication before auto selects a carrier; a buffered stream may authorize but never deliver KIP.
	requested := uint32(7)
	if o.Sudoku.packedUplink {
		requested |= 8
	}
	record, features, err := sudokuHandshake(c, o.Sudoku, requested)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil || !stop() {
		return nil, ctx.Err()
	}
	c.SetDeadline(time.Time{})
	ok = true
	return &sudokuHTTPReady{Conn: c, record: record, features: features}, nil
}

func (c *sudokuHTTPClient) request(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	c.meta.RLock()
	base, query, _ := strings.Cut(c.url, "?")
	c.meta.RUnlock()
	url := base + path
	if query != "" {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		url += separator + query
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Host = c.host
	req.Header.Set("X-Sudoku-Tunnel", c.mode)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.mode == "poll" {
		req.Header.Set("Content-Type", "text/plain")
	}
	return c.transport.RoundTrip(req)
}

func (c *sudokuHTTPClient) pause(attempt int) error {
	timer := time.NewTimer(time.Duration(25<<attempt) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *sudokuHTTPClient) post(ctx context.Context, path string, payload []byte) error {
	for attempt := 0; ; attempt++ {
		response, err := c.request(ctx, "POST", path, payload)
		if err == nil {
			_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4097))
			response.Body.Close()
			if response.StatusCode == 200 && readErr == nil {
				return nil
			}
			err = fmt.Errorf("Sudoku HTTP upload status %d", response.StatusCode)
			if response.StatusCode < 500 {
				return err
			}
		}
		if attempt == 2 || ctx.Err() != nil {
			return err
		}
		if err = c.pause(attempt); err != nil {
			return err
		}
	}
}

func (c *sudokuHTTPClient) write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(b) > 0 {
		n := min(len(b), 32768)
		payload := b[:n]
		if c.mode == "poll" {
			payload = base64.StdEncoding.AppendEncode(nil, payload)
			payload = append(payload, '\n')
		}
		if err := c.post(c.ctx, "/api/v1/upload?seq="+strconv.FormatUint(c.seq, 10), payload); err != nil {
			return written, err
		}
		c.seq++
		written += n
		b = b[n:]
	}
	return written, nil
}

func (c *sudokuHTTPClient) read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	for {
		if len(c.pending) > 0 {
			n := copy(b, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
		if c.eof {
			return 0, io.EOF
		}
		if c.response == nil {
			var err error
			for attempt := 0; ; attempt++ {
				c.response, err = c.request(c.ctx, "GET", "/stream", nil)
				if err == nil && c.response.StatusCode == 200 {
					break
				}
				if err == nil {
					c.response.Body.Close()
					err = fmt.Errorf("Sudoku HTTP pull status %d", c.response.StatusCode)
					if c.response.StatusCode < 500 {
						return 0, err
					}
				}
				c.response = nil
				if attempt == 2 || c.ctx.Err() != nil {
					return 0, err
				}
				if err = c.pause(attempt); err != nil {
					return 0, err
				}
			}
			if c.mode == "poll" {
				c.lines = bufio.NewScanner(c.response.Body)
				c.lines.Buffer(make([]byte, 4096), 65536)
			}
		}
		var n int
		var err error
		if c.mode == "stream" {
			n, err = c.response.Body.Read(b)
		} else if c.lines.Scan() {
			line := bytes.TrimSpace(c.lines.Bytes())
			if len(line) == 0 {
				continue
			}
			c.pending, err = base64.StdEncoding.Strict().DecodeString(string(line))
			if err == nil {
				continue
			}
		} else {
			err = c.lines.Err()
			if err == nil {
				err = io.EOF
			}
		}
		if err == io.EOF {
			c.eof = c.response.Trailer.Get("X-Sudoku-Stream-EOF") == "1"
			c.response.Body.Close()
			c.response = nil
			if n > 0 {
				return n, nil
			}
			if !c.eof {
				if err = c.pause(0); err != nil {
					return 0, err
				}
			}
			continue
		}
		return n, err
	}
}

func (c *sudokuHTTPClient) finish() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	return c.post(c.ctx, "/api/v1/upload?fin=1", nil)
}

func (c *sudokuHTTPClient) shutdown() {
	c.cancel()
	c.transport.CloseIdleConnections()
	c.meta.RLock()
	url := c.url
	c.meta.RUnlock()
	if !strings.Contains(url, "?token=") {
		close(c.withdrawn)
		return
	}
	// Closing a logical connection must interrupt its caller immediately, even if the peer is offline.
	c.r.mu.Lock()
	if c.r.closed {
		c.r.mu.Unlock()
		close(c.withdrawn)
		return
	}
	c.r.workers.Add(1)
	c.r.mu.Unlock()
	go func() {
		defer c.r.workers.Done()
		defer close(c.withdrawn)
		ctx, cancel := context.WithTimeout(context.WithoutCancel(c.r.ctx), time.Second)
		defer cancel()
		// The normal pool's dial hook belongs to the cancelled logical session.
		// A bounded one-shot pool can still withdraw its server-side registration.
		transport := c.transport.Clone()
		dial := func(_ context.Context, _, _ string) (net.Conn, error) {
			return c.r.dialProxyTransportRaw(ctx, c.base)
		}
		transport.DialContext, transport.DialTLSContext = dial, dial
		defer transport.CloseIdleConnections()
		cleanup := &sudokuHTTPClient{ctx: ctx, transport: transport, url: url, host: c.host, mode: c.mode}
		_ = cleanup.post(ctx, "/api/v1/upload?close=1", nil)
	}()
}
