package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sudokuHTTPMaxUpload = 1 << 20

type sudokuHTTPChunkWriter struct {
	mu     sync.Mutex
	writer io.WriteCloser
	conn   net.Conn
	closed bool
}

func (w *sudokuHTTPChunkWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	return w.writer.Write(b)
}

func (w *sudokuHTTPChunkWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if err := w.writer.Close(); err != nil {
		return err
	}
	return writeAll(w.conn, []byte("\r\n"))
}

// Two synchronous pipes preserve independent FIN and bound an idle session to its metadata.
func sudokuHTTPPipe(local, remote net.Addr) (net.Conn, net.Conn, net.Conn) {
	read, up := net.Pipe()
	down, write := net.Pipe()
	app := &httpStreamConn{
		reader: read, writer: write, local: local, remote: remote,
		readDeadline: read.SetReadDeadline, writeDeadline: write.SetWriteDeadline,
		closeWrite: write.Close, close: func() { read.Close(); write.Close() },
	}
	return app, up, down
}

type sudokuHTTPSession struct {
	r                *Runtime
	options          *SudokuOptions
	token, mode      string
	app, up, down    net.Conn
	mu, upload, pull sync.Mutex
	next             uint64
	pulling          net.Conn
	pending          []byte
	timer            *time.Timer
	stop             func() bool
	closed           bool
	closeOnce        sync.Once
	account          *sudokuAccount
}

func (p *sudokuHTTPSession) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		p.closed = true
		p.timer.Stop()
		p.stop()
		if p.pulling != nil {
			p.pulling.Close()
		}
		p.mu.Unlock()
		if p.account != nil {
			p.account.Close()
		}
		p.app.Close()
		p.up.Close()
		p.down.Close()
		p.r.mu.Lock()
		delete(p.r.sudokuHTTPSessions, p.token)
		p.r.mu.Unlock()
	})
	return nil
}

func (p *sudokuHTTPSession) touch() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.timer.Reset(2 * time.Minute)
	return true
}

func sudokuHTTPReply(c net.Conn, status int, body string) error {
	if body == "" {
		body = http.StatusText(status)
	}
	return writeAll(c, fmt.Appendf(nil, "HTTP/1.1 %d %s\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nPragma: no-cache\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body))
}

func sudokuHTTPLines(wire []byte) ([]byte, error) {
	decoded := make([]byte, 0, base64.StdEncoding.DecodedLen(len(wire)))
	for len(wire) > 0 {
		var line []byte
		line, wire, _ = bytes.Cut(wire, []byte{'\n'})
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var err error
		decoded, err = base64.StdEncoding.Strict().AppendDecode(decoded, line)
		if err != nil {
			return nil, err
		}
	}
	return decoded, nil
}

func (r *Runtime) acceptSudokuHTTPSession(o *SudokuOptions, c net.Conn, reader *bufio.Reader, header []byte, req *http.Request, account *sudokuAccount) (net.Conn, *sudokuRecord, uint32, error) {
	reject := func(code int) (net.Conn, *sudokuRecord, uint32, error) {
		return nil, nil, 0, sudokuHTTPReply(c, code, "")
	}
	mode := req.Header.Get("X-Sudoku-Tunnel")
	if (mode != "stream" && mode != "poll") || o.HTTPMask.Mode != "auto" && o.HTTPMask.Mode != mode {
		return reject(404)
	}
	path := strings.TrimPrefix(req.URL.Path, o.HTTPMask.path())
	query := req.URL.Query()
	token := query.Get("token")
	if req.Method == "GET" && path == "/session" && token == "" {
		if req.ContentLength != 0 || len(req.TransferEncoding) != 0 {
			return reject(400)
		}
		encoded := query.Get("ed")
		if len(encoded) > base64.RawURLEncoding.EncodedLen(16384) {
			return reject(413)
		}
		early, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil {
			return reject(400)
		}
		var prepared *sudokuRecord
		var features uint32
		var reply []byte
		if len(early) > 0 {
			hello := &sudokuHTTPHello{Conn: c, input: bytes.NewReader(early)}
			prepared, err = o.acceptCodec(hello)
			if err == nil {
				prepared.account = account
				features, err = r.sudokuServerHello(o, prepared)
			}
			if err != nil {
				return reject(403)
			}
			reply = hello.output.Bytes()
		}
		var random [24]byte
		rand.Read(random[:])
		token = base64.RawURLEncoding.EncodeToString(random[:])
		r.mu.Lock()
		if r.closed || len(r.sudokuHTTPSessions) >= 512 {
			r.mu.Unlock()
			return reject(503)
		}
		app, up, down := sudokuHTTPPipe(c.LocalAddr(), c.RemoteAddr())
		p := &sudokuHTTPSession{r: r, options: o, token: token, mode: mode, app: app, up: up, down: down, next: 1, account: account}
		if account != nil {
			account.mu.Lock()
			if account.closed {
				account.mu.Unlock()
				r.mu.Unlock()
				app.Close()
				up.Close()
				down.Close()
				return nil, nil, 0, net.ErrClosed
			}
			account.logical = app
			account.mu.Unlock()
		}
		p.mu.Lock()
		p.timer = time.AfterFunc(2*time.Minute, func() { p.Close() })
		p.stop = context.AfterFunc(r.ctx, func() { p.Close() })
		r.sudokuHTTPSessions[token] = p
		p.mu.Unlock()
		r.mu.Unlock()
		body := "token=" + token + "\ncap=upload-seq"
		if len(reply) > 0 {
			body += "\ned=" + base64.RawURLEncoding.EncodeToString(reply)
		}
		if err = sudokuHTTPReply(c, 200, body); err != nil {
			p.Close()
			return nil, nil, 0, err
		}
		c.Close()
		app.SetDeadline(time.Now().Add(handshakeTimeout))
		if prepared != nil {
			prepared.Conn = prepared.options.codec(app, false).Conn
		}
		return app, prepared, features, nil
	}
	if req.Method == "POST" && path == "/stream" && token == "" && mode == "stream" {
		// The stream-one variant uses a chunked body in both directions.
		body, err := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader)))
		if err != nil {
			return reject(400)
		}
		if err = sudokuHTTPPullHeader(c); err != nil {
			return nil, nil, 0, err
		}
		writer := &sudokuHTTPChunkWriter{writer: httputil.NewChunkedWriter(c), conn: c}
		stream := &httpStreamConn{reader: body.Body, writer: writer, local: c.LocalAddr(), remote: c.RemoteAddr(), readDeadline: c.SetReadDeadline, writeDeadline: c.SetWriteDeadline, close: func() { c.Close() }}
		stream.closeWrite = writer.Close
		return stream, nil, 0, nil
	}
	if path != "/stream" && path != "/api/v1/upload" || token == "" {
		return reject(400)
	}
	r.mu.Lock()
	p := r.sudokuHTTPSessions[token]
	r.mu.Unlock()
	if p == nil || p.options != o || p.mode != mode || !p.touch() {
		return reject(403)
	}
	if account != nil {
		if p.account == nil {
			return reject(403)
		}
		if err := account.join(p.account); err != nil {
			return nil, nil, 0, err
		}
	}
	if req.Method == "GET" && path == "/stream" && req.ContentLength == 0 && len(req.TransferEncoding) == 0 {
		return nil, nil, 0, p.download(c)
	}
	if req.Method != "POST" || path != "/api/v1/upload" {
		return reject(400)
	}
	if query.Get("close") == "1" {
		p.Close()
		return reject(200)
	}
	if query.Get("fin") == "1" {
		p.upload.Lock()
		p.up.Close()
		p.upload.Unlock()
		return reject(200)
	}
	seq, err := strconv.ParseUint(query.Get("seq"), 10, 64)
	if err != nil || seq == 0 {
		return reject(400)
	}
	select {
	case r.sudokuHTTPUploads <- struct{}{}:
		defer func() { <-r.sudokuHTTPUploads }()
	default:
		return reject(503)
	}
	// Reparse with the original buffered body; never trust a declared length alone.
	body, err := http.ReadRequest(bufio.NewReader(io.MultiReader(bytes.NewReader(header), reader)))
	if err != nil {
		return reject(400)
	}
	wire, err := io.ReadAll(io.LimitReader(body.Body, sudokuHTTPMaxUpload+1))
	if len(wire) > sudokuHTTPMaxUpload {
		return reject(413)
	}
	if err == nil && mode == "poll" {
		wire, err = sudokuHTTPLines(wire)
	}
	if err != nil {
		return reject(400)
	}
	p.upload.Lock()
	defer p.upload.Unlock()
	if seq < p.next {
		return reject(200)
	}
	if seq > p.next {
		return reject(409)
	}
	p.up.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	err = writeAll(p.up, wire)
	p.up.SetWriteDeadline(time.Time{})
	if err != nil {
		p.Close()
		return reject(410)
	}
	p.next++
	return reject(200)
}

func sudokuHTTPPullHeader(c net.Conn) error {
	return writeAll(c, []byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nTrailer: X-Sudoku-Stream-EOF\r\nCache-Control: no-store\r\nPragma: no-cache\r\nConnection: close\r\nX-Accel-Buffering: no\r\n\r\n"))
}

func (p *sudokuHTTPSession) download(c net.Conn) error {
	c.SetDeadline(time.Time{})
	c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	// A replacement pull cancels the old HTTP socket, not the authenticated session.
	p.mu.Lock()
	if p.pulling != nil {
		p.pulling.Close()
		p.down.SetReadDeadline(time.Now())
	}
	p.pulling = c
	p.mu.Unlock()
	p.pull.Lock()
	defer p.pull.Unlock()
	p.mu.Lock()
	current := !p.closed && p.pulling == c
	p.mu.Unlock()
	if !current {
		return net.ErrClosed
	}
	defer func() {
		p.mu.Lock()
		if p.pulling == c {
			p.pulling = nil
		}
		p.mu.Unlock()
	}()
	if err := sudokuHTTPPullHeader(c); err != nil {
		return err
	}
	writer := httputil.NewChunkedWriter(c)
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	for {
		p.mu.Lock()
		current = !p.closed && p.pulling == c
		if current {
			p.down.SetReadDeadline(time.Now().Add(20 * time.Second))
		}
		p.mu.Unlock()
		if !current {
			return net.ErrClosed
		}
		payload := p.pending
		var err error
		if len(payload) == 0 {
			n, e := p.down.Read(buffer[:32768])
			payload, err = buffer[:n], e
		}
		if len(payload) > 0 {
			wire := payload
			if p.mode == "poll" {
				wire = base64.StdEncoding.AppendEncode(nil, payload)
				wire = append(wire, '\n')
			}
			c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			_, e := writer.Write(wire)
			if e != nil {
				p.pending = bytes.Clone(payload)
				return e
			}
			p.pending = nil
			p.touch()
		}
		if err != nil {
			c.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			if errors.Is(err, io.EOF) {
				err = writeAll(c, []byte("0\r\nX-Sudoku-Stream-EOF: 1\r\n\r\n"))
				if err == nil {
					p.Close()
				}
				return err
			}
			if e, ok := err.(net.Error); ok && e.Timeout() {
				writer.Close()
				return writeAll(c, []byte("\r\n"))
			}
			return err
		}
	}
}
