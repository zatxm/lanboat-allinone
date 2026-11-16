package native

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type SudokuHTTPMask struct {
	Mode     string `json:"mode,omitempty"`
	Host     string `json:"host,omitempty"`
	PathRoot string `json:"path_root,omitempty"`
}

type sudokuHTTPHello struct {
	net.Conn
	input  *bytes.Reader
	output bytes.Buffer
}

func (c *sudokuHTTPHello) Read(p []byte) (int, error)  { return c.input.Read(p) }
func (c *sudokuHTTPHello) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *sudokuHTTPHello) Close() error                { return nil }

func (m *SudokuHTTPMask) prepare() error {
	if m == nil {
		return nil
	}
	if m.Mode == "" {
		m.Mode = "legacy"
	}
	if m.Mode != "legacy" && m.Mode != "ws" && m.Mode != "stream" && m.Mode != "poll" && m.Mode != "auto" {
		return errors.New("Sudoku HTTP mask supports legacy, ws, stream, poll or auto")
	}
	if m.Host != "" && !validHTTPHost(m.Host) {
		return errors.New("invalid Sudoku HTTP mask host")
	}
	m.PathRoot = strings.Trim(m.PathRoot, "/")
	if len(m.PathRoot) > 128 {
		return errors.New("Sudoku HTTP mask path root exceeds128 bytes")
	}
	for _, c := range m.PathRoot {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return errors.New("Sudoku HTTP mask path root must be one URL segment")
		}
	}
	return nil
}

func (m *SudokuHTTPMask) path() string {
	if m.PathRoot == "" {
		return ""
	}
	return "/" + m.PathRoot
}

// This authentication envelope is separate from the KIP handshake and its replay protection.
func sudokuWSAuth(key string, stamp int64) string {
	h := sha256.Sum256([]byte("sudoku-httpmask-auth-v1:" + key))
	var token [24]byte
	binary.BigEndian.PutUint64(token[:8], uint64(stamp))
	mac := hmac.New(sha256.New, h[:])
	mac.Write([]byte("ws\x00GET\x00/ws\x00"))
	mac.Write(token[:8])
	copy(token[8:], mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString(token[:])
}

func sudokuWSAuthorized(key, token string, now int64) bool {
	if len(token) > 7 && strings.EqualFold(token[:7], "Bearer ") {
		token = token[7:]
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(value) != 24 {
		return false
	}
	stamp := int64(binary.BigEndian.Uint64(value[:8]))
	return stamp >= now-60 && stamp <= now+60 && hmac.Equal([]byte(token), []byte(sudokuWSAuth(key, stamp)))
}

func (o *SudokuOptions) dialHTTPMask(c net.Conn, host string) (net.Conn, error) {
	m := o.HTTPMask
	if m == nil {
		return c, nil
	}
	if m.Host != "" {
		host = m.Host
	}
	if m.Mode == "legacy" {
		preamble := fmt.Sprintf("POST %s/api/%s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/octet-stream\r\nContent-Length: 1048576\r\nConnection: keep-alive\r\n\r\n", m.path(), rand.Text(), host)
		return c, writeAll(c, []byte(preamble))
	}
	token := sudokuWSAuth(o.wireKey(), time.Now().Unix())
	return dialTransportHandshake(c, Outbound{Server: host, Transport: Transport{Type: "ws", Path: m.path() + "/ws?auth=" + token, Headers: map[string]headerValues{"Authorization": {"Bearer " + token}}}}, nil)
}

func (r *Runtime) acceptSudokuHTTPMask(o *SudokuOptions, c net.Conn, account ...*sudokuAccount) (net.Conn, *sudokuRecord, uint32, error) {
	var a *sudokuAccount
	if len(account) > 0 {
		a = account[0]
	}
	m := o.HTTPMask
	if m == nil {
		return c, nil, 0, nil
	}
	reader := bufio.NewReader(c)
	header, err := readHTTPHeader(reader)
	if err != nil {
		return nil, nil, 0, err
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if err != nil || req.URL.IsAbs() || !strings.HasPrefix(req.URL.Path, m.path()+"/") {
		return nil, nil, 0, errors.New("invalid Sudoku HTTP mask request")
	}
	if m.Mode == "stream" || m.Mode == "poll" || m.Mode == "auto" {
		return r.acceptSudokuHTTPSession(o, c, reader, header, req, a)
	}
	if m.Mode == "legacy" {
		switch req.Method {
		case "GET", "POST", "HEAD", "PUT", "OPTIONS", "PATCH", "DELETE":
			return &bufferedConn{Conn: c, reader: reader}, nil, 0, nil
		}
		return nil, nil, 0, errors.New("invalid Sudoku legacy method")
	}
	token := req.Header.Get("Authorization")
	if token == "" {
		token = req.URL.Query().Get("auth")
	}
	if req.URL.Path != m.path()+"/ws" || !sudokuWSAuthorized(o.wireKey(), token, time.Now().Unix()) {
		return nil, nil, 0, errors.New("Sudoku WebSocket authorization failed")
	}
	encoded := req.URL.Query().Get("ed")
	if len(encoded) > base64.RawURLEncoding.EncodedLen(16384) {
		return nil, nil, 0, errors.New("Sudoku early handshake exceeds16KiB")
	}
	early, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, nil, 0, errors.New("invalid Sudoku early handshake")
	}
	var prepared *sudokuRecord
	var features uint32
	var responseHeaders http.Header
	if len(early) > 0 {
		hello := &sudokuHTTPHello{Conn: c, input: bytes.NewReader(early)}
		prepared, err = o.acceptCodec(hello)
		if err == nil {
			prepared.account = a
			features, err = r.sudokuServerHello(o, prepared)
		}
		if err != nil {
			return nil, nil, 0, err
		}
		responseHeaders = http.Header{"X-Sudoku-Early": {base64.RawURLEncoding.EncodeToString(hello.output.Bytes())}}
	}
	// Reuse the normal WebSocket upgrade checks after authenticating the mask query.
	line, fields, _ := bytes.Cut(header, []byte("\r\n"))
	_, rest, _ := bytes.Cut(line, []byte(" "))
	_, version, _ := bytes.Cut(rest, []byte(" "))
	prefix := []byte(req.Method + " " + req.URL.Path + " " + string(version) + "\r\n")
	stream, err := acceptTransport(&bufferedConn{Conn: c, reader: bufio.NewReader(io.MultiReader(bytes.NewReader(append(prefix, fields...)), reader))}, Transport{Type: "ws", Path: req.URL.Path, responseHeaders: responseHeaders})
	if err != nil {
		return nil, nil, 0, err
	}
	if prepared != nil {
		prepared.Conn = prepared.options.codec(stream, false).Conn
	}
	return stream, prepared, features, nil
}
