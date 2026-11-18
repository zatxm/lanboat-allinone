package native

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type headerValues []string

func (v *headerValues) UnmarshalJSON(raw []byte) error {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		*v = []string{one}
		return nil
	}
	return json.Unmarshal(raw, (*[]string)(v))
}

type Transport struct {
	KCP *MKCPOptions `json:"kcp,omitempty"`
	XHTTPOptions
	closeProbe          bool
	rawUpgrade          bool
	legacyText          bool
	responseHeaders     http.Header
	websocketProtocol   string
	Type                string                  `json:"type,omitempty"`
	Path                string                  `json:"path,omitempty"`
	Host                string                  `json:"host,omitempty"`
	Method              string                  `json:"method,omitempty"`
	ServiceName         string                  `json:"service_name,omitempty"`
	Headers             map[string]headerValues `json:"headers,omitempty"`
	MaxEarlyData        int                     `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string                  `json:"early_data_header_name,omitempty"`
	IdleTimeout         string                  `json:"idle_timeout,omitempty"`
	PingTimeout         string                  `json:"ping_timeout,omitempty"`
	PermitWithoutStream bool                    `json:"permit_without_stream,omitempty"`
}

func (t Transport) isHTTP() bool { return t.Type == "http" || t.Type == "grpc" }

func (t Transport) usesHTTP2(tls bool) bool { return t.Type == "grpc" || t.Type == "http" && tls }

func (t Transport) httpPath() string {
	if t.Type == "grpc" {
		return "/" + t.ServiceName + "/Tun"
	}
	if t.Path == "" {
		return "/"
	}
	return t.Path
}

func (t Transport) validateFor(protocol string) error {
	if err := t.validate(); err != nil {
		return err
	}
	if t.Type == "" {
		return nil
	}
	if protocol == "brook" && (t.Type == "ws" || t.Type == "quic") {
		if t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
			return errors.New("Brook WebSocket does not use V2Ray early data")
		}
		return nil
	}
	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "relay":
		return nil
	}
	return fmt.Errorf("%s does not support transport overrides", protocol)
}

func (t Transport) validate() error {
	if e := t.validateMKCP(); e != nil {
		return e
	}
	if e := t.XHTTPOptions.validate(t); e != nil {
		return e
	}
	if t.IdleTimeout != "" || t.PingTimeout != "" || t.PermitWithoutStream {
		if !t.isHTTP() {
			return errors.New("HTTP keepalive requires http or grpc transport")
		}
		for name, value := range map[string]string{"idle_timeout": t.IdleTimeout, "ping_timeout": t.PingTimeout} {
			if value == "" {
				continue
			}
			d, err := time.ParseDuration(value)
			if err != nil || d < 0 {
				return fmt.Errorf("invalid transport %s", name)
			}
		}
		if t.PermitWithoutStream && t.Type != "grpc" {
			return errors.New("permit_without_stream requires grpc transport")
		}
	}
	if t.MaxEarlyData < 0 || t.MaxEarlyData > 32768 {
		return errors.New("WebSocket max_early_data must be0-32768")
	}
	if t.MaxEarlyData != 0 || t.EarlyDataHeaderName != "" {
		if t.Type != "ws" {
			return errors.New("early data requires WebSocket transport")
		}
		if t.EarlyDataHeaderName != "" {
			if err := transportHeaderName(t.EarlyDataHeaderName, true); err != nil {
				return fmt.Errorf("invalid early_data_header_name: %w", err)
			}
			if strings.EqualFold(t.EarlyDataHeaderName, "Host") {
				return errors.New("early data cannot replace Host")
			}
		}
		for name := range t.Headers {
			if strings.EqualFold(name, t.EarlyDataHeaderName) {
				return errors.New("early data header cannot also be set in headers")
			}
		}
	}
	if t.Type == "" {
		if t.Path != "" || t.Host != "" || len(t.Headers) > 0 || t.Method != "" || t.ServiceName != "" {
			return errors.New("transport type is required")
		}
		return nil
	}
	if t.Type == "quic" || t.Type == "mkcp" {
		if t.Path != "" || t.Host != "" || len(t.Headers) != 0 || t.Method != "" || t.ServiceName != "" {
			return errors.New("UDP stream transports accept no HTTP options")
		}
		return nil
	}
	if t.Type != "ws" && t.Type != "httpupgrade" && t.Type != "xhttp" && !t.isHTTP() {
		return fmt.Errorf("independent runtime has no %q transport", t.Type)
	}
	if t.ServiceName != "" && (t.Type != "grpc" || strings.ContainsAny(t.ServiceName, "/\r\n\x00 ?#") || len(t.ServiceName) > 256) {
		return errors.New("invalid gRPC service_name")
	}
	if t.Type == "grpc" && t.Path != "" {
		return errors.New("gRPC uses service_name instead of path")
	}
	if t.Method != "" && (t.Type != "http" || t.Method != "PUT" && t.Method != "POST") {
		return errors.New("HTTP stream method must be PUT or POST")
	}
	if t.Path != "" {
		u, err := url.ParseRequestURI(t.Path)
		if err != nil || !strings.HasPrefix(t.Path, "/") || u.IsAbs() || u.Fragment != "" || len(t.Path) > 4096 {
			return errors.New("invalid transport path")
		}
	}
	if t.Host != "" && !validHTTPHost(t.Host) {
		return errors.New("invalid transport Host")
	}
	for key, values := range t.Headers {
		if err := transportHeaderName(key, false); err != nil {
			return err
		}
		if strings.EqualFold(key, "Host") && (len(values) != 1 || !validHTTPHost(values[0])) {
			return errors.New("transport Host header requires one valid host")
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n\x00") {
				return errors.New("invalid transport header value")
			}
		}
	}
	return nil
}

func transportHeaderName(key string, early bool) error {
	if key == "" || len(key) > 256 {
		return errors.New("invalid transport header name length")
	}
	for _, b := range []byte(key) {
		if b <= 32 || b >= 127 || strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(b)) {
			return errors.New("invalid transport header name")
		}
	}
	switch strings.ToLower(key) {
	case "content-length", "transfer-encoding", "connection", "upgrade":
		return fmt.Errorf("transport owns header %q", key)
	}
	if strings.HasPrefix(strings.ToLower(key), "sec-websocket-") && !(early && strings.EqualFold(key, "Sec-WebSocket-Protocol")) {
		return fmt.Errorf("transport owns header %q", key)
	}
	return nil
}

func headerToken(value, want string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), want) {
			return true
		}
	}
	return false
}
func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func dialTransport(c net.Conn, o Outbound) (net.Conn, error) {
	if o.Transport.MaxEarlyData > 0 {
		return &earlyTransportConn{Conn: c, transport: o.Transport, server: o.Server, protocol: o.Type}, nil
	}
	return dialTransportHandshake(c, o, nil)
}

func dialTransportHandshake(c net.Conn, o Outbound, early []byte) (net.Conn, error) {
	t := o.Transport
	if t.Type == "" || t.Type == "mkcp" {
		return c, nil
	}
	path := t.Path
	if path == "" {
		path = "/"
	}
	if t.MaxEarlyData > 0 {
		if t.EarlyDataHeaderName == "" {
			path += base64.RawURLEncoding.EncodeToString(early)
		}
		path = (&url.URL{Path: path}).EscapedPath()
	}
	host := o.Server
	for key, values := range t.Headers {
		if strings.EqualFold(key, "Host") && len(values) > 0 {
			host = values[0]
		}
	}
	if t.Host != "" {
		host = t.Host
	}
	if !validHTTPHost(host) {
		return nil, errors.New("invalid transport Host")
	}
	if t.Type == "http" {
		method := t.Method
		if method == "" {
			method = "PUT"
		}
		var request strings.Builder
		request.WriteString(method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n")
		for key, values := range t.Headers {
			if strings.EqualFold(key, "Host") {
				continue
			}
			for _, value := range values {
				request.WriteString(key + ": " + value + "\r\n")
			}
		}
		request.WriteString("\r\n")
		if err := writeAll(c, []byte(request.String())); err != nil {
			return nil, err
		}
		return &plainHTTPConn{Conn: c, reader: bufio.NewReader(c), client: true}, nil
	}
	header := http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}
	var key string
	if t.Type == "ws" {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		key = base64.StdEncoding.EncodeToString(random[:])
		header.Set("Sec-WebSocket-Version", "13")
		header.Set("Sec-WebSocket-Key", key)
	}
	for name, values := range t.Headers {
		if strings.EqualFold(name, "Host") {
			continue
		}
		if strings.EqualFold(name, "Connection") || strings.EqualFold(name, "Upgrade") || strings.HasPrefix(strings.ToLower(name), "sec-websocket-") {
			return nil, errors.New("transport handshake headers cannot be overridden")
		}
		for _, value := range values {
			header.Add(name, value)
		}
	}
	if len(early) > 0 && t.EarlyDataHeaderName != "" {
		header.Set(t.EarlyDataHeaderName, base64.RawURLEncoding.EncodeToString(early))
	}
	if t.websocketProtocol != "" {
		header.Set("Sec-WebSocket-Protocol", t.websocketProtocol)
	}
	var request strings.Builder
	request.WriteString("GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n")
	for name, values := range header {
		for _, value := range values {
			request.WriteString(name + ": " + value + "\r\n")
		}
	}
	request.WriteString("\r\n")
	if err := writeAll(c, []byte(request.String())); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(c)
	raw, err := readHTTPHeader(reader)
	if err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(raw))), &http.Request{Method: "GET"})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 101 || !headerToken(response.Header.Get("Connection"), "upgrade") || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("transport HTTP upgrade rejected")
	}
	buffered := &bufferedConn{Conn: c, reader: reader}
	if t.Type == "httpupgrade" {
		return buffered, nil
	}
	if subtle.ConstantTimeCompare([]byte(response.Header.Get("Sec-WebSocket-Accept")), []byte(websocketAccept(key))) != 1 {
		return nil, errors.New("WebSocket accept key mismatch")
	}
	if t.websocketProtocol != "" && response.Header.Get("Sec-WebSocket-Protocol") != t.websocketProtocol {
		return nil, errors.New("WebSocket subprotocol mismatch")
	}
	if o.Type == "brook" {
		return buffered, nil
	}
	return &websocketConn{Conn: buffered, client: true}, nil
}

func acceptTransport(c *bufferedConn, t Transport) (net.Conn, error) {
	if t.Type == "" || t.Type == "mkcp" {
		return c, nil
	}
	header, err := readHTTPHeader(c.reader)
	if err != nil {
		return nil, err
	}
	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(string(header))))
	if err != nil {
		return nil, err
	}
	path := t.Path
	if path == "" {
		path = "/"
	}
	if t.Type == "http" {
		method := t.Method
		if method == "" {
			method = "PUT"
		}
		if request.Method != method || !strings.HasPrefix(request.URL.RequestURI(), path) || t.Host != "" && !strings.EqualFold(request.Host, t.Host) || len(request.TransferEncoding) > 0 || request.ContentLength > 0 {
			return nil, errors.New("invalid HTTP stream request")
		}
		return &plainHTTPConn{Conn: c, reader: c.reader, headers: t.Headers}, nil
	}
	var early []byte
	requestPath := request.URL.RequestURI()
	if t.MaxEarlyData > 0 {
		requestPath = request.URL.Path
		encoded := ""
		if t.EarlyDataHeaderName == "" {
			if !strings.HasPrefix(requestPath, path) {
				return nil, errors.New("WebSocket early data path mismatch")
			}
			encoded, requestPath = strings.TrimPrefix(requestPath, path), path
		} else {
			values := request.Header.Values(t.EarlyDataHeaderName)
			if len(values) > 1 {
				return nil, errors.New("duplicate WebSocket early data header")
			}
			encoded = request.Header.Get(t.EarlyDataHeaderName)
		}
		if len(encoded) > base64.RawURLEncoding.EncodedLen(t.MaxEarlyData) {
			return nil, errors.New("WebSocket early data exceeds max_early_data")
		}
		early, err = base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err != nil || len(early) > t.MaxEarlyData {
			return nil, errors.New("invalid WebSocket early data")
		}
	}
	if request.Method != "GET" || requestPath != path || !headerToken(request.Header.Get("Connection"), "upgrade") || !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") || len(request.TransferEncoding) != 0 || request.ContentLength > 0 {
		return nil, errors.New("invalid transport upgrade request")
	}
	if t.Host != "" && !strings.EqualFold(request.Host, t.Host) {
		return nil, errors.New("transport Host mismatch")
	}
	response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
	if t.Type == "ws" {
		key := request.Header.Get("Sec-WebSocket-Key")
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 16 || request.Header.Get("Sec-WebSocket-Version") != "13" {
			return nil, errors.New("invalid WebSocket handshake")
		}
		response += "Sec-WebSocket-Accept: " + websocketAccept(key) + "\r\n"
	}
	for key, values := range t.responseHeaders {
		for _, value := range values {
			response += key + ": " + value + "\r\n"
		}
	}
	if err := writeAll(c, []byte(response+"\r\n")); err != nil {
		return nil, err
	}
	if t.Type == "httpupgrade" || t.rawUpgrade {
		return c, nil
	}
	var stream net.Conn = &websocketConn{Conn: c, legacyText: t.legacyText, closeProbe: t.closeProbe}
	if len(early) > 0 {
		stream = &earlyDataConn{Conn: stream, pending: early}
	}
	return stream, nil
}

type websocketConn struct {
	net.Conn
	client          bool
	legacyText      bool
	readMu, writeMu sync.Mutex
	remaining       uint64
	mask            [4]byte
	masked          bool
	maskOffset      int
	fragmented      bool
	writeClosed     bool
	closeProbe      bool
	closeOnce       sync.Once
	closeErr        error
	closePong       chan struct{}
	closeToken      [8]byte
	// readHeader is per-frame scratch guarded by readMu; a local array would
	// escape through io.ReadFull.
	readHeader [8]byte
}

// wsMask XORs b with the WebSocket mask, starting at mask position offset.
func wsMask(b []byte, mask [4]byte, offset int) {
	var m [8]byte
	for i := range m {
		m[i] = mask[(offset+i)&3]
	}
	word := binary.LittleEndian.Uint64(m[:])
	for len(b) >= 8 {
		binary.LittleEndian.PutUint64(b, binary.LittleEndian.Uint64(b)^word)
		b = b[8:]
	}
	for i := range b {
		b[i] ^= m[i]
	}
}

func (c *websocketConn) Read(p []byte) (int, error) {
	n, err := c.readPayload(p)
	if err != nil && c.closeProbe {
		c.finishCloseProbe(nil, true)
	}
	return n, err
}

func (c *websocketConn) finishCloseProbe(data []byte, ended bool) {
	c.writeMu.Lock()
	if c.closePong != nil && (ended || bytes.Equal(data, c.closeToken[:])) {
		close(c.closePong)
		c.closePong = nil
	}
	c.writeMu.Unlock()
}

func (c *websocketConn) Close() error {
	err := c.Conn.Close()
	if c.closeProbe {
		c.finishCloseProbe(nil, true)
	}
	return err
}

func (c *websocketConn) readPayload(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for c.remaining == 0 {
		header := c.readHeader[:2]
		if _, err := io.ReadFull(c.Conn, header); err != nil {
			return 0, err
		}
		fin, opcode := header[0]&128 != 0, header[0]&15
		if header[0]&0x70 != 0 {
			return 0, errors.New("unsupported WebSocket reserved bits")
		}
		masked := header[1]&128 != 0
		if masked == c.client {
			return 0, errors.New("invalid WebSocket masking direction")
		}
		size := uint64(header[1] & 127)
		if size == 126 {
			extended := c.readHeader[:2]
			if _, err := io.ReadFull(c.Conn, extended); err != nil {
				return 0, err
			}
			size = uint64(binary.BigEndian.Uint16(extended))
			if size < 126 {
				return 0, errors.New("noncanonical WebSocket size")
			}
		} else if size == 127 {
			extended := c.readHeader[:8]
			if _, err := io.ReadFull(c.Conn, extended); err != nil {
				return 0, err
			}
			size = binary.BigEndian.Uint64(extended)
			if size < 65536 {
				return 0, errors.New("noncanonical WebSocket size")
			}
		}
		if size > 16<<20 {
			return 0, errors.New("WebSocket frame exceeds 16MiB")
		}
		c.masked = masked
		c.maskOffset = 0
		if masked {
			if _, err := io.ReadFull(c.Conn, c.mask[:]); err != nil {
				return 0, err
			}
		}
		if opcode >= 8 {
			if !fin || size > 125 {
				return 0, errors.New("invalid WebSocket control frame")
			}
			data := make([]byte, int(size))
			if _, err := io.ReadFull(c.Conn, data); err != nil {
				return 0, err
			}
			if masked {
				wsMask(data, c.mask, 0)
			}
			switch opcode {
			case 8:
				if size == 1 {
					return 0, errors.New("invalid WebSocket close payload")
				}
				return 0, io.EOF
			case 9:
				if err := c.writeFrame(10, data); err != nil {
					return 0, err
				}
			case 10:
				c.finishCloseProbe(data, false)
			default:
				return 0, errors.New("unknown WebSocket control opcode")
			}
			continue
		}
		if opcode == 2 || opcode == 1 && c.legacyText {
			if c.fragmented {
				return 0, errors.New("nested WebSocket message")
			}
			c.fragmented = !fin
		} else if opcode == 0 {
			if !c.fragmented {
				return 0, errors.New("WebSocket continuation without message")
			}
			if fin {
				c.fragmented = false
			}
		} else {
			return 0, errors.New("proxy transport requires binary WebSocket messages")
		}
		c.remaining = size
	}
	n, err := c.Conn.Read(p[:min(uint64(len(p)), c.remaining)])
	if c.masked {
		wsMask(p[:n], c.mask, c.maskOffset)
		c.maskOffset = (c.maskOffset + n) & 3
	}
	c.remaining -= uint64(n)
	return n, err
}

func (c *websocketConn) writeFrame(opcode byte, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		if opcode == 8 {
			return nil
		}
		if opcode != 10 {
			return io.ErrClosedPipe
		}
	}
	// Header and payload go out in one write: one syscall, and one record
	// when the transport is TLS.
	owner := buffers.Get().(*[32 * 1024]byte)
	defer buffers.Put(owner)
	packet := append(owner[:0], 128|opcode)
	maskBit := byte(0)
	if c.client {
		maskBit = 128
	}
	if len(data) < 126 {
		packet = append(packet, maskBit|byte(len(data)))
	} else if len(data) < 65536 {
		packet = append(packet, maskBit|126)
		packet = binary.BigEndian.AppendUint16(packet, uint16(len(data)))
	} else {
		packet = append(packet, maskBit|127)
		packet = binary.BigEndian.AppendUint64(packet, uint64(len(data)))
	}
	var mask [4]byte
	if c.client {
		if _, err := rand.Read(mask[:]); err != nil {
			return err
		}
		packet = append(packet, mask[:]...)
	}
	header := len(packet)
	packet = append(packet, data...)
	if c.client {
		wsMask(packet[header:], mask, 0)
	}
	err := writeAll(c.Conn, packet)
	if err == nil && opcode == 8 {
		c.writeClosed = true
	}
	return err
}
func (c *websocketConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 32750)
		if err := c.writeFrame(2, p[:n]); err != nil {
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}
func (c *websocketConn) CloseWrite() error {
	c.closeOnce.Do(func() {
		if c.closeProbe {
			// Let legacy plugin readers drain the final data message before closing their pipes.
			var token [8]byte
			if _, c.closeErr = rand.Read(token[:]); c.closeErr != nil {
				return
			}
			done := make(chan struct{})
			c.writeMu.Lock()
			c.closeToken, c.closePong = token, done
			c.writeMu.Unlock()
			if c.closeErr = c.writeFrame(9, token[:]); c.closeErr != nil {
				return
			}
			timer := time.NewTimer(time.Second)
			select {
			case <-done:
			case <-timer.C:
			}
			timer.Stop()
		}
		c.closeErr = c.writeFrame(8, []byte{3, 232})
	})
	return c.closeErr
}
