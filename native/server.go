package native

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func (r *Runtime) serve(in Inbound, raw net.Conn) error {
	if in.Type == "sudoku" && in.Sudoku.users != nil && in.plugin == nil {
		in.sudokuAccount = newSudokuAccount()
		raw = in.sudokuAccount.wrap(raw)
		defer raw.Close()
		defer in.sudokuAccount.finish()
	}
	if in.Type == "direct" {
		remote, err := r.routeDial(r.ctx, request{origin: r.socketOrigin(raw.RemoteAddr(), raw.LocalAddr()), network: "tcp", address: in.directTarget(raw.LocalAddr()), inbound: in.Tag, source: raw.RemoteAddr().String()})
		if err != nil {
			return err
		}
		r.relay(raw, remote)
		return nil
	}
	if in.plugin != nil && in.plugin.cloak != nil {
		return r.serveCloak(in, raw, raw.RemoteAddr().String())
	}
	conn := raw
	if in.Type == "shadowtls" {
		return r.serveShadowTLS(in, raw)
	}
	if p := in.plugin; p != nil && p.shadow != nil {
		st := Inbound{Version: fmt.Sprint(p.shadow.version), Password: p.shadow.password, ShadowTLSOptions: p.shadow.options}
		if p.shadow.version == 3 {
			st.Password = ""
			st.Users = []User{{Password: p.shadow.password}}
		}
		var e error
		conn, e = r.shadowAccept(raw, st)
		if e != nil || conn == nil {
			return e
		}
	}
	if in.TLS.realityEnabled() {
		var err error
		conn, err = r.realityAccept(in, raw, r.serverTLS[in.Tag])
		if err != nil || conn == nil {
			return err
		}
	} else if cfg := r.serverTLS[in.Tag]; cfg != nil {
		tlsRaw := raw
		if hasVision(in) {
			tlsRaw = &visionRecordConn{Conn: tlsRaw}
		}
		var secured tlsConnection
		var err error
		if in.Type == "openconnect" {
			secured, err = handshakeOCTLS(r.ctx, tlsRaw, cfg, in.TLS, true)
		} else {
			secured = serverTLSConnection(tlsRaw, cfg, in.TLS)
			err = secured.HandshakeContext(r.ctx)
		}
		if err != nil {
			return err
		}
		conn = secured
	}
	var err error
	conn, err = in.SIP003Options.wrap(conn, true)
	if err != nil {
		return err
	}
	return r.serveProtocol(in, conn, raw.RemoteAddr().String())
}

func (r *Runtime) serveProtocol(in Inbound, conn net.Conn, source string) error {
	reader := bufio.NewReaderSize(conn, 4096)
	c := &bufferedConn{Conn: conn, reader: reader}
	if in.Transport.Type != "" && in.Transport.Type != "quic" && in.Transport.Type != "xhttp" && !in.Transport.usesHTTP2(in.TLS.Enabled) {
		transport := in.Transport
		// Brook upgrades with the WebSocket handshake, then carries encrypted
		// records directly instead of RFC6455 data frames.
		transport.rawUpgrade = in.Type == "brook"
		transport.legacyText = in.Type == "trojan"
		wrapped, err := acceptTransport(c, transport)
		if err != nil {
			return err
		}
		reader = bufio.NewReader(wrapped)
		c = &bufferedConn{Conn: wrapped, reader: reader}
	}
	kind := in.Type
	if kind == "mixed" {
		peek, err := reader.Peek(1)
		if err != nil {
			return err
		}
		if peek[0] == 5 {
			kind = "socks"
		} else {
			kind = "http"
		}
	}
	q := request{origin: r.socketOrigin(conn.RemoteAddr(), conn.LocalAddr()), network: "tcp", inbound: in.Tag, source: source}
	if p := in.plugin; p != nil && p.kcp != nil {
		in.Transport = Transport{}
		in.SIP003Options = SIP003Options{}
		return r.serveKCPTUN(in, c, source, p.kcp)
	}
	if p := in.plugin; p != nil && p.mux {
		in.Transport = Transport{}
		in.SIP003Options = SIP003Options{}
		if p.smux {
			return r.serveSMUXPlugin(in, c, source)
		}
		return r.serveMuxCool(c, q, &in, false)
	}
	switch kind {
	case "sudoku":
		return r.serveSudoku(in, c, q)
	case "mieru":
		return r.serveMieru(in, c)
	case "openconnect":
		return r.serveOpenConnect(in, c)
	case "brook":
		return r.serveBrook(in, c, q)
	case "ssh":
		return r.serveSSH(in, c, q)
	case "dns":
		return r.serveDNSStream(c, in.Tag)
	case "socks":
		return r.serveSOCKS(in, c, q)
	case "http":
		return r.serveHTTP(in, c, q)
	case "vmess":
		return r.serveVMess(in, c, q)
	case "anytls":
		return r.serveAnyTLS(in, c, q)
	case "relay":
		return r.serveRelay(in, c, q)
	case "snell":
		return r.serveSnell(in, c, q)
	case "shadowsocksr":
		stream, err := ssrAccept(c, in, r.keys["in:"+in.Tag], &r.replay)
		if err != nil {
			return err
		}
		address, err := readSSRAddress(stream)
		if err != nil {
			return err
		}
		q.address = address
		remote, err := r.routeDial(r.ctx, q)
		if err != nil {
			return err
		}
		r.relay(stream, remote)
	case "shadowsocks":
		if isSS2022(in.Method) {
			return r.serveSS2022(in, c, q)
		}
		stream := newSSConn(c, r.keys["in:"+in.Tag], &r.replay)
		if in.OTA {
			var err error
			stream, err = ssrAccept(c, Inbound{Protocol: "verify_sha1"}, r.keys["in:"+in.Tag], &r.replay)
			if err != nil {
				return err
			}
		}
		address, err := readSSRAddress(stream)
		if err != nil {
			return err
		}
		q.address = address
		remote, err := r.routeDial(r.ctx, q)
		if err != nil {
			return err
		}
		r.relay(stream, remote)
	case "trojan":
		var stream net.Conn = c
		if in.Shadowsocks != nil && in.Shadowsocks.Enabled {
			stream = newSSConn(c, r.keys["in:"+in.Tag], &r.replay)
		}
		var hash [58]byte
		if _, err := io.ReadFull(stream, hash[:]); err != nil {
			return err
		}
		if string(hash[56:]) != "\r\n" {
			return errors.New("invalid Trojan authentication delimiter")
		}
		valid := 0
		var account User
		for _, user := range in.Users {
			sum := sha256.Sum224([]byte(user.Password))
			expected := []byte(hex.EncodeToString(sum[:]))
			match := subtle.ConstantTimeCompare(hash[:56], expected)
			valid |= match
			if match == 1 {
				account = user
			}
		}
		if valid != 1 {
			return errors.New("Trojan authentication rejected")
		}
		var command [1]byte
		if _, err := io.ReadFull(stream, command[:]); err != nil {
			return err
		}
		address, err := readAddress(stream)
		if err != nil {
			return err
		}
		if err := readCRLF(stream); err != nil {
			return err
		}
		vision := command[0] == 0x71 || command[0] == 0x73
		if vision != (account.Flow != "") {
			return errors.New("Trojan account flow mismatch")
		}
		if vision {
			stream, err = trojanVisionServer(stream, account.Password)
			if err != nil {
				return err
			}
			command[0] &= 0x0f
		}
		q.metadata.AuthUser = account.Name
		q.address = address
		if command[0] == 127 {
			return r.serveTrojanMux(stream, q)
		}
		if command[0] == 3 {
			_ = stream.SetDeadline(time.Time{})
			return r.serveStreamPackets(stream, q, true)
		}
		if command[0] != 1 {
			return errors.New("unknown Trojan command")
		}
		remote, err := r.routeDial(r.ctx, q)
		if err != nil {
			return err
		}
		r.relay(stream, remote)
	case "vless":
		var header [18]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return err
		}
		if header[0] != 0 {
			return errors.New("invalid VLESS version")
		}
		valid := 0
		var account User
		var userID [16]byte
		copy(userID[:], header[1:17])
		for _, user := range in.Users {
			id, _ := parseUUID(user.UUID)
			match := subtle.ConstantTimeCompare(id[:], header[1:17])
			valid |= match
			if match == 1 {
				account = user
			}
		}
		if valid != 1 {
			return errors.New("VLESS authentication rejected")
		}
		flow, err := readVLESSFlow(c, header[17])
		if err != nil {
			return err
		}
		if flow != account.Flow && !(flow == "" && account.Flow == visionFlow) {
			return errors.New("VLESS account flow mismatch")
		}
		if account.Flow != "" {
			q.metadata.AuthUser = account.Name
			if q.metadata.AuthUser == "" {
				q.metadata.AuthUser = account.UUID
			}
		}

		var command [1]byte
		if _, err := io.ReadFull(c, command[:]); err != nil {
			return err
		}
		if account.Flow != "" && flow == "" && command[0] != 3 {
			return errors.New("VLESS Vision flow is required")
		}
		if flow != "" && command[0] == 2 {
			return errors.New("Vision UDP uses XUDP instead of the basic UDP command")
		}
		var stream net.Conn = c
		if flow != "" {
			stream, err = newVisionConn(c, userID)
			if err != nil {
				return err
			}
		}
		if command[0] == 3 {
			if err = writeAll(c, []byte{0, 0}); err != nil {
				return err
			}
			return r.serveMuxCool(stream, q, nil, account.Flow != "")
		}
		address, err := readVLESSAddress(c)
		if err != nil {
			return err
		}
		q.address = address
		if command[0] == 2 {
			if err := writeAll(c, []byte{0, 0}); err != nil {
				return err
			}
			_ = c.SetDeadline(time.Time{})
			return r.serveStreamPackets(c, q, false)
		}
		if command[0] != 1 {
			return errors.New("unknown VLESS command")
		}
		remote, err := r.routeDial(r.ctx, q)
		if err != nil {
			return err
		}
		if err := writeAll(c, []byte{0, 0}); err != nil {
			remote.Close()
			return err
		}
		r.relay(stream, remote)
	}
	return nil
}

func validUser(users []User, username, password string) bool {
	if len(users) == 0 {
		return true
	}
	valid := 0
	for _, user := range users {
		name := user.Username
		if name == "" {
			name = user.Name
		}
		valid |= subtle.ConstantTimeCompare([]byte(username), []byte(name)) & subtle.ConstantTimeCompare([]byte(password), []byte(user.Password))
	}
	return valid == 1
}

func (r *Runtime) serveSOCKS(in Inbound, c net.Conn, q request) error {
	var greeting [2]byte
	if _, err := io.ReadFull(c, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != 5 || greeting[1] == 0 {
		return errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	method := byte(0)
	if len(in.Users) > 0 {
		method = 2
	}
	acceptable := false
	for _, m := range methods {
		acceptable = acceptable || m == method
	}
	if !acceptable {
		_ = writeAll(c, []byte{5, 255})
		return errors.New("no acceptable SOCKS authentication")
	}
	if err := writeAll(c, []byte{5, method}); err != nil {
		return err
	}
	if method == 2 {
		var header [2]byte
		if _, err := io.ReadFull(c, header[:]); err != nil {
			return err
		}
		if header[0] != 1 || header[1] == 0 {
			return errors.New("invalid SOCKS credentials header")
		}
		user := make([]byte, int(header[1]))
		if _, err := io.ReadFull(c, user); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, header[:1]); err != nil {
			return err
		}
		password := make([]byte, int(header[0]))
		if _, err := io.ReadFull(c, password); err != nil {
			return err
		}
		if !validUser(in.Users, string(user), string(password)) {
			_ = writeAll(c, []byte{1, 1})
			return errors.New("SOCKS authentication rejected")
		}
		if err := writeAll(c, []byte{1, 0}); err != nil {
			return err
		}
	}
	var header [3]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	if header[0] != 5 || header[2] != 0 {
		return errors.New("invalid SOCKS request")
	}
	address, err := readAddress(c)
	if err != nil {
		return err
	}
	if header[1] == 3 {
		return r.serveSOCKSPackets(c, q)
	}
	if header[1] != 1 {
		_ = writeAll(c, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return errors.New("SOCKS command is not supported")
	}
	q.address = address
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		_ = writeAll(c, []byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return err
	}
	if err := writeAll(c, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		remote.Close()
		return err
	}
	r.relay(c, remote)
	return nil
}

// Header buffering is bounded without applying a byte limit to the tunneled body.
func readHTTPHeader(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 0, 1024)
	for len(header) < 65536 {
		line, err := reader.ReadSlice('\n')
		header = append(header, line...)
		if len(header) > 65536 {
			break
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(header) >= 4 && string(header[len(header)-4:]) == "\r\n\r\n" {
			return header, nil
		}
	}
	return nil, errors.New("HTTP proxy headers exceed 64KiB")
}

func (r *Runtime) serveHTTP(in Inbound, c *bufferedConn, q request) error {
	header, err := readHTTPHeader(c.reader)
	if err != nil {
		return err
	}
	// Reattach buffered body bytes so net/http enforces Content-Length and chunk framing.
	requestReader := bufio.NewReader(io.MultiReader(strings.NewReader(string(header)), c.reader))
	req, err := http.ReadRequest(requestReader)
	if err != nil {
		return err
	}
	if r.acme != nil {
		if value, ok := r.acme.httpValue(req); ok {
			return writeAll(c, []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nCache-Control: no-store\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(value), value)))
		}
	}
	if len(in.Users) > 0 {
		value := req.Header.Get("Proxy-Authorization")
		username, password := "", ""
		if strings.HasPrefix(value, "Basic ") {
			raw, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "Basic "))
			if decodeErr == nil {
				username, password, _ = strings.Cut(string(raw), ":")
			}
		}
		if !validUser(in.Users, username, password) {
			_ = writeAll(c, []byte("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Lanboat\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			return errors.New("HTTP proxy authentication rejected")
		}
	}
	if req.Method == http.MethodConnect {
		if observer := r.requestLogger.Load(); observer != nil {
			entry := RequestLog{URL: req.Host, Method: http.MethodConnect, Destination: req.Host, Inbound: in.Tag}
			if observer.full {
				entry.Headers = req.Header.Clone()
				entry.Headers.Del("Proxy-Authorization")
			}
			observer.push(entry)
		}
		if !validHTTPHost(req.Host) {
			return errors.New("invalid CONNECT authority")
		}
		address := req.Host
		if _, _, err := net.SplitHostPort(address); err != nil {
			address = net.JoinHostPort(address, "443")
		}
		if _, err := encodeAddress(address); err != nil {
			return err
		}
		q.address = address
		remote, err := r.routeDial(r.ctx, q)
		if err != nil {
			_ = writeAll(c, []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return err
		}
		if err := writeAll(c, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			remote.Close()
			return err
		}
		r.relay(&bufferedConn{Conn: c.Conn, reader: requestReader}, remote)
		return nil
	}
	if req.URL.Scheme != "http" || !validHTTPHost(req.URL.Host) || req.URL.User != nil {
		return errors.New("HTTP proxy requires an absolute http URL")
	}
	stripProxyHeaders(req.Header)
	req.RequestURI = ""
	req.Close = true
	_ = c.SetDeadline(time.Time{})
	transport := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: handshakeTimeout, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		next := q
		next.address = address
		return r.routeDial(ctx, next)
	}}
	defer transport.CloseIdleConnections()
	req = req.WithContext(r.ctx)
	response, err := transport.RoundTrip(req)
	if err != nil {
		_ = writeAll(c, []byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return err
	}
	defer response.Body.Close()
	stripProxyHeaders(response.Header)
	response.Close = true
	return response.Write(c)
}

func stripProxyHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
	for _, key := range []string{"Proxy-Authorization", "Proxy-Authenticate", "Proxy-Connection", "Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(key)
	}
}

func (r *Runtime) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	ips, err := r.resolver.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		result = append(result, net.IP(ip.AsSlice()))
	}
	return result, nil
}
