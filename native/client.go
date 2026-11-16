package native

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type ownedConn struct {
	net.Conn
	runtime *Runtime
	once    sync.Once
}

func (c *ownedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.runtime.mu.Lock(); delete(c.runtime.connections, c); c.runtime.mu.Unlock() })
	return err
}
func (c *ownedConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (r *Runtime) own(c net.Conn) (net.Conn, error) {
	if c == nil {
		return nil, errors.New("nil connection")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		c.Close()
		return nil, net.ErrClosed
	}
	owned := &ownedConn{Conn: c, runtime: r}
	r.connections[owned] = struct{}{}
	r.mu.Unlock()
	return owned, nil
}

func (r *Runtime) directIPs(ctx context.Context, host string) ([]netip.Addr, error) {
	if tag, ok := ctx.Value(dnsBootstrapKey{}).(string); ok {
		return r.resolver.lookupMode(ctx, host, true, tag)
	} else if ref := r.config.Route.DefaultDomainResolver; ref != "" {
		options := ref.options()
		child, cancel := ref.apply(ctx)
		defer cancel()
		return r.resolver.lookupMode(child, host, true, options.Server)
	}
	return r.resolver.lookupReal(ctx, host)
}

func (r *Runtime) direct(ctx context.Context, network, address string) (net.Conn, error) {
	return r.directWithOptions(ctx, DialOptions{}, network, address)
}

func (r *Runtime) directWithOptions(ctx context.Context, options DialOptions, network, address string) (net.Conn, error) {
	if options.ConnectTimeout != "" {
		timeout, _ := optionDuration(options.ConnectTimeout, 0)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ips, err := r.directIPs(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result)
	addressDelay := 150 * time.Millisecond
	if options.FallbackDelay != "" {
		addressDelay = options.NetworkOptions.delay()
	}
	for i, ip := range ips {
		go func() {
			if i > 0 {
				timer := time.NewTimer(time.Duration(i) * addressDelay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-child.Done():
					return
				}
			}
			conn, err := r.dialSocket(child, options, network, net.JoinHostPort(ip.String(), port))
			select {
			case results <- result{conn, err}:
			case <-child.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	for range ips {
		select {
		case item := <-results:
			if item.err == nil {
				return r.own(item.conn)
			}
			err = item.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err == nil {
		err = errors.New("DNS returned no addresses")
	}
	return nil, err
}

func (r *Runtime) dialOutbound(ctx context.Context, tag, network, address string) (net.Conn, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, net.ErrClosed
	}
	o, exists := r.outbounds[tag]
	if !exists {
		return nil, fmt.Errorf("unknown outbound %q", tag)
	}
	if policy, _ := ctx.Value(networkRouteKey{}).(*NetworkOptions); policy != nil && o.Type != "direct" && r.groups[tag] == nil {
		ctx = context.WithValue(ctx, networkRouteKey{}, (*NetworkOptions)(nil))
	}
	timeout := handshakeTimeout
	if o.Type == "openconnect" {
		timeout = o.authDuration()
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stopRuntime := context.AfterFunc(r.ctx, cancel)
	defer stopRuntime()
	if ep := r.wgEndpoints[tag]; ep != nil {
		return ep.dial(ctx, network, address)
	}
	if o.ocEndpoint != nil {
		return r.ocClients[tag].dial(ctx, network, address)
	}
	if o.DomainResolver != "" {
		options := o.DomainResolver.options()
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, options.Server)
		ctx = context.WithValue(ctx, dnsQueryOptionsKey{}, options)
	}
	if o.Type == "block" {
		return nil, ErrRejected
	}
	if o.Type == "shadowtls" {
		if network != "tcp" {
			return nil, errors.New("ShadowTLS carries TCP streams; UDP requires an inner protocol")
		}
		return r.shadowDial(ctx, o, shadowVersion(o.Version), o.Password, o.TLS)
	}
	if g := r.groups[tag]; g != nil {
		return g.dial(ctx, network, address)
	}
	if o.Type == "direct" {
		options := o.DialOptions.routeNetwork(ctx)
		if policy, _ := ctx.Value(networkRouteKey{}).(*NetworkOptions); policy != nil {
			ctx = context.WithValue(ctx, networkRouteKey{}, (*NetworkOptions)(nil))
		}
		return r.directWithOptions(ctx, options, network, address)
	}
	if o.Type == "brook" && o.tengoProgram != nil {
		var metadata Metadata
		metadata, _ = ctx.Value(metadataKey{}).(Metadata)
		decision, err := o.addressDecision(ctx, network, address, "", metadata)
		if err != nil {
			return nil, err
		}
		address = decision.address
		if decision.bypass {
			return r.direct(ctx, network, address)
		}
		if decision.detour != "" {
			next, err := brookScriptPath(ctx, tag)
			if err != nil {
				return nil, err
			}
			return r.dialOutbound(next, decision.detour, network, address)
		}
	}
	if mux := r.genericMuxClients[tag]; mux != nil && ctx.Value(genericMuxBypassKey{}) != tag {
		return mux.dial(ctx, network, address)
	}
	if o.Type == "lua" {
		return r.dialLua(ctx, o, network, address)
	}
	if o.Type == "wireguard" {
		return r.wgClients[tag].dial(ctx, network, address)
	}
	if o.Type == "tailscale" {
		return r.tailscaleClient(tag).dial(ctx, network, address)
	}
	if o.Type == "ssh" {
		return r.sshDial(ctx, o, network, address)
	}
	if o.Type == "naive" {
		return r.trustClients[tag].dialNaive(ctx, network, address)
	}
	if o.Type == "openconnect" {
		return r.ocClients[tag].dial(ctx, network, address)
	}
	if o.Type == "mieru" {
		return r.mieruClients[tag].dial(ctx, network, address)
	}
	if o.Type == "masque" {
		return r.masqueClients[tag].dial(ctx, network, address)
	}
	if o.Type == "masque-server" {
		return r.masqueServers[tag].dial(ctx, r, network, address)
	}
	if o.Type == "trusttunnel" {
		return r.trustClients[tag].dial(ctx, network, address)
	}
	if isQUICProxy(o.Type) {
		return r.quicClients[tag].dial(ctx, network, address)
	}
	if o.Type == "trojan" && o.Multiplex.Enabled && !o.Multiplex.generic(o.Type) {
		return r.trojanMuxClients[tag].dial(ctx, network, address)
	}
	if o.Type == "sudoku" && o.Multiplex.Enabled && !o.Multiplex.generic(o.Type) && network == "tcp" {
		return r.sudokuMuxClients[tag].dial(ctx, address)
	}
	if o.Type == "vless" && o.Flow != "" && network == "udp" {
		_, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		number, _ := shadowPort(port)
		if number == 443 {
			return nil, errors.New("Vision disables UDP443")
		}
		return r.proxyMuxClients[tag].dial(ctx, network, address)
	}
	if (o.Type == "vmess" || o.Type == "vless") && o.Multiplex.Enabled && !o.Multiplex.generic(o.Type) {
		return r.proxyMuxClients[tag].dial(ctx, network, address)
	}
	if o.Type == "snell" && o.Multiplex.Enabled && !o.Multiplex.generic(o.Type) && network == "tcp" {
		return r.snellClients[tag].dial(ctx, address)
	}
	if o.Type == "anytls" {
		return r.anyClients[tag].dial(ctx, network, address)
	}
	if network == "udp" && o.Type == "snell" && snellVersion(o.Version) == 5 {
		return r.snell5PacketClient(o, address)
	}
	if network == "udp" {
		if o.plugin != nil && (o.plugin.kcp != nil || o.plugin.cloak != nil) {
			return nil, errors.New("plugin carries TCP streams only")
		}
		if o.Type == "shadowsocks" && (o.Transport.Type == "quic" || o.Transport.Type == "mkcp" || o.Transport.xhttp3(o.TLS)) {
			return nil, errors.New("Shadowsocks UDP stream transport has no native UDP channel")
		}
		switch o.Type {
		case "brook":
			if o.Transport.Type == "quic" && !o.UDPOverStream {
				return r.brookQUICPacketClient(ctx, o, address)
			}
			if o.Transport.Type == "" && !o.UDPOverTCP {
				return r.brookPacketClient(ctx, o, address)
			}
		case "socks":
			return r.socksPacketClient(ctx, o, address)
		case "shadowsocks":
			return r.ssPacketClient(ctx, o, address)
		case "shadowsocksr":
			return r.ssrPacketClient(ctx, o, address)
		case "vless", "trojan", "vmess", "relay", "snell", "sudoku":
		default:
			return nil, fmt.Errorf("%s cannot relay UDP", o.Type)
		}
	}
	conn, err := r.dialProxyTransport(ctx, o)
	if err != nil {
		return nil, err
	}
	transport := conn
	closeOnError := true
	defer func() {
		if closeOnError {
			transport.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { transport.Close() })
	defer stop()
	switch o.Type {
	case "sudoku":
		conn, err = sudokuClient(conn, o.Sudoku, address, network == "udp")
	case "brook":
		conn, err = brookClient(conn, o, address, network == "udp", &r.replay)
	case "socks":
		if err = socksAuthenticate(conn, o.Username, o.Password); err == nil {
			_, err = socksRequest(conn, 1, address)
		}
	case "http":
		conn, err = httpConnect(conn, o, address)
	case "relay":
		conn, err = relayClient(conn, o, address, network == "udp")
	case "snell":
		conn, err = dialSnellObfs(conn, o)
		if err != nil {
			return nil, err
		}
		conn, err = snellClient(conn, o, address, network == "udp", &r.replay)
	case "shadowsocksr":
		conn, err = ssrClient(conn, o, r.keys["out:"+o.Tag])
		if err == nil {
			var destination []byte
			destination, err = encodeAddress(address)
			if err == nil {
				err = writeAll(conn, destination)
			}
		}
	case "shadowsocks":
		if isSS2022(o.Method) {
			conn, err = ss2022Client(conn, r.keys["out:"+o.Tag], address)
			break
		}
		stream := newSSConn(conn, r.keys["out:"+o.Tag], &r.replay)
		if o.OTA {
			stream, err = ssrClient(conn, Outbound{Protocol: "verify_sha1"}, r.keys["out:"+o.Tag])
			if err != nil {
				return nil, err
			}
		}
		var destination []byte
		destination, err = encodeAddress(address)
		if err == nil {
			err = writeAll(stream, destination)
		}
		conn = stream
	case "trojan":
		if o.Shadowsocks != nil && o.Shadowsocks.Enabled {
			conn = &ssConn{Conn: conn, key: r.keys["out:"+o.Tag], replay: &r.replay, lineSalt: o.Transport.Type == ""}
		}
		sum := sha256.Sum224([]byte(o.Password))
		command := byte(1)
		if network == "udp" {
			command = 3
		}
		if o.Flow != "" {
			command |= 0x70
		}
		header := append([]byte(hex.EncodeToString(sum[:])+"\r\n"), command)
		var destination []byte
		destination, err = encodeAddress(address)
		if err == nil {
			header = append(header, destination...)
			header = append(header, 13, 10)
			err = writeAll(conn, header)
		}
		if err == nil && o.Flow != "" {
			conn, err = trojanVisionClient(conn, o.Password)
		}
		if network == "udp" {
			conn = &streamPacketConn{Conn: conn, address: address, trojan: true}
		}
	case "vless":
		conn, err = vlessClient(conn, o, network, address)
	case "vmess":
		conn, err = vmessClient(conn, o, r.vmessUsers["out:"+o.Tag][0], network, address)
	}
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	closeOnError = false
	// Keep the transport tracked as well as the wrapper; closing the runtime interrupts TLS and AEAD reads.
	return r.own(conn)
}

func socksAuthenticate(c io.ReadWriter, username, password string) error {
	method := byte(0)
	if username != "" || password != "" {
		method = 2
	}
	if err := writeAll(c, []byte{5, 1, method}); err != nil {
		return err
	}
	var reply [2]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return err
	}
	if reply != [2]byte{5, method} {
		return errors.New("SOCKS authentication method rejected")
	}
	if method == 2 {
		b := append([]byte{1, byte(len(username))}, username...)
		b = append(b, byte(len(password)))
		b = append(b, password...)
		if err := writeAll(c, b); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, reply[:]); err != nil {
			return err
		}
		if reply != [2]byte{1, 0} {
			return errors.New("SOCKS authentication rejected")
		}
	}
	return nil
}

func socksRequest(c io.ReadWriter, command byte, address string) (string, error) {
	var b []byte
	var err error
	if command == 3 {
		b = []byte{1, 0, 0, 0, 0, 0, 0}
	} else {
		b, err = encodeAddress(address)
		if err != nil {
			return "", err
		}
	}
	if err := writeAll(c, append([]byte{5, command, 0}, b...)); err != nil {
		return "", err
	}
	var reply [3]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		return "", err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return "", fmt.Errorf("SOCKS request failed: %d", reply[1])
	}
	return readAddress(c)
}

func httpConnect(c net.Conn, o Outbound, address string) (net.Conn, error) {
	if _, err := encodeAddress(address); err != nil {
		return nil, err
	}
	request := "CONNECT " + address + " HTTP/1.1\r\nHost: " + address + "\r\n"
	if o.Username != "" || o.Password != "" {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(o.Username+":"+o.Password)) + "\r\n"
	}
	if err := writeAll(c, []byte(request+"\r\n")); err != nil {
		return nil, err
	}
	reader := bufio.NewReaderSize(c, 4096)
	header, err := readHTTPHeader(reader)
	if err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(header))), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		return nil, fmt.Errorf("HTTP CONNECT rejected: %d", response.StatusCode)
	}
	return &bufferedConn{Conn: c, reader: reader}, nil
}

type vlessConn struct {
	net.Conn
	readMu                      sync.Mutex
	header                      [2]byte
	headerRead, addonsRemaining int
	headerParsed, ready         bool
	discard                     [255]byte
	err                         error
}

func (c *vlessConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	if !c.ready {
		for c.headerRead < 2 {
			n, e := c.Conn.Read(c.header[c.headerRead:])
			c.headerRead += n
			if e != nil {
				return 0, e
			}
			if n == 0 {
				return 0, io.ErrNoProgress
			}
		}
		if !c.headerParsed {
			if c.header[0] != 0 {
				c.err = errors.New("invalid VLESS response version")
				return 0, c.err
			}
			c.addonsRemaining = int(c.header[1])
			c.headerParsed = true
		}
		for c.addonsRemaining > 0 {
			n, e := c.Conn.Read(c.discard[:c.addonsRemaining])
			c.addonsRemaining -= n
			if e != nil {
				return 0, e
			}
			if n == 0 {
				return 0, io.ErrNoProgress
			}
		}
		c.ready = true
	}
	return c.Conn.Read(b)
}
func (c *vlessConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (r *Runtime) dialProxyTransport(ctx context.Context, o Outbound) (net.Conn, error) {
	if p := o.plugin; p != nil && p.mux {
		return r.proxyMuxClients[o.Tag].dial(ctx, "tcp", "127.0.0.1:1")
	}
	return r.dialProxyTransportRaw(ctx, o)
}

func (r *Runtime) dialProxyTransportRaw(ctx context.Context, o Outbound) (net.Conn, error) {
	if o.Type == "sudoku" && o.Sudoku.HTTPMask != nil {
		mode := o.Sudoku.HTTPMask.Mode
		if mode == "stream" || mode == "poll" || mode == "auto" {
			return r.dialSudokuHTTP(ctx, o)
		}
	}
	if o.plugin != nil && o.plugin.cloak != nil {
		return r.cloakClients[o.Tag].dial(ctx)
	}
	if o.plugin != nil && o.plugin.kcp != nil {
		return r.kcpClients[o.Tag].dial(ctx)
	}
	if p := o.plugin; p != nil && p.shadow != nil {
		return r.shadowDial(ctx, o, p.shadow.version, p.shadow.password, p.tls)
	}
	if o.Transport.Type == "xhttp" {
		return r.xhttpClients[o.Tag].dial(ctx)
	}
	if o.Transport.Type == "quic" {
		return r.quicTransports[o.Tag].dial(ctx)
	}
	var raw net.Conn
	var err error
	if o.Transport.Type == "mkcp" {
		raw, err = r.dialMKCP(ctx, o)
	} else if o.Transport.usesHTTP2(o.TLS.Enabled) {
		raw, err = r.dialHTTPTransport(ctx, o)
	} else {
		raw, err = r.endpoint(ctx, o, "tcp")
	}
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	if d, exists := ctx.Deadline(); exists {
		_ = raw.SetDeadline(d)
	}
	conn := raw
	if r.clientTLS[o.Tag] != nil && !o.Transport.usesHTTP2(o.TLS.Enabled) {
		cfg, e := r.outboundTLS(ctx, o)
		if e != nil {
			return nil, e
		}
		if o.TLS.realityEnabled() {
			tlsRaw := raw
			if o.Flow != "" {
				tlsRaw = &visionRecordConn{Conn: raw}
			}
			conn, e = dialReality(ctx, tlsRaw, cfg, o.TLS)
			if e != nil {
				return nil, e
			}
		} else {
			var secured tlsConnection
			if o.Flow != "" {
				if o.TLS.browserEnabled() {
					secured = clientTLS(&visionRecordConn{Conn: raw}, cfg, o.TLS)
				} else {
					transport, config := clientTLSConnection(raw, cfg, o.TLS)
					config = config.Clone()
					config.MinVersion = tls.VersionTLS13
					secured = tls.Client(&visionRecordConn{Conn: transport}, config)
				}
			} else {
				secured = clientTLS(raw, cfg, o.TLS)
			}
			if e = secured.HandshakeContext(ctx); e != nil {
				return nil, e
			}
			conn = secured
		}
	}
	if !o.Transport.usesHTTP2(o.TLS.Enabled) {
		conn, err = dialTransport(conn, o)
		if err != nil {
			return nil, err
		}
	}
	conn, err = o.SIP003Options.wrap(conn, false)
	if err != nil {
		return nil, err
	}
	if o.Type == "sudoku" && o.Sudoku.HTTPMask != nil {
		deadline := time.Now().Add(handshakeTimeout)
		if d, exists := ctx.Deadline(); exists && d.Before(deadline) {
			deadline = d
		}
		_ = conn.SetDeadline(deadline)
		conn, err = o.Sudoku.dialHTTPMask(conn, o.Server)
		if err != nil {
			return nil, err
		}
	}
	ok = true
	return conn, nil
}

func (r *Runtime) endpoint(ctx context.Context, o Outbound, network string) (net.Conn, error) {
	if p := o.plugin; p != nil && (p.gost || p.shadow != nil) && network == "tcp" {
		if p.server != "" {
			o.Server = p.server
		}
		if p.port != 0 {
			o.ServerPort = p.port
		}
	}
	address := portAddress(o.Server, o.ServerPort)
	if o.Detour != "" {
		return r.dialOutbound(ctx, o.Detour, network, address)
	}
	return r.directWithOptions(ctx, o.DialOptions, network, address)
}

func validHTTPHost(host string) bool { return host != "" && !strings.ContainsAny(host, "\r\n\t /?#") }
