package native

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

func isQUICInbound(in Inbound) bool {
	return in.Transport.xhttp3(in.TLS) || in.Transport.Type == "quic" || in.Type == "masque" && in.masqueServes(3) || isQUICProxy(in.Type) || isDNSQUIC(in.Type) || in.Type == "trusttunnel" && in.HTTPVersion == 3 || in.Type == "naive" && in.Network != "tcp"
}
func validateTrustOptions(kind string, version int, tls TLSOptions) error {
	if kind == "masque" {
		return nil
	}
	if kind == "naive" {
		if version != 0 {
			return errors.New("Naive uses network/quic instead of http_version")
		}
		return nil
	}
	if kind != "trusttunnel" {
		if version != 0 {
			return errors.New("http_version requires TrustTunnel")
		}
		return nil
	}
	if version != 0 && version != 2 && version != 3 {
		return errors.New("TrustTunnel http_version must be 2 or 3")
	}
	if !tls.Enabled || tls.DisableSNI {
		return errors.New("TrustTunnel requires TLS with SNI")
	}
	if tls.MinVersion == "1.0" || tls.MinVersion == "1.1" || tls.MaxVersion == "1.0" || tls.MaxVersion == "1.1" {
		return errors.New("TrustTunnel requires TLS1.2 or newer")
	}
	alpn := "h2"
	if version == 3 {
		alpn = "h3"
	}
	if len(tls.ALPN) > 0 && !slices.Contains(tls.ALPN, alpn) {
		return errors.New("TrustTunnel ALPN must include " + alpn)
	}
	if version == 3 {
		return tls.validateQUICVersion()
	}
	return nil
}

type trustClient struct {
	runtime         *Runtime
	outbound        Outbound
	http            *http.Transport
	mu              sync.Mutex
	physical        net.Conn
	quic            *quicConn
	epoch           uint64
	muxMu           sync.Mutex
	udp             *trustUDPMux
	icmp            *trustICMPMux
	naiveCreate     sync.Mutex
	naiveH2         *naiveH2Session
	naiveSessions   map[*naiveH2Session]struct{}
	naiveH3         *chromiumH3Session
	naiveH3Sessions map[*chromiumH3Session]struct{}
}

func newTrustClient(r *Runtime, o Outbound) *trustClient {
	c := &trustClient{runtime: r, outbound: o}
	if o.HTTPVersion != 3 && !o.QUIC {
		c.http = r.newHTTPTransport(o)
		c.http.MaxConnsPerHost = 1
		if o.Type == "naive" {
			return c
		}
		dial := c.http.DialTLSContext
		c.http.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			c.mu.Lock()
			epoch := c.epoch
			c.mu.Unlock()
			conn, err := dial(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.epoch != epoch || r.ctx.Err() != nil {
				conn.Close()
				return nil, net.ErrClosed
			}
			c.physical = conn
			return conn, nil
		}
	}
	return c
}
func (c *trustClient) reset() {
	c.muxMu.Lock()
	udp, icmp := c.udp, c.icmp
	c.udp, c.icmp = nil, nil
	c.mu.Lock()
	raw, q := c.physical, c.quic
	naive := c.naiveSessions
	naiveH3 := c.naiveH3Sessions
	c.naiveH2, c.naiveSessions = nil, nil
	c.naiveH3, c.naiveH3Sessions = nil, nil
	c.physical, c.quic = nil, nil
	c.epoch++
	c.mu.Unlock()
	c.muxMu.Unlock()
	for m := range naive {
		m.fail(net.ErrClosed)
	}
	for n := range naiveH3 {
		n.q.Close()
	}
	if udp != nil {
		udp.close()
	}
	if icmp != nil {
		icmp.close()
	}
	if raw != nil {
		raw.Close()
	}
	if q != nil {
		q.Close()
	}
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
}
func (c *trustClient) authorization() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(c.outbound.Username+":"+c.outbound.Password))
}
func (c *trustClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "udp" {
		return c.dialPacket(ctx, address)
	}
	if network != "tcp" {
		return nil, fmt.Errorf("TrustTunnel network %q unsupported", network)
	}
	if _, err := encodeAddress(address); err != nil {
		return nil, err
	}
	conn, err := c.connect(ctx, address)
	if err != nil {
		return nil, err
	}
	return c.runtime.own(conn)
}
func (c *trustClient) connect(ctx context.Context, authority string) (net.Conn, error) {
	if c.outbound.HTTPVersion == 3 || c.outbound.QUIC {
		return c.connectH3(ctx, authority)
	}
	if c.outbound.Type == "naive" {
		return c.connectNaiveH2(ctx, authority)
	}
	requestCtx, cancel := context.WithCancel(c.runtime.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	reader, writer := io.Pipe()
	req, err := http.NewRequestWithContext(requestCtx, "CONNECT", "https://"+portAddress(c.outbound.Server, c.outbound.ServerPort), reader)
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		return nil, err
	}
	req.Host = authority
	req.Header.Set("Proxy-Authorization", c.authorization())
	req.Header.Set("User-Agent", runtime.GOOS+" Lanboat "+authority)
	response, err := c.http.RoundTrip(req)
	if err == nil && (response.ProtoMajor != 2 || response.StatusCode != 200) {
		err = fmt.Errorf("TrustTunnel CONNECT: HTTP %d", response.StatusCode)
	}
	if err != nil {
		cancel()
		reader.Close()
		writer.Close()
		if response != nil {
			response.Body.Close()
		}
		// Authentication invalidates the whole session, including existing streams.
		// This also closes an in-flight shared mux without taking its creation lock.
		if response != nil && response.StatusCode == 407 {
			c.invalidateHTTP()
		}
		return nil, err
	}
	conn := &httpStreamConn{reader: response.Body, writer: writer, closeWrite: writer.Close, local: streamAddr("trusttunnel"), remote: streamAddr(authority)}
	conn.close = func() { cancel(); reader.Close(); writer.Close(); response.Body.Close() }
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}
func (c *trustClient) invalidateHTTP() {
	c.mu.Lock()
	raw := c.physical
	c.physical = nil
	c.epoch++
	c.mu.Unlock()
	if raw != nil {
		raw.Close()
	}
	c.http.CloseIdleConnections()
}
func trustUser(in Inbound, authorization string) (string, bool) {
	method, encoded, ok := strings.Cut(authorization, " ")
	if !ok || !strings.EqualFold(method, "Basic") || len(encoded) > 4096 {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	user, password, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", false
	}
	for _, u := range in.Users {
		name := u.Username
		if name == "" {
			name = u.Name
		}
		if subtle.ConstantTimeCompare([]byte(name), []byte(user))&subtle.ConstantTimeCompare([]byte(u.Password), []byte(password)) == 1 {
			return name, true
		}
	}
	return "", false
}
func (r *Runtime) serveTrustHTTP(in Inbound, w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.workers.Add(1)
	r.mu.Unlock()
	defer r.workers.Done()
	if in.naiveFrontend != nil {
		_, authenticated := trustUser(in, req.Header.Get("Proxy-Authorization"))
		if req.Method != "CONNECT" || !authenticated || req.ProtoMajor == 1 {
			in.naiveFrontend.ServeHTTP(w, req)
			return
		}
	}
	if req.Method != "CONNECT" || req.ProtoMajor != 2 && !(in.Type == "naive" && req.ProtoMajor == 3) {
		w.WriteHeader(405)
		return
	}
	controller := http.NewResponseController(w)
	local, remote := httpStreamAddresses(req)
	conn := &httpStreamConn{reader: req.Body, writer: &flushingWriter{w: w, controller: controller}, local: local, remote: remote, readDeadline: controller.SetReadDeadline, writeDeadline: controller.SetWriteDeadline}
	conn.close = func() { req.Body.Close(); _ = controller.SetWriteDeadline(time.Now()) }
	defer req.Body.Close()
	respond := func(status int) error {
		if status == 407 {
			w.Header().Set("Proxy-Authenticate", `Basic realm="Lanboat"`)
		}
		w.WriteHeader(status)
		return controller.Flush()
	}
	if in.Type == "naive" {
		_, present := req.Header["Padding"]
		padded, reply, err := naivePaddingSelect(present, req.Header.Get("Padding-Type-Request"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if present {
			w.Header().Set("Padding", naiveHeader(true))
		}
		if reply != "" {
			w.Header().Set("Padding-Type-Reply", reply)
		}
		r.serveNaive(in, conn, req.Host, req.Header.Get("Proxy-Authorization"), padded, respond)
	} else {
		r.serveTrust(in, conn, req.Host, req.Header.Get("Proxy-Authorization"), respond)
	}
}
func (r *Runtime) serveTrust(in Inbound, conn net.Conn, authority, authorization string, respond func(int) error) {
	if r.trustStreams.Add(1) > 1024 {
		r.trustStreams.Add(-1)
		_ = respond(503)
		return
	}
	defer r.trustStreams.Add(-1)
	user, ok := trustUser(in, authorization)
	if !ok {
		_ = respond(407)
		return
	}
	q := request{origin: r.socketOrigin(conn.RemoteAddr(), conn.LocalAddr()), inbound: in.Tag, source: conn.RemoteAddr().String(), metadata: Metadata{AuthUser: user}, network: "tcp", address: authority}
	switch authority {
	case "_check":
		_ = respond(200)
		return
	case "_udp2", "_icmp":
		if respond(200) != nil {
			return
		}
		if authority == "_udp2" {
			_ = r.serveTrustUDP(conn, q)
		} else {
			_ = r.serveTrustICMP(conn, q)
		}
		return
	}
	if _, err := encodeAddress(authority); err != nil {
		_ = respond(400)
		return
	}
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		_ = respond(502)
		return
	}
	defer remote.Close()
	if respond(200) != nil {
		return
	}
	r.relay(conn, remote)
}
