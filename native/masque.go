package native

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type MasqueOptions struct {
	nat                    *masqueNATSettings
	connection             *masqueConnectionSettings
	DNS                    []MasqueDNSConfiguration `json:"masque_dns,omitempty"`
	PREF64                 []netip.Prefix           `json:"masque_pref64,omitempty"`
	AcceptDNS              bool                     `json:"masque_accept_dns,omitempty"`
	DatagramContexts       bool                     `json:"masque_contexts,omitempty"`
	AcceptPREF64           bool                     `json:"masque_accept_pref64,omitempty"`
	MasquePublicKey        string                   `json:"public_key,omitempty"`
	Mode                   string                   `json:"masque_mode,omitempty"`
	URI                    string                   `json:"masque_uri,omitempty"`
	DisableVersionFallback bool                     `json:"disable_version_fallback,omitempty"`
	Headers                map[string]headerValues  `json:"masque_headers,omitempty"`
	endpoint               bool
	versions               []int
	routes                 []netip.Prefix
	serverAddress          []string
	reverse                bool
	onDemand               bool
	system                 bool
	interfaceName          string
	template               *masqueURITemplate
}

func (o MasqueOptions) mode() string {
	if o.Mode == "" {
		return "ip"
	}
	return o.Mode
}
func (o MasqueOptions) path() string {
	if o.template != nil {
		return o.template.wildcard
	}
	if o.URI != "" {
		return o.URI
	}
	return "/.well-known/masque/ip/*/*/"
}
func (o *MasqueOptions) validate(kind string, t TLSOptions, version, mtu int, local []string, server bool) error {
	if kind != "masque" {
		if o.DatagramContexts || o.Mode != "" || o.URI != "" || o.MasquePublicKey != "" || o.DisableVersionFallback || len(o.Headers) != 0 || o.DNS != nil || o.PREF64 != nil || o.AcceptDNS || o.AcceptPREF64 {
			return errors.New("MASQUE options require masque type")
		}
		return nil
	}
	if o.mode() != "ip" && o.mode() != "udp" {
		return errors.New("masque_mode must be ip or udp")
	}
	if (o.DNS != nil || o.PREF64 != nil || o.AcceptDNS || o.AcceptPREF64) && o.mode() != "ip" {
		return errors.New("MASQUE DNS/PREF64 requires IP mode")
	}
	if server && (o.AcceptDNS || o.AcceptPREF64) || !server && (o.DNS != nil || o.PREF64 != nil) {
		return errors.New("MASQUE servers advertise DNS/PREF64;clients explicitly accept it")
	}
	if _, err := masqueDNSBytes(o.DNS); err != nil {
		return err
	}
	if _, err := masquePREF64Bytes(o.PREF64); err != nil {
		return err
	}
	if version < 0 || version > 3 || (version == 0 || version == 3) && !t.Enabled {
		return errors.New("MASQUE requires HTTP version1-3 and TLS for HTTP3")
	}
	if !t.Enabled && !reflect.ValueOf(t).IsZero() {
		return errors.New("MASQUE TLS options require enabled TLS")
	}
	if err := validateMasqueHeaders(o.Headers); err != nil {
		return err
	}
	alpn := "h3"
	if version == 1 {
		alpn = "http/1.1"
	} else if version == 2 {
		alpn = "h2"
	}
	if version == 0 || version == 3 {
		if e := t.validateQUICVersion(); e != nil {
			return e
		}
	} else if t.MinVersion == "1.0" || t.MinVersion == "1.1" || t.MaxVersion == "1.0" || t.MaxVersion == "1.1" {
		return errors.New("MASQUE requires TLS1.2 or newer")
	}
	if len(t.ALPN) > 0 && !slices.Contains(t.ALPN, alpn) {
		return errors.New("MASQUE ALPN must include " + alpn)
	}
	if o.mode() == "udp" && o.URI != "" {
		return errors.New("masque_uri configures CONNECT-IP only")
	}
	var err error
	if o.template, err = compileMasqueURI(o.URI); err != nil {
		return err
	}
	if mtu != 0 && (mtu < 1280 || mtu > 65535) {
		return errors.New("MASQUE MTU must be1280-65535")
	}
	for _, v := range local {
		p, e := netip.ParsePrefix(v)
		if e != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().Zone() != "" {
			return errors.New("invalid MASQUE local_address")
		}
	}
	return nil
}

type masqueClient struct {
	nat      *masqueNAT
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	session  *masqueSession
	ip       atomic.Pointer[masqueIP]
	wake     chan struct{}
	paused   bool
}

func (c *masqueClient) reset() {
	c.mu.Lock()
	m := c.session
	c.session = nil
	c.ip.Store(nil)
	c.mu.Unlock()
	if m != nil {
		m.close()
		m.workers.Wait()
	}
}
func (c *masqueClient) ensure(ctx context.Context, version int) (*masqueSession, error) {
	if m := c.session; m != nil {
		select {
		case <-m.done:
			c.session = nil
			c.ip.Store(nil)
		default:
			return m, nil
		}
	}
	if version == 1 || version == 2 {
		m := newMasqueHTTPSession(c.runtime.ctx)
		m.version = version
		if version == 2 {
			m.http = c.runtime.newHTTPTransport(c.outbound)
			m.http.MaxConnsPerHost = 1
			c.outbound.connection.http2(m.http.HTTP2)
			if settings := c.outbound.connection; settings != nil && settings.idle >= 0 {
				m.http.IdleConnTimeout = settings.idle
			}
			m.http.HTTP2.MaxReadFrameSize = 16384
			dial := m.http.DialTLSContext
			if !c.outbound.TLS.Enabled {
				dial = m.http.DialContext
			}
			wrapped := func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, e := dial(ctx, network, address)
				if e != nil {
					return nil, e
				}
				return newMasqueHTTP2Client(conn, m.ctx), nil
			}
			if c.outbound.TLS.Enabled {
				m.http.DialTLSContext = wrapped
			} else {
				m.http.DialContext = wrapped
			}
		}
		c.session = m
		return m, nil
	}
	raw, e := c.runtime.endpoint(ctx, c.outbound, "udp")
	if e != nil {
		return nil, e
	}
	cfg, e := c.runtime.outboundTLS(ctx, c.outbound)
	if e != nil {
		raw.Close()
		return nil, e
	}
	cfg = masqueTLSConfig(cfg)
	cfg.NextProtos = []string{"h3"}
	q, e := dialQUIC(ctx, c.runtime.ctx, raw, cfg, c.outbound.connection.quic())
	if e != nil {
		return nil, e
	}
	m, e := newMasqueSession(q)
	if e != nil {
		return nil, e
	}
	m.version = 3
	m.start(nil)
	if e = m.waitSettings(ctx); e != nil {
		m.close()
		m.workers.Wait()
		return nil, e
	}
	c.session = m
	return m, nil
}
func (c *masqueClient) open(ctx context.Context, m *masqueSession, protocol, path, authority string) (*masqueFlow, error) {
	if m.q == nil {
		return c.openHTTP(ctx, m, protocol, path, authority)
	}
	s, e := m.q.OpenStream(ctx, false)
	if e != nil {
		return nil, e
	}
	f, e := m.flow(s)
	if e != nil {
		s.Close()
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { f.Close() })
	defer stop()
	if d, ok := ctx.Deadline(); ok {
		s.SetDeadline(d)
	}
	h := [][2]string{{":method", "CONNECT"}, {":authority", authority}}
	if protocol != "" {
		h = append(h, [2]string{":protocol", protocol}, [2]string{":scheme", "https"}, [2]string{":path", path})
	}
	for name, values := range c.outbound.Headers {
		if strings.EqualFold(name, "via") && strings.TrimSpace(strings.Join(values, "")) != "" {
			f.via = true
		}
		separator := ", "
		if strings.EqualFold(name, "cookie") {
			separator = "; "
		}
		h = append(h, [2]string{strings.ToLower(name), strings.Join(values, separator)})
	}
	h = append(h, [2]string{"proxy-authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(c.outbound.Username+":"+c.outbound.Password))})
	if protocol != "" {
		if c.outbound.DatagramContexts {
			h = append(h, [2]string{masqueContextsHeader, masqueContextsAdvertisement(protocol)})
		}
		h = append(h, [2]string{"capsule-protocol", "?1"}, [2]string{"authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(c.outbound.Username+":"+c.outbound.Password))})
	}
	if e = h3WriteFrame(s, 1, h3Encode(h)); e == nil {
		var headers map[string]string
		headers, e = h3Status(s)
		if e == nil {
			status, _ := strconv.Atoi(headers[":status"])
			if status < 200 || status > 299 {
				e = masqueStatusError(status)
			}
			f.via = f.via || strings.TrimSpace(headers["via"]) != ""
			if e == nil && (protocol == "connect-ip" || protocol == "connect-udp" && f.via) && headers["capsule-protocol"] != "?1" {
				e = errors.New("MASQUE response did not negotiate capsules")
			}
			f.capsules = protocol == "" || headers["capsule-protocol"] == "?1"
			if e == nil && c.outbound.DatagramContexts && protocol != "" && f.capsules {
				f.negotiateContexts(protocol, headers[masqueContextsHeader], false)
			}
		}
	}
	if e == nil {
		e = ctx.Err()
	}
	if e != nil {
		f.Close()
		return nil, e
	}
	s.SetDeadline(time.Time{})
	return f, nil
}
func (c *masqueClient) ipSession(ctx context.Context) (*masqueIP, error) {
	return c.ipSessionMode(ctx, false)
}
func (c *masqueClient) ipSessionMode(ctx context.Context, background bool) (*masqueIP, error) {
	if ref := c.outbound.DomainResolver; ref != "" {
		call, cancel := ref.apply(ctx)
		defer cancel()
		ctx = context.WithValue(call, dnsBootstrapKey{}, ref.tag())
	}
	// An endpoint cannot bootstrap its own hostname through its not-yet-created DNS tunnel.
	if c.outbound.AcceptDNS && c.outbound.DomainResolver == "" && c.runtime.config.Route.DefaultDomainResolver == "" && ctx.Value(dnsBootstrapKey{}) == nil {
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, "@local")
	}
	c.mu.Lock()
	if background && c.paused {
		c.mu.Unlock()
		return nil, errMasquePaused
	}
	if !background && c.paused {
		c.paused = false
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	p := c.ip.Load()
	if p == nil || p.flow.isClosed() {
		f, e := c.openSession(ctx, "connect-ip", c.outbound.path(), portAddress(c.outbound.Server, c.outbound.ServerPort))
		if e != nil {
			c.mu.Unlock()
			return nil, e
		}
		inbound := ""
		if len(c.outbound.routes) != 0 {
			inbound = c.outbound.Tag
		}
		p = newMasqueIP(c.runtime, f, inbound, false, c.outbound.MTU, nil, c.outbound.LocalAddress, "", c.outbound.routes, c.nat)
		p.client, p.acceptDNS, p.acceptPREF64 = c, c.outbound.AcceptDNS, c.outbound.AcceptPREF64
		if c.outbound.system {
			p.useSystem(nil)
		}
		c.ip.Store(p)
		p.start()
		if e = p.requestAddresses(); e != nil {
			f.Close()
			c.mu.Unlock()
			return nil, e
		}
		if e = p.advertiseClient(); e != nil {
			f.Close()
			c.mu.Unlock()
			return nil, e
		}
	}
	c.mu.Unlock()
	if e := p.waitAddress(ctx); e != nil {
		if background {
			p.flow.Close()
		}
		return nil, e
	}
	if c.outbound.system {
		if e := p.openSystem(); e != nil {
			p.flow.Close()
			return nil, e
		}
	}
	return p, nil
}
func (c *masqueClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if c.outbound.mode() == "ip" {
		p, e := c.ipSession(ctx)
		if e != nil {
			return nil, e
		}
		conn, e := p.stack.dial(ctx, network, address)
		if e != nil {
			return nil, e
		}
		return c.runtime.own(conn)
	}
	protocol, path, authority := "", "", address
	if network == "udp" {
		host, port, _ := net.SplitHostPort(address)
		protocol = "connect-udp"
		path = "/.well-known/masque/udp/" + url.PathEscape(host) + "/" + port + "/"
		authority = portAddress(c.outbound.Server, c.outbound.ServerPort)
	}
	c.mu.Lock()
	f, e := c.openSession(ctx, protocol, path, authority)
	c.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if network == "tcp" {
		return c.runtime.own(&masqueTCPConn{Conn: f.body, flow: f})
	}
	f.session.goWork(func() { _ = f.readCapsules() })
	return c.runtime.own(f)
}

type masqueTCPConn struct {
	net.Conn
	flow *masqueFlow
}

func (c *masqueTCPConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
func (c *masqueTCPConn) Close() error { return c.flow.Close() }
func (f *masqueFlow) isClosed() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.closed }
func (r *Runtime) serveMasque(in Inbound, q *quicConn) error {
	m, e := newMasqueSession(q)
	if e != nil {
		return e
	}
	defer func() { m.close(); m.workers.Wait() }()
	m.start(func(s *quicStream) { r.serveMasqueRequest(in, m, s) })
	<-q.done
	return q.err()
}
func (r *Runtime) serveMasqueRequest(in Inbound, m *masqueSession, s *quicStream) {
	s.SetDeadline(time.Now().Add(handshakeTimeout))
	ctx, cancel := context.WithTimeout(m.q.ctx, handshakeTimeout)
	defer cancel()
	if m.waitSettings(ctx) != nil {
		return
	}
	kind, b, e := h3ReadFrame(s)
	if e != nil || kind != 1 {
		return
	}
	h, e := h3Decode(b)
	if e != nil {
		return
	}
	respond := func(status int) error {
		headers := [][2]string{{":status", strconv.Itoa(status)}}
		if status == 200 && h[":protocol"] != "" {
			headers = append(headers, [2]string{"capsule-protocol", "?1"})
			if in.DatagramContexts {
				if value := masqueContextsResponse(h[":protocol"], h[masqueContextsHeader]); value != "" {
					headers = append(headers, [2]string{masqueContextsHeader, value})
				}
			}
		}
		if status == 407 {
			headers = append(headers, [2]string{"proxy-authenticate", `Basic realm="Lanboat"`})
		}
		e := h3WriteFrame(s, 1, h3Encode(headers))
		if status != 200 {
			_ = s.CloseWrite()
		}
		return e
	}
	r.serveMasqueConnect(in, m, s, &trustH3Conn{quicStream: s}, s.id, h, m.q.state, respond)
}
func (r *Runtime) serveMasqueConnect(in Inbound, m *masqueSession, stream, body net.Conn, id uint64, h map[string]string, state tls.ConnectionState, respond func(int) error) {
	var e error
	auth := h["authorization"]
	if auth == "" {
		auth = h["proxy-authorization"]
	}
	user, ok := trustUser(in, auth)
	if len(in.Users) == 0 && len(state.PeerCertificates) > 0 {
		ok = true
		user = state.PeerCertificates[0].Subject.CommonName
	}
	if in.endpoint && len(in.Users) == 0 && in.TLS.ClientAuthentication != "require-and-verify" {
		ok = true
	}
	if !ok {
		_ = respond(407)
		return
	}
	if h[":method"] != "CONNECT" {
		_ = respond(405)
		return
	}
	protocol := h[":protocol"]
	address := h[":authority"]
	if protocol == "" {
		if h[":path"] != "" || h[":scheme"] != "" {
			_ = respond(400)
			return
		}
		if _, e = encodeAddress(address); e != nil {
			_ = respond(400)
			return
		}
		remote, e := r.routeDial(m.ctx, request{origin: r.socketOrigin(stream.RemoteAddr(), stream.LocalAddr()), network: "tcp", inbound: in.Tag, address: address, source: stream.RemoteAddr().String(), metadata: Metadata{AuthUser: user}})
		if e != nil {
			_ = respond(502)
			return
		}
		defer remote.Close()
		stop := context.AfterFunc(m.ctx, func() { remote.Close() })
		defer stop()
		if respond(200) != nil {
			return
		}
		r.relay(body, remote)
		return
	}
	scheme := "http"
	if in.TLS.Enabled {
		scheme = "https"
	}
	if h[":scheme"] != scheme || h[":authority"] == "" || h["capsule-protocol"] != "?1" {
		_ = respond(400)
		return
	}
	var scope masqueScope
	var permitted []netip.Prefix
	if protocol == "connect-ip" {
		var status int
		scope, status = in.template.match(h[":path"])
		if status != 0 {
			_ = respond(status)
			return
		}
		ctx, cancel := context.WithTimeout(m.ctx, handshakeTimeout)
		permitted, e = scope.routes(ctx, r, in.routes, in.Address)
		cancel()
		if e != nil {
			status = 502
			if errors.Is(e, ErrRejected) {
				status = 403
			}
			_ = respond(status)
			return
		}
	} else if protocol == "connect-udp" {
		var e error
		address, e = masqueUDPTarget(h[":path"])
		if e != nil {
			_ = respond(400)
			return
		}
	} else {
		_ = respond(501)
		return
	}
	f, e := m.registerFlow(stream, id, body)
	if e != nil {
		_ = respond(503)
		return
	}
	defer f.Close()
	if in.DatagramContexts && masqueContextsResponse(protocol, h[masqueContextsHeader]) != "" {
		f.negotiateContexts(protocol, h[masqueContextsHeader], true)
	}
	// A QUIC hop's MTU says nothing about the far side of an HTTP intermediary.
	f.via = strings.TrimSpace(h["via"]) != ""
	stream.SetDeadline(time.Time{})
	if protocol == "connect-ip" {
		assigned, local := in.Address, []string(nil)
		server := r.masqueServers[in.Tag]
		if server != nil {
			assigned, e = server.allocate(f)
			if e != nil {
				_ = respond(503)
				return
			}
			defer server.remove(f)
			local = in.serverAddress
		}
		p := newMasqueIP(r, f, in.Tag, true, in.MTU, assigned, local, user, nil, serverNAT(server))
		p.permitted, p.scope = permitted, scope
		if in.system {
			p.useSystem(server.system)
		}
		if server != nil {
			server.attach(f, p)
		}
		p.networkServer = r.masqueNetworkServers[in.Tag]
		f.control = p.control
		if respond(200) != nil {
			return
		}
		p.start()
		if p.advertise() != nil {
			return
		}
		<-f.done
		return
	}
	remote, e := r.routeDial(m.ctx, request{origin: r.socketOrigin(stream.RemoteAddr(), stream.LocalAddr()), network: "udp", inbound: in.Tag, address: address, source: stream.RemoteAddr().String(), metadata: Metadata{AuthUser: user}})
	if e != nil {
		_ = respond(502)
		return
	}
	defer remote.Close()
	if respond(200) != nil {
		return
	}
	m.goWork(func() { _ = f.readCapsules() })
	stop := context.AfterFunc(m.ctx, func() { remote.Close() })
	defer stop()
	r.relayDatagrams(f, remote, r.udpTimeoutFor(in.Tag, udpTimeout))
}

func masqueUDPTarget(path string) (string, error) {
	parts := strings.Split(path, "/")
	if len(parts) != 7 || parts[0] != "" || parts[1] != ".well-known" || parts[2] != "masque" || parts[3] != "udp" || parts[6] != "" {
		return "", errors.New("invalid CONNECT-UDP path")
	}
	host, e := url.PathUnescape(parts[4])
	if e != nil || host == "" || strings.ContainsAny(host, "/%\x00\r\n") {
		return "", errors.New("invalid CONNECT-UDP host")
	}
	address := net.JoinHostPort(host, parts[5])
	if _, e = encodeAddress(address); e != nil {
		return "", e
	}
	return address, nil
}
