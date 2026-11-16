package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func cloakWSRead(conn net.Conn) ([]byte, error) {
	ws, ok := conn.(*websocketConn)
	if !ok {
		return nil, errors.New("Cloak requires a WebSocket message transport")
	}
	b := make([]byte, cloakWireLimit)
	n := 0
	for {
		if n == len(b) {
			return nil, errors.New("Cloak WebSocket message exceeds limit")
		}
		size, e := ws.Read(b[n:])
		n += size
		if e != nil {
			return nil, e
		}
		ws.readMu.Lock()
		done := ws.remaining == 0 && !ws.fragmented
		ws.readMu.Unlock()
		if done {
			return b[:n], nil
		}
	}
}
func (r *Runtime) dialCloakLink(ctx context.Context, node Outbound, session uint32) (link *cloakLink, key [32]byte, err error) {
	o := node.plugin.cloak
	if o.server != "" {
		node.Server = o.server
	}
	if o.port != 0 {
		node.ServerPort = o.port
	}
	raw, e := r.endpoint(ctx, node, "tcp")
	if e != nil {
		err = e
		return
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	deadline := time.Now().Add(handshakeTimeout)
	if d, exists := ctx.Deadline(); exists && d.Before(deadline) {
		deadline = d
	}
	raw.SetDeadline(deadline)
	public, encrypted, shared, e := o.auth(session)
	if e != nil {
		err = e
		return
	}
	host := o.host
	if host == "" {
		host = node.Server
	}
	if len(o.names) > 0 {
		var random [1]byte
		rand.Read(random[:])
		host = o.names[int(random[0])%len(o.names)]
	}
	if o.mode == "direct" {
		if err = writeAll(raw, cloakClientHello(o.browser, host, public, encrypted)); err != nil {
			return
		}
		key, err = cloakDirectReply(raw, encrypted[:32], shared)
		if err != nil {
			return
		}
		link = &cloakLink{Conn: raw}
	} else {
		tlsOptions := o.tls
		tlsOptions.Enabled = true
		sni := o.sni
		if sni == "" {
			sni = tlsOptions.ServerName
		}
		if sni == "" {
			sni = host
		}
		tlsOptions.ServerName = sni
		cfg, e := tlsOptions.config(false, sni)
		if e != nil {
			err = e
			return
		}
		node.TLS = tlsOptions
		if node.echDynamic() && node.DomainResolver != "" {
			child, cancel := node.DomainResolver.apply(ctx)
			defer cancel()
			ctx = context.WithValue(child, dnsBootstrapKey{}, node.DomainResolver.tag())
		}
		cfg, e = prepareClientTLS(ctx, cfg, tlsOptions, r.resolver)
		if e != nil {
			err = e
			return
		}
		cfg = cfg.Clone()
		cfg.NextProtos = []string{"http/1.1"}
		secured := clientTLS(raw, cfg, tlsOptions)
		if err = secured.HandshakeContext(ctx); err != nil {
			return
		}
		httpHost := o.origin
		if httpHost == "" {
			httpHost = host
		}
		token := base64.StdEncoding.EncodeToString(append(append([]byte(nil), public...), encrypted...))
		conn, e := dialTransport(secured, Outbound{Server: node.Server, Transport: Transport{Type: "ws", Path: o.path, Host: httpHost, Headers: map[string]headerValues{"Hidden": {token}}}})
		if e != nil {
			err = e
			return
		}
		reply, e := cloakWSRead(conn)
		if e != nil {
			err = e
			return
		}
		key, err = cloakReplyKey(reply, shared)
		if err != nil {
			return
		}
		link = &cloakLink{Conn: conn, websocket: true}
	}
	if err = raw.SetDeadline(time.Time{}); err != nil {
		return
	}
	ok = true
	return
}

type cloakClient struct {
	r       *Runtime
	o       Outbound
	mu      sync.Mutex
	session *smuxSession
}

func (p *cloakClient) dial(ctx context.Context) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if p.session != nil {
		p.session.mu.Lock()
		closed := p.session.err != nil
		p.session.mu.Unlock()
		if closed {
			p.session = nil
		}
	}
	if p.session == nil {
		var id [4]byte
		rand.Read(id[:])
		session := binary.BigEndian.Uint32(id[:])
		options := p.o.plugin.cloak
		links := make([]*cloakLink, options.connections)
		keys := make([][32]byte, options.connections)
		failures := make([]error, options.connections)
		var work sync.WaitGroup
		child, cancel := context.WithCancel(ctx)
		defer cancel()
		for i := range links {
			work.Go(func() {
				links[i], keys[i], failures[i] = p.r.dialCloakLink(child, p.o, session)
				if failures[i] != nil {
					cancel()
				}
			})
		}
		work.Wait()
		var err error
		for i, e := range failures {
			if e != nil {
				err = e
			}
			if i > 0 && subtle.ConstantTimeCompare(keys[i][:], keys[0][:]) != 1 {
				err = errors.New("Cloak server returned different session keys")
			}
		}
		if err != nil {
			for _, l := range links {
				if l != nil {
					l.Close()
				}
			}
			return nil, err
		}
		transport, e := newCloakMux(p.r, keys[0], options.encryption, links)
		if e != nil {
			for _, l := range links {
				l.Close()
			}
			return nil, e
		}
		p.session = newMuxConfigured(p.r.ctx, transport, true, muxSMUX, 1, 0, true)
		go cloakExpiry(p.session, transport, options.timeout)
	}
	return p.session.open(ctx)
}
func (p *cloakClient) reset() {
	p.mu.Lock()
	s := p.session
	p.session = nil
	p.mu.Unlock()
	if s != nil {
		s.close(net.ErrClosed)
	}
}
func cloakExpiry(s *smuxSession, c *cloakMuxConn, timeout time.Duration) {
	interval := 10 * time.Second
	if timeout > 0 {
		interval = min(interval, timeout)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			c.mu.Lock()
			var ids []uint32
			for id, state := range c.states {
				if timeout > 0 && now.Sub(state.active) >= timeout {
					ids = append(ids, id)
				}
			}
			c.mu.Unlock()
			for _, id := range ids {
				s.mu.Lock()
				stream := s.streams[id]
				s.mu.Unlock()
				if stream != nil {
					stream.Close()
				}
			}
			s.mu.Lock()
			idle := len(s.streams) == 0 && now.Sub(time.Unix(0, s.idleAt.Load())) >= 30*time.Second
			s.mu.Unlock()
			if idle {
				s.close(net.ErrClosed)
				return
			}
		case <-s.done:
			return
		}
	}
}

type cloakServer struct {
	r        *Runtime
	mu       sync.Mutex
	sessions map[uint32]*cloakServerSession
}
type cloakServerSession struct {
	owner     *cloakServer
	in        Inbound
	id        uint32
	method    byte
	key       [32]byte
	transport *cloakMuxConn
	mu        sync.Mutex
	session   *smuxSession
	done      chan struct{}
	admitted  int
}

func (s *cloakServer) get(in Inbound, identity cloakIdentity) (*cloakServerSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	g := s.sessions[identity.id]
	if g == nil {
		if len(s.sessions) >= 32 {
			return nil, errors.New("Cloak session capacity reached")
		}
		g = &cloakServerSession{owner: s, in: in, id: identity.id, method: identity.method, done: make(chan struct{})}
		rand.Read(g.key[:])
		transport, e := newCloakMux(s.r, g.key, g.method, nil)
		if e != nil {
			return nil, e
		}
		g.transport = transport
		s.sessions[identity.id] = g
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.method != identity.method || g.admitted >= 8 || g.transport.ctx.Err() != nil {
		return nil, errors.New("Cloak session parameters or capacity rejected")
	}
	g.admitted++
	return g, nil
}
func (g *cloakServerSession) attach(link *cloakLink, source string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e := g.transport.addLink(link); e != nil {
		return e
	}
	if g.session == nil {
		g.session = newMuxConfigured(g.owner.r.ctx, g.transport, false, muxSMUX, 1, 0, true)
		go g.run(source)
		go cloakExpiry(g.session, g.transport, g.in.plugin.cloak.timeout)
	}
	return nil
}
func (g *cloakServerSession) run(source string) {
	s := g.session
	in := g.in
	in.SIP003Options = SIP003Options{}
	in.Transport = Transport{}
	var work sync.WaitGroup
	defer func() {
		s.close(net.ErrClosed)
		work.Wait()
		g.owner.mu.Lock()
		if g.owner.sessions[g.id] == g {
			delete(g.owner.sessions, g.id)
		}
		g.owner.mu.Unlock()
		close(g.done)
	}()
	for {
		select {
		case stream := <-s.accept:
			work.Go(func() {
				defer stream.Close()
				stream.SetDeadline(time.Now().Add(handshakeTimeout))
				_ = g.owner.r.serveProtocol(in, stream, source)
			})
		case <-s.done:
			return
		}
	}
}
func (s *cloakServer) reset() {
	s.mu.Lock()
	groups := make([]*cloakServerSession, 0, len(s.sessions))
	for _, g := range s.sessions {
		groups = append(groups, g)
	}
	s.sessions = map[uint32]*cloakServerSession{}
	s.mu.Unlock()
	for _, g := range groups {
		g.mu.Lock()
		session := g.session
		g.mu.Unlock()
		if session != nil {
			session.close(net.ErrClosed)
			<-g.done
		} else {
			g.transport.Close()
		}
	}
}
func (s *cloakServer) failed(g *cloakServerSession) {
	s.mu.Lock()
	g.mu.Lock()
	g.admitted--
	remove := g.admitted == 0 && g.session == nil
	if remove && s.sessions[g.id] == g {
		delete(s.sessions, g.id)
	}
	g.mu.Unlock()
	s.mu.Unlock()
	if remove {
		g.transport.Close()
	}
}
func (r *Runtime) cloakFallback(c net.Conn, o *cloakOptions, wire []byte, cause error) error {
	if o.redirect == "" {
		return cause
	}
	ctx, cancel := context.WithTimeout(r.ctx, handshakeTimeout)
	defer cancel()
	to, e := r.direct(ctx, "tcp", o.redirect)
	if e != nil {
		return e
	}
	defer to.Close()
	stop := context.AfterFunc(ctx, func() { c.Close(); to.Close() })
	defer stop()
	to.SetDeadline(time.Now().Add(handshakeTimeout))
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	if e = writeAll(to, wire); e != nil {
		return e
	}
	r.relay(c, to)
	return nil
}
func (r *Runtime) serveCloak(in Inbound, raw net.Conn, source string) error {
	if r.cloakHandshakes.Add(1) > 64 {
		r.cloakHandshakes.Add(-1)
		return errors.New("Cloak handshake capacity reached")
	}
	handshaking := true
	defer func() {
		if handshaking {
			r.cloakHandshakes.Add(-1)
		}
	}()
	o := in.plugin.cloak
	var conn net.Conn = raw
	if cfg := r.serverTLS[in.Tag]; cfg != nil {
		cfg = cfg.Clone()
		cfg.NextProtos = []string{"http/1.1"}
		secured := serverTLSConnection(raw, cfg, in.TLS)
		if e := secured.HandshakeContext(r.ctx); e != nil {
			return e
		}
		conn = secured
	}
	reader := bufio.NewReader(conn)
	c := &bufferedConn{Conn: conn, reader: reader}
	first, e := reader.Peek(1)
	if e != nil {
		return e
	}
	var public, encrypted, session, wire []byte
	var request *http.Request
	direct := first[0] == 22
	if direct {
		var capture bytes.Buffer
		_, hello, e := shadowHello(io.TeeReader(c, &capture))
		wire = capture.Bytes()
		if e != nil {
			return r.cloakFallback(c, o, wire, e)
		}
		var share []byte
		public, session, share, e = cloakHelloFields(hello, false)
		if e != nil {
			return r.cloakFallback(c, o, wire, e)
		}
		encrypted = append(append([]byte(nil), session...), share...)
	} else {
		wire, e = readHTTPHeader(reader)
		if e != nil {
			return e
		}
		request, e = http.ReadRequest(bufio.NewReader(bytes.NewReader(wire)))
		if e != nil {
			return r.cloakFallback(c, o, wire, e)
		}
		if request.Method != "GET" || request.URL.RequestURI() != o.path || len(request.Header.Values("Hidden")) != 1 || !headerToken(request.Header.Get("Connection"), "upgrade") || !strings.EqualFold(request.Header.Get("Upgrade"), "websocket") || request.Header.Get("Sec-WebSocket-Version") != "13" || request.ContentLength > 0 || len(request.TransferEncoding) > 0 || o.origin != "" && !strings.EqualFold(request.Host, o.origin) {
			return r.cloakFallback(c, o, wire, errors.New("invalid Cloak WebSocket upgrade"))
		}
		token, e := base64.StdEncoding.DecodeString(request.Header.Get("Hidden"))
		if e != nil || len(token) != 96 {
			return r.cloakFallback(c, o, wire, errors.New("invalid Cloak WebSocket authentication"))
		}
		public, encrypted = token[:32], token[32:]
	}
	identity, e := o.authenticate(public, encrypted)
	if e != nil {
		return r.cloakFallback(c, o, wire, e)
	}
	if e = r.replay.claimFor("cloak/"+in.Tag+string(public), 7*time.Minute); e != nil {
		return r.cloakFallback(c, o, wire, e)
	}
	server := r.cloakServers[in.Tag]
	g, e := server.get(in, identity)
	if e != nil {
		return e
	}
	attached := false
	defer func() {
		if !attached {
			server.failed(g)
		}
	}()
	reply := cloakReply(g.key, identity.shared)
	link := &cloakLink{Conn: c}
	if direct {
		if e = writeAll(c, cloakServerHello(session, reply)); e != nil {
			return e
		}
	} else {
		key := request.Header.Get("Sec-WebSocket-Key")
		decoded, e := base64.StdEncoding.DecodeString(key)
		if e != nil || len(decoded) != 16 {
			return errors.New("invalid Cloak WebSocket key")
		}
		if e = writeAll(c, []byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: "+websocketAccept(key)+"\r\n\r\n")); e != nil {
			return e
		}
		ws := &websocketConn{Conn: c}
		if _, e = ws.Write(reply); e != nil {
			return e
		}
		link = &cloakLink{Conn: ws, websocket: true}
	}
	if e = conn.SetDeadline(time.Time{}); e != nil {
		return e
	}
	if e = g.attach(link, source); e != nil {
		return e
	}
	attached = true
	r.cloakHandshakes.Add(-1)
	handshaking = false
	select {
	case <-g.done:
		return nil
	case <-r.ctx.Done():
		return net.ErrClosed
	}
}
