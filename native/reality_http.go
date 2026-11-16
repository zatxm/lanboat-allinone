package native

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type realityHTTPContext struct{}
type realityListener struct {
	net.Listener
	r   *Runtime
	in  Inbound
	tls *tls.Config
}

func (l *realityListener) Accept() (net.Conn, error) {
	raw, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &realityLazyConn{Conn: raw, listener: l}, nil
}

// Defer authentication to the HTTP connection's goroutine so a slow peer
// cannot block Accept. Close and deadlines always act on the raw socket.
type realityLazyConn struct {
	net.Conn
	listener *realityListener
	once     sync.Once
	secure   net.Conn
	err      error
}

func (c *realityLazyConn) initialize() error {
	c.once.Do(func() {
		c.Conn.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		c.secure, c.err = c.listener.r.realityAccept(c.listener.in, c.Conn, c.listener.tls)
		c.Conn.SetWriteDeadline(time.Time{})
		if c.err == nil && c.secure == nil {
			c.err = io.EOF
		}
	})
	return c.err
}
func (c *realityLazyConn) Read(b []byte) (int, error) {
	if err := c.initialize(); err != nil {
		return 0, err
	}
	return c.secure.Read(b)
}
func (c *realityLazyConn) Write(b []byte) (int, error) {
	if err := c.initialize(); err != nil {
		return 0, err
	}
	return c.secure.Write(b)
}

func (r *Runtime) realityHTTPServer(in Inbound, server *http.Server, listener net.Listener) net.Listener {
	server.Protocols.SetUnencryptedHTTP2(true)
	server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, realityHTTPContext{}, c)
	}
	handler := server.Handler
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		c := req.Context().Value(realityHTTPContext{}).(*realityLazyConn)
		state := c.secure.(tlsStream).ConnectionState()
		if state.NegotiatedProtocol == "h2" && req.ProtoMajor != 2 || state.NegotiatedProtocol == "http/1.1" && req.ProtoMajor != 1 {
			http.Error(w, "invalid negotiated protocol", 400)
			return
		}
		req.TLS = &state
		handler.ServeHTTP(w, req)
	})
	return &realityListener{Listener: listener, r: r, in: in, tls: server.TLSConfig}
}
