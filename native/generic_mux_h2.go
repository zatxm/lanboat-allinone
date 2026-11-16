package native

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type genericH2Client struct {
	wire      net.Conn
	transport *http.Transport
	ctx       context.Context
	closed    atomic.Bool
}

func newGenericH2Client(ctx context.Context, wire net.Conn) *genericH2Client {
	s := &genericH2Client{wire: wire, ctx: ctx}
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	var dialed atomic.Bool
	s.transport = &http.Transport{Protocols: protocols, DisableCompression: true, MaxConnsPerHost: 1, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: handshakeTimeout, MaxResponseHeaderBytes: 16384,
		HTTP2: &http.HTTP2Config{StrictMaxConcurrentRequests: true, MaxReceiveBufferPerConnection: 1 << 20, MaxReceiveBufferPerStream: 128 << 10, WriteByteTimeout: handshakeTimeout},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if s.closed.Load() || dialed.Swap(true) {
				return nil, net.ErrClosed
			}
			return &genericH2Wire{Conn: wire, onClose: func() { s.closed.Store(true) }}, nil
		}}
	return s
}
func (s *genericH2Client) dead() bool { return s.closed.Load() }
func (s *genericH2Client) close(error) {
	s.closed.Store(true)
	s.wire.Close()
	s.transport.CloseIdleConnections()
}
func (s *genericH2Client) open(ctx context.Context) (net.Conn, error) {
	if s.dead() {
		return nil, net.ErrClosed
	}
	child, cancel := context.WithCancel(s.ctx)
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	reader, writer := io.Pipe()
	req, _ := http.NewRequestWithContext(child, http.MethodConnect, "http://localhost", reader)
	req.Header.Set("User-Agent", "")
	body := &httpResponseBody{ready: make(chan struct{})}
	go func() {
		body.response, body.err = s.transport.RoundTrip(req)
		if body.err == nil && body.response.StatusCode != http.StatusOK {
			body.err = errors.New("h2mux CONNECT rejected")
		}
		close(body.ready)
		if body.err != nil {
			reader.CloseWithError(body.err)
			writer.CloseWithError(body.err)
		}
	}()
	c := &httpStreamConn{reader: body, writer: writer, closeWrite: writer.Close, local: s.wire.LocalAddr(), remote: s.wire.RemoteAddr()}
	c.close = func() { cancel(); reader.Close(); writer.Close(); body.Close() }
	if err := ctx.Err(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

type genericH2Wire struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (c *genericH2Wire) Close() error { err := c.Conn.Close(); c.once.Do(c.onClose); return err }

type genericH2Listener struct {
	wire  net.Conn
	given bool
	done  chan struct{}
	once  sync.Once
}

func (l *genericH2Listener) Accept() (net.Conn, error) {
	if !l.given {
		l.given = true
		return &genericH2Wire{Conn: l.wire, onClose: func() { l.Close() }}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *genericH2Listener) Close() error {
	l.once.Do(func() { close(l.done); l.wire.Close() })
	return nil
}
func (l *genericH2Listener) Addr() net.Addr { return l.wire.LocalAddr() }
func (r *Runtime) serveGenericH2(wire net.Conn, serve func(net.Conn)) error {
	listener := &genericH2Listener{wire: wire, done: make(chan struct{})}
	defer listener.Close()
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	var workers sync.WaitGroup
	var handlerMu sync.Mutex
	closing := false
	var active atomic.Int32
	server := &http.Server{Protocols: protocols, ReadHeaderTimeout: handshakeTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384, ErrorLog: zap.NewStdLog(r.logger.Named("h2mux")),
		HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 128, MaxReceiveBufferPerConnection: 1 << 20, MaxReceiveBufferPerStream: 128 << 10, WriteByteTimeout: handshakeTimeout},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			handlerMu.Lock()
			if closing {
				handlerMu.Unlock()
				return
			}
			workers.Add(1)
			handlerMu.Unlock()
			defer workers.Done()
			if req.Method != http.MethodConnect || req.ProtoMajor != 2 {
				http.Error(w, "CONNECT required", 405)
				return
			}
			if active.Add(1) > 128 {
				active.Add(-1)
				http.Error(w, "stream capacity exceeded", 503)
				return
			}
			defer active.Add(-1)
			controller := http.NewResponseController(w)
			w.WriteHeader(200)
			if controller.Flush() != nil {
				return
			}
			c := &httpStreamConn{reader: req.Body, writer: &flushingWriter{w: w, controller: controller}, local: wire.LocalAddr(), remote: wire.RemoteAddr(), readDeadline: controller.SetReadDeadline, writeDeadline: controller.SetWriteDeadline}
			c.close = func() { req.Body.Close(); controller.SetWriteDeadline(time.Now()) }
			serve(c)
			c.Close()
		})}
	stop := context.AfterFunc(r.ctx, func() { listener.Close() })
	defer stop()
	err := server.Serve(listener)
	server.Close()
	handlerMu.Lock()
	closing = true
	handlerMu.Unlock()
	workers.Wait()
	return err
}
