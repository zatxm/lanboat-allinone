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

const xHTTPBudget = 32 << 20

type xHTTPServer struct {
	r        *Runtime
	in       Inbound
	x        XHTTPOptions
	mu       sync.Mutex
	sessions map[string]*xHTTPSession
	buffered atomic.Int64
}

// ResponseController belongs to its handler; never retain a live controller
// after net/http has returned the response writer to its pool.
type xHTTPReadStop struct {
	mu         sync.Mutex
	controller *http.ResponseController
}

func (s *xHTTPReadStop) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controller != nil {
		_ = s.controller.SetReadDeadline(time.Now())
	}
}
func (s *xHTTPReadStop) detach() { s.mu.Lock(); s.controller = nil; s.mu.Unlock() }

type xHTTPSession struct {
	server                   *xHTTPServer
	id                       string
	mu                       sync.Mutex
	done, notify, uploadDone chan struct{}
	once, uploadOnce         sync.Once
	timer                    *time.Timer
	down, upload, packet     bool
	stream                   io.ReadCloser
	stopRead                 func()
	pending                  map[uint64][]byte
	next                     uint64
	current                  []byte
	currentSize              int
}

func newXHTTPServer(r *Runtime, in Inbound) *xHTTPServer {
	return &xHTTPServer{r: r, in: in, x: in.Transport.XHTTPOptions.normalized(), sessions: map[string]*xHTTPSession{}}
}
func (s *xHTTPServer) close() {
	s.mu.Lock()
	list := make([]*xHTTPSession, 0, len(s.sessions))
	for _, p := range s.sessions {
		list = append(list, p)
	}
	s.mu.Unlock()
	for _, p := range list {
		p.Close()
	}
}
func (s *xHTTPServer) session(id string) (*xHTTPSession, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	if p := s.sessions[id]; p != nil {
		return p, nil
	}
	if len(s.sessions) >= 512 {
		return nil, errors.New("XHTTP pending session limit reached")
	}
	p := &xHTTPSession{server: s, id: id, done: make(chan struct{}), notify: make(chan struct{}), uploadDone: make(chan struct{}), pending: map[uint64][]byte{}}
	s.sessions[id] = p
	p.timer = time.AfterFunc(30*time.Second, func() { p.Close() })
	return p, nil
}
func (p *xHTTPSession) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		close(p.done)
		if p.timer != nil {
			p.timer.Stop()
		}
		count := p.currentSize
		for _, b := range p.pending {
			count += len(b)
		}
		p.current = nil
		p.currentSize = 0
		p.pending = nil
		body, stop := p.stream, p.stopRead
		p.mu.Unlock()
		p.server.buffered.Add(-int64(count))
		if stop != nil {
			stop()
		}
		if body != nil {
			body.Close()
		}
		p.server.mu.Lock()
		if p.server.sessions[p.id] == p {
			delete(p.server.sessions, p.id)
		}
		p.server.mu.Unlock()
	})
	return nil
}
func (p *xHTTPSession) signal() { close(p.notify); p.notify = make(chan struct{}) }
func (p *xHTTPSession) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		p.mu.Lock()
		select {
		case <-p.done:
			p.mu.Unlock()
			return 0, net.ErrClosed
		default:
		}
		if p.stream != nil {
			body := p.stream
			p.mu.Unlock()
			n, e := body.Read(b)
			if e != nil {
				p.uploadOnce.Do(func() { close(p.uploadDone) })
			}
			return n, e
		}
		if len(p.current) == 0 {
			if packet, ok := p.pending[p.next]; ok {
				delete(p.pending, p.next)
				p.next++
				p.current = packet
				p.currentSize = len(packet)
				if len(packet) == 0 {
					p.mu.Unlock()
					continue
				}
			}
		}
		if len(p.current) > 0 {
			n := copy(b, p.current)
			p.current = p.current[n:]
			if len(p.current) == 0 {
				p.server.buffered.Add(-int64(p.currentSize))
				p.currentSize = 0
				p.current = nil
			}
			p.mu.Unlock()
			return n, nil
		}
		notify := p.notify
		p.mu.Unlock()
		select {
		case <-p.done:
			return 0, net.ErrClosed
		case <-notify:
		}
	}
}
func (p *xHTTPSession) packetBody(seq uint64, b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	if p.upload && !p.packet || seq < p.next || seq-p.next >= uint64(p.server.x.ScMaxBufferedPosts) || len(p.pending) >= p.server.x.ScMaxBufferedPosts {
		return errors.New("XHTTP sequence window exceeded")
	}
	if _, exists := p.pending[seq]; exists {
		return errors.New("duplicate XHTTP sequence")
	}
	p.packet, p.upload = true, true
	p.pending[seq] = b
	p.signal()
	return nil
}
func (s *xHTTPServer) packet(req *http.Request) ([]byte, error) {
	_, maxBytes, _ := s.x.ScMaxEachPostBytes.bounds(1000000, 1000000)
	if s.x.UplinkDataPlacement != "body" {
		b, e := s.x.dataHeaders(req, maxBytes)
		if e != nil {
			return nil, e
		}
		if s.buffered.Add(int64(len(b))) > xHTTPBudget {
			s.buffered.Add(-int64(len(b)))
			return nil, errors.New("XHTTP upload memory limit reached")
		}
		return b, nil
	}
	if req.ContentLength > int64(maxBytes) {
		return nil, errors.New("XHTTP packet exceeds maximum size")
	}
	var out []byte
	var buffer [16384]byte
	for {
		n, e := req.Body.Read(buffer[:])
		if n > 0 {
			if len(out)+n > maxBytes || s.buffered.Add(int64(n)) > xHTTPBudget {
				if len(out)+n <= maxBytes {
					s.buffered.Add(-int64(n))
				}
				s.buffered.Add(-int64(len(out)))
				return nil, errors.New("XHTTP packet/buffer limit reached")
			}
			out = append(out, buffer[:n]...)
		}
		if e == io.EOF {
			return out, nil
		}
		if e != nil {
			s.buffered.Add(-int64(len(out)))
			return nil, e
		}
	}
}
func (s *xHTTPServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.ProtoMajor < 1 || req.ProtoMajor > 3 || s.in.Transport.Host != "" && req.Host != s.in.Transport.Host || !s.x.checkPadding(req) {
		http.NotFound(w, req)
		return
	}
	id, seq, e := s.in.Transport.xhttpFields(req)
	if e != nil {
		http.NotFound(w, req)
		return
	}
	controller := http.NewResponseController(w)
	_ = controller.EnableFullDuplex()
	if req.Method == "OPTIONS" {
		s.headers(w.Header())
		w.WriteHeader(200)
		return
	}
	if seq != nil {
		if req.Method != s.x.UplinkHTTPMethod || s.x.Mode != "auto" && s.x.Mode != "packet-up" {
			http.NotFound(w, req)
			return
		}
		p, e := s.session(id)
		if e != nil {
			http.Error(w, "busy", 503)
			return
		}
		_ = controller.SetReadDeadline(time.Now().Add(handshakeTimeout))
		body, e := s.packet(req)
		_ = controller.SetReadDeadline(time.Time{})
		if e == nil {
			e = p.packetBody(*seq, body)
			if e != nil {
				s.buffered.Add(-int64(len(body)))
			}
		}
		if e != nil {
			p.Close()
			http.Error(w, "invalid upload", 400)
			return
		}
		s.headers(w.Header())
		w.WriteHeader(200)
		return
	}
	if req.Method == s.x.UplinkHTTPMethod && req.Method != "GET" && id != "" {
		if s.x.Mode != "auto" && s.x.Mode != "stream-up" {
			http.NotFound(w, req)
			return
		}
		p, e := s.session(id)
		if e != nil {
			http.Error(w, "busy", 503)
			return
		}
		p.mu.Lock()
		if p.upload {
			p.mu.Unlock()
			http.Error(w, "duplicate upload", 409)
			return
		}
		p.upload = true
		p.stream = req.Body
		readStop := &xHTTPReadStop{controller: controller}
		defer readStop.detach()
		p.stopRead = readStop.stop
		p.signal()
		p.mu.Unlock()
		s.headers(w.Header())
		interval := s.x.ScStreamUpServerSecs.pick(20, 80)
		if s.x.ScStreamUpServerSecs == "-1" {
			interval = 0
		}
		var ticks <-chan time.Time
		if interval > 0 {
			w.WriteHeader(200)
			if e = controller.Flush(); e != nil {
				p.Close()
				return
			}
			ticker := time.NewTicker(time.Duration(interval) * time.Second)
			defer ticker.Stop()
			ticks = ticker.C
		}
		for {
			select {
			case <-req.Context().Done():
				p.Close()
				return
			case <-s.r.ctx.Done():
				p.Close()
				return
			case <-p.done:
				return
			case <-p.uploadDone:
				return
			case <-ticks:
				if _, e = w.Write([]byte(xPadding(s.x.XPaddingBytes.pick(100, 1000), s.x.XPaddingMethod))); e != nil {
					p.Close()
					return
				}
				if e = controller.Flush(); e != nil {
					p.Close()
					return
				}
			}
		}
	}
	one := id == "" && req.Method == s.x.UplinkHTTPMethod
	if one {
		if s.x.Mode == "packet-up" {
			http.NotFound(w, req)
			return
		}
	} else if id == "" || req.Method != "GET" || s.x.Mode == "stream-one" {
		http.NotFound(w, req)
		return
	}
	var p *xHTTPSession
	if one {
		p, e = s.session(xSessionID())
		if e != nil {
			http.Error(w, "busy", 503)
			return
		}
		p.mu.Lock()
		p.timer.Stop()
		p.stream = req.Body
		p.stopRead = func() { _ = controller.SetReadDeadline(time.Now()) }
		p.mu.Unlock()
	} else {
		p, e = s.session(id)
		if e != nil {
			http.Error(w, "busy", 503)
			return
		}
		p.mu.Lock()
		if p.down {
			p.mu.Unlock()
			http.Error(w, "duplicate download", 409)
			return
		}
		p.down = true
		p.timer.Stop()
		p.mu.Unlock()
	}
	defer p.Close()
	s.r.mu.Lock()
	if s.r.closed {
		s.r.mu.Unlock()
		return
	}
	s.r.workers.Add(1)
	s.r.mu.Unlock()
	defer s.r.workers.Done()
	stopRuntime := context.AfterFunc(s.r.ctx, func() { p.Close() })
	defer stopRuntime()
	stopRequest := context.AfterFunc(req.Context(), func() { p.Close() })
	defer stopRequest()
	s.headers(w.Header())
	if !s.x.NoSSEHeader {
		w.Header().Set("Content-Type", "text/event-stream")
	}
	w.WriteHeader(200)
	if e = controller.Flush(); e != nil {
		return
	}
	var complete atomic.Bool
	local, remote := httpStreamAddresses(req)
	c := &httpStreamConn{reader: p, writer: &flushingWriter{w: w, controller: controller}, local: local, remote: remote, writeDeadline: controller.SetWriteDeadline, close: func() {
		p.Close()
		if !complete.Load() {
			_ = controller.SetWriteDeadline(time.Now())
		}
	}}
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	e = s.r.serveProtocol(s.in, c, req.RemoteAddr)
	if e == nil || errors.Is(e, io.EOF) {
		complete.Store(true)
	}
	if e != nil && !errors.Is(e, io.EOF) && s.r.ctx.Err() == nil {
		s.r.logger.Debug("XHTTP stream ended", zap.String("inbound", s.in.Tag), zap.Error(e))
	}
	c.Close()
}
func (s *xHTTPServer) headers(h http.Header) {
	h.Set("X-Accel-Buffering", "no")
	h.Set("Cache-Control", "no-store")
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	s.x.paddingResponse(h)
	for key, values := range s.in.Transport.Headers {
		for _, v := range values {
			h.Add(key, v)
		}
	}
}
