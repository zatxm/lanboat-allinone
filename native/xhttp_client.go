package native

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type xHTTPClient struct {
	r        *Runtime
	o        Outbound
	up, down *xHTTPPool
}
type xHTTPPool struct {
	r                                          *Runtime
	o                                          Outbound
	cfg                                        *tls.Config
	version                                    int
	mu                                         sync.Mutex
	entries                                    []*xHTTPEntry
	notify                                     chan struct{}
	concurrency, connections, reuses, requests int
	lifetime                                   time.Duration
}
type xHTTPEntry struct {
	pool                     *xHTTPPool
	transport                *http.Transport
	active, reused, requests int
	until                    time.Time
	retired                  bool
	mu                       sync.Mutex
	closed                   bool
	physical                 map[net.Conn]bool
	quic                     *quicConn
}
type xPhysicalConn struct {
	net.Conn
	e    *xHTTPEntry
	once sync.Once
}

func (c *xPhysicalConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.e.mu.Lock(); delete(c.e.physical, c); c.e.mu.Unlock() })
	return e
}
func (c *xPhysicalConn) ConnectionState() tls.ConnectionState {
	if t, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return t.ConnectionState()
	}
	return tls.ConnectionState{}
}
func newXHTTPPool(r *Runtime, o Outbound) (*xHTTPPool, error) {
	cfg, e := o.TLS.config(false, o.Server)
	if e != nil {
		return nil, e
	}
	x := o.Transport.XMux
	p := &xHTTPPool{r: r, o: o, cfg: cfg, version: o.Transport.xhttpVersion(o.TLS), notify: make(chan struct{})}
	if x.defaults() {
		p.concurrency = xRange("").pick(16, 32)
		p.requests = xRange("").pick(600, 900)
		p.lifetime = time.Duration(xRange("").pick(1800, 3000)) * time.Second
	} else {
		p.concurrency = x.MaxConcurrency.pick(0, 0)
		p.connections = x.MaxConnections.pick(0, 0)
		p.requests = x.HMaxRequestTimes.pick(0, 0)
		p.reuses = x.CMaxReuseTimes.pick(0, 0)
		p.lifetime = time.Duration(x.HMaxReusableSecs.pick(0, 0)) * time.Second
	}
	if p.version == 1 {
		p.concurrency = 1
	} else if p.concurrency == 0 || p.concurrency > 32 {
		// Split modes consume two HTTP streams per flow; leave room for
		// uploads instead of filling the peer's stream limit with GETs.
		p.concurrency = 32
	}
	return p, nil
}
func newXHTTPClient(r *Runtime, o Outbound) (*xHTTPClient, error) {
	c := &xHTTPClient{r: r, o: o}
	var e error
	c.up, e = newXHTTPPool(r, o)
	if e != nil {
		return nil, e
	}
	c.down = c.up
	x := o.Transport.XHTTPOptions
	if x.DownloadTargetHost != "" || x.DownloadTargetPort != 0 || x.DownloadServerName != "" || x.DownloadHTTPHost != "" || x.DownloadTLS != nil {
		d := o
		if x.DownloadTargetHost != "" {
			d.Server = x.DownloadTargetHost
		}
		if x.DownloadTargetPort != 0 {
			d.ServerPort = x.DownloadTargetPort
		}
		if x.DownloadTLS != nil {
			d.TLS = *x.DownloadTLS
		}
		if x.DownloadServerName != "" {
			d.TLS.ServerName = x.DownloadServerName
		}
		if x.DownloadHTTPHost != "" {
			d.Transport.Host = x.DownloadHTTPHost
		}
		c.down, e = newXHTTPPool(r, d)
	}
	return c, e
}
func (c *xHTTPClient) reset() {
	c.up.reset()
	if c.down != c.up {
		c.down.reset()
	}
}
func (p *xHTTPPool) reset() {
	p.mu.Lock()
	entries := p.entries
	p.entries = nil
	close(p.notify)
	p.notify = make(chan struct{})
	p.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
}
func (e *xHTTPEntry) close() {
	e.mu.Lock()
	e.closed = true
	list := make([]net.Conn, 0, len(e.physical))
	for c := range e.physical {
		list = append(list, c)
	}
	q := e.quic
	e.mu.Unlock()
	for _, c := range list {
		c.Close()
	}
	if q != nil {
		q.Close()
	}
	if e.transport != nil {
		e.transport.CloseIdleConnections()
	}
}
func (p *xHTTPPool) acquire(ctx context.Context) (*xHTTPEntry, error) {
	for {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if e := p.r.ctx.Err(); e != nil {
			return nil, net.ErrClosed
		}
		p.mu.Lock()
		var chosen *xHTTPEntry
		live := 0
		retired := make([]*xHTTPEntry, 0)
		kept := p.entries[:0]
		for _, e := range p.entries {
			if !e.until.IsZero() && time.Now().After(e.until) || p.reuses > 0 && e.reused >= p.reuses || p.requests > 0 && e.requests >= p.requests {
				e.retired = true
			}
			if e.retired && e.active == 0 {
				retired = append(retired, e)
				continue
			}
			kept = append(kept, e)
			if e.retired {
				continue
			}
			live++
			if (p.concurrency == 0 || e.active < p.concurrency) && (chosen == nil || e.active < chosen.active) {
				chosen = e
			}
		}
		p.entries = kept
		if p.connections > 0 && live < p.connections {
			chosen = nil
		}
		if chosen == nil && (p.connections == 0 || live < p.connections) {
			chosen = &xHTTPEntry{pool: p, physical: map[net.Conn]bool{}}
			if p.lifetime > 0 {
				chosen.until = time.Now().Add(p.lifetime)
			}
			if p.version != 3 {
				chosen.transport = p.httpTransport(chosen)
			}
			p.entries = append(p.entries, chosen)
		}
		if chosen != nil {
			chosen.active++
			chosen.reused++
			p.mu.Unlock()
			for _, old := range retired {
				old.close()
			}
			return chosen, nil
		}
		notify := p.notify
		p.mu.Unlock()
		for _, old := range retired {
			old.close()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-p.r.ctx.Done():
			return nil, net.ErrClosed
		case <-notify:
		}
	}
}
func (e *xHTTPEntry) release() {
	p := e.pool
	p.mu.Lock()
	e.active--
	remove := e.active == 0 && (e.retired || p.version == 1)
	if remove {
		for i, item := range p.entries {
			if item == e {
				p.entries = append(p.entries[:i], p.entries[i+1:]...)
				break
			}
		}
	}
	close(p.notify)
	p.notify = make(chan struct{})
	p.mu.Unlock()
	if remove {
		e.close()
	}
}
func (p *xHTTPPool) httpTransport(entry *xHTTPEntry) *http.Transport {
	t := p.r.newHTTPTransport(p.o)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(p.version == 1)
	protocols.SetHTTP2(p.version == 2)
	t.Protocols = protocols
	t.MaxConnsPerHost = 1
	if p.version == 1 {
		t.MaxConnsPerHost = 2
	}
	t.DisableCompression = true
	dial := func(ctx context.Context, secured bool) (net.Conn, error) {
		conn, e := p.r.endpoint(ctx, p.o, "tcp")
		if e != nil {
			return nil, e
		}
		if secured {
			cfg, e := prepareClientTLS(ctx, p.cfg, p.o.TLS, p.r.resolver)
			if e != nil {
				conn.Close()
				return nil, e
			}
			cfg = cloneTLSConfig(cfg)
			alpn := "http/1.1"
			if p.version == 2 {
				alpn = "h2"
			}
			cfg.NextProtos = []string{alpn}
			tlsConn, e := handshakeTLS(ctx, conn, cfg, p.o.TLS)
			if e != nil {
				conn.Close()
				return nil, e
			}
			if p.version == 2 && tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
				conn.Close()
				return nil, errors.New("XHTTP peer did not negotiate h2")
			}
			conn = tlsConn
		}
		if p.version == 2 {
			health := p.o.Transport
			period := health.XMux.HKeepAlivePeriod
			if period == 0 {
				period = 45
			}
			if period > 0 {
				health.IdleTimeout = (time.Duration(period) * time.Second).String()
				health.PingTimeout = "15s"
				conn = httpHealthConnection(conn, health)
			}
		}
		tracked := &xPhysicalConn{Conn: conn, e: entry}
		entry.mu.Lock()
		if entry.closed {
			entry.mu.Unlock()
			conn.Close()
			return nil, net.ErrClosed
		}
		entry.physical[tracked] = true
		entry.mu.Unlock()
		return tracked, nil
	}
	t.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, false) }
	t.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, true) }
	return t
}

type xReleaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *xReleaseBody) Close() error { e := b.ReadCloser.Close(); b.once.Do(b.release); return e }
func (e *xHTTPEntry) roundTrip(req *http.Request) (*http.Response, error) {
	p := e.pool
	p.mu.Lock()
	move := e.retired || p.requests > 0 && e.requests >= p.requests || !e.until.IsZero() && time.Now().After(e.until)
	if move {
		e.retired = true
	} else {
		e.requests++
	}
	p.mu.Unlock()
	if move {
		next, err := p.acquire(req.Context())
		if err != nil {
			return nil, err
		}
		response, err := next.roundTrip(req)
		if err != nil {
			next.release()
			return nil, err
		}
		response.Body = &xReleaseBody{ReadCloser: response.Body, release: next.release}
		return response, nil
	}
	if p.version == 3 {
		return e.roundTripH3(req)
	}
	return e.transport.RoundTrip(req)
}
func xSessionID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	s := hex.EncodeToString(b[:])
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}
func (c *xHTTPClient) dial(ctx context.Context) (net.Conn, error) {
	up, e := c.up.acquire(ctx)
	if e != nil {
		return nil, e
	}
	down := up
	if c.down != c.up {
		down, e = c.down.acquire(ctx)
		if e != nil {
			up.release()
			return nil, e
		}
	}
	x := c.o.Transport.XHTTPOptions.normalized()
	mode := x.Mode
	if mode == "auto" {
		mode = "packet-up"
		if c.up.version == 2 {
			mode = "stream-up"
		}
	}
	if mode == "stream-one" && c.down != c.up {
		up.release()
		down.release()
		return nil, errors.New("XHTTP stream-one cannot split upload and download")
	}
	call, cancel := context.WithCancel(c.r.ctx)
	reader := &httpResponseBody{ready: make(chan struct{})}
	var writer io.Writer
	var closeWriter func() error
	var uploadReader *io.PipeReader
	var uploadWriter *io.PipeWriter
	session := xSessionID()
	if mode == "stream-one" {
		session = ""
	}
	if mode == "packet-up" {
		packet := &xPacketWriter{client: c, entry: up, ctx: call, session: session, options: x}
		writer = packet
		closeWriter = packet.CloseWrite
	} else {
		uploadReader, uploadWriter = io.Pipe()
		writer = uploadWriter
		closeWriter = uploadWriter.Close
	}
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			cancel()
			if uploadWriter != nil {
				uploadWriter.Close()
				uploadReader.Close()
			}
			reader.Close()
			up.release()
			if down != up {
				down.release()
			}
		})
	}
	requestPool := down
	var body io.Reader
	if mode == "stream-one" {
		requestPool = up
		body = uploadReader
	}
	req, e := x.request(call, requestPool.pool.o, c.o.Transport.xhttpPath(), session, nil, body)
	if e != nil {
		close(reader.ready)
		closeAll()
		return nil, e
	}
	go func() {
		defer close(reader.ready)
		reader.response, reader.err = requestPool.roundTrip(req)
		if reader.err == nil && reader.response.StatusCode != 200 {
			reader.err = errors.New("XHTTP download rejected: " + reader.response.Status)
		}
		if reader.err != nil {
			cancel()
			if uploadWriter != nil {
				uploadWriter.CloseWithError(reader.err)
			}
		}
	}()
	if mode == "stream-up" {
		request, e := x.request(call, c.o, c.o.Transport.xhttpPath(), session, nil, uploadReader)
		if e != nil {
			closeAll()
			return nil, e
		}
		go func() {
			response, e := up.roundTrip(request)
			if e == nil {
				if response.StatusCode != 200 {
					e = errors.New("XHTTP upload rejected: " + response.Status)
				} else {
					_, e = io.Copy(io.Discard, response.Body)
				}
				response.Body.Close()
			}
			if e != nil && call.Err() == nil {
				uploadWriter.CloseWithError(e)
				cancel()
			}
		}()
	}
	conn := &httpStreamConn{reader: reader, writer: writer, closeWrite: closeWriter, close: closeAll, local: streamAddr("xhttp-client"), remote: streamAddr(c.o.Server)}
	if e = ctx.Err(); e != nil {
		conn.Close()
		return nil, e
	}
	return conn, nil
}

type xPacketWriter struct {
	client   *xHTTPClient
	entry    *xHTTPEntry
	ctx      context.Context
	session  string
	options  XHTTPOptions
	mu       sync.Mutex
	sequence uint64
	last     time.Time
	closed   bool
}

func (w *xPacketWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, net.ErrClosed
	}
	n := 0
	for len(data) > 0 {
		size := min(len(data), w.options.ScMaxEachPostBytes.pick(1000000, 1000000))
		if w.options.UplinkDataPlacement != "body" {
			size = min(size, 24<<10)
			if lower, upper, _ := w.options.UplinkChunkSize.bounds(0, 0); upper > 0 {
				size = min(size, max(1, lower)*128*3/4)
			}
		}
		if !w.last.IsZero() {
			delay := time.Duration(w.options.ScMinPostsIntervalMs.pick(30, 30))*time.Millisecond - time.Since(w.last)
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-w.ctx.Done():
					timer.Stop()
					return n, w.ctx.Err()
				}
			}
		}
		req, e := w.options.request(w.ctx, w.client.o, w.client.o.Transport.xhttpPath(), w.session, &w.sequence, nil)
		if e != nil {
			return n, e
		}
		req.Method = w.options.UplinkHTTPMethod
		w.options.putData(req, data[:size])
		w.last = time.Now()
		response, e := w.entry.roundTrip(req)
		if e != nil {
			return n, e
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 65537))
		response.Body.Close()
		if response.StatusCode != 200 {
			return n, errors.New("XHTTP packet upload rejected: " + response.Status)
		}
		if readErr != nil {
			return n, readErr
		}
		w.sequence++
		n += size
		data = data[size:]
	}
	return n, nil
}
func (w *xPacketWriter) CloseWrite() error { w.mu.Lock(); w.closed = true; w.mu.Unlock(); return nil }
