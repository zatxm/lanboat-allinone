package native

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ControllerOptions struct {
	ExternalController               string   `json:"external_controller"`
	Secret                           string   `json:"secret,omitempty"`
	DefaultMode                      string   `json:"default_mode,omitempty"`
	AccessControlAllowOrigin         []string `json:"access_control_allow_origin,omitempty"`
	AccessControlAllowPrivateNetwork bool     `json:"access_control_allow_private_network,omitempty"`
	ReadOnly                         *bool    `json:"read_only,omitempty"`
}

func (c Config) controllerOptions() (*ControllerOptions, error) {
	o := c.Experimental.ClashAPI
	if c.ExternalController != "" || c.Secret != "" {
		if o != nil {
			return nil, errors.New("external_controller/secret conflict with experimental.clash_api")
		}
		o = &ControllerOptions{ExternalController: c.ExternalController, Secret: c.Secret, AccessControlAllowPrivateNetwork: true}
	}
	if o == nil {
		return nil, nil
	}
	host, port, err := net.SplitHostPort(o.ExternalController)
	n, e := strconv.Atoi(port)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || e != nil || n < 0 || n > 65535 || host != "" && host != "localhost" && ipErr != nil {
		return nil, errors.New("controller requires an IP or localhost and port0-65535")
	}
	if host != "localhost" && (!ip.IsValid() || !ip.Unmap().IsLoopback()) && o.Secret == "" {
		return nil, errors.New("a non-loopback controller requires a secret")
	}
	if len(o.Secret) > 4096 || strings.ContainsAny(o.Secret, "\x00\r\n") {
		return nil, errors.New("invalid controller secret")
	}
	if o.DefaultMode != "" && !slices.Contains([]string{"rule", "global", "direct"}, o.DefaultMode) {
		return nil, errors.New("controller default_mode must be rule,global or direct")
	}
	for _, origin := range o.AccessControlAllowOrigin {
		if origin == "*" {
			if o.Secret == "" {
				return nil, errors.New("wildcard controller origins require a secret")
			}
			continue
		}
		u, e := url.Parse(origin)
		if e != nil || u.Scheme != "http" && u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("invalid controller origin")
		}
	}
	return o, nil
}

type controller struct {
	r                                            *Runtime
	o                                            ControllerOptions
	ctx                                          context.Context
	cancel                                       context.CancelFunc
	listener                                     net.Listener
	server                                       *http.Server
	token                                        [32]byte
	mode                                         atomic.Uint32
	proxy, global                                atomic.Value
	virtualProxy, virtualGlobal, readOnly        bool
	directTag, blockTag                          string
	up, down, wireUp, wireDown, upRate, downRate atomic.Int64
	mu                                           sync.Mutex
	closed                                       bool
	inflight, streams                            int
	jobs                                         sync.WaitGroup
	flows                                        map[string]*controllerConn
	history                                      map[string]*controllerHistory
	historyOrder                                 []string
	logs                                         map[chan controllerLog]struct{}
	// logMu guards logs separately from mu so broadcasting log entries does
	// not contend with per-connection tracking.
	logMu      sync.Mutex
	logReaders atomic.Int32
	probes     chan struct{}
	logLevel   zapcore.Level
}

func newController(r *Runtime, o ControllerOptions) *controller {
	ctx, cancel := context.WithCancel(r.ctx)
	c := &controller{r: r, o: o, ctx: ctx, cancel: cancel, token: sha256.Sum256([]byte(o.Secret)), flows: map[string]*controllerConn{}, history: map[string]*controllerHistory{}, logs: map[chan controllerLog]struct{}{}, probes: make(chan struct{}, 8)}
	_, hasProxy := r.outbounds["PROXY"]
	_, hasGlobal := r.outbounds["GLOBAL"]
	c.virtualProxy, c.virtualGlobal = !hasProxy, !hasGlobal
	c.proxy.Store(r.config.Route.Final)
	c.global.Store("PROXY")
	if !c.virtualGlobal {
		c.global.Store("GLOBAL")
	}
	c.setMode(o.DefaultMode)
	server, client := false, false
	for _, in := range r.config.Inbounds {
		server = server || in.Type == "sudoku"
		client = client || in.Type == "mixed" || in.Type == "socks" || in.Type == "http"
	}
	for _, out := range r.config.Outbounds {
		client = client || out.Type == "sudoku"
	}
	c.logLevel = zapcore.InfoLevel
	if r.config.Log.Level != "" {
		if level, err := parseLogLevel(r.config.Log.Level); err == nil {
			c.logLevel = level
		}
	}
	c.readOnly = server && !client
	if o.ReadOnly != nil {
		c.readOnly = *o.ReadOnly
	}
	if c.readOnly {
		c.setMode("rule")
	}
	add := func(kind string) string {
		tag := "@lanboat-controller-" + kind
		for r.outbounds[tag].Type != "" {
			tag += "#"
		}
		r.outbounds[tag] = Outbound{Type: kind, Tag: tag}
		return tag
	}
	c.directTag, c.blockTag = add("direct"), add("block")
	return c
}

func (c *controller) modeName() string { return [...]string{"rule", "global", "direct"}[c.mode.Load()] }
func (c *controller) setMode(mode string) {
	switch mode {
	case "global", "proxy":
		c.mode.Store(1)
	case "direct":
		c.mode.Store(2)
	default:
		c.mode.Store(0)
	}
}

func (c *controller) start() error {
	l, err := net.Listen("tcp", c.o.ExternalController)
	if err != nil {
		return fmt.Errorf("controller: %w", err)
	}
	c.listener = l
	c.server = &http.Server{Handler: http.HandlerFunc(c.serve), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 64 << 10, BaseContext: func(net.Listener) context.Context { return c.ctx }, ErrorLog: zap.NewStdLog(c.r.logger)}
	c.r.workers.Add(2)
	go func() { defer c.r.workers.Done(); _ = c.server.Serve(l) }()
	go func() {
		defer c.r.workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		beforeUp, beforeDown := c.totals()
		before := time.Now()
		for {
			select {
			case <-c.ctx.Done():
				return
			case now := <-ticker.C:
				up, down := c.totals()
				seconds := now.Sub(before).Seconds()
				c.upRate.Store(int64(float64(up-beforeUp) / seconds))
				c.downRate.Store(int64(float64(down-beforeDown) / seconds))
				beforeUp, beforeDown, before = up, down, now
			}
		}
	}()
	return nil
}

func (c *controller) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.cancel()
	flows := make([]*controllerConn, 0, len(c.flows))
	for _, flow := range c.flows {
		flows = append(flows, flow)
	}
	c.mu.Unlock()
	if c.server != nil {
		_ = c.server.Close()
	}
	for _, flow := range flows {
		flow.Close()
	}
	c.jobs.Wait()
}

func (r *Runtime) ControllerAddress() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.controller == nil || r.controller.listener == nil {
		return ""
	}
	return r.controller.listener.Addr().String()
}

func (c *controller) originAllowed(req *http.Request) bool {
	origin := req.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	if c.o.Secret == "" && !strings.EqualFold(u.Host, req.Host) {
		return slices.Contains(c.o.AccessControlAllowOrigin, origin)
	}
	return len(c.o.AccessControlAllowOrigin) == 0 || slices.Contains(c.o.AccessControlAllowOrigin, "*") || slices.Contains(c.o.AccessControlAllowOrigin, origin)
}

func controllerWS(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") && headerToken(req.Header.Get("Connection"), "upgrade")
}

func (c *controller) serve(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if c.o.Secret == "" {
		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		ip, err := netip.ParseAddr(host)
		if !strings.EqualFold(host, "localhost") && (err != nil || !ip.Unmap().IsLoopback()) {
			controllerError(w, 403, "Forbidden")
			return
		}
	}
	if !c.originAllowed(req) {
		controllerError(w, 403, "Forbidden")
		return
	}
	if origin := req.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	if req.Method == "OPTIONS" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "300")
		if c.o.AccessControlAllowPrivateNetwork && req.Header.Get("Access-Control-Request-Private-Network") == "true" {
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
		}
		w.WriteHeader(204)
		return
	}
	if c.o.Secret != "" {
		token := ""
		auth := req.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && len(req.Header.Values("Authorization")) == 1 {
			token = strings.TrimPrefix(auth, "Bearer ")
		}
		if token == "" && controllerWS(req) && req.Method == http.MethodGet && (slices.Contains([]string{"/traffic", "/memory", "/logs"}, req.URL.Path) || req.URL.Path == "/connections" && !c.readOnly || req.URL.Path == "/users" && c.readOnly) {
			token = req.URL.Query().Get("token")
		}
		hash := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(hash[:], c.token[:]) != 1 {
			controllerError(w, 401, "Unauthorized")
			return
		}
	}
	c.mu.Lock()
	if c.closed || c.inflight >= 32 {
		c.mu.Unlock()
		controllerError(w, 503, "Busy")
		return
	}
	c.inflight++
	c.jobs.Add(1)
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.inflight--; c.mu.Unlock(); c.jobs.Done() }()
	path := req.URL.Path
	if req.Method == "GET" {
		switch path {
		case "/":
			controllerJSON(w, map[string]any{"hello": "mihomo"})
			return
		case "/version":
			controllerJSON(w, map[string]any{"meta": true, "version": "lanboat " + Version})
			return
		case "/traffic", "/memory", "/logs":
			c.stream(w, req, path)
			return
		case "/users":
			if c.readOnly {
				if controllerWS(req) {
					c.stream(w, req, path)
				} else {
					controllerJSON(w, c.users())
				}
				return
			}
		}
	}
	if slices.Contains([]string{"/", "/version", "/traffic", "/memory", "/logs"}, path) {
		w.WriteHeader(405)
		return
	}
	if c.readOnly {
		http.NotFound(w, req)
		return
	}
	c.serveClient(w, req)
}

func controllerJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = json.NewEncoder(w).Encode(v)
}
func controllerError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}
func controllerBody(w http.ResponseWriter, req *http.Request, v any, limit int64) error {
	response := http.NewResponseController(w)
	_ = response.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer response.SetReadDeadline(time.Time{})
	d := json.NewDecoder(http.MaxBytesReader(w, req.Body, limit))
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("extra JSON data")
	}
	return nil
}
func controllerMemory() uint64 {
	samples := [2]metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(samples[:])
	return samples[0].Value.Uint64() - samples[1].Value.Uint64()
}
func (c *controller) totals() (int64, int64) {
	if c.readOnly {
		up, down := c.wireUp.Load(), c.wireDown.Load()
		for _, registry := range c.r.sudokuUsers {
			for _, user := range registry.all {
				up += int64(user.up.Load())
				down += int64(user.down.Load())
			}
		}
		return up, down
	}
	return c.up.Load(), c.down.Load()
}
func (c *controller) users() any {
	users := c.r.SudokuUserStats()
	var active int
	var up, down uint64
	for _, stat := range users {
		if stat.Conns > 0 {
			active++
		}
		up += stat.Up
		down += stat.Down
	}
	return map[string]any{"count": len(users), "active": active, "up": up, "down": down, "users": users}
}

func (c *controller) stream(w http.ResponseWriter, req *http.Request, path string) {
	interval := time.Second
	if raw := req.URL.Query().Get("interval"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > 60000 {
			controllerError(w, 400, "Body invalid")
			return
		}
		interval = time.Duration(max(n, 100)) * time.Millisecond
	}
	level := zapcore.InfoLevel
	if path == "/logs" {
		switch req.URL.Query().Get("level") {
		case "", "info":
		case "debug":
			level = zapcore.DebugLevel
		case "warning", "warn":
			level = zapcore.WarnLevel
		case "error":
			level = zapcore.ErrorLevel
		case "silent":
			level = zapcore.FatalLevel + 1
		default:
			controllerError(w, 400, "Body invalid")
			return
		}
	}
	ws := controllerWS(req)
	if ws {
		key := req.Header.Get("Sec-WebSocket-Key")
		raw, err := base64.StdEncoding.DecodeString(key)
		if req.ProtoMajor != 1 || req.Header.Get("Sec-WebSocket-Version") != "13" || err != nil || len(raw) != 16 || req.ContentLength > 0 || len(req.TransferEncoding) > 0 {
			controllerError(w, 400, "Body invalid")
			return
		}
	}
	c.mu.Lock()
	if c.streams >= 16 {
		c.mu.Unlock()
		controllerError(w, 503, "Busy")
		return
	}
	c.streams++
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.streams--; c.mu.Unlock() }()
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	var write func(any) error
	if ws {
		raw, buf, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer raw.Close()
		stop := context.AfterFunc(ctx, func() { raw.Close() })
		defer stop()
		_ = raw.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, err = fmt.Fprintf(buf, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n", websocketAccept(req.Header.Get("Sec-WebSocket-Key")))
		if err == nil {
			err = buf.Flush()
		}
		if err != nil {
			return
		}
		conn := &websocketConn{Conn: &controllerWriteDeadlineConn{Conn: &bufferedConn{Conn: raw, reader: buf.Reader}}}
		readDone := make(chan struct{})
		defer func() { raw.Close(); <-readDone }()
		go func() {
			defer close(readDone)
			defer cancel()
			buf := make([]byte, 256)
			for {
				if _, err := conn.Read(buf); err != nil {
					return
				}
			}
		}()
		write = func(v any) error {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			_ = raw.SetWriteDeadline(time.Now().Add(10 * time.Second))
			return conn.writeFrame(1, b)
		}
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("X-Accel-Buffering", "no")
		response := http.NewResponseController(w)
		write = func(v any) error {
			_ = response.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := json.NewEncoder(w).Encode(v); err != nil {
				return err
			}
			return response.Flush()
		}
	}
	if path == "/logs" {
		ch := make(chan controllerLog, 256)
		c.logMu.Lock()
		c.logs[ch] = struct{}{}
		c.logReaders.Add(1)
		c.logMu.Unlock()
		defer func() { c.logMu.Lock(); delete(c.logs, ch); c.logReaders.Add(-1); c.logMu.Unlock() }()
		structured := req.URL.Query().Get("format") == "structured"
		if !ws {
			response := http.NewResponseController(w)
			_ = response.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if response.Flush() != nil {
				return
			}
		}
		for {
			select {
			case <-ctx.Done():
				return
			case entry := <-ch:
				if entry.level < level {
					continue
				}
				var v any = map[string]any{"type": entry.levelName(), "payload": entry.message}
				if structured {
					v = map[string]any{"time": entry.at.Format("15:04:05"), "level": entry.level.String(), "message": entry.message, "fields": []any{}}
				}
				if write(v) != nil {
					return
				}
			}
		}
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		up, down := c.totals()
		var value any
		switch path {
		case "/traffic":
			value = map[string]any{"up": c.upRate.Load(), "down": c.downRate.Load(), "upTotal": up, "downTotal": down}
		case "/memory":
			value = map[string]any{"inuse": controllerMemory(), "oslimit": 0}
		case "/connections":
			value = c.connections()
		case "/users":
			value = c.users()
		}
		if write(value) != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type controllerLog struct {
	at      time.Time
	level   zapcore.Level
	message string
}

func (e controllerLog) levelName() string {
	if e.level == zapcore.WarnLevel {
		return "warning"
	}
	return e.level.String()
}

type controllerLogCore struct{ c *controller }

func (l *controllerLogCore) Enabled(level zapcore.Level) bool {
	return !l.c.r.config.Log.Disabled && l.c.logReaders.Load() > 0 && level >= l.c.logLevel
}
func (l *controllerLogCore) With([]zapcore.Field) zapcore.Core { return l }
func (l *controllerLogCore) Check(e zapcore.Entry, check *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if l.Enabled(e.Level) {
		return check.AddCore(e, l)
	}
	return check
}
func (l *controllerLogCore) Sync() error { return nil }
func (l *controllerLogCore) Write(e zapcore.Entry, _ []zapcore.Field) error {
	message := e.Message
	if e.LoggerName != "" {
		message = withLogTag(message, e.LoggerName)
	}
	if len(message) > 4096 {
		message = message[:4096]
	}
	message = strings.ToValidUTF8(message, "�")
	if strings.Contains(message, "\x1b[") {
		var plain strings.Builder
		for i := 0; i < len(message); i++ {
			if message[i] == '\x1b' && i+1 < len(message) && message[i+1] == '[' {
				i += 2
				for i < len(message) && (message[i] < 0x40 || message[i] > 0x7e) {
					i++
				}
			} else {
				plain.WriteByte(message[i])
			}
		}
		message = plain.String()
	}
	entry := controllerLog{e.Time, e.Level, message}
	l.c.logMu.Lock()
	defer l.c.logMu.Unlock()
	for ch := range l.c.logs {
		select {
		case ch <- entry:
		default:
		}
	}
	return nil
}

// Control replies also need a fresh deadline after an idle log subscription.
type controllerWriteDeadlineConn struct{ net.Conn }

func (c *controllerWriteDeadlineConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return c.Conn.Write(p)
}
