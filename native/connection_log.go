package native

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Connection log messages are constant so log processors can group them; the
// varying parts are fields.
const (
	logInboundConnection  = "inbound connection"
	logOutboundConnection = "outbound connection"
	logConnectionFailed   = "connection failed"
	logConnectionClosed   = "connection closed"
)

// ConnectionEvent identifies a connection lifecycle stage.
type ConnectionEvent uint8

const (
	ConnectionOpened ConnectionEvent = iota + 1
	ConnectionFailed
	ConnectionClosed
)

func (e ConnectionEvent) String() string {
	switch e {
	case ConnectionOpened:
		return "opened"
	case ConnectionFailed:
		return "failed"
	case ConnectionClosed:
		return "closed"
	}
	return "unknown"
}

// ConnectionLog describes a routed connection. Opened and Failed events are
// emitted once the route has been dialed; Closed carries the totals and is
// emitted for routed streams and UDP sessions only.
type ConnectionLog struct {
	Event ConnectionEvent
	// ID is shared by every event of one connection, including zap entries.
	ID          uint64
	Time        time.Time
	Network     string
	Inbound     string
	Source      string
	Destination string
	Domain      string
	Protocol    string
	Client      string
	ProcessName string
	ProcessPath string
	// SourceMACAddress and SourceHostname come from neighbor discovery.
	SourceMACAddress string
	SourceHostname   string
	// RouteOutbound is the routed tag; Outbound is the group member actually
	// used, or REJECT when a rule rejected the connection.
	RouteOutbound string
	Outbound      string
	// Rule describes the matched route rule, or "final" when none matched.
	Rule string
	// Elapsed is measured from inbound acceptance: the dial latency for Opened
	// and Failed, the lifetime for Closed.
	Elapsed          time.Duration
	Upload, Download int64
	Error            error
}

type connectionLogger struct {
	closed bool
	*logQueue[ConnectionLog]
}

// SetConnectionLogger receives connection events independently of the zap
// level, with the same ordering and drop policy as SetRequestLogger. Closed
// events are delivered only when closed is true, because tracking totals adds
// a wrapper to every routed connection.
func (r *Runtime) SetConnectionLogger(record func(ConnectionLog), closed bool) {
	r.logQueueMu.Lock()
	defer r.logQueueMu.Unlock()
	var next *connectionLogger
	if record != nil && !r.logQueuesClosed {
		next = &connectionLogger{closed: closed, logQueue: startLogQueue(r, record, &r.connectionLogDrops)}
	}
	if old := r.connectionLogger.Swap(next); old != nil {
		old.close()
	}
}

// ConnectionLogDrops reports connection events dropped because the callback fell behind.
func (r *Runtime) ConnectionLogDrops() uint64 { return r.connectionLogDrops.Load() }

func (r *Runtime) logInbound(q *request) {
	var entry *zapcore.CheckedEntry
	if !r.config.Log.Disabled {
		entry = r.logger.Check(zapcore.InfoLevel, logInboundConnection)
	}
	if entry == nil && r.connectionLogger.Load() == nil {
		return
	}
	q.logID = r.logSequence.Add(1)
	q.logStart = time.Now()
	if entry != nil {
		entry.Write(zap.Uint64("connection_id", q.logID), zap.String("network", q.network), zap.String("inbound", q.inbound), zap.String("source", q.source), zap.String("destination", q.address))
	}
}

func connectionLogLevel(err error) zapcore.Level {
	if err == nil {
		return zapcore.InfoLevel
	}
	if errors.Is(err, ErrRejected) || errors.Is(err, ErrDropped) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return zapcore.DebugLevel
	}
	return zapcore.ErrorLevel
}

// logConnection reports the routing result. With track it returns conn wrapped
// to report its close when anything consumes close events.
func (r *Runtime) logConnection(q request, tag string, conn net.Conn, err error, track bool) net.Conn {
	observer := r.connectionLogger.Load()
	logging := !r.config.Log.Disabled
	var entry *zapcore.CheckedEntry
	if logging {
		message := logOutboundConnection
		if err != nil {
			message = logConnectionFailed
		}
		entry = r.logger.Check(connectionLogLevel(err), message)
	}
	track = track && err == nil && conn != nil && (observer != nil && observer.closed || logging && r.logger.Core().Enabled(zapcore.DebugLevel))
	if entry == nil && observer == nil && !track {
		return conn
	}
	if q.logID == 0 {
		q.logID = r.logSequence.Add(1)
	}
	event := r.connectionEvent(&q, tag, conn, err)
	if entry != nil {
		entry.Write(event.fields()...)
	}
	if observer != nil {
		observer.push(event)
	}
	if track {
		return &connectionLogConn{Conn: conn, r: r, event: event, start: q.logStart}
	}
	return conn
}

func (r *Runtime) connectionEvent(q *request, tag string, conn net.Conn, err error) ConnectionLog {
	if tag == "" && (errors.Is(err, ErrRejected) || errors.Is(err, ErrDropped)) {
		tag = "REJECT"
	}
	selected := tag
	for conn != nil {
		switch v := conn.(type) {
		case *ownedConn:
			conn = v.Conn
		case *controllerConn:
			conn = v.Conn
		case *icmpErrorConn:
			conn = v.Conn
		case *groupConn:
			selected = v.member
			conn = v.Conn
		default:
			conn = nil
		}
	}
	if c := r.controller; c != nil {
		if selected == c.directTag {
			selected = "DIRECT"
		}
		if tag == c.directTag {
			tag = "DIRECT"
		}
	}
	if err != nil {
		// url.Error includes paths and queries; the transport cause is sufficient.
		var u *url.Error
		if errors.As(err, &u) {
			err = u.Err
		}
	}
	now := time.Now()
	var elapsed time.Duration
	if !q.logStart.IsZero() {
		elapsed = now.Sub(q.logStart)
	}
	m := &q.metadata
	kind := ConnectionOpened
	if err != nil {
		kind = ConnectionFailed
	}
	return ConnectionLog{
		Event: kind, ID: q.logID, Time: now, Network: q.network, Inbound: q.inbound, Source: q.source, Destination: q.address,
		Domain: m.Domain, Protocol: m.Protocol, Client: m.Client, ProcessName: m.ProcessName, ProcessPath: m.ProcessPath,
		SourceMACAddress: m.SourceMACAddress, SourceHostname: m.SourceHostname,
		RouteOutbound: tag, Outbound: selected, Rule: r.ruleLabel(q.logRule), Elapsed: elapsed, Error: err,
	}
}

func (e *ConnectionLog) fields() []zap.Field {
	fields := make([]zap.Field, 0, 20)
	fields = append(fields, zap.Uint64("connection_id", e.ID), zap.String("network", e.Network), zap.String("inbound", e.Inbound), zap.String("source", e.Source), zap.String("destination", e.Destination), zap.String("outbound", e.Outbound), zap.String("route_outbound", e.RouteOutbound))
	if e.Rule != "" {
		fields = append(fields, zap.String("rule", e.Rule))
	}
	fields = append(fields, zap.Int64("elapsed_ms", e.Elapsed.Milliseconds()))
	if e.Domain != "" {
		fields = append(fields, zap.String("domain", e.Domain))
	}
	if e.Protocol != "" {
		fields = append(fields, zap.String("protocol", e.Protocol))
	}
	if e.Client != "" {
		fields = append(fields, zap.String("client", e.Client))
	}
	if e.ProcessName != "" {
		fields = append(fields, zap.String("process_name", e.ProcessName), zap.String("process_path", e.ProcessPath))
	}
	if e.SourceMACAddress != "" {
		fields = append(fields, zap.String("source_mac_address", e.SourceMACAddress))
	}
	if e.SourceHostname != "" {
		fields = append(fields, zap.String("source_hostname", e.SourceHostname))
	}
	if e.Event == ConnectionClosed {
		fields = append(fields, zap.Int64("upload", e.Upload), zap.Int64("download", e.Download))
	}
	if e.Error != nil {
		fields = append(fields, zap.Error(e.Error))
	}
	return fields
}

// ruleLabels hold one short description per top-level route rule, built once
// so connection logs never format rules on the dial path.
func newRuleLabels(rules []Rule) []string {
	labels := make([]string, len(rules))
	for i, o := range rules {
		d := ruleDescription(o)
		payload := d.Payload
		if d.Type == "Rule" && payload != "" {
			// Unnamed conditions are summarized without the action fields.
			o.Action, o.Outbound = "", ""
			if b, err := json.Marshal(o); err == nil {
				payload = string(b)
			}
		}
		if len(payload) > 64 {
			payload = payload[:61] + "..."
		}
		labels[i] = "#" + strconv.Itoa(i) + " " + d.Type
		if payload != "" {
			labels[i] += "(" + payload + ")"
		}
	}
	return labels
}

// logRule values: 0 when routing did not evaluate rules, -1 when no rule
// matched, otherwise the matched rule index plus one.
func (r *Runtime) ruleLabel(rule int32) string {
	switch {
	case rule < 0:
		return "final"
	case rule > 0 && int(rule) <= len(r.ruleLabels):
		return r.ruleLabels[rule-1]
	}
	return ""
}

func (r *Runtime) logRule(q request, index int, o Rule) {
	if q.logID == 0 || r.config.Log.Disabled {
		return
	}
	if entry := r.logger.Check(zapcore.DebugLevel, "routing rule matched"); entry != nil {
		entry.Write(zap.Uint64("connection_id", q.logID), zap.Int("rule_index", index), zap.String("action", o.Action), zap.String("outbound", o.Outbound))
	}
}

// connectionLogConn reports a routed connection's totals once it closes.
type connectionLogConn struct {
	net.Conn
	r        *Runtime
	event    ConnectionLog
	start    time.Time
	up, down atomic.Int64
	failure  atomic.Pointer[error]
	once     sync.Once
}

func (c *connectionLogConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.count(false, n, err)
	return n, err
}
func (c *connectionLogConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.count(true, n, err)
	return n, err
}
func (c *connectionLogConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.report)
	return err
}
func (c *connectionLogConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

func (c *connectionLogConn) count(up bool, n int, err error) {
	if n > 0 {
		if up {
			c.up.Add(int64(n))
		} else {
			c.down.Add(int64(n))
		}
	}
	if err != nil {
		c.fail(err)
	}
}

// fail keeps the first error that ended the connection abnormally.
func (c *connectionLogConn) fail(err error) {
	if err == io.EOF || errors.Is(err, net.ErrClosed) {
		return
	}
	c.failure.CompareAndSwap(nil, &err)
}

func (c *connectionLogConn) report() {
	e := c.event
	e.Event = ConnectionClosed
	e.Time = time.Now()
	if !c.start.IsZero() {
		e.Elapsed = e.Time.Sub(c.start)
	}
	e.Upload, e.Download = c.up.Load(), c.down.Load()
	if err := c.failure.Load(); err != nil {
		e.Error = *err
	}
	if !c.r.config.Log.Disabled {
		if entry := c.r.logger.Check(zapcore.DebugLevel, logConnectionClosed); entry != nil {
			entry.Write(e.fields()...)
		}
	}
	if observer := c.r.connectionLogger.Load(); observer != nil && observer.closed {
		observer.push(e)
	}
}

type connectionLogUDP struct {
	owner *connectionLogConn
	inner addressedUDP
}

func (c *connectionLogUDP) readPacket(p []byte) (int, string, error) {
	n, address, err := c.inner.readPacket(p)
	c.owner.count(false, n, err)
	return n, address, err
}
func (c *connectionLogUDP) writePacket(p []byte, address string) (int, error) {
	n, err := c.inner.writePacket(p, address)
	c.owner.count(true, n, err)
	return n, err
}

// logText renders an entry as one human-readable line for Clash API log
// subscribers. Connection entries use the sing-box style "[id elapsed]" prefix.
func logText(message string, fields []zapcore.Field) string {
	var id, network, inbound, source, destination, domain, outbound, route, rule, failure string
	elapsed, upload, download := int64(-1), int64(-1), int64(-1)
	for _, f := range fields {
		switch f.Key {
		case "connection_id":
			id = strconv.FormatUint(uint64(f.Integer), 10)
		case "network":
			network = f.String
		case "inbound":
			inbound = f.String
		case "source":
			source = f.String
		case "destination":
			destination = f.String
		case "domain":
			domain = f.String
		case "outbound":
			outbound = f.String
		case "route_outbound":
			route = f.String
		case "rule":
			rule = f.String
		case "elapsed_ms":
			elapsed = f.Integer
		case "upload":
			upload = f.Integer
		case "download":
			download = f.Integer
		case "error":
			if err, ok := f.Interface.(error); ok && f.Type == zapcore.ErrorType && err != nil {
				failure = err.Error()
			} else if f.Type == zapcore.StringType {
				failure = f.String
			}
		}
	}
	var b strings.Builder
	if destination == "" {
		// Other fields may carry credentials; subscribers only get the cause.
		if id != "" {
			b.WriteString("[" + id + "] ")
		}
		b.WriteString(message)
		if failure != "" {
			b.WriteString(": ")
			b.WriteString(failure)
		}
		return b.String()
	}
	b.WriteString("[")
	b.WriteString(id)
	if elapsed >= 0 {
		b.WriteByte(' ')
		b.WriteString(logDuration(elapsed))
	}
	b.WriteString("] ")
	b.WriteString(message)
	b.WriteString(": ")
	b.WriteString(network)
	if inbound != "" {
		b.WriteByte(' ')
		b.WriteString(inbound)
	}
	if source != "" {
		b.WriteByte(' ')
		b.WriteString(source)
	}
	b.WriteString(" → ")
	b.WriteString(destination)
	if host, _, err := net.SplitHostPort(destination); domain != "" && (err != nil || host != domain) {
		b.WriteString(" (")
		b.WriteString(domain)
		b.WriteByte(')')
	}
	if route != "" {
		b.WriteString(" via ")
		b.WriteString(route)
		if outbound != "" && outbound != route {
			b.WriteByte('/')
			b.WriteString(outbound)
		}
	}
	if rule != "" {
		b.WriteString(" [")
		b.WriteString(rule)
		b.WriteByte(']')
	}
	if upload >= 0 {
		b.WriteString(" ↑")
		b.WriteString(logBytes(upload))
		b.WriteString(" ↓")
		b.WriteString(logBytes(download))
	}
	if failure != "" {
		b.WriteString(": ")
		b.WriteString(failure)
	}
	return b.String()
}

func logDuration(ms int64) string {
	switch d := time.Duration(ms) * time.Millisecond; {
	case d < time.Second:
		return strconv.FormatInt(ms, 10) + "ms"
	case d < time.Minute:
		return strconv.FormatFloat(d.Seconds(), 'f', 1, 64) + "s"
	default:
		return d.Round(time.Second).String()
	}
}

func logBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	value, suffix := float64(n)/unit, "KB"
	for _, next := range []string{"MB", "GB", "TB"} {
		if value < unit {
			break
		}
		value, suffix = value/unit, next
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + " " + suffix
}
