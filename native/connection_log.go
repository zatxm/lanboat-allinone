package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap/zapcore"
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
	// ID is shared by every event of one connection and matches the
	// "[id elapsed]" prefix of its log lines.
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
	// Rule is the matched route rule's condition in sing-box form, such as
	// "domain_suffix=example.com", or "final" when none matched.
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

// logPrefix is sing-box's "[id elapsed] " connection prefix.
func (q *request) logPrefix(now time.Time) string {
	if q.logStart.IsZero() {
		q.logStart = now
	}
	return "[" + strconv.FormatUint(q.logID, 10) + " " + formatLogDuration(now.Sub(q.logStart)) + "] "
}

// logRequest writes a connection-scoped entry: "[id elapsed] tag: parts: err".
func (r *Runtime) logRequest(q *request, level zapcore.Level, tag string, err error, parts ...string) {
	if q.logID == 0 || r.config.Log.Disabled {
		return
	}
	if entry := r.logger.Check(level, ""); entry != nil {
		entry.Message = q.logPrefix(time.Now()) + tag + ": " + joinLog(err, parts)
		entry.Write()
	}
}

func packetWord(network string) string {
	if network == "tcp" {
		return ""
	}
	return "packet "
}

func (r *Runtime) logInbound(q *request) {
	logging := !r.config.Log.Disabled && r.logger.Core().Enabled(zapcore.InfoLevel)
	if !logging && r.connectionLogger.Load() == nil {
		return
	}
	q.logID = r.logSequence.Add(1)
	q.logStart = time.Now()
	if !logging {
		return
	}
	tag, kind := r.inboundLabel(q.inbound), packetWord(q.network)
	if q.source != "" {
		r.logRequest(q, zapcore.InfoLevel, tag, nil, "inbound ", kind, "connection from ", q.source)
	}
	r.logRequest(q, zapcore.InfoLevel, tag, nil, "inbound ", kind, "connection to ", q.address)
}

func closedOrRejected(err error) bool {
	return errors.Is(err, ErrRejected) || errors.Is(err, ErrDropped) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)
}

// logConnection reports the routing result the way sing-box does: the chosen
// outbound announces the connection, router failures are logged by "router"
// and dial failures by "connection". With track it returns conn wrapped to
// report its close when anything consumes close events.
func (r *Runtime) logConnection(q request, tag string, conn net.Conn, err error, track bool) net.Conn {
	observer := r.connectionLogger.Load()
	logging := !r.config.Log.Disabled
	level := zapcore.InfoLevel
	if err != nil {
		level = zapcore.ErrorLevel
		if closedOrRejected(err) {
			level = zapcore.DebugLevel
		}
	}
	enabled := logging && r.logger.Core().Enabled(level)
	track = track && err == nil && conn != nil && (observer != nil && observer.closed || logging && r.logger.Core().Enabled(zapcore.DebugLevel))
	if !enabled && observer == nil && !track {
		return conn
	}
	if q.logID == 0 {
		q.logID = r.logSequence.Add(1)
	}
	event := r.connectionEvent(&q, tag, conn, err)
	if enabled {
		switch {
		case err == nil:
			r.logRequest(&q, level, r.outboundLabel(event.selected), nil, "outbound ", packetWord(q.network), "connection to ", q.address)
		case closedOrRejected(err):
			r.logRequest(&q, level, "router", event.Error, "connection closed")
		case tag == "":
			r.logRequest(&q, level, "router", event.Error)
		default:
			r.logRequest(&q, level, "connection", event.Error, "open outbound connection")
		}
	}
	if observer != nil {
		observer.push(event.ConnectionLog)
	}
	if track {
		return &connectionLogConn{Conn: conn, r: r, event: event.ConnectionLog, start: q.logStart}
	}
	return conn
}

type connectionEvent struct {
	ConnectionLog
	// selected is the internal tag of the outbound that carries the connection.
	selected string
}

func (r *Runtime) connectionEvent(q *request, tag string, conn net.Conn, err error) connectionEvent {
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
	routed, used := tag, selected
	if c := r.controller; c != nil {
		if used == c.directTag {
			used = "DIRECT"
		}
		if routed == c.directTag {
			routed = "DIRECT"
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
	if q.logStart.IsZero() {
		q.logStart = now
	}
	kind := ConnectionOpened
	if err != nil {
		kind = ConnectionFailed
	}
	m := &q.metadata
	return connectionEvent{selected: selected, ConnectionLog: ConnectionLog{
		Event: kind, ID: q.logID, Time: now, Network: q.network, Inbound: q.inbound, Source: q.source, Destination: q.address,
		Domain: m.Domain, Protocol: m.Protocol, Client: m.Client, ProcessName: m.ProcessName, ProcessPath: m.ProcessPath,
		SourceMACAddress: m.SourceMACAddress, SourceHostname: m.SourceHostname,
		RouteOutbound: routed, Outbound: used, Rule: r.ruleText(q.logRule), Elapsed: now.Sub(q.logStart), Error: err,
	}}
}

// ruleLog holds sing-box style descriptions of the top-level route rules,
// built once so routing never formats rules.
type ruleLog struct {
	condition string
	// match is the debug message "match[i] condition => action".
	match string
}

func newRuleLogs(rules []Rule) []ruleLog {
	logs := make([]ruleLog, len(rules))
	for i, o := range rules {
		condition := ruleCondition(o)
		logs[i] = ruleLog{condition: condition, match: "match[" + strconv.Itoa(i) + "] " + condition + " => " + ruleAction(o)}
	}
	return logs
}

// Rule fields that configure the action rather than select connections.
var ruleActionFields = map[string]bool{"override_address": true, "override_port": true, "sniffer": true, "timeout": true, "server": true, "strategy": true, "disable_cache": true, "disable_optimistic_cache": true, "rewrite_ttl": true, "client_subnet": true, "method": true, "no_drop": true, "type": true, "mode": true, "rules": true, "invert": true, "action": true, "outbound": true}

func ruleCondition(o Rule) string {
	var text string
	if o.Type == "logical" {
		op := " && "
		if o.Mode == "or" {
			op = " || "
		}
		parts := make([]string, len(o.Rules))
		for i, child := range o.Rules {
			parts[i] = ruleCondition(child)
		}
		text = "(" + strings.Join(parts, op) + ")"
	} else {
		var items []string
		v, t := reflect.ValueOf(o), reflect.TypeOf(o)
		for i := range t.NumField() {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if f.Anonymous || !f.IsExported() || name == "" || ruleActionFields[name] || v.Field(i).IsZero() {
				continue
			}
			items = append(items, ruleItem(name, v.Field(i)))
		}
		text = strings.Join(items, " ")
	}
	if o.Invert {
		return "!(" + text + ")"
	}
	return text
}

func ruleItem(name string, v reflect.Value) string {
	switch v.Kind() {
	case reflect.Bool:
		return name
	case reflect.Slice:
		if v.Len() == 1 {
			return name + "=" + fmt.Sprint(v.Index(0).Interface())
		}
		values := make([]string, v.Len())
		for i := range values {
			values[i] = fmt.Sprint(v.Index(i).Interface())
		}
		return name + "=[" + strings.Join(values, " ") + "]"
	case reflect.Pointer:
		return name + "=" + fmt.Sprint(v.Elem().Interface())
	}
	return name + "=" + fmt.Sprint(v.Interface())
}

func ruleAction(o Rule) string {
	switch o.Action {
	case "", "route":
		return "route(" + o.Outbound + ")"
	case "reject":
		if o.Method == "" || o.Method == "default" {
			return "reject"
		}
		return "reject(" + o.Method + ")"
	case "sniff":
		if len(o.Sniffer) == 0 {
			return "sniff"
		}
		return "sniff(" + strings.Join(o.Sniffer, ",") + ")"
	case "resolve":
		if o.Server == "" {
			return "resolve"
		}
		return "resolve(" + o.Server + ")"
	case "bypass":
		if o.Outbound == "" {
			return "bypass"
		}
		return "bypass(" + o.Outbound + ")"
	}
	return o.Action
}

// logRule values: 0 when routing did not evaluate rules, -1 when no rule
// matched, otherwise the matched rule index plus one.
func (r *Runtime) ruleText(rule int32) string {
	switch {
	case rule < 0:
		return "final"
	case rule > 0 && int(rule) <= len(r.ruleLogs):
		return r.ruleLogs[rule-1].condition
	}
	return ""
}

func (r *Runtime) logRule(q *request, index int) {
	if index < len(r.ruleLogs) {
		r.logRequest(q, zapcore.DebugLevel, "router", nil, r.ruleLogs[index].match)
	}
}

// logMetadata reports what routing discovered about the connection's origin.
func (r *Runtime) logMetadata(q *request) {
	m := &q.metadata
	if q.logID == 0 || m.ProcessPath == "" && m.ProcessName == "" && m.PackageName == "" && m.User == "" && m.UserID == nil && m.SourceMACAddress == "" && m.SourceHostname == "" {
		return
	}
	switch {
	case m.ProcessPath != "":
		r.logRequest(q, zapcore.InfoLevel, "router", nil, "found process path: ", m.ProcessPath)
	case m.ProcessName != "":
		r.logRequest(q, zapcore.InfoLevel, "router", nil, "found process name: ", m.ProcessName)
	}
	if m.PackageName != "" {
		r.logRequest(q, zapcore.InfoLevel, "router", nil, "found package name: ", m.PackageName)
	}
	if m.User != "" {
		r.logRequest(q, zapcore.InfoLevel, "router", nil, "found user: ", m.User)
	} else if m.UserID != nil {
		r.logRequest(q, zapcore.InfoLevel, "router", nil, "found user id: ", strconv.FormatUint(uint64(*m.UserID), 10))
	}
	if m.SourceMACAddress != "" {
		r.logRequest(q, zapcore.InfoLevel, "router", nil, "found source MAC address: ", m.SourceMACAddress)
	}
	if m.SourceHostname != "" {
		r.logRequest(q, zapcore.InfoLevel, "router", nil, "found source hostname: ", m.SourceHostname)
	}
}

// logSniff matches sing-box's sniff result message.
func (r *Runtime) logSniff(q *request) {
	m := &q.metadata
	if m.Protocol == "" {
		return
	}
	parts := []string{"sniffed ", packetWord(q.network), "protocol: ", m.Protocol}
	if m.Domain != "" {
		parts = append(parts, ", domain: ", m.Domain)
	}
	if m.Client != "" {
		parts = append(parts, ", client: ", m.Client)
	}
	r.logRequest(q, zapcore.DebugLevel, "router", nil, parts...)
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
	q := request{logID: e.ID, logStart: c.start}
	c.r.logRequest(&q, zapcore.DebugLevel, "connection", e.Error, "connection closed (upload ", logBytes(e.Upload), ", download ", logBytes(e.Download), ")")
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
