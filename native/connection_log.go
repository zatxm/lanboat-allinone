package native

import (
	"context"
	"errors"
	"net"
	"net/url"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func (r *Runtime) logInbound(q *request) {
	if r.config.Log.Disabled || !r.logger.Core().Enabled(zapcore.InfoLevel) {
		return
	}
	entry := r.logger.Check(zapcore.InfoLevel, "inbound connection to "+q.address)
	if entry == nil {
		return
	}
	q.logID = r.logSequence.Add(1)
	entry.Write(zap.Uint64("connection_id", q.logID), zap.String("network", q.network), zap.String("inbound", q.inbound), zap.String("source", q.source), zap.String("destination", q.address))
}

func (r *Runtime) logConnection(q request, tag string, conn net.Conn, err error) {
	if r.config.Log.Disabled {
		return
	}
	level := zapcore.InfoLevel
	if err != nil {
		level = zapcore.ErrorLevel
		if errors.Is(err, ErrRejected) || errors.Is(err, ErrDropped) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
			level = zapcore.DebugLevel
		}
	}
	if !r.logger.Core().Enabled(level) {
		return
	}
	message := "outbound connection to "
	if err != nil {
		message = "connection failed to "
	}
	entry := r.logger.Check(level, message+q.address)
	if entry == nil {
		return
	}
	if q.logID == 0 {
		q.logID = r.logSequence.Add(1)
	}
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
	fields := []zap.Field{zap.Uint64("connection_id", q.logID), zap.String("network", q.network), zap.String("inbound", q.inbound), zap.String("source", q.source), zap.String("destination", q.address), zap.String("outbound", selected), zap.String("route_outbound", tag)}
	if q.metadata.Domain != "" {
		fields = append(fields, zap.String("domain", q.metadata.Domain))
	}
	if q.metadata.Protocol != "" {
		fields = append(fields, zap.String("protocol", q.metadata.Protocol))
	}
	if q.metadata.Client != "" {
		fields = append(fields, zap.String("client", q.metadata.Client))
	}
	if q.metadata.ProcessName != "" {
		fields = append(fields, zap.String("process_name", q.metadata.ProcessName), zap.String("process_path", q.metadata.ProcessPath))
	}
	if q.metadata.SourceMACAddress != "" {
		fields = append(fields, zap.String("source_mac_address", q.metadata.SourceMACAddress))
	}
	if q.metadata.SourceHostname != "" {
		fields = append(fields, zap.String("source_hostname", q.metadata.SourceHostname))
	}
	if err != nil {
		// url.Error includes paths and queries; the transport cause is sufficient.
		var u *url.Error
		if errors.As(err, &u) {
			err = u.Err
		}
		fields = append(fields, zap.Error(err))
	}
	entry.Write(fields...)
}

func (r *Runtime) logRule(q request, index int, o Rule) {
	if q.logID == 0 || r.config.Log.Disabled {
		return
	}
	if entry := r.logger.Check(zapcore.DebugLevel, "routing rule matched"); entry != nil {
		entry.Write(zap.Uint64("connection_id", q.logID), zap.Int("rule_index", index), zap.String("action", o.Action), zap.String("outbound", o.Outbound))
	}
}
