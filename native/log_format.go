package native

import (
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// Log entries follow sing-box: the zap message is the complete line body
// "[id elapsed] tag: message: error", so every zap sink (log files, the Clash
// API, embedding applications) shows the same text. The encoder below only
// adds the timestamp and level.

// logEvent writes parts and err as one message. Formatting happens only when
// level is enabled.
func logEvent(l *zap.Logger, level zapcore.Level, err error, parts ...string) {
	if entry := l.Check(level, ""); entry != nil {
		entry.Message = joinLog(err, parts)
		entry.Write()
	}
}

func joinLog(err error, parts []string) string {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	var cause string
	if err != nil {
		cause = err.Error()
		n += 2 + len(cause)
	}
	var b strings.Builder
	b.Grow(n)
	for _, p := range parts {
		b.WriteString(p)
	}
	if err != nil {
		b.WriteString(": ")
		b.WriteString(cause)
	}
	return b.String()
}

// parseLogLevel accepts sing-box level names; trace is zap's debug.
func parseLogLevel(text string) (zapcore.Level, error) {
	if text == "trace" {
		return zapcore.DebugLevel, nil
	}
	var level zapcore.Level
	err := level.UnmarshalText([]byte(text))
	return level, err
}

// formatLogDuration matches sing-box's [id elapsed] prefix.
func formatLogDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return strconv.FormatInt(d.Milliseconds(), 10) + "ms"
	case d < time.Minute:
		centis := d.Milliseconds() / 10
		return strconv.FormatInt(centis/100, 10) + "." + twoDigits(centis%100) + "s"
	default:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m" + strconv.FormatInt(int64(d/time.Second)%60, 10) + "s"
	}
}

func twoDigits(v int64) string {
	if v < 10 {
		return "0" + strconv.FormatInt(v, 10)
	}
	return strconv.FormatInt(v, 10)
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

func (r *Runtime) inboundLabel(tag string) string {
	if label := r.inboundLabels[tag]; label != "" {
		return label
	}
	if tag == "" {
		return "inbound"
	}
	return "inbound/" + tag
}

func (r *Runtime) outboundLabel(tag string) string {
	o, ok := r.outbounds[tag]
	if !ok {
		return "outbound/" + tag
	}
	if c := r.controller; c != nil && (tag == c.directTag || tag == c.blockTag) {
		tag = strings.ToUpper(o.Type)
	}
	kind := "outbound/"
	if o.Type == "tailscale" || o.Type == "wireguard" && r.wgEndpoints[o.Tag] != nil {
		kind = "endpoint/"
	}
	return kind + o.Type + "[" + tag + "]"
}

const logTimeLayout = "-0700 2006-01-02 15:04:05"

// logEncoder renders sing-box lines. Fields are not part of the format; any
// that callers still attach are appended as JSON so nothing is lost.
type logEncoder struct {
	// The embedded JSON encoder holds context fields added through With.
	zapcore.Encoder
	start     time.Time
	timestamp bool
	file      bool
	color     bool
}

var logBuffers = buffer.NewPool()

func newLogEncoder(timestamp, file, color bool) *logEncoder {
	fields := zapcore.NewJSONEncoder(zapcore.EncoderConfig{SkipLineEnding: true, EncodeDuration: zapcore.StringDurationEncoder, EncodeTime: zapcore.ISO8601TimeEncoder})
	return &logEncoder{Encoder: fields, start: time.Now(), timestamp: timestamp, file: file, color: color}
}

func (e *logEncoder) Clone() zapcore.Encoder {
	c := *e
	c.Encoder = e.Encoder.Clone()
	return &c
}

func (e *logEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	b := logBuffers.Get()
	level := logLevelName(entry.Level)
	if e.color {
		level = logLevelColor(entry.Level) + level + "\x1b[0m"
	}
	switch {
	case e.timestamp:
		b.AppendString(entry.Time.Format(logTimeLayout))
		b.AppendByte(' ')
		b.AppendString(level)
		b.AppendByte(' ')
	case e.file:
		b.AppendString(level)
		b.AppendByte(' ')
	default:
		seconds := strconv.FormatInt(int64(entry.Time.Sub(e.start)/time.Second), 10)
		b.AppendString(level)
		b.AppendByte('[')
		b.AppendString(strings.Repeat("0", max(0, 4-len(seconds))))
		b.AppendString(seconds)
		b.AppendString("] ")
	}
	message := entry.Message
	if e.color {
		message = colorLogID(message)
	}
	if entry.LoggerName != "" {
		message = withLogTag(message, entry.LoggerName)
	}
	b.AppendString(message)
	extra, err := e.Encoder.EncodeEntry(zapcore.Entry{}, fields)
	if err == nil {
		if extra.Len() > 2 {
			b.AppendByte(' ')
			b.AppendString(extra.String())
		}
		extra.Free()
	}
	b.AppendByte('\n')
	return b, nil
}

// withLogTag inserts a logger name as the tag, after any [id elapsed] prefix.
func withLogTag(message, tag string) string {
	if strings.HasPrefix(message, "[") {
		if i := strings.Index(message, "] "); i > 0 {
			return message[:i+2] + tag + ": " + message[i+2:]
		}
	}
	return tag + ": " + message
}

func logLevelName(level zapcore.Level) string {
	switch level {
	case zapcore.DebugLevel:
		return "DEBUG"
	case zapcore.InfoLevel:
		return "INFO"
	case zapcore.WarnLevel:
		return "WARN"
	case zapcore.ErrorLevel:
		return "ERROR"
	case zapcore.FatalLevel:
		return "FATAL"
	}
	return "PANIC"
}

func logLevelColor(level zapcore.Level) string {
	switch level {
	case zapcore.DebugLevel:
		return "\x1b[37m"
	case zapcore.InfoLevel:
		return "\x1b[36m"
	case zapcore.WarnLevel:
		return "\x1b[33m"
	}
	return "\x1b[31m"
}

// colorLogID colors a leading connection ID the way sing-box does: a stable
// 256-color index derived from the ID, avoiding colors too dark to read.
func colorLogID(message string) string {
	if len(message) < 3 || message[0] != '[' {
		return message
	}
	end := 1
	for end < len(message) && message[end] >= '0' && message[end] <= '9' {
		end++
	}
	if end == 1 || end == len(message) || message[end] != ' ' && message[end] != ']' {
		return message
	}
	id, err := strconv.ParseUint(message[1:end], 10, 64)
	if err != nil {
		return message
	}
	color := uint(uint8(id)) % 215
	row, column := color/36, color%36
	red, green, blue := float32(row*51), float32(column/6*51), float32(column%6*51)
	if 0.2126*red+0.7152*green+0.0722*blue < 60 {
		row, column = 5-row, 35-column
		color = row*36 + column
	}
	return "[\x1b[38;5;" + strconv.FormatUint(uint64(color+16), 10) + "m" + message[1:end] + "\x1b[0m" + message[end:]
}

// consoleColor reports whether output is an interactive terminal.
func consoleColor(output string) bool {
	f := os.Stderr
	if output == "stdout" {
		f = os.Stdout
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == ""
}

func logDebug(l *zap.Logger, err error, parts ...string) {
	logEvent(l, zapcore.DebugLevel, err, parts...)
}
func logInfo(l *zap.Logger, err error, parts ...string) {
	logEvent(l, zapcore.InfoLevel, err, parts...)
}
func logWarn(l *zap.Logger, err error, parts ...string) {
	logEvent(l, zapcore.WarnLevel, err, parts...)
}
func logError(l *zap.Logger, err error, parts ...string) {
	logEvent(l, zapcore.ErrorLevel, err, parts...)
}

// NewLogger builds the sing-box style logger used when no logger is supplied.
// The returned function flushes and closes the output.
func NewLogger(options LogOptions) (*zap.Logger, func(), error) {
	if options.Disabled {
		return zap.NewNop(), func() {}, nil
	}
	level := zapcore.InfoLevel
	if options.Level != "" {
		parsed, err := parseLogLevel(options.Level)
		if err != nil {
			return nil, nil, err
		}
		level = parsed
	}
	output := options.Output
	if output == "" {
		output = "stderr"
	}
	writer, release, err := zap.Open(output)
	if err != nil {
		return nil, nil, err
	}
	console := output == "stdout" || output == "stderr"
	stop := func() {}
	if !console {
		// File logs batch writes instead of one locked syscall per entry;
		// closing flushes, and entries reach disk within a second otherwise.
		buffered := &zapcore.BufferedWriteSyncer{WS: writer, Size: 256 << 10, FlushInterval: time.Second}
		writer, stop = buffered, func() { _ = buffered.Stop() }
	}
	logger := zap.New(zapcore.NewCore(newLogEncoder(options.Timestamp, !console, console && consoleColor(output)), writer, level))
	return logger, func() { _ = logger.Sync(); stop(); release() }, nil
}
