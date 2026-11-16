package native

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const resolvedName = "org.freedesktop.resolve1"
const resolvedPath = "/org/freedesktop/resolve1"
const resolvedInterface = resolvedName + ".Manager"
const dbusLimit = 128 << 10

type busVariant struct {
	signature string
	value     any
}
type busMessage struct {
	kind, flags                                                  byte
	serial, reply                                                uint32
	path, iface, member, sender, destination, signature, failure string
	values                                                       []any
}

func busType(sig string, depth int) (int, error) {
	if len(sig) == 0 || depth > 16 {
		return 0, errors.New("invalid D-Bus signature")
	}
	switch sig[0] {
	case 'y', 'b', 'q', 'i', 'u', 't', 'x', 's', 'o', 'g', 'v':
		return 1, nil
	case 'a':
		n, e := busType(sig[1:], depth+1)
		return n + 1, e
	case '(', '{':
		end := byte(')')
		if sig[0] == '{' {
			end = '}'
		}
		pos, count := 1, 0
		for pos < len(sig) && sig[pos] != end {
			n, e := busType(sig[pos:], depth+1)
			if e != nil {
				return 0, e
			}
			pos += n
			count++
		}
		if pos == len(sig) || count == 0 || sig[0] == '{' && count != 2 {
			return 0, errors.New("invalid D-Bus structure")
		}
		return pos + 1, nil
	}
	return 0, errors.New("unsupported D-Bus type")
}
func busAlign(sig string) int {
	switch sig[0] {
	case 'y', 'g', 'v':
		return 1
	case 'q':
		return 2
	case 't', 'x', '(', '{':
		return 8
	default:
		return 4
	}
}

type busDecoder struct {
	data  []byte
	pos   int
	order binary.ByteOrder
	count int
}

func (d *busDecoder) take(n, alignment int) ([]byte, error) {
	pos := (d.pos + alignment - 1) & -alignment
	if n < 0 || pos > len(d.data) || n > len(d.data)-pos {
		return nil, io.ErrUnexpectedEOF
	}
	for _, b := range d.data[d.pos:pos] {
		if b != 0 {
			return nil, errors.New("nonzero D-Bus padding")
		}
	}
	d.pos = pos + n
	return d.data[pos:d.pos], nil
}
func (d *busDecoder) value(sig string, depth int) (any, error) {
	d.count++
	if depth > 16 || d.count > 8192 {
		return nil, errors.New("D-Bus value limit")
	}
	switch sig[0] {
	case 'y':
		b, e := d.take(1, 1)
		if e != nil {
			return nil, e
		}
		return b[0], nil
	case 'q':
		b, e := d.take(2, 2)
		if e != nil {
			return nil, e
		}
		return d.order.Uint16(b), nil
	case 'i', 'u', 'b':
		b, e := d.take(4, 4)
		if e != nil {
			return nil, e
		}
		v := d.order.Uint32(b)
		if sig[0] == 'i' {
			return int32(v), nil
		}
		if sig[0] == 'b' {
			if v > 1 {
				return nil, errors.New("invalid D-Bus boolean")
			}
			return v == 1, nil
		}
		return v, nil
	case 't', 'x':
		b, e := d.take(8, 8)
		if e != nil {
			return nil, e
		}
		if sig[0] == 'x' {
			return int64(d.order.Uint64(b)), nil
		}
		return d.order.Uint64(b), nil
	case 's', 'o', 'g':
		n := 0
		if sig[0] == 'g' {
			b, e := d.take(1, 1)
			if e != nil {
				return nil, e
			}
			n = int(b[0])
		} else {
			b, e := d.take(4, 4)
			if e != nil {
				return nil, e
			}
			n = int(d.order.Uint32(b))
		}
		b, e := d.take(n+1, 1)
		if e != nil {
			return nil, e
		}
		if b[n] != 0 || !utf8.Valid(b[:n]) || strings.ContainsRune(string(b[:n]), 0) {
			return nil, errors.New("invalid D-Bus string")
		}
		return string(b[:n]), nil
	case 'v':
		v, e := d.value("g", depth+1)
		if e != nil {
			return nil, e
		}
		s := v.(string)
		n, e := busType(s, depth+1)
		if e != nil || n != len(s) {
			return nil, errors.New("invalid D-Bus variant")
		}
		v, e = d.value(s, depth+1)
		return busVariant{s, v}, e
	case 'a':
		b, e := d.take(4, 4)
		if e != nil {
			return nil, e
		}
		n := int(d.order.Uint32(b))
		if _, e = d.take(0, busAlign(sig[1:])); e != nil {
			return nil, e
		}
		end := d.pos + n
		if n > dbusLimit || end > len(d.data) {
			return nil, errors.New("oversized D-Bus array")
		}
		if sig == "ay" {
			return d.take(n, 1)
		}
		var values []any
		for d.pos < end {
			v, e := d.value(sig[1:], depth+1)
			if e != nil {
				return nil, e
			}
			values = append(values, v)
		}
		if d.pos != end {
			return nil, errors.New("invalid D-Bus array length")
		}
		return values, nil
	case '(', '{':
		if _, e := d.take(0, 8); e != nil {
			return nil, e
		}
		return d.values(sig[1:len(sig)-1], depth+1)
	}
	return nil, errors.New("unsupported D-Bus value")
}
func (d *busDecoder) values(sig string, depth int) ([]any, error) {
	var out []any
	for len(sig) > 0 {
		n, e := busType(sig, depth)
		if e != nil {
			return nil, e
		}
		v, e := d.value(sig[:n], depth)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
		sig = sig[n:]
	}
	return out, nil
}

// Only fixed internal reply schemas reach the encoder; all incoming values are bounded above.
func busEncode(b []byte, sig string, values []any) []byte {
	for _, v := range values {
		n, _ := busType(sig, 0)
		s := sig[:n]
		sig = sig[n:]
		b = append(b, make([]byte, (-len(b))&(busAlign(s)-1))...)
		switch s[0] {
		case 'y':
			b = append(b, v.(byte))
		case 'q':
			b = binary.LittleEndian.AppendUint16(b, v.(uint16))
		case 'i':
			b = binary.LittleEndian.AppendUint32(b, uint32(v.(int32)))
		case 'u':
			b = binary.LittleEndian.AppendUint32(b, v.(uint32))
		case 'b':
			x := uint32(0)
			if v.(bool) {
				x = 1
			}
			b = binary.LittleEndian.AppendUint32(b, x)
		case 't':
			b = binary.LittleEndian.AppendUint64(b, v.(uint64))
		case 'x':
			b = binary.LittleEndian.AppendUint64(b, uint64(v.(int64)))
		case 's', 'o', 'g':
			x := v.(string)
			if s[0] == 'g' {
				b = append(b, byte(len(x)))
			} else {
				b = binary.LittleEndian.AppendUint32(b, uint32(len(x)))
			}
			b = append(b, x...)
			b = append(b, 0)
		case 'v':
			x := v.(busVariant)
			b = busEncode(b, "g", []any{x.signature})
			b = busEncode(b, x.signature, []any{x.value})
		case 'a':
			pos := len(b)
			b = append(b, 0, 0, 0, 0)
			b = append(b, make([]byte, (-len(b))&(busAlign(s[1:])-1))...)
			start := len(b)
			if s == "ay" {
				b = append(b, v.([]byte)...)
			} else {
				for _, x := range v.([]any) {
					b = busEncode(b, s[1:], []any{x})
				}
			}
			binary.LittleEndian.PutUint32(b[pos:], uint32(len(b)-start))
		case '(', '{':
			b = busEncode(b, s[1:len(s)-1], v.([]any))
		}
	}
	return b
}
func busRead(r io.Reader) (busMessage, error) {
	var m busMessage
	h := make([]byte, 16)
	if _, e := io.ReadFull(r, h); e != nil {
		return m, e
	}
	var order binary.ByteOrder = binary.LittleEndian
	if h[0] == 'B' {
		order = binary.BigEndian
	} else if h[0] != 'l' {
		return m, errors.New("invalid D-Bus byte order")
	}
	m.kind, m.flags, m.serial = h[1], h[2], order.Uint32(h[8:])
	body, fields := int(order.Uint32(h[4:])), int(order.Uint32(h[12:]))
	if h[3] != 1 || m.kind < 1 || m.kind > 4 || m.serial == 0 || fields > 65536 || body > dbusLimit {
		return m, errors.New("invalid D-Bus header")
	}
	data := make([]byte, (fields+7)&-8)
	if _, e := io.ReadFull(r, data); e != nil {
		return m, e
	}
	d := busDecoder{data: data[:fields], order: order}
	seen := map[byte]bool{}
	for d.pos < fields {
		v, e := d.value("(yv)", 0)
		if e != nil {
			return m, e
		}
		pair := v.([]any)
		key, x := pair[0].(byte), pair[1].(busVariant)
		if key == 0 || seen[key] {
			return m, errors.New("duplicate D-Bus header")
		}
		seen[key] = true
		if key == 5 || key == 9 {
			if x.signature != "u" {
				return m, errors.New("invalid D-Bus integer header")
			}
			if key == 5 {
				m.reply = x.value.(uint32)
			} else if x.value.(uint32) != 0 {
				return m, errors.New("D-Bus file descriptors are not supported")
			}
			continue
		}
		if key > 9 {
			continue
		}
		expected := "s"
		if key == 1 {
			expected = "o"
		}
		if key == 8 {
			expected = "g"
		}
		if x.signature != expected {
			return m, errors.New("invalid D-Bus header type")
		}
		s := x.value.(string)
		switch key {
		case 1:
			m.path = s
		case 2:
			m.iface = s
		case 3:
			m.member = s
		case 4:
			m.failure = s
		case 6:
			m.destination = s
		case 7:
			m.sender = s
		case 8:
			m.signature = s
		}
	}
	for _, b := range data[fields:] {
		if b != 0 {
			return m, errors.New("invalid D-Bus header padding")
		}
	}
	data = make([]byte, body)
	if _, e := io.ReadFull(r, data); e != nil {
		return m, e
	}
	d = busDecoder{data: data, order: order}
	var e error
	m.values, e = d.values(m.signature, 0)
	if e == nil && d.pos != body {
		e = errors.New("trailing D-Bus body")
	}
	return m, e
}
func (m busMessage) encode() []byte {
	b := make([]byte, 16)
	b[0], b[1], b[2], b[3] = 'l', m.kind, m.flags, 1
	binary.LittleEndian.PutUint32(b[8:], m.serial)
	field := func(key byte, sig string, v any) { b = busEncode(b, "(yv)", []any{[]any{key, busVariant{sig, v}}}) }
	if m.path != "" {
		field(1, "o", m.path)
	}
	if m.iface != "" {
		field(2, "s", m.iface)
	}
	if m.member != "" {
		field(3, "s", m.member)
	}
	if m.failure != "" {
		field(4, "s", m.failure)
	}
	if m.reply != 0 {
		field(5, "u", m.reply)
	}
	if m.destination != "" {
		field(6, "s", m.destination)
	}
	if m.sender != "" {
		field(7, "s", m.sender)
	}
	if m.signature != "" {
		field(8, "g", m.signature)
	}
	binary.LittleEndian.PutUint32(b[12:], uint32(len(b)-16))
	b = append(b, make([]byte, (-len(b))&7)...)
	start := len(b)
	b = busEncode(b, m.signature, m.values)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)-start))
	return b
}

type resolvedBus struct {
	conn     net.Conn
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	serial   uint32
	pending  map[uint32]chan busMessage
	done     chan struct{}
	requests chan busMessage
	workers  sync.WaitGroup
}

func connectSystemBus(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	address := os.Getenv("DBUS_SYSTEM_BUS_ADDRESS")
	if address == "" {
		address = "unix:path=/run/dbus/system_bus_socket"
	}
	var conn net.Conn
	last := errors.New("D-Bus requires a local unix address")
	for _, part := range strings.Split(address, ";") {
		if !strings.HasPrefix(part, "unix:") {
			continue
		}
		path := ""
		for _, option := range strings.Split(part[5:], ",") {
			k, v, ok := strings.Cut(option, "=")
			if !ok {
				continue
			}
			v, e := url.PathUnescape(v)
			if e != nil {
				return nil, nil, e
			}
			if k == "path" {
				path = v
			} else if k == "abstract" {
				path = "\x00" + v
			}
		}
		if path == "" {
			continue
		}
		conn, last = (&net.Dialer{}).DialContext(ctx, "unix", path)
		if last == nil {
			break
		}
	}
	if last != nil {
		return nil, nil, last
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	reader := bufio.NewReaderSize(conn, 4096)
	uid := hex.EncodeToString([]byte(strconv.Itoa(os.Getuid())))
	if e := writeAll(conn, []byte("\x00AUTH EXTERNAL "+uid+"\r\n")); e != nil {
		conn.Close()
		return nil, nil, e
	}
	line, e := reader.ReadSlice('\n')
	if e != nil || !strings.HasPrefix(string(line), "OK ") {
		conn.Close()
		return nil, nil, errors.New("D-Bus EXTERNAL authentication failed")
	}
	if e = writeAll(conn, []byte("BEGIN\r\n")); e != nil {
		conn.Close()
		return nil, nil, e
	}
	conn.SetDeadline(time.Time{})
	return conn, reader, nil
}

func connectResolvedBus(ctx context.Context) (*resolvedBus, error) {
	conn, reader, e := connectSystemBus(ctx)
	if e != nil {
		return nil, e
	}
	child, cancel := context.WithCancel(ctx)
	b := &resolvedBus{conn: conn, ctx: child, cancel: cancel, pending: map[uint32]chan busMessage{}, done: make(chan struct{}), requests: make(chan busMessage, 16)}
	go b.read(reader)
	call, cancelCall := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCall()
	if _, e = b.call(call, "Hello", "", nil); e == nil {
		var response busMessage
		response, e = b.call(call, "RequestName", "su", []any{resolvedName, uint32(4)})
		if e == nil && (len(response.values) != 1 || response.signature != "u" || response.values[0].(uint32) != 1) {
			e = errors.New("resolved D-Bus name is already owned")
		}
	}
	if e != nil {
		b.close()
		return nil, e
	}
	return b, nil
}
func (b *resolvedBus) read(reader io.Reader) {
	defer close(b.done)
	defer b.cancel()
	defer b.conn.Close()
	for {
		m, e := busRead(reader)
		if e != nil {
			return
		}
		if m.kind == 2 || m.kind == 3 {
			if m.sender != "org.freedesktop.DBus" {
				continue
			}
			b.mu.Lock()
			ch := b.pending[m.reply]
			if ch != nil {
				delete(b.pending, m.reply)
				ch <- m
			}
			b.mu.Unlock()
		} else if m.kind == 1 {
			select {
			case b.requests <- m:
			default:
				b.respond(m, "", "", nil, "org.freedesktop.DBus.Error.LimitsExceeded", "too many pending resolved requests")
			}
		}
	}
}
func (b *resolvedBus) send(m busMessage, response chan busMessage) (uint32, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.serial++
	if b.serial == 0 {
		b.serial++
	}
	m.serial = b.serial
	if response != nil {
		b.pending[m.serial] = response
	}
	b.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	e := writeAll(b.conn, m.encode())
	if e != nil {
		delete(b.pending, m.serial)
		b.cancel()
		b.conn.Close()
	}
	return m.serial, e
}
func (b *resolvedBus) call(ctx context.Context, member, sig string, values []any) (busMessage, error) {
	ch := make(chan busMessage, 1)
	id, e := b.send(busMessage{kind: 1, path: "/org/freedesktop/DBus", iface: "org.freedesktop.DBus", destination: "org.freedesktop.DBus", member: member, signature: sig, values: values}, ch)
	if e != nil {
		return busMessage{}, e
	}
	defer func() { b.mu.Lock(); delete(b.pending, id); b.mu.Unlock() }()
	select {
	case m := <-ch:
		if m.kind == 3 {
			return m, fmt.Errorf("D-Bus %s", m.failure)
		}
		return m, nil
	case <-ctx.Done():
		return busMessage{}, ctx.Err()
	case <-b.ctx.Done():
		return busMessage{}, errors.New("resolved D-Bus disconnected")
	}
}
func (b *resolvedBus) respond(request busMessage, iface, sig string, values []any, failure, detail string) {
	if request.flags&1 != 0 {
		return
	}
	m := busMessage{kind: 2, reply: request.serial, destination: request.sender, signature: sig, values: values}
	if failure != "" {
		m.kind = 3
		m.failure = failure
		m.signature = "s"
		m.values = []any{detail}
	}
	_, _ = b.send(m, nil)
}
func (b *resolvedBus) close() { b.cancel(); b.conn.Close(); <-b.done; b.workers.Wait() }
