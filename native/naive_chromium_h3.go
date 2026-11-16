package native

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type chromiumH3Session struct {
	q                                     *quicConn
	mu                                    sync.Mutex
	critical                              map[uint64]bool
	settings                              chan struct{}
	draining                              bool
	peerHeader                            uint64
	goaway                                uint64
	active                                int
	space                                 chan struct{}
	control, encoderStream, decoderStream *quicStream
	encodeMu, decoderWrite                sync.Mutex
	reported                              uint64
	encoder                               chromiumQPACKEncoder
	decodeMu                              sync.Mutex
	decoder                               chromiumQPACKTable
	decodeWake                            chan struct{}
	blocked                               int
	preamble                              sync.Once
	preambleErr                           error
}

func chromiumH3Settings() []byte {
	var random [8]byte
	rand.Read(random[:])
	grease := uint64(binary.BigEndian.Uint32(random[:4]))*31 + 33
	value := uint64(binary.BigEndian.Uint32(random[4:]) & 0x3fffffff)
	var out []byte
	for _, setting := range [][2]uint64{{1, 65536}, {6, 262144}, {7, 100}, {0x33, 1}, {grease, value}} {
		out = quicVar(out, setting[0])
		out = quicVar(out, setting[1])
	}
	return out
}

func newChromiumH3(ctx context.Context, q *quicConn) (*chromiumH3Session, error) {
	n := &chromiumH3Session{q: q, settings: make(chan struct{}), critical: map[uint64]bool{}, peerHeader: ^uint64(0), goaway: ^uint64(0), decodeWake: make(chan struct{}), space: make(chan struct{})}
	var err error
	deadline := time.Now().Add(handshakeTimeout)
	if value, ok := ctx.Deadline(); ok && value.Before(deadline) {
		deadline = value
	}
	// Stream IDs are observable: control, encoder, decoder must open in order.
	for _, item := range []struct {
		kind uint64
		out  **quicStream
	}{{0, &n.control}, {2, &n.encoderStream}, {3, &n.decoderStream}} {
		*item.out, err = q.OpenStream(ctx, true)
		if err != nil {
			return nil, err
		}
		_ = (*item.out).SetWriteDeadline(deadline)
		if err = writeAll(*item.out, quicVar(nil, item.kind)); err != nil {
			return nil, err
		}
	}
	if err = h3WriteFrame(n.control, 4, chromiumH3Settings()); err != nil {
		return nil, err
	}
	for _, stream := range []*quicStream{n.control, n.encoderStream, n.decoderStream} {
		_ = stream.SetWriteDeadline(time.Time{})
	}
	return n, nil
}

func qpackInteger(r *bufio.Reader, prefix uint) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	mask := uint64(1<<prefix) - 1
	value := uint64(first) & mask
	if value < mask {
		return value, nil
	}
	for shift := uint(0); shift <= 56; shift += 7 {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		value += uint64(b&127) << shift
		if b&128 == 0 {
			return value, nil
		}
	}
	return 0, errors.New("QPACK integer overflow")
}
func qpackString(r *bufio.Reader, prefix uint, huffman byte) (string, error) {
	first, err := r.Peek(1)
	if err != nil {
		return "", err
	}
	compressed := first[0]&huffman != 0
	size, err := qpackInteger(r, prefix)
	if err != nil {
		return "", err
	}
	if size > 262144 {
		return "", errors.New("QPACK literal exceeds limit")
	}
	b := make([]byte, int(size))
	if _, err = io.ReadFull(r, b); err != nil {
		return "", err
	}
	if compressed {
		return h3Huffman(b)
	}
	return string(b), nil
}
func (n *chromiumH3Session) decoderInstruction(wire []byte, acknowledged uint64) error {
	n.decoderWrite.Lock()
	defer n.decoderWrite.Unlock()
	err := n.writeDecoder(wire)
	if err == nil {
		n.reported = max(n.reported, acknowledged)
	}
	return err
}

func (n *chromiumH3Session) writeDecoder(wire []byte) error {
	_ = n.decoderStream.SetWriteDeadline(time.Now().Add(handshakeTimeout))
	err := writeAll(n.decoderStream, wire)
	_ = n.decoderStream.SetWriteDeadline(time.Time{})
	return err
}

func (n *chromiumH3Session) reportInsert() error {
	n.decoderWrite.Lock()
	defer n.decoderWrite.Unlock()
	n.decodeMu.Lock()
	count := n.decoder.inserted
	n.decodeMu.Unlock()
	if count == n.reported {
		return nil
	}
	// Section ACKs can overtake insertion notifications; never count them twice.
	if err := n.writeDecoder(h3Int(nil, 6, 0, count-n.reported)); err != nil {
		return err
	}
	n.reported = count
	return nil
}

func (n *chromiumH3Session) encoderInstructions(s *quicStream) error {
	r := bufio.NewReaderSize(s, 4096)
	for {
		peek, err := r.Peek(1)
		if err != nil {
			return err
		}
		first := peek[0]
		var field [2]string
		var index uint64
		switch {
		case first&0x80 != 0:
			index, err = qpackInteger(r, 6)
			if err != nil {
				return err
			}
			n.decodeMu.Lock()
			if first&0x40 != 0 {
				if index >= uint64(len(h3Static)) {
					err = errors.New("QPACK insert static name outside table")
				} else {
					field = h3Static[index]
				}
			} else if index >= n.decoder.inserted {
				err = errors.New("QPACK insert relative name outside table")
			} else {
				field, err = n.decoder.at(n.decoder.inserted - index - 1)
			}
			n.decodeMu.Unlock()
			if err != nil {
				return err
			}
			field[1], err = qpackString(r, 7, 0x80)
		case first&0xc0 == 0x40:
			field[0], err = qpackString(r, 5, 0x20)
			if err == nil {
				field[1], err = qpackString(r, 7, 0x80)
			}
		case first&0xe0 == 0x20:
			index, err = qpackInteger(r, 5)
			if err != nil {
				return err
			}
			if index > 65536 {
				return errors.New("QPACK peer capacity exceeds advertised maximum")
			}
			n.decodeMu.Lock()
			n.decoder.capacity = int(index)
			n.decoder.trim(0)
			n.decodeMu.Unlock()
			continue
		default:
			index, err = qpackInteger(r, 5)
			if err != nil {
				return err
			}
			n.decodeMu.Lock()
			if index >= n.decoder.inserted {
				err = errors.New("QPACK duplicate outside table")
			} else {
				field, err = n.decoder.at(n.decoder.inserted - index - 1)
			}
			n.decodeMu.Unlock()
		}
		if err != nil {
			return err
		}
		n.decodeMu.Lock()
		err = n.decoder.insert(field)
		if err == nil {
			close(n.decodeWake)
			n.decodeWake = make(chan struct{})
		}
		n.decodeMu.Unlock()
		if err != nil {
			return err
		}
		if err = n.reportInsert(); err != nil {
			return err
		}
	}
}

func (n *chromiumH3Session) decoderInstructions(s *quicStream) error {
	r := bufio.NewReaderSize(s, 4096)
	for {
		peek, err := r.Peek(1)
		if err != nil {
			return err
		}
		first := peek[0]
		prefix := uint(6)
		if first&0x80 != 0 {
			prefix = 7
		}
		value, err := qpackInteger(r, prefix)
		if err != nil {
			return err
		}
		n.encodeMu.Lock()
		err = n.encoder.acknowledge(first, value)
		n.encodeMu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (n *chromiumH3Session) controlFrames(s *quicStream) error {
	first := true
	for {
		kind, size, err := readChromiumH3Frame(s)
		if err != nil {
			return err
		}
		if first && kind != 4 {
			return errors.New("missing Chromium HTTP3 settings")
		}
		if !first && kind == 4 {
			return errors.New("duplicate HTTP3 settings")
		}
		first = false
		if kind != 4 && kind != 7 {
			switch kind {
			case 0, 1, 2, 3, 5, 6, 8, 9, 13:
				return errors.New("unexpected HTTP3 control frame")
			}
			if _, err = io.CopyN(io.Discard, s, int64(size)); err != nil {
				return err
			}
			continue
		}
		if size > 65536 {
			return errors.New("HTTP3 control frame exceeds limit")
		}
		b := make([]byte, int(size))
		if _, err = io.ReadFull(s, b); err != nil {
			return err
		}
		switch kind {
		case 4:
			values := map[uint64]uint64{}
			r := quicReader(b)
			for len(r) > 0 {
				key, err := r.v()
				if err != nil {
					return err
				}
				value, err := r.v()
				if err != nil {
					return err
				}
				if _, ok := values[key]; ok || key >= 2 && key <= 5 {
					return errors.New("duplicate or forbidden HTTP3 setting")
				}
				if (key == 8 || key == 0x33) && value > 1 {
					return errors.New("invalid HTTP3 boolean setting")
				}
				values[key] = value
			}
			n.encodeMu.Lock()
			n.encoder.maximum = values[1]
			n.encoder.blocked = min(values[7], 100)
			n.encoder.table.capacity = int(min(values[1], 65536))
			n.encodeMu.Unlock()
			n.mu.Lock()
			if value, ok := values[6]; ok {
				n.peerHeader = value
			}
			close(n.settings)
			n.mu.Unlock()
		case 7:
			r := quicReader(b)
			last, err := r.v()
			if err != nil || len(r) != 0 || last&3 != 0 {
				return errors.New("invalid HTTP3 GOAWAY")
			}
			n.mu.Lock()
			if last > n.goaway {
				n.mu.Unlock()
				return errors.New("increasing HTTP3 GOAWAY")
			}
			n.goaway = last
			n.draining = true
			close(n.space)
			n.space = make(chan struct{})
			empty := n.active == 0
			n.mu.Unlock()
			if empty {
				n.q.Close()
			}
		}
	}
}

func (n *chromiumH3Session) peerStreams(owner *trustClient) {
	defer func() { n.q.Close(); owner.mu.Lock(); delete(owner.naiveH3Sessions, n); owner.mu.Unlock() }()
	slots := make(chan struct{}, 16)
	for {
		s, err := n.q.AcceptStream(n.q.ctx)
		if err != nil {
			return
		}
		if s.id&2 == 0 {
			s.Close()
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			s.Close()
			return
		}
		go func() {
			defer func() { <-slots }()
			kind, err := readQUICVar(s)
			if err != nil {
				n.q.Close()
				return
			}
			if kind == 0 || kind == 2 || kind == 3 {
				n.mu.Lock()
				duplicate := n.critical[kind]
				n.critical[kind] = true
				n.mu.Unlock()
				if duplicate {
					n.q.Close()
					return
				}
				switch kind {
				case 0:
					err = n.controlFrames(s)
				case 2:
					err = n.encoderInstructions(s)
				case 3:
					err = n.decoderInstructions(s)
				}
				n.q.Close()
				return
			}
			if kind == 1 {
				n.q.Close()
				return
			}
			_, _ = io.CopyN(io.Discard, s, 65536)
			s.Close()
		}()
	}
}

func chromiumResponseFields(fields [][2]string, trailers bool) (map[string]string, error) {
	result := map[string]string{}
	regular := false
	for _, field := range fields {
		key, value := field[0], field[1]
		_, duplicate := result[key]
		if key == "" || key != strings.ToLower(key) || strings.ContainsAny(key+value, "\r\n\x00") {
			return nil, errors.New("invalid Chromium HTTP3 header")
		}
		if strings.HasPrefix(key, ":") {
			if trailers || regular || key != ":status" || duplicate {
				return nil, errors.New("invalid HTTP3 response pseudo-header")
			}
		} else {
			regular = true
			if err := validateHTTPHeader(key, []string{value}); err != nil {
				return nil, err
			}
			switch key {
			case "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
				return nil, errors.New("forbidden HTTP3 connection header")
			}
			if (key == "content-length" || key == "padding-type-reply") && duplicate {
				return nil, errors.New("duplicate HTTP3 response control header")
			}
		}
		result[key] = value
	}
	return result, nil
}

func (n *chromiumH3Session) decodeHeaders(ctx context.Context, stream *quicStream, wire []byte, trailers bool) (map[string]string, error) {
	id := stream.id
	n.decodeMu.Lock()
	required, base, fields, err := qpackBase(wire, n.decoder.inserted, 65536)
	if err != nil {
		n.decodeMu.Unlock()
		n.q.Close()
		return nil, err
	}
	if required > n.decoder.inserted {
		if n.blocked >= 100 {
			n.decodeMu.Unlock()
			return nil, errors.New("too many blocked QPACK streams")
		}
		n.blocked++
		for required > n.decoder.inserted {
			wake := n.decodeWake
			n.decodeMu.Unlock()
			stream.mu.Lock()
			deadline := stream.readDeadline
			stream.mu.Unlock()
			var timer *time.Timer
			var timeout <-chan time.Time
			if !deadline.IsZero() {
				timer = time.NewTimer(max(0, time.Until(deadline)))
				timeout = timer.C
			}
			select {
			case <-wake:
			case <-stream.readWake:
			case <-stream.closed:
				err = net.ErrClosed
			case <-timeout:
				err = os.ErrDeadlineExceeded
			case <-ctx.Done():
				err = ctx.Err()
			case <-n.q.done:
				err = net.ErrClosed
			}
			if timer != nil {
				timer.Stop()
			}
			n.decodeMu.Lock()
			if err != nil {
				n.blocked--
				n.decodeMu.Unlock()
				_ = n.decoderInstruction(h3Int(nil, 6, 0x40, id), 0)
				return nil, err
			}
		}
		n.blocked--
	}
	decoded, err := n.decoder.decode(fields, base, required)
	n.decodeMu.Unlock()
	if err != nil {
		n.q.Close()
		return nil, err
	}
	if required > 0 {
		if err = n.decoderInstruction(h3Int(nil, 7, 0x80, id), required); err != nil {
			return nil, err
		}
	}
	return chromiumResponseFields(decoded, trailers)
}

func (n *chromiumH3Session) writeHeaders(s *quicStream, fields [][2]string) error {
	n.mu.Lock()
	limit := n.peerHeader
	n.mu.Unlock()
	size := uint64(0)
	for _, field := range fields {
		size += uint64(32 + len(field[0]) + len(field[1]))
	}
	if size > limit {
		return errors.New("HTTP3 request headers exceed peer limit")
	}
	n.encodeMu.Lock()
	defer n.encodeMu.Unlock()
	block, instructions := n.encoder.encode(s.id, fields)
	if len(instructions) > 0 {
		_ = n.encoderStream.SetWriteDeadline(time.Now().Add(handshakeTimeout))
		err := writeAll(n.encoderStream, instructions)
		_ = n.encoderStream.SetWriteDeadline(time.Time{})
		if err != nil {
			n.q.Close()
			return err
		}
	}
	return h3WriteFrame(s, 1, block)
}

func (n *chromiumH3Session) open(ctx context.Context) (*quicStream, error) {
	select {
	case <-n.settings:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-n.q.done:
		return nil, net.ErrClosed
	}
	for {
		n.mu.Lock()
		if n.draining {
			n.mu.Unlock()
			return nil, errChromiumH3Draining
		}
		if n.active < 128 {
			n.active++
			n.mu.Unlock()
			break
		}
		space := n.space
		n.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.q.done:
			return nil, net.ErrClosed
		case <-space:
		}
	}
	s, err := n.q.OpenStream(ctx, false)
	if err != nil {
		n.release()
		return nil, err
	}
	n.mu.Lock()
	refused := s.id >= n.goaway
	n.mu.Unlock()
	if refused {
		s.Close()
		n.release()
		return nil, errChromiumH3Draining
	}
	return s, nil
}
func (n *chromiumH3Session) release() {
	n.mu.Lock()
	n.active--
	close(n.space)
	n.space = make(chan struct{})
	empty := n.draining && n.active == 0
	n.mu.Unlock()
	if empty {
		n.q.Close()
	}
}

var errChromiumH3Draining = errors.New("Chromium HTTP3 request refused by GOAWAY")

func (n *chromiumH3Session) response(ctx context.Context, s *quicStream) (map[string]string, error) {
	for information := 0; information < 17; information++ {
		for {
			kind, size, err := readChromiumH3Frame(s)
			if err != nil {
				return nil, err
			}
			if kind == 0 || kind == 2 || kind == 3 || kind == 4 || kind == 5 || kind == 6 || kind == 7 || kind == 8 || kind == 9 || kind == 13 {
				return nil, errors.New("unexpected HTTP3 response frame")
			}
			if kind != 1 {
				if _, err = io.CopyN(io.Discard, s, int64(size)); err != nil {
					return nil, err
				}
				continue
			}
			b := make([]byte, int(size))
			if _, err = io.ReadFull(s, b); err != nil {
				return nil, err
			}
			headers, err := n.decodeHeaders(ctx, s, b, false)
			if err != nil {
				return nil, err
			}
			status := headers[":status"]
			code, err := strconv.Atoi(status)
			if err != nil || len(status) != 3 || code < 100 || code > 599 || code == 101 {
				return nil, errors.New("invalid HTTP3 response status")
			}
			if code >= 200 {
				return headers, nil
			}
			break
		}
	}
	return nil, errors.New("too many informational HTTP3 responses")
}
func readChromiumH3Frame(s io.Reader) (kind, size uint64, err error) {
	kind, err = readQUICVar(s)
	if err != nil {
		return
	}
	size, err = readQUICVar(s)
	if err == nil && kind == 1 && size > 262144 {
		err = errors.New("HTTP3 frame exceeds limit")
	}
	return
}

type chromiumH3Body struct {
	*trustH3Conn
	session *chromiumH3Session
	once    sync.Once
}

func (c *chromiumH3Body) Close() error {
	err := c.trustH3Conn.Close()
	c.once.Do(c.session.release)
	return err
}

func (n *chromiumH3Session) request(ctx context.Context, fields [][2]string, finish bool) (*chromiumH3Body, map[string]string, error) {
	s, err := n.open(ctx)
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { s.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetDeadline(deadline)
	}
	if err = n.writeHeaders(s, fields); err == nil && finish {
		err = h3FinishRequest(s)
	}
	var headers map[string]string
	if err == nil {
		headers, err = n.response(ctx, s)
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		s.Close()
		n.release()
		return nil, nil, err
	}
	_ = s.SetDeadline(time.Time{})
	body := &chromiumH3Body{trustH3Conn: &trustH3Conn{quicStream: s}, session: n}
	body.decodeTrailers = func(b []byte) error { _, err := n.decodeHeaders(n.q.ctx, s, b, true); return err }
	return body, headers, nil
}

func (n *chromiumH3Session) connect(ctx context.Context, c *trustClient, authority string) (net.Conn, error) {
	n.preamble.Do(func() {
		body, _, err := n.request(ctx, chromiumPreamble(c.outbound), true)
		n.preambleErr = err
		if err != nil {
			n.q.Close()
			return
		}
		go func() {
			defer body.Close()
			_ = body.SetReadDeadline(time.Now().Add(handshakeTimeout))
			_, _ = io.CopyN(io.Discard, body, 8<<20)
		}()
	})
	if n.preambleErr != nil {
		return nil, n.preambleErr
	}
	body, headers, err := n.request(ctx, c.chromiumConnectHeaders(authority), false)
	if err != nil {
		return nil, err
	}
	if headers[":status"] != "200" {
		body.Close()
		if headers[":status"] == "407" {
			n.q.Close()
		}
		return nil, errors.New("Naive HTTP3 CONNECT: HTTP " + headers[":status"])
	}
	_, present := headers["padding"]
	padded, err := naivePaddingReply(present, headers["padding-type-reply"])
	if err != nil {
		body.Close()
		return nil, err
	}
	if padded {
		return &naiveConn{Conn: body}, nil
	}
	return body, nil
}
