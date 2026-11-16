package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Each direction has its own salt and monotonically increasing AEAD nonce.
type snellConn struct {
	net.Conn
	key             *ssKey
	replay          *replayWindow
	version         int
	rmu, wmu        sync.Mutex
	r, w            cipher.AEAD
	rnonce, wnonce  [24]byte
	buffer, pending []byte
	rerr, werr      error
	ended           bool
	limit           int
	lastWrite       time.Time
}

func snellVersion(s string) int {
	if s == "" {
		return 1
	}
	n, _ := strconv.Atoi(s)
	return n
}
func newSnellConn(c net.Conn, password, version string, replay *replayWindow) *snellConn {
	return &snellConn{Conn: c, version: snellVersion(version), key: &ssKey{method: "snell-" + version, master: []byte(password)}, replay: replay}
}
func (c *snellConn) aead(salt []byte) (cipher.AEAD, error) {
	key := snellKey(c.key.master, salt)
	if c.version == 1 {
		return newChaChaAEAD(key, false)
	}
	b, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
func (c *snellConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.rerr != nil {
		return 0, c.rerr
	}
	if len(c.pending) == 0 {
		c.pending, c.rerr = c.readRecord()
		if c.rerr != nil {
			return 0, c.rerr
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
func (c *snellConn) readRecord() ([]byte, error) {
	var salt []byte
	if c.r == nil {
		salt = make([]byte, 16)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return nil, err
		}
		var err error
		c.r, err = c.aead(salt)
		if err != nil {
			return nil, err
		}
		c.buffer = make([]byte, 2*0x3fff+16)
	}
	headerSize := 2
	if c.version >= 4 {
		headerSize = 7
	}
	var header [23]byte
	encrypted := header[:headerSize+16]
	if _, err := io.ReadFull(c.Conn, encrypted); err != nil {
		return nil, err
	}
	plain, err := c.r.Open(encrypted[:0], c.rnonce[:12], encrypted, nil)
	incrementNonce(&c.rnonce)
	if err != nil {
		return nil, err
	}
	if salt != nil {
		if err := c.replay.add(c.key, salt); err != nil {
			return nil, err
		}
	}
	size, padding := int(binary.BigEndian.Uint16(plain)), 0
	if c.version >= 4 {
		if !bytes.Equal(plain[:3], []byte{4, 0, 0}) {
			return nil, errors.New("invalid Snell record header")
		}
		padding = int(binary.BigEndian.Uint16(plain[3:5]))
		size = int(binary.BigEndian.Uint16(plain[5:7]))
	}
	if padding > 0x3fff || size > 0x3fff || size == 0 && padding != 0 {
		return nil, errors.New("invalid Snell record length")
	}
	if size == 0 {
		return nil, io.EOF
	}
	frame := c.buffer[:padding+size+16]
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return nil, err
	}
	body := frame[padding:]
	for i := 0; i < min(padding, len(body)); i += 2 {
		frame[i], body[i] = body[i], frame[i]
	}
	plain, err = c.r.Open(body[:0], c.rnonce[:12], body, nil)
	incrementNonce(&c.rnonce)
	return plain, err
}
func (c *snellConn) record(b []byte, padding int) error {
	var out []byte
	if c.w == nil {
		out = make([]byte, 16)
		if _, err := rand.Read(out); err != nil {
			return err
		}
		var err error
		c.w, err = c.aead(out)
		if err != nil {
			return err
		}
		if err = c.replay.add(c.key, out); err != nil {
			return err
		}
	}
	header := binary.BigEndian.AppendUint16(nil, uint16(len(b)))
	if c.version >= 4 {
		header = []byte{4, 0, 0}
		header = binary.BigEndian.AppendUint16(header, uint16(padding))
		header = binary.BigEndian.AppendUint16(header, uint16(len(b)))
	}
	out = c.w.Seal(out, c.wnonce[:12], header, nil)
	incrementNonce(&c.wnonce)
	if len(b) != 0 {
		start := len(out)
		out = append(out, make([]byte, padding)...)
		if _, err := rand.Read(out[start:]); err != nil {
			return err
		}
		out = c.w.Seal(out, c.wnonce[:12], b, nil)
		incrementNonce(&c.wnonce)
		body := out[start+padding:]
		for i := 0; i < min(padding, len(body)); i += 2 {
			out[start+i], body[i] = body[i], out[start+i]
		}
	}
	return writeAll(c.Conn, out)
}
func (c *snellConn) write(b []byte, packet bool) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	if c.ended {
		return 0, io.ErrClosedPipe
	}
	padding, limit := 0, 0x3fff
	if c.version >= 4 {
		if c.w == nil {
			var random [1]byte
			if _, err := rand.Read(random[:]); err != nil {
				return 0, err
			}
			padding = 256 + int(random[0])
			c.limit = 1460 - 55 - padding
		} else if time.Since(c.lastWrite) >= 31*time.Second {
			c.limit = 1460 - 39
		}
		limit = c.limit
	}
	if packet && len(b) > limit {
		return 0, errors.New("Snell datagram exceeds current record capacity")
	}
	if len(b) == 0 {
		return 0, nil
	}
	c.limit = min(0x3fff, limit+1421)
	c.lastWrite = time.Now()
	written := 0
	for len(b) > 0 {
		n := min(len(b), limit)
		if err := c.record(b[:n], padding); err != nil {
			c.werr = err
			return written, err
		}
		padding = 0
		b = b[n:]
		written += n
	}
	return written, nil
}
func (c *snellConn) Write(b []byte) (int, error) { return c.write(b, false) }
func (c *snellConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.ended {
		return c.werr
	}
	c.ended = true
	if c.werr == nil {
		c.werr = c.record(nil, 0)
	}
	return c.werr
}

type snellReplyConn struct {
	*snellConn
	once sync.Once
	err  error
}

func (c *snellReplyConn) response() error {
	c.once.Do(func() {
		var response [1]byte
		_, c.err = io.ReadFull(c.snellConn, response[:])
		if c.err == nil && response[0] != 0 {
			c.err = fmt.Errorf("Snell request rejected: %d", response[0])
		}
	})
	return c.err
}
func (c *snellReplyConn) Read(b []byte) (int, error) {
	if err := c.response(); err != nil {
		return 0, err
	}
	return c.snellConn.Read(b)
}

func snellClient(c net.Conn, o Outbound, address string, udp bool, replay *replayWindow) (net.Conn, error) {
	return snellClientStream(newSnellConn(c, o.Password, o.Version, replay), o, address, udp)
}
func snellClientStream(stream *snellConn, o Outbound, address string, udp bool) (net.Conn, error) {
	header := []byte{1, 6, 0}
	if !udp {
		host, portText, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || len(host) == 0 || len(host) > 255 || port == 0 {
			return nil, errors.New("invalid Snell destination")
		}
		cmd := byte(1)
		if stream.version == 2 || stream.version >= 4 {
			cmd = 5
		}
		header = append([]byte{1, cmd, 0, byte(len(host))}, host...)
		header = binary.BigEndian.AppendUint16(header, uint16(port))
	}
	if err := writeAll(stream, header); err != nil {
		return nil, err
	}
	reply := &snellReplyConn{snellConn: stream}
	if !udp {
		return reply, nil
	}
	if stream.version < 3 {
		return nil, errors.New("Snell UDP requires version 3 or later")
	}
	if err := reply.response(); err != nil {
		return nil, err
	}
	return &snellPacketConn{snellReplyConn: reply, address: address}, nil
}

type snellPacketConn struct {
	*snellReplyConn
	address string
	mu      sync.Mutex
}

func (c *snellPacketConn) Write(b []byte) (int, error) {
	return c.writePacket(b, c.address)
}
func (c *snellPacketConn) writePacket(b []byte, address string) (int, error) {
	addr, err := encodeAddress(address)
	if err != nil {
		return 0, err
	}
	header := []byte{1}
	switch addr[0] {
	case 1:
		header = append(header, 0, 4)
	case 4:
		header = append(header, 0, 6)
	case 3:
	default:
		return 0, errors.New("invalid Snell address type")
	}
	header = append(header, addr[1:]...)
	_, err = c.snellConn.write(append(header, b...), true)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (c *snellPacketConn) Read(b []byte) (int, error) {
	n, _, err := c.readPacket(b)
	return n, err
}
func (c *snellPacketConn) readPacket(b []byte) (int, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rmu.Lock()
	defer c.rmu.Unlock()
	frame, err := c.readRecord()
	if err != nil {
		return 0, "", err
	}
	if len(frame) == 0 {
		return 0, "", io.ErrUnexpectedEOF
	}
	if frame[0] == 4 {
		frame[0] = 1
	} else if frame[0] == 6 {
		frame[0] = 4
	} else {
		return 0, "", errors.New("invalid Snell reply address")
	}
	reader := bytes.NewReader(frame)
	address, err := readAddress(reader)
	if err != nil {
		return 0, "", err
	}
	if reader.Len() > len(b) {
		return 0, "", io.ErrShortBuffer
	}
	n, err := io.ReadFull(reader, b[:reader.Len()])
	return n, address, err
}

func (r *Runtime) serveSnell(in Inbound, c net.Conn, q request) error {
	wrapped, err := acceptSnellObfs(c, in)
	if err != nil {
		return err
	}
	stream := newSnellConn(wrapped, in.Password, in.Version, &r.replay)
	for {
		var header [3]byte
		if _, err := io.ReadFull(stream, header[:]); err != nil {
			return err
		}
		if header[0] != 1 || header[1] != 1 && header[1] != 5 && header[1] != 6 {
			return errors.New("invalid Snell request")
		}
		if _, err := io.CopyN(io.Discard, stream, int64(header[2])); err != nil {
			return err
		}
		if header[1] == 6 {
			if stream.version < 3 {
				return errors.New("Snell UDP requires version 3 or later")
			}
			if err := writeAll(stream, []byte{0}); err != nil {
				return err
			}
			_ = c.SetDeadline(time.Time{})
			return r.serveSnellPackets(stream, q)
		}
		var size [1]byte
		if _, err := io.ReadFull(stream, size[:]); err != nil {
			return err
		}
		if size[0] == 0 {
			return errors.New("empty Snell destination")
		}
		dest := make([]byte, int(size[0])+2)
		if _, err := io.ReadFull(stream, dest); err != nil {
			return err
		}
		port := binary.BigEndian.Uint16(dest[len(dest)-2:])
		if port == 0 {
			return errors.New("invalid Snell port")
		}
		q.address = portAddress(string(dest[:len(dest)-2]), port)
		remote, err := r.routeDial(r.ctx, q)
		if err != nil {
			_ = writeAll(stream, []byte{2})
			return err
		}
		if err := writeAll(stream, []byte{0}); err != nil {
			remote.Close()
			return err
		}
		r.relay(stream, remote)
		if header[1] != 5 {
			return nil
		}
		stream.rmu.Lock()
		if stream.rerr != io.EOF {
			stream.rmu.Unlock()
			return stream.rerr
		}
		stream.rerr = nil
		stream.rmu.Unlock()
		stream.wmu.Lock()
		stream.ended = false
		stream.wmu.Unlock()
		_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	}
}
func (r *Runtime) serveSnellPackets(c *snellConn, q request) error {
	flows := newUDPFlows(r)
	defer flows.Close()
	for {
		frame, err := c.readRecord()
		if err != nil {
			return err
		}
		if len(frame) < 2 || frame[0] != 1 {
			return errors.New("invalid Snell datagram")
		}
		var addr []byte
		if frame[1] != 0 {
			addr = append([]byte{3}, frame[1:]...)
		} else {
			if len(frame) < 3 {
				return io.ErrUnexpectedEOF
			}
			switch frame[2] {
			case 4:
				addr = append([]byte{1}, frame[3:]...)
			case 6:
				addr = append([]byte{4}, frame[3:]...)
			default:
				return errors.New("invalid Snell datagram family")
			}
		}
		reader := bytes.NewReader(addr)
		q.address, err = readAddress(reader)
		if err != nil {
			return err
		}
		payload := addr[len(addr)-reader.Len():]
		err = flows.send(q.address, q, payload, func(b []byte, address string) error {
			a, err := encodeAddress(address)
			if err != nil {
				return err
			}
			if a[0] == 3 {
				host, port, _ := net.SplitHostPort(address)
				ips, e := r.resolver.lookupReal(r.ctx, host)
				if e != nil {
					return e
				}
				a, err = encodeAddress(net.JoinHostPort(ips[0].String(), port))
				if err != nil {
					return err
				}
			}
			if a[0] == 1 {
				a[0] = 4
			} else {
				a[0] = 6
			}
			_, err = c.write(append(a, b...), true)
			return err
		})
		if err != nil {
			return err
		}
	}
}
