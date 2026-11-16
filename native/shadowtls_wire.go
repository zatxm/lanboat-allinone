package native

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const shadowRecordLimit = 18432

var errShadowMAC = errors.New("ShadowTLS record authentication failed")

func shadowPort(s string) (uint16, error) {
	n, e := strconv.ParseUint(s, 10, 16)
	if e != nil || n == 0 {
		return 0, errors.New("port must be1-65535")
	}
	return uint16(n), nil
}
func shadowReadRecord(r io.Reader, b []byte) ([]byte, error) {
	if _, e := io.ReadFull(r, b[:5]); e != nil {
		return nil, e
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if n == 0 || n > shadowRecordLimit || b[1] != 3 || b[2] > 4 || b[0] < 20 || b[0] > 23 {
		return nil, errors.New("invalid ShadowTLS record")
	}
	_, e := io.ReadFull(r, b[5:5+n])
	return b[:5+n], e
}
func shadowFrame(kind byte, body []byte) []byte {
	b := make([]byte, 5+len(body))
	b[0], b[1], b[2] = kind, 3, 3
	binary.BigEndian.PutUint16(b[3:5], uint16(len(body)))
	copy(b[5:], body)
	return b
}
func shadowMAC(password string, seed []byte) hash.Hash {
	h := hmac.New(sha1.New, []byte(password))
	h.Write(seed)
	return h
}
func shadowSum(h hash.Hash, n int) []byte { var b [20]byte; return h.Sum(b[:0])[:n] }
func shadowProbe(h hash.Hash, body []byte) (hash.Hash, bool) {
	if len(body) < 4 {
		return nil, false
	}
	copy, e := h.(hash.Cloner).Clone()
	if e != nil {
		panic(e)
	}
	copy.Write(body[4:])
	return copy, hmac.Equal(body[:4], shadowSum(copy, 4))
}
func shadowHello(r io.Reader) (wire, hello []byte, err error) {
	var b [5 + shadowRecordLimit]byte
	for i := 0; i < 16; i++ {
		frame, e := shadowReadRecord(r, b[:])
		if e != nil {
			return nil, nil, e
		}
		if frame[0] != 22 {
			return nil, nil, errors.New("ShadowTLS requires ClientHello")
		}
		wire = append(wire, frame...)
		hello = append(hello, frame[5:]...)
		if len(hello) > 65536 {
			return nil, nil, errors.New("ShadowTLS ClientHello exceeds64KiB")
		}
		if len(hello) >= 4 {
			size := 4 + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
			if size < len(hello) || hello[0] != 1 {
				return nil, nil, errors.New("invalid ShadowTLS ClientHello")
			}
			if size == len(hello) {
				return wire, hello, nil
			}
		}
	}
	return nil, nil, errors.New("too many ShadowTLS ClientHello fragments")
}
func shadowSession(hello []byte) ([]byte, error) {
	if len(hello) < 39 || hello[0] != 1 || hello[38] != 32 || len(hello) < 71 {
		return nil, errors.New("ShadowTLS3 requires32byte ClientHello session ID")
	}
	return hello[39:71], nil
}
func shadowHelloAuth(hello []byte, password string) bool {
	sid, e := shadowSession(hello)
	if e != nil {
		return false
	}
	h := shadowMAC(password, nil)
	h.Write(hello[:67])
	h.Write([]byte{0, 0, 0, 0})
	h.Write(hello[71:])
	return subtle.ConstantTimeCompare(sid[28:], shadowSum(h, 4)) == 1
}
func shadowServerHello(body []byte) (random []byte, version uint16, err error) {
	if len(body) < 42 || body[0] != 2 {
		return nil, 0, errors.New("invalid ShadowTLS ServerHello")
	}
	random = body[6:38]
	version = binary.BigEndian.Uint16(body[4:6])
	p := 39 + int(body[38])
	if p+3 > len(body) {
		return nil, 0, errors.New("truncated ShadowTLS ServerHello")
	}
	p += 3
	if p == len(body) {
		return random, version, nil
	}
	if p+2 > len(body) || int(binary.BigEndian.Uint16(body[p:])) != len(body)-p-2 {
		return nil, 0, errors.New("invalid ServerHello extensions")
	}
	p += 2
	for p < len(body) {
		if p+4 > len(body) {
			return nil, 0, io.ErrUnexpectedEOF
		}
		kind, n := binary.BigEndian.Uint16(body[p:]), int(binary.BigEndian.Uint16(body[p+2:]))
		p += 4
		if p+n > len(body) {
			return nil, 0, io.ErrUnexpectedEOF
		}
		if kind == 43 {
			if n != 2 {
				return nil, 0, errors.New("invalid TLS selected version")
			}
			version = binary.BigEndian.Uint16(body[p:])
		}
		p += n
	}
	return random, version, nil
}

type shadowStream struct {
	net.Conn
	version                         int
	readMAC, writeMAC, handshakeMAC hash.Hash
	readBuf                         []byte
	readPending                     []byte
	writeBuf                        []byte
	firstPrefix                     []byte
	readErr, writeErr               error
	readSum, writeSum               [20]byte
	coverCipher                     *stRecordCipher
	coverRecords, coverBytes        int
	rmu, wmu                        sync.Mutex
}

func (c *shadowStream) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	for len(c.readPending) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		if c.readBuf == nil {
			c.readBuf = make([]byte, 5+shadowRecordLimit)
		}
		frame, e := shadowReadRecord(c.Conn, c.readBuf)
		if e != nil {
			c.readErr = e
			if !errors.Is(e, io.EOF) {
				c.fail(50)
			}
			return 0, e
		}
		body := frame[5:]
		if c.coverCipher != nil && frame[0] == 23 {
			kind, _, err := c.coverCipher.open(frame)
			if err == nil {
				c.coverRecords++
				c.coverBytes += len(frame)
				if (kind != 22 && kind != 21) || c.coverRecords > 32 || c.coverBytes > 1<<20 {
					c.readErr = errors.New("unexpected ShadowTLS cover data")
					c.fail(10)
					return 0, c.readErr
				}
				continue
			}
			c.coverCipher = nil
		}
		if frame[0] == 21 {
			c.readErr = io.EOF
			if len(body) < 2 || body[1] != 0 {
				c.readErr = errors.New("ShadowTLS peer sent TLS alert")
			}
			return 0, c.readErr
		}
		if frame[0] != 23 {
			c.readErr = errors.New("unexpected ShadowTLS data record")
			c.fail(10)
			return 0, c.readErr
		}
		if c.version == 3 {
			if c.handshakeMAC != nil {
				next, ok := shadowProbe(c.handshakeMAC, body)
				if ok {
					c.handshakeMAC = next
					continue
				}
			}
			c.handshakeMAC = nil
			if len(body) < 4 {
				c.readErr = errShadowMAC
				c.fail(20)
				return 0, c.readErr
			}
			c.readMAC.Write(body[4:])
			if !hmac.Equal(body[:4], c.readMAC.Sum(c.readSum[:0])[:4]) {
				c.readErr = errShadowMAC
				c.fail(20)
				return 0, c.readErr
			}
			c.readMAC.Write(body[:4])
			body = body[4:]
		}
		c.readPending = body
	}
	n := copy(b, c.readPending)
	c.readPending = c.readPending[n:]
	return n, nil
}
func (c *shadowStream) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(b) == 0 {
		return 0, nil
	}
	if c.writeBuf == nil {
		c.writeBuf = make([]byte, 5+16384+8)
	}
	n := 0
	for len(b) > 0 {
		prefix := 0
		if c.version == 3 {
			prefix = 4
		} else {
			prefix = len(c.firstPrefix)
		}
		size := min(len(b), 16384-prefix)
		out := c.writeBuf[:5+prefix+size]
		out[0], out[1], out[2] = 23, 3, 3
		binary.BigEndian.PutUint16(out[3:5], uint16(prefix+size))
		copy(out[5+prefix:], b[:size])
		if c.version == 3 {
			c.writeMAC.Write(b[:size])
			copy(out[5:9], c.writeMAC.Sum(c.writeSum[:0])[:4])
			c.writeMAC.Write(out[5:9])
		} else {
			copy(out[5:], c.firstPrefix)
			c.firstPrefix = nil
		}
		if e := writeAll(c.Conn, out); e != nil {
			c.writeErr = e
			return n, e
		}
		n += size
		b = b[size:]
	}
	return n, nil
}

// A malformed peer must not deadlock a blocked application writer.
func (c *shadowStream) fail(reason byte) {
	if c.wmu.TryLock() {
		_ = c.Conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		_ = writeAll(c.Conn, []byte{21, 3, 3, 0, 2, 2, reason})
		c.writeErr = net.ErrClosed
		c.wmu.Unlock()
	}
	c.Conn.Close()
}
func (c *shadowStream) alert(reason byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return c.writeErr
	}
	e := writeAll(c.Conn, []byte{21, 3, 3, 0, 2, 1, reason})
	c.writeErr = e
	if e == nil {
		c.writeErr = net.ErrClosed
	}
	return e
}
func (c *shadowStream) CloseWrite() error {
	if e := c.alert(0); e != nil {
		return e
	}
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}
