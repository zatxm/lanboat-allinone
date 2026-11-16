package native

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

const visionFlow = "xtls-rprx-vision"

func validateVision(kind, flow string, tls TLSOptions, transport Transport, mux bool, plugin string) error {
	if flow == "" {
		return nil
	}
	if (kind != "vless" && kind != "trojan") || flow != visionFlow {
		return errors.New("flow supports VLESS or Lanboat Trojan xtls-rprx-vision")
	}
	if !tls.Enabled || tls.MaxVersion != "" && tls.MaxVersion != "1.3" {
		return errors.New("Vision requires TLS1.3")
	}
	if tls.KernelTX || tls.KernelRX {
		return errors.New("Vision raw bypass cannot use a kernel TLS socket")
	}
	if transport.Type != "" || plugin != "" || mux {
		return errors.New("Vision requires raw TLS transport; TCP multiplex is not supported")
	}
	return nil
}
func hasVision(in Inbound) bool {
	for _, u := range in.Users {
		if u.Flow != "" {
			return true
		}
	}
	return false
}

// Limit TLS read-ahead to the current record. After the last padded frame there
// are no private TLS buffers to recover when changing to the underlying stream.
type visionRecordConn struct {
	net.Conn
	header              [5]byte
	position, remaining int
	direct              atomic.Bool
}

func (c *visionRecordConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if c.direct.Load() {
		return c.Conn.Read(b)
	}
	if c.position < 5 {
		n, e := c.Conn.Read(b[:min(len(b), 5-c.position)])
		copy(c.header[c.position:], b[:n])
		c.position += n
		if c.position == 5 {
			c.remaining = int(binary.BigEndian.Uint16(c.header[3:]))
			if c.remaining > 18432 {
				return n, errors.New("Vision outer TLS record exceeds limit")
			}
			if c.remaining == 0 {
				c.position = 0
			}
		}
		return n, e
	}
	n, e := c.Conn.Read(b[:min(len(b), c.remaining)])
	c.remaining -= n
	if c.remaining == 0 {
		c.position = 0
	}
	return n, e
}
func (c *visionRecordConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

type visionState struct{ tls, tls13 atomic.Bool }
type visionProbe struct {
	header                  [5]byte
	position, remaining     int
	typeID                  byte
	bad, application        bool
	handshake               [4]byte
	hsPosition, hsRemaining int
	hello                   []byte
	observed                int
}

func (p *visionProbe) observe(b []byte, s *visionState) bool {
	app := false
	for len(b) > 0 && !p.bad {
		if p.position < 5 {
			n := copy(p.header[p.position:], b)
			p.position += n
			b = b[n:]
			if p.position < 5 {
				break
			}
			p.typeID = p.header[0]
			p.remaining = int(binary.BigEndian.Uint16(p.header[3:]))
			if p.typeID < 20 || p.typeID > 23 || p.header[1] != 3 || p.header[2] > 3 || p.remaining == 0 || p.remaining > 18432 {
				p.bad = true
				break
			}
		}
		n := min(len(b), p.remaining)
		if p.typeID == 22 && p.observed < 65536 {
			p.inspect(b[:n], s)
			p.observed += n
		}
		b = b[n:]
		p.remaining -= n
		if p.remaining == 0 {
			if p.typeID == 23 {
				app = true
			}
			p.position = 0
		}
	}
	return app && p.position == 0 && !p.bad
}
func (p *visionProbe) inspect(b []byte, s *visionState) {
	for len(b) > 0 {
		if p.hsPosition < 4 {
			n := copy(p.handshake[p.hsPosition:], b)
			p.hsPosition += n
			b = b[n:]
			if p.hsPosition < 4 {
				return
			}
			p.hsRemaining = int(p.handshake[1])<<16 | int(p.handshake[2])<<8 | int(p.handshake[3])
			if p.hsRemaining > 65536 || p.hsRemaining == 0 {
				p.observed = 65536
				return
			}
			if p.handshake[0] == 1 {
				s.tls.Store(true)
			}
		}
		n := min(len(b), p.hsRemaining)
		if p.handshake[0] == 2 && len(p.hello)+p.hsRemaining <= 65536 {
			p.hello = append(p.hello, b[:n]...)
		}
		p.hsRemaining -= n
		b = b[n:]
		if p.hsRemaining == 0 {
			if p.handshake[0] == 2 {
				if visionServerHello(p.hello) {
					s.tls.Store(true)
					s.tls13.Store(true)
				}
				p.hello = nil
			}
			p.hsPosition = 0
		}
	}
}
func visionServerHello(b []byte) bool {
	if len(b) < 38 || b[0] != 3 || b[1] != 3 {
		return false
	}
	// RFC8446 HelloRetryRequest cannot authorize a switch before the real hello.
	hrr := [32]byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}
	if bytes.Equal(b[2:34], hrr[:]) {
		return false
	}
	pos := 35 + int(b[34])
	if pos+5 > len(b) || b[34] > 32 {
		return false
	}
	cipher := binary.BigEndian.Uint16(b[pos:])
	if cipher < 0x1301 || cipher > 0x1304 || b[pos+2] != 0 {
		return false
	}
	n := int(binary.BigEndian.Uint16(b[pos+3:]))
	b = b[pos+5:]
	if n != len(b) {
		return false
	}
	selected := false
	for len(b) > 0 {
		if len(b) < 4 {
			return false
		}
		kind := binary.BigEndian.Uint16(b)
		n = int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if n > len(b) {
			return false
		}
		if kind == 43 {
			if selected || n != 2 || b[0] != 3 || b[1] != 4 {
				return false
			}
			selected = true
		}
		b = b[n:]
	}
	return selected
}

type visionConn struct {
	net.Conn
	raw                          *visionRecordConn
	id                           [16]byte
	state                        visionState
	readMu, writeMu              sync.Mutex
	reader, writer               visionProbe
	firstRead, firstWrite        bool
	uuidPosition, headerPosition int
	uuid                         [16]byte
	header                       [5]byte
	paddingBuffer                [256]byte
	content, padding             int
	command                      byte
	readEnd, writeEnd            bool
	readDirect, writeDirect      atomic.Bool
	writeClosed                  bool
	readErr, writeErr            error
	buffer                       []byte
}

func visionTransport(c net.Conn) (*visionRecordConn, error) {
	for {
		switch v := c.(type) {
		case *bufferedConn:
			c = v.Conn
		case *vlessConn:
			c = v.Conn
		case *controllerConn:
			c = v.Conn
		case *controllerWireConn:
			c = v.Conn
		case *ownedConn:
			c = v.Conn
		case *tls.Conn:
			if v.ConnectionState().Version != tls.VersionTLS13 {
				return nil, errors.New("Vision negotiated TLS version is not1.3")
			}
			raw, ok := v.NetConn().(*visionRecordConn)
			if !ok {
				return nil, errors.New("Vision TLS record boundary adapter missing")
			}
			return raw, nil
		case *realityConn:
			c = v.NetConn()
		case *kernelTLSHandshake:
			secure := v.secure.Load()
			if secure == nil {
				return nil, errors.New("Vision TLS handshake incomplete")
			}
			c = *secure
		case *tlsRecordFragmentConn:
			c = v.Conn
		case *tlsFragmentConn:
			c = v.Conn
		case *visionRecordConn:
			return v, nil
		default:
			return nil, errors.New("Vision requires a direct TLS connection")
		}
	}
}
func newVisionConn(c net.Conn, id [16]byte) (*visionConn, error) {
	raw, e := visionTransport(c)
	if e != nil {
		return nil, e
	}
	return &visionConn{Conn: c, raw: raw, id: id, firstRead: true, firstWrite: true}, nil
}
func (c *visionConn) failRead(e error) (int, error) { c.readErr = e; c.raw.Close(); return 0, e }
func (c *visionConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	for frames := 0; frames < 64; frames++ {
		if c.readDirect.Load() {
			return c.raw.Read(b)
		}
		if c.readEnd {
			n, e := c.Conn.Read(b)
			c.reader.observe(b[:n], &c.state)
			return n, e
		}
		if c.firstRead {
			for c.uuidPosition < 16 {
				n, e := c.Conn.Read(c.uuid[c.uuidPosition:])
				c.uuidPosition += n
				if e != nil {
					return 0, e
				}
				if n == 0 {
					return 0, io.ErrNoProgress
				}
			}
			if c.uuid != c.id {
				return c.failRead(errors.New("Vision UUID mismatch"))
			}
			c.firstRead = false
		}
		for c.headerPosition < 5 {
			n, e := c.Conn.Read(c.header[c.headerPosition:])
			c.headerPosition += n
			if c.headerPosition == 5 {
				c.command = c.header[0]
				if c.command > 2 {
					return c.failRead(errors.New("invalid Vision command"))
				}
				c.content = int(binary.BigEndian.Uint16(c.header[1:]))
				c.padding = int(binary.BigEndian.Uint16(c.header[3:]))
			}
			if e != nil {
				return 0, e
			}
			if n == 0 {
				return 0, io.ErrNoProgress
			}
		}

		if c.content > 0 {
			n, e := c.Conn.Read(b[:min(len(b), c.content)])
			c.content -= n
			c.reader.observe(b[:n], &c.state)
			return n, e
		}
		for c.padding > 0 {
			n, e := c.Conn.Read(c.paddingBuffer[:min(len(c.paddingBuffer), c.padding)])
			c.padding -= n
			if e != nil {
				return 0, e
			}
			if n == 0 {
				return 0, io.ErrNoProgress
			}
		}
		switch c.command {
		case 1:
			c.readEnd = true
		case 2:
			if !c.state.tls13.Load() {
				return c.failRead(errors.New("Vision direct switch without TLS1.3 ServerHello"))
			}
			if c.raw.position != 0 || c.raw.remaining != 0 {
				return c.failRead(errors.New("Vision switch is not at an outer TLS record boundary"))
			}
			c.raw.direct.Store(true)
			c.readDirect.Store(true)
		}
		c.headerPosition = 0
	}
	return c.failRead(errors.New("too many empty Vision frames"))
}
func (c *visionConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(b) == 0 {
		return 0, nil
	}
	if c.writeDirect.Load() {
		return c.raw.Write(b)
	}
	if c.writeEnd {
		return c.Conn.Write(b)
	}
	complete := c.writer.observe(b, &c.state)
	command := byte(0)
	if complete {
		if c.state.tls13.Load() {
			command = 2
		} else {
			command = 1
		}
	} else if c.writer.bad || c.writer.observed >= 65536 {
		command = 1
	}
	sent := 0
	for len(b) > 0 {
		n := min(len(b), 16000)
		last := n == len(b)
		cmd := byte(0)
		if last {
			cmd = command
		}
		var random [2]byte
		rand.Read(random[:])
		pad := int(binary.BigEndian.Uint16(random[:]) & 255)
		if c.firstWrite && n < 900 {
			pad += 900 - n
		}
		c.buffer = c.buffer[:0]
		if c.firstWrite {
			c.buffer = append(c.buffer, c.id[:]...)
		}
		c.buffer = append(c.buffer, cmd)
		c.buffer = binary.BigEndian.AppendUint16(c.buffer, uint16(n))
		c.buffer = binary.BigEndian.AppendUint16(c.buffer, uint16(pad))
		c.buffer = append(c.buffer, b[:n]...)
		start := len(c.buffer)
		c.buffer = append(c.buffer, make([]byte, pad)...)
		rand.Read(c.buffer[start:])
		if e := writeAll(c.Conn, c.buffer); e != nil {
			c.writeErr = e
			c.raw.Close()
			return sent, e
		}
		c.firstWrite = false
		sent += n
		b = b[n:]
		if cmd != 0 {
			c.writeEnd = true
			if cmd == 2 {
				c.writeDirect.Store(true)
			}
			c.buffer = nil
		}
	}
	return sent, nil
}
func (c *visionConn) Close() error { return c.raw.Close() }
func (c *visionConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true
	if c.writeDirect.Load() {
		return c.raw.CloseWrite()
	}
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func readVLESSFlow(r io.Reader, n byte) (string, error) {
	var raw [255]byte
	if _, e := io.ReadFull(r, raw[:int(n)]); e != nil {
		return "", e
	}
	b := raw[:int(n)]
	flow := ""
	seenFlow := false
	for len(b) > 0 {
		key, k := binary.Uvarint(b)
		if k <= 0 || key>>3 == 0 {
			return "", errors.New("invalid VLESS addon key")
		}
		b = b[k:]
		if key>>3 == 1 && key&7 != 2 {
			return "", errors.New("invalid VLESS flow wire type")
		}
		switch key & 7 {
		case 0:
			_, k = binary.Uvarint(b)
			if k <= 0 {
				return "", errors.New("invalid VLESS addon value")
			}
			b = b[k:]
		case 2:
			n, k := binary.Uvarint(b)
			if k <= 0 || n > uint64(len(b)-k) {
				return "", errors.New("invalid VLESS addon length")
			}
			b = b[k:]
			if key>>3 == 1 {
				if seenFlow {
					return "", errors.New("duplicate VLESS flow")
				}
				seenFlow = true
				flow = string(b[:int(n)])
			}
			b = b[int(n):]
		case 1, 5:
			n := 8
			if key&7 == 5 {
				n = 4
			}
			if len(b) < n {
				return "", io.ErrUnexpectedEOF
			}
			b = b[n:]
		default:
			return "", errors.New("unsupported VLESS addon wire type")
		}
	}
	if flow != "" && flow != visionFlow {
		return "", errors.New("unsupported VLESS flow")
	}
	return flow, nil
}
