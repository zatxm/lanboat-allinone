package native

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const brookSimpleUDPChunk = 65505

func brookSimpleTimestamp(b []byte) error {
	if len(b) < 4 {
		return errors.New("short Brook simple timestamp")
	}
	delta := time.Now().Unix() - int64(binary.BigEndian.Uint32(b))
	if delta < -60 || delta > 60 {
		return errors.New("Brook simple timestamp outside60-second window")
	}
	return nil
}

func brookSimpleHeader(password string, target []byte, udp bool) []byte {
	passwordHash := sha256.Sum256([]byte(password))
	b := make([]byte, 34, 38+len(target))
	copy(b, passwordHash[:])
	binary.BigEndian.PutUint16(b[32:], uint16(4+len(target)))
	stamp := uint32(time.Now().Unix())
	parity := uint32(0)
	if udp {
		parity = 1
	}
	stamp += (stamp ^ parity) & 1
	b = binary.BigEndian.AppendUint32(b, stamp)
	return append(b, target...)
}

func brookReadSimpleHeader(r io.Reader, password string) (string, string, error) {
	var header [34]byte
	if _, e := io.ReadFull(r, header[:]); e != nil {
		return "", "", e
	}
	passwordHash := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(header[:32], passwordHash[:]) != 1 {
		return "", "", errors.New("invalid Brook simple credentials")
	}
	n := int(binary.BigEndian.Uint16(header[32:]))
	if n < 9 || n > 263 {
		return "", "", errors.New("invalid Brook simple destination length")
	}
	var body [263]byte
	if _, e := io.ReadFull(r, body[:n]); e != nil {
		return "", "", e
	}
	if e := brookSimpleTimestamp(body[:n]); e != nil {
		return "", "", e
	}
	reader := bytes.NewReader(body[4:n])
	address, e := readAddress(reader)
	if e != nil || reader.Len() != 0 {
		return "", "", errors.New("invalid Brook simple destination")
	}
	if _, e = encodeAddress(address); e != nil {
		return "", "", e
	}
	network := "tcp"
	if body[3]&1 != 0 {
		network = "udp"
	}
	return network, address, nil
}

func brookSimpleClient(raw net.Conn, o Outbound, target []byte, udp bool) (net.Conn, error) {
	if e := writeAll(raw, brookSimpleHeader(o.Password, target, udp)); e != nil {
		return nil, e
	}
	if udp {
		return &brookSimplePacketConn{Conn: raw}, nil
	}
	return raw, nil
}

func (r *Runtime) serveBrookSimple(in Inbound, raw net.Conn, q request) error {
	network, address, e := brookReadSimpleHeader(raw, in.Password)
	if e != nil {
		return e
	}
	q.network, q.address = network, address
	remote, e := r.routeDial(r.ctx, q)
	if e != nil {
		return e
	}
	if network == "tcp" {
		r.relay(raw, remote)
		return nil
	}
	defer remote.Close()
	raw.SetDeadline(time.Time{})
	return r.relayDatagrams(&brookSimplePacketConn{Conn: raw}, remote, r.udpTimeoutFor(in.Tag, udpTimeout))
}

// Simple packets rely on the authenticated outer QUIC connection, not Brook AEAD.
func brookOpenSimpleDatagram(password string, packet []byte) ([]byte, error) {
	if len(packet) < 41 || len(packet) > 65507 {
		return nil, errors.New("invalid Brook simple datagram length")
	}
	passwordHash := sha256.Sum256([]byte(password))
	if subtle.ConstantTimeCompare(packet[:32], passwordHash[:]) != 1 {
		return nil, errors.New("invalid Brook simple credentials")
	}
	if e := brookSimpleTimestamp(packet[32:]); e != nil {
		return nil, e
	}
	return packet[32:], nil
}

type brookSimplePacketConn struct {
	net.Conn
	readMu, writeMu         sync.Mutex
	header                  [2]byte
	headerPos, payloadPos   int
	readBuffer, writeBuffer []byte
	readErr, writeErr       error
}

func (c *brookSimplePacketConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.headerPos < 2 {
		n, e := io.ReadFull(c.Conn, c.header[c.headerPos:])
		c.headerPos += n
		if e != nil {
			return 0, e
		}
	}
	size := int(binary.BigEndian.Uint16(c.header[:]))
	if size > brookSimpleUDPChunk {
		c.readErr = errors.New("Brook simple UDP record exceeds65505 bytes")
		return 0, c.readErr
	}
	if cap(c.readBuffer) < size {
		c.readBuffer = make([]byte, size)
	}
	c.readBuffer = c.readBuffer[:size]
	n, e := io.ReadFull(c.Conn, c.readBuffer[c.payloadPos:])
	c.payloadPos += n
	if e != nil {
		return 0, e
	}
	c.headerPos, c.payloadPos = 0, 0
	if size > len(b) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, c.readBuffer), nil
}

func (c *brookSimplePacketConn) Write(b []byte) (int, error) {
	if len(b) > brookSimpleUDPChunk {
		return 0, errors.New("Brook simple UDP record exceeds65505 bytes")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if cap(c.writeBuffer) < len(b)+2 {
		c.writeBuffer = make([]byte, len(b)+2)
	}
	frame := c.writeBuffer[:len(b)+2]
	binary.BigEndian.PutUint16(frame, uint16(len(b)))
	copy(frame[2:], b)
	position := 0
	for position < len(frame) {
		n, e := c.Conn.Write(frame[position:])
		position += n
		if e == nil && n == 0 {
			e = io.ErrNoProgress
		}
		if e != nil {
			if position > 0 {
				c.writeErr = e
			}
			return 0, e
		}
	}
	return len(b), nil
}
