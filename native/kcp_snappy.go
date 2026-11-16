package native

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"sync"
)

var snappyCRC = crc32.MakeTable(crc32.Castagnoli)

func snappyChecksum(b []byte) uint32 {
	c := crc32.Checksum(b, snappyCRC)
	return (c>>15 | c<<17) + 0xa282ead8
}

func snappyLiteral(out, b []byte) []byte {
	if len(b) == 0 {
		return out
	}
	n := uint32(len(b) - 1)
	if n < 60 {
		out = append(out, byte(n<<2))
	} else {
		size := 1
		for n>>uint(8*size) != 0 {
			size++
		}
		out = append(out, byte((59+size)<<2))
		for i := range size {
			out = append(out, byte(n>>uint(8*i)))
		}
	}
	return append(out, b...)
}
func encodeSnappy(b []byte) []byte {
	out := binary.AppendUvarint(make([]byte, 0, len(b)+10), uint64(len(b)))
	var table [4096]int
	start, pos := 0, 0
	for pos+4 <= len(b) {
		h := (binary.LittleEndian.Uint32(b[pos:]) * 0x1e35a7bd) >> 20
		previous := table[h] - 1
		table[h] = pos + 1
		if previous < 0 || pos-previous > 65535 || binary.LittleEndian.Uint32(b[previous:]) != binary.LittleEndian.Uint32(b[pos:]) {
			pos++
			continue
		}
		out = snappyLiteral(out, b[start:pos])
		length := 4
		for pos+length < len(b) && b[previous+length] == b[pos+length] {
			length++
		}
		offset := pos - previous
		for left := length; left > 0; {
			n := min(left, 64)
			out = append(out, byte((n-1)<<2)|2, byte(offset), byte(offset>>8))
			left -= n
		}
		pos += length
		start = pos
	}
	return snappyLiteral(out, b[start:])
}
func decodeSnappy(b []byte) ([]byte, error) {
	size, n := binary.Uvarint(b)
	if n <= 0 || size > 65536 {
		return nil, errors.New("invalid Snappy block size")
	}
	b = b[n:]
	out := make([]byte, 0, int(size))
	for len(b) > 0 {
		tag := b[0]
		b = b[1:]
		length, offset := 0, 0
		switch tag & 3 {
		case 0:
			length = int(tag>>2) + 1
			if length >= 61 {
				bytes := length - 60
				if len(b) < bytes {
					return nil, io.ErrUnexpectedEOF
				}
				var v uint32
				for i := range bytes {
					v |= uint32(b[i]) << uint(8*i)
				}
				b = b[bytes:]
				if uint64(v)+1 > size {
					return nil, errors.New("invalid Snappy literal length")
				}
				length = int(v) + 1
			}
			if length > len(b) || len(out)+length > int(size) {
				return nil, errors.New("invalid Snappy literal")
			}
			out = append(out, b[:length]...)
			b = b[length:]
			continue
		case 1:
			if len(b) < 1 {
				return nil, io.ErrUnexpectedEOF
			}
			length = 4 + int(tag>>2&7)
			offset = int(tag&0xe0)<<3 | int(b[0])
			b = b[1:]
		case 2:
			if len(b) < 2 {
				return nil, io.ErrUnexpectedEOF
			}
			length = 1 + int(tag>>2)
			offset = int(binary.LittleEndian.Uint16(b))
			b = b[2:]
		case 3:
			if len(b) < 4 {
				return nil, io.ErrUnexpectedEOF
			}
			length = 1 + int(tag>>2)
			v := binary.LittleEndian.Uint32(b)
			if v > 65536 {
				return nil, errors.New("invalid Snappy copy offset")
			}
			offset = int(v)
			b = b[4:]
		}
		if offset == 0 || offset > len(out) || len(out)+length > int(size) {
			return nil, errors.New("invalid Snappy copy")
		}
		for range length {
			out = append(out, out[len(out)-offset])
		}
	}
	if len(out) != int(size) {
		return nil, io.ErrUnexpectedEOF
	}
	return out, nil
}

type kcpSnappyConn struct {
	net.Conn
	rmu, wmu      sync.Mutex
	started, seen bool
	writeErr      error
	read          []byte
	err           error
}

func (c *kcpSnappyConn) Read(b []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(b) == 0 {
		return 0, nil
	}
	if c.err != nil {
		return 0, c.err
	}
	for len(c.read) == 0 {
		var h [4]byte
		if _, e := io.ReadFull(c.Conn, h[:]); e != nil {
			c.err = e
			return 0, e
		}
		n := int(h[1]) | int(h[2])<<8 | int(h[3])<<16
		if n > 131072 {
			c.err = errors.New("Snappy frame exceeds limit")
			return 0, c.err
		}
		payload := make([]byte, n)
		if _, e := io.ReadFull(c.Conn, payload); e != nil {
			c.err = e
			return 0, e
		}
		switch h[0] {
		case 0xff:
			if string(payload) != "sNaPpY" {
				c.err = errors.New("invalid Snappy stream identifier")
			} else {
				c.seen = true
			}
		case 0, 1:
			if !c.seen || n < 4 || h[0] == 1 && n > 65540 {
				c.err = errors.New("short Snappy data frame")
				break
			}
			data := payload[4:]
			if h[0] == 0 {
				data, c.err = decodeSnappy(data)
			}
			if c.err == nil && snappyChecksum(data) != binary.LittleEndian.Uint32(payload) {
				c.err = errors.New("Snappy checksum mismatch")
			}
			if c.err == nil {
				c.read = data
			}
		default:
			if h[0] < 0x80 {
				c.err = errors.New("unsupported Snappy chunk")
			}
		}
		if c.err != nil {
			return 0, c.err
		}
	}
	n := copy(b, c.read)
	c.read = c.read[n:]
	return n, nil
}
func (c *kcpSnappyConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if !c.started {
		if e := writeAll(c.Conn, []byte{0xff, 6, 0, 0, 's', 'N', 'a', 'P', 'p', 'Y'}); e != nil {
			c.writeErr = e
			return 0, e
		}
		c.started = true
	}
	written := 0
	for len(b) > 0 {
		n := min(65536, len(b))
		chunk := b[:n]
		encoded := encodeSnappy(chunk)
		kind := byte(0)
		if len(encoded) >= len(chunk) {
			kind = 1
			encoded = chunk
		}
		size := len(encoded) + 4
		frame := make([]byte, 8, size+4)
		frame[0], frame[1], frame[2], frame[3] = kind, byte(size), byte(size>>8), byte(size>>16)
		binary.LittleEndian.PutUint32(frame[4:], snappyChecksum(chunk))
		frame = append(frame, encoded...)
		if e := writeAll(c.Conn, frame); e != nil {
			c.writeErr = e
			return written, e
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
