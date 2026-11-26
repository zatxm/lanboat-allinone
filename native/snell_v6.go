package native

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"time"
)

const (
	v6SaltSize         = 16
	v6TagSize          = 16
	v6HeaderPlainSize  = 7
	v6HeaderCipherSize = v6HeaderPlainSize + v6TagSize
	v6MaxPrefixSize    = 128
	v6MaxPayload       = 0xffff
)

type snellV6State struct {
	profile   *v6Profile
	raw       bool
	rseq      uint32
	readEnded bool
	wseq      uint32
	wire      []byte
}

func (c *snellConn) readV6Record() ([]byte, error) {
	v6 := c.v6
	v6.readEnded = false
	var salt []byte
	if !v6.raw && c.r == nil {
		var block [v6SaltSize + v6MaxPrefixSize]byte
		size := v6SaltSize
		if v6.profile != nil {
			size = v6.profile.saltBlockLen
		}
		if _, err := io.ReadFull(c.Conn, block[:size]); err != nil {
			return nil, err
		}
		salt = block[:v6SaltSize]
		if v6.profile != nil {
			decoded := v6.profile.extractSalt(block[:size])
			salt = decoded[:]
		}
		var err error
		c.r, err = c.aead(salt)
		if err != nil {
			return nil, err
		}
	}

	prefixSize, headerSize := 0, v6HeaderCipherSize
	if v6.raw {
		headerSize = v6HeaderPlainSize
	}
	if v6.profile != nil {
		prefixSize = v6.profile.recordPrefixLen(v6.rseq)
	}
	var head [v6MaxPrefixSize + v6HeaderCipherSize]byte
	if _, err := io.ReadFull(c.Conn, head[:prefixSize+headerSize]); err != nil {
		if salt != nil && err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	header := head[prefixSize : prefixSize+headerSize]
	if c.r != nil {
		var err error
		header, err = c.r.Open(header[:0], c.rnonce[:12], header, head[:prefixSize])
		incrementNonce(&c.rnonce)
		if err != nil {
			return nil, err
		}
	}
	paddingSize := int(binary.BigEndian.Uint16(header[3:5]))
	payloadSize := int(binary.BigEndian.Uint16(header[5:7]))
	if header[0] != 4 || v6.profile == nil && (header[1] != 0 || header[2] != 0 || paddingSize != 0) {
		return nil, errors.New("invalid Snell v6 record header")
	}
	tagSize := 0
	if c.r != nil && payloadSize != 0 {
		tagSize = v6TagSize
	}
	size := paddingSize + payloadSize + tagSize
	c.buffer = slices.Grow(c.buffer[:0], size)[:size]
	if _, err := io.ReadFull(c.Conn, c.buffer); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}

	padding, payload := c.buffer[:paddingSize], c.buffer[paddingSize:]
	if tagSize != 0 {
		if v6.profile != nil {
			v6.profile.mixPaddingPayload(v6.rseq, padding, payload)
		}
		var err error
		payload, err = c.r.Open(payload[:0], c.rnonce[:12], payload, padding)
		incrementNonce(&c.rnonce)
		if err != nil {
			return nil, err
		}
	}
	if salt != nil {
		if err := c.replay.add(c.key, salt); err != nil {
			return nil, err
		}
	}
	v6.rseq++
	if payloadSize == 0 {
		v6.readEnded = true
		return nil, io.EOF
	}
	return payload, nil
}

func (c *snellConn) writeV6Record(payload []byte) error {
	v6 := c.v6
	saltSize, prefixSize, paddingSize := 0, 0, 0
	headerSize, tagSize := v6HeaderCipherSize, 0
	switch {
	case v6.raw:
		headerSize = v6HeaderPlainSize
	case c.w == nil && v6.profile != nil:
		saltSize = v6.profile.saltBlockLen
	case c.w == nil:
		saltSize = v6SaltSize
	}
	if v6.profile != nil {
		prefixSize = v6.profile.recordPrefixLen(v6.wseq)
		paddingSize = v6.profile.paddingLen(v6.wseq, len(payload), prefixSize, saltSize)
	}
	if !v6.raw && len(payload) != 0 {
		tagSize = v6TagSize
	}
	size := saltSize + prefixSize + headerSize + paddingSize + len(payload) + tagSize
	out := slices.Grow(v6.wire[:0], size)[:size]
	v6.wire = out

	if saltSize != 0 {
		var salt [v6SaltSize]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return err
		}
		var err error
		c.w, err = c.aead(salt[:])
		if err != nil {
			return err
		}
		if err := c.replay.add(c.key, salt[:]); err != nil {
			return err
		}
		if v6.profile == nil {
			copy(out, salt[:])
		} else {
			v6.profile.fillPadding(^uint32(0), out[:saltSize])
			v6.profile.writeSaltBlock(salt[:], out[:saltSize])
		}
	}
	prefix := out[saltSize : saltSize+prefixSize]
	header := out[saltSize+prefixSize : saltSize+prefixSize+headerSize]
	rest := out[saltSize+prefixSize+headerSize:]
	padding, body := rest[:paddingSize], rest[paddingSize:]
	if v6.profile != nil {
		v6.profile.fillPadding(v6.wseq, prefix)
		v6.profile.fillPadding(v6.wseq, padding)
	}
	header[0], header[1], header[2] = 4, 0, 0
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingSize))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	if c.w != nil {
		c.w.Seal(header[:0], c.wnonce[:12], header[:v6HeaderPlainSize], prefix)
		incrementNonce(&c.wnonce)
	}
	if tagSize != 0 {
		c.w.Seal(body[:0], c.wnonce[:12], payload, padding)
		incrementNonce(&c.wnonce)
		if v6.profile != nil {
			v6.profile.mixPaddingPayload(v6.wseq, padding, body)
		}
	} else {
		copy(body, payload)
	}
	v6.wseq++
	return writeAll(c.Conn, out)
}

func (c *snellConn) v6PayloadLimit(now time.Time) int {
	p := c.v6.profile
	if p == nil {
		return v6MaxPayload
	}
	if c.limit == 0 || now.Unix()-c.lastWrite.Unix() > int64(p.idleResetSec) {
		c.limit = p.chunkInitial
	}
	limit := p.chunkPayloadLimit(c.v6.wseq, c.limit)
	if c.v6.wseq == 0 {
		limit = min(limit, p.firstRecordCap)
	}
	c.limit = p.nextChunkSize(c.limit)
	c.lastWrite = now
	return limit
}

func (c *snellConn) writeV6(b []byte, packet bool) (int, error) {
	if packet && len(b) > v6MaxPayload {
		return 0, errors.New("Snell v6 datagram exceeds record capacity")
	}
	now := time.Now()
	written := 0
	for len(b) > 0 {
		limit := c.v6PayloadLimit(now)
		n := len(b)
		if !packet {
			n = min(n, limit)
		}
		if err := c.writeV6Record(b[:n]); err != nil {
			c.werr = err
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
