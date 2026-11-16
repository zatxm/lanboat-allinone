package native

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

func ssrRandom(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
func ssrMAC(h func() hash.Hash, key, data []byte, n int) []byte {
	m := hmac.New(h, key)
	m.Write(data)
	return m.Sum(nil)[:n]
}
func ssrPasswordKey(password string, n int) []byte {
	var out, previous []byte
	for len(out) < n {
		h := md5.New()
		h.Write(previous)
		h.Write([]byte(password))
		previous = h.Sum(nil)
		out = append(out, previous...)
	}
	return out[:n]
}

type ssrAuthConn struct {
	readErr, writeErr error
	server            bool
	net.Conn
	protocol                       string
	key, iv, userKey, uid, pending []byte
	hash                           func() hash.Hash
	sent                           bool
	sendID, recvID                 uint32
	readMu, writeMu                sync.Mutex
}

func authIdentity() []byte {
	b := binary.LittleEndian.AppendUint32(nil, uint32(time.Now().Unix()))
	b = append(b, ssrRandom(4)...)
	id := binary.LittleEndian.Uint32(ssrRandom(4)) & 0xffffff
	return binary.LittleEndian.AppendUint32(b, id)
}
func (c *ssrAuthConn) encode(data []byte, first bool) ([]byte, error) {
	first = first && !c.server
	if c.protocol == "verify_deflate" {
		var b bytes.Buffer
		w := zlib.NewWriter(&b)
		_, _ = w.Write(data)
		if err := w.Close(); err != nil {
			return nil, err
		}
		compressed := b.Bytes()
		out := binary.BigEndian.AppendUint16(nil, uint16(len(compressed)))
		return append(out, compressed[2:]...), nil
	}
	if c.protocol == "auth_sha1_v4" {
		if first {
			body := append(append([]byte{1}, authIdentity()...), data...)
			size := len(body) + 16
			out := binary.BigEndian.AppendUint16(nil, uint16(size))
			checksum := crc32.ChecksumIEEE(append(append(append([]byte(nil), out...), []byte("auth_sha1_v4")...), c.key...))
			out = binary.LittleEndian.AppendUint32(out, checksum)
			out = append(out, body...)
			return append(out, ssrMAC(sha1.New, append(append([]byte(nil), c.iv...), c.key...), out, 10)...), nil
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(data)+9))
		out = binary.LittleEndian.AppendUint16(out, uint16(crc32.ChecksumIEEE(out)))
		out = append(out, 1)
		out = append(out, data...)
		return binary.LittleEndian.AppendUint32(out, adler32.Checksum(out)), nil
	}
	if strings.HasPrefix(c.protocol, "auth_aes128_") {
		if first {
			header := authIdentity()
			size := 7 + 4 + 16 + 4 + len(data) + 4
			header = binary.LittleEndian.AppendUint16(header, uint16(size))
			header = binary.LittleEndian.AppendUint16(header, 0)
			key := ssrPasswordKey(base64.StdEncoding.EncodeToString(c.userKey)+c.protocol, 16)
			block, _ := aes.NewCipher(key)
			encrypted := make([]byte, 16)
			cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(encrypted, header)
			mk := append(append([]byte(nil), c.iv...), c.key...)
			prefix := ssrRandom(1)
			out := append(prefix, ssrMAC(c.hash, mk, prefix, 6)...)
			identity := append(append([]byte(nil), c.uid...), encrypted...)
			out = append(out, identity...)
			out = append(out, ssrMAC(c.hash, mk, identity, 4)...)
			out = append(out, data...)
			return append(out, ssrMAC(c.hash, c.userKey, out, 4)...), nil
		}
		if c.sendID == 0 {
			return nil, errors.New("SSR send counter exhausted")
		}
		key := binary.LittleEndian.AppendUint32(append([]byte(nil), c.userKey...), c.sendID)
		c.sendID++
		out := binary.LittleEndian.AppendUint16(nil, uint16(len(data)+9))
		out = append(out, ssrMAC(c.hash, key, out, 2)...)
		out = append(out, 1)
		out = append(out, data...)
		return append(out, ssrMAC(c.hash, key, out, 4)...), nil
	}
	return c.legacyEncode(data, first)
}
func (c *ssrAuthConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	n, err := c.write(b)
	if err != nil {
		c.writeErr = err
	}
	return n, err
}
func (c *ssrAuthConn) write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		limit := 8100
		if c.protocol == "verify_deflate" {
			limit = 32000
		}
		if !c.sent {
			limit = min(limit, 64)
		}
		n := min(len(b), limit)
		out, err := c.encode(b[:n], !c.sent)
		if err != nil {
			return written, err
		}
		c.sent = true
		if err = writeAll(c.Conn, out); err != nil {
			return written, err
		}
		written += n
		b = b[n:]
	}
	return written, nil
}
func (c *ssrAuthConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	n, err := c.read(b)
	if err != nil {
		c.readErr = err
	}
	return n, err
}
func (c *ssrAuthConn) read(b []byte) (int, error) {
	for len(c.pending) == 0 {
		var h [2]byte
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(h[:]))
		aesMode := strings.HasPrefix(c.protocol, "auth_aes128_")
		if aesMode {
			size = int(binary.LittleEndian.Uint16(h[:]))
		}
		limit := 8192
		if c.protocol == "verify_deflate" {
			limit = 32768
		}
		if size < 7 || size >= limit {
			return 0, errors.New("invalid SSR frame length")
		}
		frame := make([]byte, size)
		copy(frame, h[:])
		if _, err := io.ReadFull(c.Conn, frame[2:]); err != nil {
			return 0, err
		}
		if c.protocol == "verify_deflate" {
			r, err := zlib.NewReader(io.MultiReader(bytes.NewReader([]byte{0x78, 0x9c}), bytes.NewReader(frame[2:])))
			if err != nil {
				return 0, err
			}
			data, err := io.ReadAll(io.LimitReader(r, 32769))
			r.Close()
			if err != nil || len(data) > 32768 {
				return 0, errors.New("invalid SSR compressed frame")
			}
			c.pending = data
			continue
		}
		if aesMode {
			if c.recvID == 0 {
				return 0, errors.New("SSR receive counter exhausted")
			}
			key := binary.LittleEndian.AppendUint32(append([]byte(nil), c.userKey...), c.recvID)
			if !hmac.Equal(ssrMAC(c.hash, key, h[:], 2), frame[2:4]) || !hmac.Equal(ssrMAC(c.hash, key, frame[:size-4], 4), frame[size-4:]) {
				return 0, errors.New("SSR frame authentication failed")
			}
			c.recvID++
		} else if c.protocol == "auth_sha1_v4" {
			if uint16(crc32.ChecksumIEEE(h[:])) != binary.LittleEndian.Uint16(frame[2:]) || adler32.Checksum(frame[:size-4]) != binary.LittleEndian.Uint32(frame[size-4:]) {
				return 0, errors.New("SSR frame checksum failed")
			}
		} else {
			data, err := c.legacyDecode(frame)
			if err != nil {
				return 0, err
			}
			c.pending = data
			continue
		}
		position := 4 + int(frame[4])
		if frame[4] == 255 {
			if len(frame) < 11 {
				return 0, io.ErrUnexpectedEOF
			}
			padding := binary.BigEndian.Uint16(frame[5:])
			if aesMode {
				padding = binary.LittleEndian.Uint16(frame[5:])
			}
			position = 4 + int(padding)
		}
		if position < 5 || position > size-4 {
			return 0, errors.New("invalid SSR padding")
		}
		c.pending = frame[position : size-4]
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *ssrAuthConn) legacyEncode(data []byte, first bool) ([]byte, error) {
	if c.protocol != "auth_sha1" && c.protocol != "auth_sha1_v2" {
		return nil, errors.New("unknown SSR authentication")
	}
	if !first {
		out := binary.BigEndian.AppendUint16(nil, uint16(len(data)+7))
		out = append(out, 1)
		out = append(out, data...)
		return binary.LittleEndian.AppendUint32(out, adler32.Checksum(out)), nil
	}
	identity := authIdentity()
	crcData := c.key
	if c.protocol == "auth_sha1_v2" {
		identity = ssrRandom(12)
		identity[8] &= 0x7f
		crcData = append([]byte(c.protocol), c.key...)
	}
	out := binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(crcData))
	out = binary.BigEndian.AppendUint16(out, uint16(4+2+1+12+len(data)+10))
	out = append(out, 1)
	out = append(out, identity...)
	out = append(out, data...)
	return append(out, ssrMAC(sha1.New, append(append([]byte(nil), c.iv...), c.key...), out, 10)...), nil
}
func (c *ssrAuthConn) legacyDecode(frame []byte) ([]byte, error) {
	if c.protocol != "auth_sha1" && c.protocol != "auth_sha1_v2" {
		return nil, errors.New("unknown SSR authentication")
	}
	size := len(frame)
	if adler32.Checksum(frame[:size-4]) != binary.LittleEndian.Uint32(frame[size-4:]) {
		return nil, errors.New("SSR frame checksum failed")
	}
	pos := int(frame[2]) + 2
	if c.protocol == "auth_sha1_v2" && frame[2] == 255 {
		if size < 9 {
			return nil, errors.New("invalid SSR padding")
		}
		pos = int(binary.BigEndian.Uint16(frame[3:])) + 2
	}
	if pos < 3 || pos > size-4 {
		return nil, errors.New("invalid SSR padding")
	}
	return frame[pos : size-4], nil
}
