package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type xorShift struct{ a, b uint64 }

func (r *xorShift) next() uint64 {
	x, y := r.a, r.b
	r.a = y
	x ^= x << 23
	x ^= y ^ (x >> 17) ^ (y >> 26)
	r.b = x
	return x + y
}
func (r *xorShift) init(data []byte, size int) {
	var seed [16]byte
	copy(seed[:], data)
	if size >= 0 {
		binary.LittleEndian.PutUint16(seed[:], uint16(size))
	}
	r.a = binary.LittleEndian.Uint64(seed[:8])
	r.b = binary.LittleEndian.Uint64(seed[8:])
	if size >= 0 {
		for i := 0; i < 4; i++ {
			r.next()
		}
	}
}

type chainConn struct {
	readErr, writeErr error
	server            bool
	sent              bool
	net.Conn
	mode                                                  string
	userKey, key, clientHash, serverHash, prefix, pending []byte
	enc, dec                                              *rc4.Cipher
	sendID, recvID                                        uint32
	overhead                                              int
	sizes, sizes2                                         []int
	readMu, writeMu                                       sync.Mutex
}

func newSSRChain(stream *ssStreamConn, o Outbound) (net.Conn, error) {
	mode := o.Protocol
	userKey := stream.key.master
	uid := ssrRandom(4)
	if user, password, ok := strings.Cut(o.ProtocolParam, ":"); ok {
		userID, err := strconv.ParseUint(user, 10, 32)
		if err != nil {
			return nil, errors.New("invalid SSR user ID")
		}
		uid = binary.LittleEndian.AppendUint32(nil, uint32(userID))
		userKey = []byte(strings.Split(password, "#")[0])
	}
	conn := &chainConn{Conn: stream, mode: mode, userKey: userKey, key: stream.key.master, sendID: 1, recvID: 1, overhead: 4}
	if strings.HasPrefix(string(o.Obfs), "tls") {
		conn.overhead += 5
	}
	seed := ssrRandom(4)
	mk := append(append([]byte(nil), stream.writeIV...), stream.key.master...)
	conn.clientHash = ssrMAC(md5.New, mk, seed, 16)
	conn.prefix = append(seed, conn.clientHash[:8]...)
	header := binary.LittleEndian.AppendUint16(authIdentity(), uint16(conn.overhead))
	header = append(header, 0, 0)
	block, _ := aes.NewCipher(ssrPasswordKey(base64.StdEncoding.EncodeToString(userKey)+mode, 16))
	encrypted := make([]byte, 16)
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(encrypted, header)
	for i := range uid {
		uid[i] ^= conn.clientHash[8+i]
	}
	identity := append(uid, encrypted...)
	conn.serverHash = ssrMAC(md5.New, userKey, identity, 16)
	conn.prefix = append(conn.prefix, identity...)
	conn.prefix = append(conn.prefix, conn.serverHash[:4]...)
	key := ssrPasswordKey(base64.StdEncoding.EncodeToString(userKey)+base64.StdEncoding.EncodeToString(conn.clientHash), 16)
	conn.enc, _ = rc4.NewCipher(key)
	conn.dec, _ = rc4.NewCipher(key)
	conn.initSizes(o.ProtocolParam)
	return conn, nil
}
func (c *chainConn) initSizes(param string) {
	if c.mode == "auth_chain_a" {
		return
	}
	key := append([]byte(nil), c.key...)
	if c.mode == "auth_chain_f" {
		interval := uint64(86400)
		if _, text, ok := strings.Cut(param, "#"); ok {
			if v, err := strconv.ParseUint(text, 10, 64); err == nil && v > 0 {
				interval = v
			}
		}
		epoch := uint64(time.Now().Unix()) / interval
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], epoch)
		for i := range b {
			key[i] ^= b[i]
		}
	}
	r := xorShift{}
	r.init(key, -1)
	generate := func(length int) []int {
		list := make([]int, length)
		for i := range list {
			list[i] = int(r.next() % 2340 % 2040 % 1440)
		}
		sort.Ints(list)
		return list
	}
	if c.mode == "auth_chain_b" {
		c.sizes = generate(int(r.next()%8 + 4))
		c.sizes2 = generate(int(r.next()%16 + 8))
		return
	}
	c.sizes = generate(int(r.next()%24 + 12))
	if c.mode == "auth_chain_d" || c.mode == "auth_chain_e" || c.mode == "auth_chain_f" {
		for c.sizes[len(c.sizes)-1] < 1300 && len(c.sizes) < 64 {
			c.sizes = append(c.sizes, int(r.next()%2340%2040%1440))
		}
		sort.Ints(c.sizes)
	}
}
func chainRandomLength(size int, r *xorShift) int {
	if size > 1440 {
		return 0
	}
	switch {
	case size > 1300:
		return int(r.next() % 31)
	case size > 900:
		return int(r.next() % 127)
	case size > 400:
		return int(r.next() % 521)
	default:
		return int(r.next() % 1021)
	}
}
func (c *chainConn) padding(size int, lastHash []byte) (int, int) {
	r := xorShift{}
	length := 0
	if c.mode == "auth_chain_a" {
		if size <= 1440 {
			r.init(lastHash, size)
			length = chainRandomLength(size, &r)
		}
	} else if c.mode == "auth_chain_b" {
		if size < 1440 {
			r.init(lastHash, size)
			pos := sort.SearchInts(c.sizes, size+c.overhead)
			index := pos + int(r.next()%uint64(len(c.sizes)))
			if index < len(c.sizes) {
				length = c.sizes[index] - size - c.overhead
			} else {
				pos = sort.SearchInts(c.sizes2, size+c.overhead)
				index = pos + int(r.next()%uint64(len(c.sizes2)))
				if index < len(c.sizes2) {
					length = c.sizes2[index] - size - c.overhead
				} else if index >= pos+len(c.sizes2)-1 {
					length = chainRandomLength(size, &r)
				}
			}
		}
	} else {
		other := size + c.overhead
		if c.mode == "auth_chain_c" || c.mode == "auth_chain_e" || c.mode == "auth_chain_f" {
			r.init(lastHash, size)
		}
		if other >= c.sizes[len(c.sizes)-1] {
			if c.mode == "auth_chain_c" {
				length = chainRandomLength(size, &r)
			}
		} else {
			if c.mode == "auth_chain_d" {
				r.init(lastHash, size)
			}
			pos := sort.SearchInts(c.sizes, other)
			index := pos
			if c.mode != "auth_chain_e" && c.mode != "auth_chain_f" {
				index += int(r.next() % uint64(len(c.sizes)-pos))
			}
			length = c.sizes[index] - other
		}
	}
	position := 0
	if length > 0 {
		position = int(r.next() % 8589934609 % uint64(length))
	}
	return length, position
}
func (c *chainConn) Write(b []byte) (int, error) {
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
func (c *chainConn) write(b []byte) (int, error) {
	written := 0
	extra := 0
	if c.server && !c.sent && len(b) > 0 {
		p := binary.LittleEndian.AppendUint16(nil, 1460)
		b = append(p, b...)
		extra = 2
		c.sent = true
	}
	for len(b) > 0 {
		n := min(len(b), 1200)
		padding, position := c.padding(n, c.clientHash)
		out := binary.LittleEndian.AppendUint16(nil, uint16(n)^binary.LittleEndian.Uint16(c.clientHash[14:]))
		random := ssrRandom(padding)
		out = append(out, random[:position]...)
		start := len(out)
		out = append(out, make([]byte, n)...)
		c.enc.XORKeyStream(out[start:], b[:n])
		out = append(out, random[position:]...)
		if c.sendID == 0 {
			return max(0, written-extra), errors.New("SSR chain send counter exhausted")
		}
		key := binary.LittleEndian.AppendUint32(append([]byte(nil), c.userKey...), c.sendID)
		c.sendID++
		c.clientHash = ssrMAC(md5.New, key, out, 16)
		out = append(out, c.clientHash[:2]...)
		if len(c.prefix) > 0 {
			out = append(c.prefix, out...)
			c.prefix = nil
		}
		if err := writeAll(c.Conn, out); err != nil {
			return max(0, written-extra), err
		}
		written += n
		b = b[n:]
	}
	return max(0, written-extra), nil
}
func (c *chainConn) Read(b []byte) (int, error) {
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
func (c *chainConn) read(b []byte) (int, error) {
	for len(c.pending) == 0 {
		var h [2]byte
		if _, err := io.ReadFull(c.Conn, h[:]); err != nil {
			return 0, err
		}
		size := int(binary.LittleEndian.Uint16(h[:]) ^ binary.LittleEndian.Uint16(c.serverHash[14:]))
		padding, position := c.padding(size, c.serverHash)
		if size+padding >= 4096 {
			return 0, errors.New("invalid SSR chain frame")
		}
		frame := make([]byte, 2+size+padding+2)
		copy(frame, h[:])
		if _, err := io.ReadFull(c.Conn, frame[2:]); err != nil {
			return 0, err
		}
		if c.recvID == 0 {
			return 0, errors.New("SSR receive counter exhausted")
		}
		key := binary.LittleEndian.AppendUint32(append([]byte(nil), c.userKey...), c.recvID)
		hash := ssrMAC(md5.New, key, frame[:len(frame)-2], 16)
		if !hmac.Equal(hash[:2], frame[len(frame)-2:]) {
			return 0, errors.New("SSR chain authentication failed")
		}
		c.serverHash = hash
		data := frame[2+position : 2+position+size]
		c.dec.XORKeyStream(data, data)
		if c.recvID == 1 && !c.server {
			if len(data) < 2 {
				return 0, io.ErrUnexpectedEOF
			}
			data = data[2:]
		}
		c.recvID++
		c.pending = data
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}
