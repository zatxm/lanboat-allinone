package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

func isSS2022(method string) bool { return strings.HasPrefix(method, "2022-") }

func newSS2022Key(method, password string) (*ssKey, error) {
	size := 32
	switch method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
	default:
		return nil, fmt.Errorf("unsupported Shadowsocks2022 method %q", method)
	}
	parts := strings.Split(password, ":")
	if len(parts) > 9 || len(parts) > 1 && method == "2022-blake3-chacha20-poly1305" {
		return nil, errors.New("Shadowsocks2022 identity chains require AES and at most8 identity keys")
	}
	k := &ssKey{method: method}
	for i, part := range parts {
		if len(part) != base64.StdEncoding.EncodedLen(size) {
			return nil, fmt.Errorf("Shadowsocks2022 PSK must encode exactly%d bytes in base64", size)
		}
		key, err := base64.StdEncoding.Strict().DecodeString(part)
		if err != nil || len(key) != size {
			return nil, fmt.Errorf("Shadowsocks2022 PSK must encode exactly%d bytes in base64", size)
		}
		if i == len(parts)-1 {
			k.master = key
		} else {
			k.identities = append(k.identities, key)
		}
	}
	if method == "2022-blake3-chacha20-poly1305" {
		k.udpAEAD, _ = newChaChaAEAD(k.master, true)
	} else {
		k.udpBlock, _ = aes.NewCipher(k.master)
		for _, key := range k.identities {
			block, _ := aes.NewCipher(key)
			k.identityBlocks = append(k.identityBlocks, block)
		}
	}
	return k, nil
}

func newSSInboundKey(in Inbound) (*ssKey, error) {
	if len(in.Destinations) > 0 {
		if in.Method != "2022-blake3-aes-128-gcm" && in.Method != "2022-blake3-aes-256-gcm" || len(in.Users) > 0 {
			return nil, errors.New("Shadowsocks2022 relay requires AES and destinations without users")
		}
		if timeout, err := optionDuration(in.UDPTimeout, time.Minute); err != nil || timeout < time.Minute {
			return nil, errors.New("Shadowsocks2022 relay udp_timeout must be at least1m")
		}
	}
	k, err := newSSKey(in.Method, in.Password)
	if err != nil || !isSS2022(in.Method) {
		return k, err
	}
	count := len(in.Users) + len(in.Destinations)
	if len(k.identities) != 0 || count > 1024 {
		return nil, errors.New("Shadowsocks2022 inbound uses one PSK and at most1024 users or destinations")
	}
	if count > 0 {
		if in.Method == "2022-blake3-chacha20-poly1305" {
			return nil, errors.New("Shadowsocks2022 multi-user identity headers require AES")
		}
		k.users = make(map[[16]byte]*ssKey, count)
		for i := range count {
			var name, password, address string
			if len(in.Users) > 0 {
				name, password = in.Users[i].Name, in.Users[i].Password
			} else {
				d := in.Destinations[i]
				name, password, address = d.Name, d.Password, portAddress(d.Server, d.ServerPort)
				if _, err := encodeAddress(address); err != nil {
					return nil, fmt.Errorf("Shadowsocks2022 relay destination%d: %w", i, err)
				}
			}
			user, err := newSS2022Key(in.Method, password)
			if err != nil || len(user.identities) > 0 {
				return nil, errors.New("Shadowsocks2022 users and destinations require a single valid PSK")
			}
			hash := blake3Sum(user.master)
			id := [16]byte(hash[:16])
			if k.users[id] != nil {
				return nil, errors.New("duplicate Shadowsocks2022 identity key")
			}
			user.userName, user.relayAddress = name, address
			k.users[id] = user
		}
	}
	return k, nil
}

func ss2022Derive(key, salt []byte, identity bool) []byte {
	var material [64]byte
	copy(material[:], key)
	copy(material[len(key):], salt)
	context := "shadowsocks 2022 session subkey"
	if identity {
		context = "shadowsocks 2022 identity subkey"
	}
	derived := blake3Derive(context, material[:len(key)+len(salt)])
	return derived[:len(key)]
}

func (k *ssKey) ss2022AEAD(salt []byte) (cipher.AEAD, error) {
	key := ss2022Derive(k.master, salt, false)
	if k.method == "2022-blake3-chacha20-poly1305" {
		return newChaChaAEAD(key, false)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func ss2022Stamp(b []byte, typ byte) error {
	if len(b) < 9 || b[0] != typ {
		return errors.New("invalid Shadowsocks2022 header type")
	}
	stamp := binary.BigEndian.Uint64(b[1:9])
	now := uint64(time.Now().Unix())
	if stamp > now && stamp-now > 30 || now > stamp && now-stamp > 30 {
		return errors.New("Shadowsocks2022 timestamp outside30-second window")
	}
	return nil
}

func ss2022Header(typ byte) []byte {
	return binary.BigEndian.AppendUint64([]byte{typ}, uint64(time.Now().Unix()))
}

type ss2022Cipher struct {
	cipher.AEAD
	nonce [12]byte
	spent bool
}

func (c *ss2022Cipher) advance() {
	for i := range c.nonce {
		c.nonce[i]++
		if c.nonce[i] != 0 {
			return
		}
	}
	c.spent = true
}

func (c *ss2022Cipher) seal(dst, plain []byte) ([]byte, error) {
	if c.spent {
		return nil, errors.New("Shadowsocks2022 nonce exhausted")
	}
	b := c.Seal(dst, c.nonce[:], plain, nil)
	c.advance()
	return b, nil
}

func (c *ss2022Cipher) open(dst, encrypted []byte) ([]byte, error) {
	if c.spent {
		return nil, errors.New("Shadowsocks2022 nonce exhausted")
	}
	b, err := c.Open(dst, c.nonce[:], encrypted, nil)
	c.advance()
	return b, err
}

type ss2022Conn struct {
	net.Conn
	key                 *ssKey
	requestSalt         []byte
	readMu, writeMu     sync.Mutex
	reader, writer      ss2022Cipher
	readErr, writeErr   error
	readBuffer, pending []byte
	writeBuffer         []byte
	readLength          [18]byte
	writeLength         [2]byte
}

func (c *ss2022Conn) initWriter(salt []byte) error {
	var err error
	c.writer.AEAD, err = c.key.ss2022AEAD(salt)
	return err
}

func ss2022Identity(key, salt, next []byte) []byte {
	block, _ := aes.NewCipher(ss2022Derive(key, salt, true))
	hash := blake3Sum(next)
	var header [16]byte
	block.Encrypt(header[:], hash[:16])
	return header[:]
}

func ss2022Client(raw net.Conn, k *ssKey, address string) (net.Conn, error) {
	target, err := encodeAddress(address)
	if err != nil {
		return nil, err
	}
	c := &ss2022Conn{Conn: raw, key: k, requestSalt: make([]byte, len(k.master))}
	if _, err := rand.Read(c.requestSalt); err != nil {
		return nil, err
	}
	if err := c.initWriter(c.requestSalt); err != nil {
		return nil, err
	}
	var random [2]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	padding := 1 + int(binary.BigEndian.Uint16(random[:]))%900
	variable := binary.BigEndian.AppendUint16(target, uint16(padding))
	start := len(variable)
	variable = append(variable, make([]byte, padding)...)
	if _, err := rand.Read(variable[start:]); err != nil {
		return nil, err
	}
	header := binary.BigEndian.AppendUint16(ss2022Header(0), uint16(len(variable)))
	packet := append([]byte(nil), c.requestSalt...)
	for i, identity := range k.identities {
		next := k.master
		if i+1 < len(k.identities) {
			next = k.identities[i+1]
		}
		packet = append(packet, ss2022Identity(identity, c.requestSalt, next)...)
	}
	packet, _ = c.writer.seal(packet, header)
	packet, _ = c.writer.seal(packet, variable)
	if n, err := raw.Write(packet); err != nil || n != len(packet) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return nil, err
	}
	return c, nil
}

func readSS2022Header(raw net.Conn, k *ssKey, client bool, requestSalt []byte) (*ss2022Conn, string, error) {
	size := len(k.master)
	fixed := 11
	identity := 0
	if client {
		fixed += size
	} else if k.users != nil {
		identity = 16
	}
	prefix := make([]byte, size+identity+fixed+16)
	// A single initial read makes incomplete probes fail at the same boundary.
	n, err := raw.Read(prefix)
	if n != len(prefix) {
		return nil, "", errors.New("incomplete Shadowsocks2022 initial header")
	}
	if err != nil {
		return nil, "", err
	}
	salt := prefix[:size]
	if identity != 0 {
		block, _ := aes.NewCipher(ss2022Derive(k.master, salt, true))
		var hash [16]byte
		block.Decrypt(hash[:], prefix[size:size+16])
		k = k.users[hash]
		if k == nil {
			return nil, "", errors.New("unknown Shadowsocks2022 user")
		}
	}
	aead, err := k.ss2022AEAD(salt)
	if err != nil {
		return nil, "", err
	}
	c := &ss2022Conn{Conn: raw, key: k, reader: ss2022Cipher{AEAD: aead}, requestSalt: requestSalt}
	header, err := c.reader.open(nil, prefix[size+identity:])
	typ := byte(0)
	if client {
		typ = 1
	}
	if err != nil {
		return nil, "", err
	}
	if err := ss2022Stamp(header, typ); err != nil {
		return nil, "", err
	}
	if client && subtle.ConstantTimeCompare(requestSalt, header[9:9+size]) != 1 {
		return nil, "", errors.New("Shadowsocks2022 response request-salt mismatch")
	}
	length := int(binary.BigEndian.Uint16(header[len(header)-2:]))
	chunk, err := c.readChunk(length)
	if err != nil {
		return nil, "", err
	}
	if client {
		c.pending = chunk
		return c, "", nil
	}
	reader := bytes.NewReader(chunk)
	address, err := readAddress(reader)
	if err != nil {
		return nil, "", err
	}
	if _, err := encodeAddress(address); err != nil {
		return nil, "", err
	}
	if reader.Len() < 2 {
		return nil, "", errors.New("missing Shadowsocks2022 padding length")
	}
	position := len(chunk) - reader.Len()
	padding := int(binary.BigEndian.Uint16(chunk[position:]))
	position += 2
	if padding > 900 || padding > len(chunk)-position || padding == 0 && position == len(chunk) {
		return nil, "", errors.New("invalid Shadowsocks2022 request padding")
	}
	c.pending = chunk[position+padding:]
	c.requestSalt = append([]byte(nil), salt...)
	return c, address, nil
}

func (c *ss2022Conn) readChunk(length int) ([]byte, error) {
	if cap(c.readBuffer) < length+16 {
		c.readBuffer = make([]byte, length+16)
	}
	b := c.readBuffer[:length+16]
	if _, err := io.ReadFull(c.Conn, b); err != nil {
		return nil, err
	}
	return c.reader.open(b[:0], b)
}

func (c *ss2022Conn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.reader.AEAD == nil {
		header, _, err := readSS2022Header(c.Conn, c.key, true, c.requestSalt)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		c.reader, c.readBuffer, c.pending = header.reader, header.readBuffer, header.pending
	}
	for empty := 0; len(c.pending) == 0; empty++ {
		if empty == 16 {
			c.readErr = errors.New("too many empty Shadowsocks2022 chunks")
			return 0, c.readErr
		}
		_, err := io.ReadFull(c.Conn, c.readLength[:])
		var length []byte
		if err == nil {
			length, err = c.reader.open(c.readLength[:0], c.readLength[:])
		}
		if err == nil {
			c.pending, err = c.readChunk(int(binary.BigEndian.Uint16(length)))
		}
		if err != nil {
			c.readErr = err
			return 0, err
		}
	}
	n := copy(b, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (c *ss2022Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	written := 0
	for len(b) > 0 {
		size := min(65535, len(b))
		if err := c.writeChunk(b[:size]); err != nil {
			c.writeErr = err
			return written, err
		}
		written += size
		b = b[size:]
	}
	return written, nil
}

func (c *ss2022Conn) writeChunk(b []byte) error {
	if cap(c.writeBuffer) < len(b)+128 {
		c.writeBuffer = make([]byte, 0, max(32768+128, len(b)+128))
	}
	packet := c.writeBuffer[:0]
	var header []byte
	if c.writer.AEAD == nil {
		salt := make([]byte, len(c.key.master))
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		if err := c.initWriter(salt); err != nil {
			return err
		}
		header = append(ss2022Header(1), c.requestSalt...)
		header = binary.BigEndian.AppendUint16(header, uint16(len(b)))
		packet = append(packet, salt...)
	} else {
		binary.BigEndian.PutUint16(c.writeLength[:], uint16(len(b)))
		header = c.writeLength[:]
	}
	var err error
	packet, err = c.writer.seal(packet, header)
	if err == nil {
		packet, err = c.writer.seal(packet, b)
	}
	if err != nil {
		return err
	}
	return writeAll(c.Conn, packet)
}

func (c *ss2022Conn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (r *Runtime) serveSS2022(in Inbound, raw net.Conn, q request) error {
	if len(in.Destinations) > 0 {
		return r.serveSS2022Relay(in, raw, q)
	}
	c, address, err := readSS2022Header(raw, r.keys["in:"+in.Tag], false, nil)
	if err != nil {
		return err
	}
	id := "ss2022\x00" + string(c.key.master) + string(c.requestSalt)
	if err := r.replay.claimFor(id, time.Minute); err != nil {
		return err
	}
	q.address = address
	q.metadata.AuthUser = c.key.userName
	remote, err := r.routeDial(r.ctx, q)
	if err != nil {
		return err
	}
	r.relay(c, remote)
	return nil
}
