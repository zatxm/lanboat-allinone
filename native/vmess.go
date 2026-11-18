package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"hash/fnv"
	"io"
	"net"
	"sync"
	"time"
)

type vmessUser struct {
	command [16]byte
	id      [16]byte
	legacy  bool
	auth    cipher.Block
}

var errVMessChunkTooLarge = errors.New("VMess datagram exceeds chunk capacity")

func newVMessUser(uuid string) (vmessUser, error) {
	id, err := parseUUID(uuid)
	if err != nil {
		return vmessUser{}, err
	}
	key := md5.Sum(append(id[:], "c48619fe-8f02-49e0-b9e9-edf763e17e21"...))
	auth, err := aes.NewCipher(vmessKDF(key[:], []byte("AES Auth ID Encryption"))[:16])
	return vmessUser{command: key, id: id, auth: auth}, err
}

// vmessKDF is VMess's nested HMAC: HMAC-SHA256 keyed "VMess AEAD KDF", with
// each path element keying another HMAC layer over the previous one.
func vmessKDF(key []byte, path ...[]byte) []byte {
	sum := vmessKDFLevel(path, len(path)-1, key)
	return sum[:]
}

// vmessKDFLevel evaluates the HMAC layer keyed by path[level] (level -1 is the
// base HMAC-SHA256) without allocating hash objects; every layer has the
// SHA-256 block size, as with crypto/hmac.
func vmessKDFLevel(path [][]byte, level int, message []byte) [sha256.Size]byte {
	var pad [sha256.BlockSize]byte
	if level < 0 {
		copy(pad[:], "VMess AEAD KDF")
	} else if label := path[level]; len(label) > sha256.BlockSize {
		sum := vmessKDFLevel(path, level-1, label)
		copy(pad[:], sum[:])
	} else {
		copy(pad[:], label)
	}
	var stack [512]byte
	buffer := stack[:0]
	for i := range pad {
		pad[i] ^= 0x36
	}
	buffer = append(append(buffer, pad[:]...), message...)
	var inner [sha256.Size]byte
	if level < 0 {
		inner = sha256.Sum256(buffer)
	} else {
		inner = vmessKDFLevel(path, level-1, buffer)
	}
	for i := range pad {
		pad[i] ^= 0x36 ^ 0x5c
	}
	buffer = append(append(buffer[:0], pad[:]...), inner[:]...)
	if level < 0 {
		return sha256.Sum256(buffer)
	}
	return vmessKDFLevel(path, level-1, buffer)
}

func vmessGCM(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return aead
}

func vmessSecurity(value string) (byte, error) {
	switch value {
	case "", "auto", "aes-128-gcm":
		return 3, nil
	case "none":
		return 5, nil
	case "zero":
		return 6, nil
	case "chacha20-poly1305":
		return 4, nil
	default:
		return 0, fmt.Errorf("independent VMess has no %q body cipher", value)
	}
}

type vmessRequest struct {
	iv, key                              [16]byte
	response, options, security, command byte
	address                              string
	legacy                               bool
}

func (q *vmessRequest) plaintext() ([]byte, error) {
	header := append([]byte{1}, q.iv[:]...)
	header = append(header, q.key[:]...)
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	padding := int(random[0] & 15)
	header = append(header, q.response, q.options, byte(padding<<4)|q.security, 0, q.command)
	if q.command != 3 {
		address, err := vlessAddress(q.address)
		if err != nil {
			return nil, err
		}
		header = append(header, address...)
	}
	header = append(header, random[:padding]...)
	h := fnv.New32a()
	_, _ = h.Write(header)
	return binary.BigEndian.AppendUint32(header, h.Sum32()), nil
}

func parseVMessPlaintext(header []byte) (vmessRequest, error) {
	var q vmessRequest
	if len(header) < 42 || header[0] != 1 {
		return q, errors.New("invalid VMess instruction header")
	}
	h := fnv.New32a()
	_, _ = h.Write(header[:len(header)-4])
	if h.Sum32() != binary.BigEndian.Uint32(header[len(header)-4:]) {
		return q, errors.New("VMess header checksum mismatch")
	}
	copy(q.iv[:], header[1:17])
	copy(q.key[:], header[17:33])
	q.response, q.options, q.security, q.command = header[33], header[34], header[35]&15, header[37]
	if q.options&^byte(0x1d) != 0 {
		return q, errors.New("invalid or unsupported VMess body options")
	}
	if q.options&16 != 0 && (q.options&1 == 0 || q.security != 3 && q.security != 4) {
		return q, errors.New("VMess authenticated length requires AEAD chunk framing")
	}
	if q.security != 3 && q.security != 4 && q.security != 5 && q.security != 6 {
		return q, errors.New("unsupported VMess security type")
	}
	if q.security != 6 && q.security != 5 && q.options&1 == 0 {
		return q, errors.New("VMess requires chunk framing")
	}
	if q.options&8 != 0 && q.options&4 == 0 {
		return q, errors.New("VMess padding requires metadata masking")
	}
	reader := bytes.NewReader(header[38 : len(header)-4])
	if q.command != 3 {
		var err error
		q.address, err = readVLESSAddress(reader)
		if err != nil {
			return q, err
		}
	}
	if reader.Len() != int(header[35]>>4) {
		return q, errors.New("invalid VMess instruction padding")
	}
	if q.command < 1 || q.command > 3 {
		return q, errors.New("invalid VMess command")
	}
	if q.command == 2 && q.options&1 == 0 {
		return q, errors.New("VMess zero cannot encode UDP datagrams")
	}
	return q, nil
}

func writeVMessRequest(c io.Writer, user vmessUser, q vmessRequest) error {
	plain, err := q.plaintext()
	if err != nil {
		return err
	}
	if q.legacy {
		return writeVMessLegacy(c, user, plain, time.Now().Unix())
	}
	var auth [16]byte
	binary.BigEndian.PutUint64(auth[:], uint64(time.Now().Unix()))
	if _, err := rand.Read(auth[8:12]); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(auth[12:], crc32.ChecksumIEEE(auth[:12]))
	user.auth.Encrypt(auth[:], auth[:])
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	derive := func(label string) []byte { return vmessKDF(user.command[:], []byte(label), auth[:], nonce[:]) }
	length := binary.BigEndian.AppendUint16(nil, uint16(len(plain)))
	header := append([]byte{}, auth[:]...)
	header = vmessGCM(derive("VMess Header AEAD Key_Length")[:16]).Seal(header, derive("VMess Header AEAD Nonce_Length")[:12], length, auth[:])
	header = append(header, nonce[:]...)
	header = vmessGCM(derive("VMess Header AEAD Key")[:16]).Seal(header, derive("VMess Header AEAD Nonce")[:12], plain, auth[:])
	return writeAll(c, header)
}

func (r *Runtime) readVMessRequest(c io.Reader, tag string) (vmessRequest, error) {
	var auth [16]byte
	if _, err := io.ReadFull(c, auth[:]); err != nil {
		return vmessRequest{}, err
	}
	var selected *vmessUser
	now := time.Now().Unix()
	for _, user := range r.vmessUsers["in:"+tag] {
		var plain [16]byte
		user.auth.Decrypt(plain[:], auth[:])
		stamp := int64(binary.BigEndian.Uint64(plain[:8]))
		if binary.BigEndian.Uint32(plain[12:]) == crc32.ChecksumIEEE(plain[:12]) && stamp >= now-120 && stamp <= now+120 {
			selected = &user
			break
		}
	}
	if selected == nil {
		return r.readVMessLegacy(c, tag, auth, now)
	}
	var prefix [26]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		return vmessRequest{}, err
	}
	nonce := prefix[18:]
	derive := func(label string) []byte { return vmessKDF(selected.command[:], []byte(label), auth[:], nonce) }
	length, err := vmessGCM(derive("VMess Header AEAD Key_Length")[:16]).Open(nil, derive("VMess Header AEAD Nonce_Length")[:12], prefix[:18], auth[:])
	if err != nil {
		return vmessRequest{}, errors.New("VMess header length authentication failed")
	}
	size := int(binary.BigEndian.Uint16(length))
	if size < 42 || size > 1024 {
		return vmessRequest{}, errors.New("VMess header exceeds instruction limit")
	}
	data := make([]byte, size+16)
	if _, err := io.ReadFull(c, data); err != nil {
		return vmessRequest{}, err
	}
	plain, err := vmessGCM(derive("VMess Header AEAD Key")[:16]).Open(data[:0], derive("VMess Header AEAD Nonce")[:12], data, auth[:])
	if err != nil {
		return vmessRequest{}, errors.New("VMess header authentication failed")
	}
	q, err := parseVMessPlaintext(plain)
	if err != nil {
		return q, err
	}
	if err := r.replay.add(&ssKey{master: selected.command[:]}, auth[:]); err != nil {
		return q, errors.New("VMess authentication replay")
	}
	return q, nil
}

func vmessResponseKeys(q vmessRequest) (key, iv [16]byte) {
	if q.legacy {
		return md5.Sum(q.key[:]), md5.Sum(q.iv[:])
	}
	k := sha256.Sum256(q.key[:])
	n := sha256.Sum256(q.iv[:])
	copy(key[:], k[:16])
	copy(iv[:], n[:16])
	return
}

func vmessResponseHeader(q vmessRequest) []byte {
	if q.legacy {
		header := []byte{q.response, 0, 0, 0}
		vmessLegacyResponse(q, header, true)
		return header
	}
	key, iv := vmessResponseKeys(q)
	length := []byte{0, 4}
	length = vmessGCM(vmessKDF(key[:], []byte("AEAD Resp Header Len Key"))[:16]).Seal(nil, vmessKDF(iv[:], []byte("AEAD Resp Header Len IV"))[:12], length, nil)
	return vmessGCM(vmessKDF(key[:], []byte("AEAD Resp Header Key"))[:16]).Seal(length, vmessKDF(iv[:], []byte("AEAD Resp Header IV"))[:12], []byte{q.response, 0, 0, 0}, nil)
}

func readVMessResponse(c io.Reader, q vmessRequest) error {
	if q.legacy {
		return readVMessLegacyResponse(c, q)
	}
	key, iv := vmessResponseKeys(q)
	var prefix [18]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		return err
	}
	length, err := vmessGCM(vmessKDF(key[:], []byte("AEAD Resp Header Len Key"))[:16]).Open(nil, vmessKDF(iv[:], []byte("AEAD Resp Header Len IV"))[:12], prefix[:], nil)
	if err != nil {
		return errors.New("VMess response length authentication failed")
	}
	size := int(binary.BigEndian.Uint16(length))
	if size < 4 || size > 1024 {
		return errors.New("invalid VMess response header size")
	}
	b := make([]byte, size+16)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	b, err = vmessGCM(vmessKDF(key[:], []byte("AEAD Resp Header Key"))[:16]).Open(b[:0], vmessKDF(iv[:], []byte("AEAD Resp Header IV"))[:12], b, nil)
	if err != nil || b[0] != q.response || b[2] != 0 || b[3] != 0 {
		return errors.New("VMess response authentication failed")
	}
	return nil
}

type vmessBody struct {
	io.ReadWriter
	aead                       cipher.AEAD
	lengthAEAD                 cipher.AEAD
	lengthNonce                [12]byte
	bodyNonce                  [12]byte
	header                     [18]byte
	mask                       *sha3.SHAKE
	iv                         [16]byte
	options, security, command byte
	counter                    uint32
	pending                    []byte
	buffer                     []byte
	end                        bool
}

func newVMessBody(c io.ReadWriter, key, iv [16]byte, q vmessRequest) vmessBody {
	b := vmessBody{ReadWriter: c, iv: iv, options: q.options, security: q.security, command: q.command}
	b.aead = vmessBodyCipher(q.security, key[:])
	if q.options&16 != 0 {
		b.lengthAEAD = vmessBodyCipher(q.security, vmessKDF(q.key[:], []byte("auth_len"))[:16])
		copy(b.lengthNonce[:], q.iv[:12])
	}
	if q.options&4 != 0 {
		b.mask = sha3.NewSHAKE128()
		_, _ = b.mask.Write(iv[:])
	}
	return b
}

func vmessBodyCipher(security byte, key []byte) cipher.AEAD {
	if security == 3 {
		return vmessGCM(key)
	}
	if security == 4 {
		first := md5.Sum(key)
		second := md5.Sum(first[:])
		aead, _ := newChaChaAEAD(append(first[:], second[:]...), false)
		return aead
	}
	return nil
}

func (b *vmessBody) framing() (padding int, mask uint16) {
	data := b.header[:2]
	if b.options&8 != 0 {
		_, _ = b.mask.Read(data)
		padding = int(binary.BigEndian.Uint16(data) % 64)
	}
	if b.mask != nil && b.lengthAEAD == nil {
		_, _ = b.mask.Read(data)
		mask = binary.BigEndian.Uint16(data)
	}
	return
}

func (b *vmessBody) nonce() ([]byte, error) {
	if b.counter >= 65536 {
		return nil, errors.New("VMess nonce counter exhausted; reconnect required")
	}
	binary.BigEndian.PutUint16(b.bodyNonce[:], uint16(b.counter))
	copy(b.bodyNonce[2:], b.iv[2:12])
	b.counter++
	return b.bodyNonce[:], nil
}

func (b *vmessBody) readChunk() ([]byte, error) {
	if b.end {
		return nil, io.EOF
	}
	padding, mask := b.framing()
	header := b.header[:]
	headerSize := 2
	if b.lengthAEAD != nil {
		if b.counter >= 65536 {
			return nil, errors.New("VMess length nonce exhausted; reconnect required")
		}
		headerSize = 18
	}
	if _, err := io.ReadFull(b.ReadWriter, header[:headerSize]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header[:2]) ^ mask)
	if b.lengthAEAD != nil {
		binary.BigEndian.PutUint16(b.lengthNonce[:], uint16(b.counter))
		plain, err := b.lengthAEAD.Open(header[:0], b.lengthNonce[:], header[:18], nil)
		if err != nil {
			return nil, errors.New("VMess body length authentication failed")
		}
		size = int(binary.BigEndian.Uint16(plain)) + b.aead.Overhead()
	}
	maximum := 16384
	// Some released peers coalesce unencrypted TCP chunks beyond the documented 16KiB.
	if b.security == 5 && b.command != 2 {
		maximum = 65535
	}
	if size < padding || size > maximum {
		return nil, fmt.Errorf("invalid VMess body chunk size %d (padding %d)", size, padding)
	}
	if cap(b.buffer) < size {
		capacity := size
		if b.options&8 != 0 {
			capacity = min(maximum, size+63-padding)
		}
		b.buffer = make([]byte, capacity)
	}
	packet := b.buffer[:size]
	if _, err := io.ReadFull(b.ReadWriter, packet); err != nil {
		return nil, err
	}
	packet = packet[:size-padding]
	if b.aead != nil {
		nonce, err := b.nonce()
		if err != nil {
			return nil, err
		}
		packet, err = b.aead.Open(packet[:0], nonce, packet, nil)
		if err != nil {
			return nil, err
		}
	}
	if len(packet) == 0 {
		b.end = true
		return nil, io.EOF
	}
	return packet, nil
}

func (b *vmessBody) writeChunk(data []byte) error {
	if b.end {
		return io.ErrClosedPipe
	}
	maximum := 16384
	if b.aead != nil {
		maximum -= b.aead.Overhead()
	}
	if b.options&8 != 0 {
		maximum -= 63
	}
	// Reject before consuming the masking stream so a later valid datagram stays synchronized.
	if len(data) > maximum {
		return errVMessChunkTooLarge
	}
	if b.aead != nil && b.counter >= 65536 {
		return errors.New("VMess nonce counter exhausted; reconnect required")
	}
	padding, mask := b.framing()
	size := len(data) + padding
	if b.aead != nil {
		size += b.aead.Overhead()
	}
	headerSize := 2
	if b.lengthAEAD != nil {
		headerSize = 18
	}
	if cap(b.buffer) < headerSize+size {
		capacity := headerSize + size
		if b.options&8 != 0 {
			capacity += 63 - padding
		}
		b.buffer = make([]byte, capacity)
	}
	packet := b.buffer[:0]
	if b.lengthAEAD != nil {
		binary.BigEndian.PutUint16(b.header[:2], uint16(size-b.aead.Overhead()))
		binary.BigEndian.PutUint16(b.lengthNonce[:], uint16(b.counter))
		packet = b.lengthAEAD.Seal(packet, b.lengthNonce[:], b.header[:2], nil)
	} else {
		packet = binary.BigEndian.AppendUint16(packet, uint16(size)^mask)
	}
	if b.aead != nil {
		nonce, err := b.nonce()
		if err != nil {
			return err
		}
		packet = b.aead.Seal(packet, nonce, data, nil)
	} else {
		packet = append(packet, data...)
	}
	if padding > 0 {
		start := len(packet)
		packet = append(packet, make([]byte, padding)...)
		if _, err := rand.Read(packet[start:]); err != nil {
			return err
		}
	}
	if err := writeAll(b.ReadWriter, packet); err != nil {
		return err
	}
	if len(data) == 0 {
		b.end = true
	}
	return nil
}

type vmessConn struct {
	net.Conn
	reader, writer      vmessBody
	request             vmessRequest
	client              bool
	readOnce, writeOnce sync.Once
	readMu, writeMu     sync.Mutex
	readErr, writeErr   error
}

func newVMessConn(c net.Conn, q vmessRequest, client bool) *vmessConn {
	key, iv := vmessResponseKeys(q)
	request, response := newVMessBody(c, q.key, q.iv, q), newVMessBody(c, key, iv, q)
	if client {
		return &vmessConn{Conn: c, reader: response, writer: request, request: q, client: true}
	}
	return &vmessConn{Conn: c, reader: request, writer: response, request: q}
}

func (c *vmessConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.readOnce.Do(func() {
		if c.client {
			c.readErr = readVMessResponse(c.Conn, c.request)
		}
	})
	if c.readErr != nil {
		return 0, c.readErr
	}
	if c.request.options&1 == 0 {
		return c.Conn.Read(p)
	}
	if len(c.reader.pending) == 0 {
		c.reader.pending, c.readErr = c.reader.readChunk()
		if c.readErr != nil {
			return 0, c.readErr
		}
	}
	if c.request.command == 2 && len(c.reader.pending) > len(p) {
		c.reader.pending = nil
		return 0, io.ErrShortBuffer
	}
	n := copy(p, c.reader.pending)
	c.reader.pending = c.reader.pending[n:]
	return n, nil
}

func (c *vmessConn) startResponse() error {
	c.writeOnce.Do(func() {
		if !c.client {
			c.writeErr = writeAll(c.Conn, vmessResponseHeader(c.request))
		}
	})
	return c.writeErr
}

func (c *vmessConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.startResponse(); err != nil {
		return 0, err
	}
	if c.request.options&1 == 0 {
		return c.Conn.Write(p)
	}
	if c.request.command == 2 {
		err := c.writer.writeChunk(p)
		if err != nil {
			if err != errVMessChunkTooLarge {
				c.writeErr = err
			}
			return 0, err
		}
		return len(p), nil
	}
	written := 0
	for len(p) > 0 {
		n := min(len(p), 16384-16-63)
		if err := c.writer.writeChunk(p[:n]); err != nil {
			c.writeErr = err
			return written, err
		}
		written += n
		p = p[n:]
	}
	return written, nil
}

func (c *vmessConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.startResponse(); err != nil {
		return err
	}
	if c.request.options&1 != 0 {
		if !c.writer.end {
			return c.writer.writeChunk(nil)
		}
		return nil
	}
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (r *Runtime) serveVMess(in Inbound, c net.Conn, request request) error {
	q, err := r.readVMessRequest(c, in.Tag)
	if err != nil {
		return err
	}
	stream := newVMessConn(c, q, false)
	if q.command == 3 {
		if err := stream.startResponse(); err != nil {
			return err
		}
		_ = c.SetDeadline(time.Time{})
		return r.serveMuxCool(stream, request, nil, false)
	}
	request.address = q.address
	if q.command == 2 {
		request.network = "udp"
		remote, err := r.routeDial(r.ctx, request)
		if err != nil {
			return err
		}
		defer remote.Close()
		_ = c.SetDeadline(time.Time{})
		return r.relayDatagrams(stream, remote, r.udpTimeoutFor(in.Tag, udpTimeout))
	}
	remote, err := r.routeDial(r.ctx, request)
	if err != nil {
		return err
	}
	r.relay(stream, remote)
	return nil
}

func (r *Runtime) relayDatagrams(a, b net.Conn, expiry ...time.Duration) error {
	timeout := udpTimeout
	if len(expiry) != 0 {
		timeout = expiry[0]
	}
	done := make(chan error, 1)
	copyPackets := func(dst, src net.Conn) error {
		packet := make([]byte, 65535)
		for {
			_ = src.SetReadDeadline(time.Now().Add(timeout))
			n, err := src.Read(packet)
			if err != nil {
				return err
			}
			_ = dst.SetReadDeadline(time.Now().Add(timeout))
			if _, err := dst.Write(packet[:n]); err != nil {
				return err
			}
		}
	}
	go func() { err := copyPackets(b, a); a.Close(); b.Close(); done <- err }()
	err := copyPackets(a, b)
	a.Close()
	b.Close()
	<-done
	return err
}
