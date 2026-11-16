package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type ssKey struct {
	master             []byte
	method             string
	identities         [][]byte
	users              map[[16]byte]*ssKey
	userName           string
	relayAddress       string
	udpBlock           cipher.Block
	udpAEAD            cipher.AEAD
	identityBlocks     []cipher.Block
	streamBlock        cipher.Block
	tableEnc, tableDec *[256]byte
}

// ShadowsocksMethods returns the ciphers implemented by this runtime.
func ShadowsocksMethods() []string {
	return []string{
		"none", "table", "rc4", "rc4-md5", "rc4-md5-6", "salsa20", "chacha20", "chacha20-ietf",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-cfb1", "aes-192-cfb1", "aes-256-cfb1",
		"aes-128-cfb8", "aes-192-cfb8", "aes-256-cfb8", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "des-cfb", "bf-cfb",
		"camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "idea-cfb", "rc2-cfb", "seed-cfb",
		"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
	}
}

func validateSSOTA(kind, method string) error {
	_, size, stream := ssStreamParameters(method)
	if kind != "shadowsocks" || !stream || size < 8 {
		return errors.New("ota requires Shadowsocks with an8-byte or longer random IV stream cipher")
	}
	return nil
}

func newSSKey(method, password string) (*ssKey, error) {
	if isSS2022(method) {
		return newSS2022Key(method, password)
	}
	size := 0
	switch method {
	case "aes-128-gcm":
		size = 16
	case "aes-192-gcm":
		size = 24
	case "aes-256-gcm":
		size = 32
	case "chacha20-ietf-poly1305", "chacha20-poly1305", "xchacha20-ietf-poly1305":
		size = 32
	default:
		var ok bool
		size, _, ok = ssStreamParameters(method)
		if !ok {
			return nil, fmt.Errorf("independent Shadowsocks has no %q cipher", method)
		}
	}
	if password == "" {
		return nil, errors.New("Shadowsocks password is required")
	}
	key := make([]byte, 0, size+16)
	var previous []byte
	for len(key) < size {
		h := md5.New()
		_, _ = h.Write(previous)
		_, _ = h.Write([]byte(password))
		previous = h.Sum(nil)
		key = append(key, previous...)
	}
	k := &ssKey{master: key[:size], method: method}
	if method == "table" {
		enc, dec := ssTable(password)
		k.tableEnc, k.tableDec = &enc, &dec
	}
	if _, _, stream := ssStreamParameters(method); stream {
		var err error
		k.streamBlock, err = newSSStreamBlock(method, k.master)
		if err != nil {
			return nil, err
		}
	}
	return k, nil
}

func (k *ssKey) aead(salt []byte) (cipher.AEAD, error) {
	if isSS2022(k.method) {
		return k.ss2022AEAD(salt)
	}
	key, err := hkdf.Key(sha1.New, k.master, salt, "ss-subkey", len(k.master))
	if err != nil {
		return nil, err
	}
	if k.method == "chacha20-ietf-poly1305" || k.method == "chacha20-poly1305" || k.method == "xchacha20-ietf-poly1305" {
		return newChaChaAEAD(key, k.method == "xchacha20-ietf-poly1305")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type replayWindow struct {
	mu    sync.Mutex
	salts map[string]time.Time
	sweep time.Time
}

func (w *replayWindow) add(key *ssKey, salt []byte) error {
	return w.claim(string(key.master) + string(salt))
}

func (w *replayWindow) claim(id string) error {
	return w.claimFor(id, 30*time.Minute)
}

func (w *replayWindow) claimFor(id string, duration time.Duration) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if w.salts == nil {
		w.salts = make(map[string]time.Time)
	}
	if until, exists := w.salts[id]; exists && now.Before(until) {
		return errors.New("authentication nonce replay")
	}
	if now.After(w.sweep) || len(w.salts) >= 65536 {
		for k, until := range w.salts {
			if now.After(until) {
				delete(w.salts, k)
			}
		}
		w.sweep = now.Add(time.Minute)
	}
	if len(w.salts) >= 65536 {
		return errors.New("authentication replay window capacity reached")
	}
	w.salts[id] = now.Add(duration)
	return nil
}

type ssConn struct {
	net.Conn
	key                     *ssKey
	replay                  *replayWindow
	readMu, writeMu         sync.Mutex
	reader, writer          cipher.AEAD
	readNonce, writeNonce   [24]byte
	readBuffer, writeBuffer []byte
	pending                 []byte
	readErr, writeErr       error
	lineSalt                bool
}

func newSSConn(c net.Conn, key *ssKey, replay *replayWindow) net.Conn {
	if _, _, stream := ssStreamParameters(key.method); stream {
		return &ssStreamConn{Conn: c, key: key}
	}
	return &ssConn{Conn: c, key: key, replay: replay}
}

func incrementNonce(n *[24]byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

func (c *ssConn) initWrite() error {
	salt := make([]byte, len(c.key.master))
	for {
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		// Trojan-Go0.10.6 probes the decrypted TLS stream as an HTTP request line.
		if !c.lineSalt || bytes.IndexByte(salt, '\n') >= 0 {
			break
		}
	}
	if err := c.replay.add(c.key, salt); err != nil {
		return err
	}
	aead, err := c.key.aead(salt)
	if err != nil {
		return err
	}
	if err := writeAll(c.Conn, salt); err != nil {
		return err
	}
	c.writer = aead
	c.writeBuffer = make([]byte, 0, 0x3fff+34)
	return nil
}

func (c *ssConn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.writer == nil {
		if err := c.initWrite(); err != nil {
			c.writeErr = err
			return 0, err
		}
	}
	written := 0
	for len(b) > 0 {
		size := min(len(b), 0x3fff)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(size))
		frame := c.writer.Seal(c.writeBuffer[:0], c.writeNonce[:c.writer.NonceSize()], length[:], nil)
		incrementNonce(&c.writeNonce)
		frame = c.writer.Seal(frame, c.writeNonce[:c.writer.NonceSize()], b[:size], nil)
		incrementNonce(&c.writeNonce)
		if err := writeAll(c.Conn, frame); err != nil {
			c.writeErr = err
			return written, err
		}
		b = b[size:]
		written += size
	}
	return written, nil
}

func (c *ssConn) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.pending) != 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	var salt []byte
	if c.reader == nil {
		salt = make([]byte, len(c.key.master))
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			c.readErr = err
			return 0, err
		}
		var err error
		c.reader, err = c.key.aead(salt)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		c.readBuffer = make([]byte, 0x3fff+16)
	}
	for empty := 0; empty < 16; empty++ {
		var encryptedLength [18]byte
		_, err := io.ReadFull(c.Conn, encryptedLength[:])
		var length []byte
		if err == nil {
			length, err = c.reader.Open(encryptedLength[:0], c.readNonce[:c.reader.NonceSize()], encryptedLength[:], nil)
			incrementNonce(&c.readNonce)
		}
		if err == nil && salt != nil {
			err = c.replay.add(c.key, salt)
			salt = nil
		}
		if err != nil {
			c.readErr = err
			return 0, err
		}
		size := int(binary.BigEndian.Uint16(length))
		if size > 0x3fff {
			c.readErr = errors.New("invalid Shadowsocks chunk size")
			return 0, c.readErr
		}
		frame := c.readBuffer[:size+16]
		if _, err := io.ReadFull(c.Conn, frame); err != nil {
			c.readErr = err
			return 0, err
		}
		c.pending, err = c.reader.Open(frame[:0], c.readNonce[:c.reader.NonceSize()], frame, nil)
		incrementNonce(&c.readNonce)
		if err != nil {
			c.readErr = err
			return 0, err
		}
		if len(c.pending) != 0 {
			n := copy(b, c.pending)
			c.pending = c.pending[n:]
			return n, nil
		}
	}
	c.readErr = errors.New("too many empty Shadowsocks chunks")
	return 0, c.readErr
}

func (c *ssConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (k *ssKey) sealPacket(payload []byte, replay *replayWindow) ([]byte, error) {
	if _, _, stream := ssStreamParameters(k.method); stream {
		return k.sealStreamPacket(payload)
	}
	salt := make([]byte, len(k.master))
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if err := replay.add(k, salt); err != nil {
		return nil, err
	}
	aead, err := k.aead(salt)
	if err != nil {
		return nil, err
	}
	return aead.Seal(salt, make([]byte, aead.NonceSize()), payload, nil), nil
}

func (k *ssKey) openPacket(packet []byte, replay *replayWindow) ([]byte, error) {
	if _, _, stream := ssStreamParameters(k.method); stream {
		return k.openStreamPacket(packet)
	}
	if len(packet) < len(k.master)+16 {
		return nil, io.ErrUnexpectedEOF
	}
	salt := packet[:len(k.master)]
	aead, err := k.aead(salt)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), packet[len(salt):], nil)
	if err != nil {
		return nil, err
	}
	if err := replay.add(k, salt); err != nil {
		return nil, err
	}
	return plain, nil
}
