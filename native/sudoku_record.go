package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"sync"
)

// Separate directional secrets and authenticated counters protect both the
// initial handshake and the X25519 session. A failed record ends the stream.
type sudokuRecordDirection struct {
	base        []byte
	aead        cipher.AEAD
	epoch       uint32
	sequence    uint64
	bytes       uint64
	initialized bool
}

type sudokuRecord struct {
	net.Conn
	options       *SudokuOptions
	account       *sudokuAccount
	method        string
	send, receive sudokuRecordDirection
	rmu, wmu      sync.Mutex
	pending       []byte
	buffer        []byte
	err           error
	rotateAfter   uint64
}

func sudokuBases(key string, shared, nonce []byte) ([]byte, []byte) {
	h := sha256.Sum256([]byte(key))
	prk := h[:]
	label := "sudoku-psk-"
	if shared != nil {
		prk, _ = hkdf.Extract(sha256.New, append(append([]byte{}, shared...), nonce...), h[:])
		label = "sudoku-session-"
	}
	a, _ := hkdf.Expand(sha256.New, prk, label+"c2s", 32)
	b, _ := hkdf.Expand(sha256.New, prk, label+"s2c", 32)
	return a, b
}

func newSudokuRecord(conn net.Conn, method string, send, receive []byte) *sudokuRecord {
	c := &sudokuRecord{Conn: conn, method: method, rotateAfter: 32 << 20}
	c.rekey(send, receive)
	return c
}

// Only called between the two handshake messages and application traffic,
// before either side starts its read/write workers.
func (c *sudokuRecord) rekey(send, receive []byte) {
	var random [12]byte
	rand.Read(random[:])
	c.send = sudokuRecordDirection{base: send, epoch: binary.BigEndian.Uint32(random[:4])&0x7fffffff | 1, sequence: binary.BigEndian.Uint64(random[4:])&0x7fffffffffffffff | 1}
	c.receive = sudokuRecordDirection{base: receive}
	c.pending, c.buffer = nil, nil
}

func (c *sudokuRecord) cipher(d *sudokuRecordDirection, epoch uint32) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, d.base)
	mac.Write([]byte("sudoku-record:" + c.method))
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	mac.Write(e[:])
	key := mac.Sum(nil)
	if c.method == "chacha20-poly1305" {
		return newChaChaAEAD(key, false)
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (c *sudokuRecord) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.method == "none" {
		return c.Conn.Read(p)
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	var size [2]byte
	if _, e := io.ReadFull(c.Conn, size[:]); e != nil {
		return c.readError(e)
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n < 28 {
		return c.readError(errors.New("short Sudoku record"))
	}
	if cap(c.buffer) < n {
		c.buffer = make([]byte, n)
	} else {
		c.buffer = c.buffer[:n]
	}
	if _, e := io.ReadFull(c.Conn, c.buffer); e != nil {
		return c.readError(e)
	}
	header := c.buffer[:12]
	epoch, sequence := binary.BigEndian.Uint32(header[:4]), binary.BigEndian.Uint64(header[4:])
	d := &c.receive
	if sequence == math.MaxUint64 || d.initialized && (epoch < d.epoch || epoch == d.epoch && sequence != d.sequence || epoch > d.epoch && epoch-d.epoch > 8) {
		return c.readError(errors.New("replayed or out-of-order Sudoku record"))
	}
	if d.aead == nil || epoch != d.epoch {
		var e error
		d.aead, e = c.cipher(d, epoch)
		if e != nil {
			return c.readError(e)
		}
	}
	plain, e := d.aead.Open(c.buffer[12:12], header, c.buffer[12:], header)
	if e != nil {
		return c.readError(errors.New("Sudoku record authentication failed"))
	}
	d.epoch, d.sequence, d.initialized = epoch, sequence+1, true
	n = copy(p, plain)
	c.pending = plain[n:]
	return n, nil
}

func (c *sudokuRecord) readError(e error) (int, error) {
	c.err = e
	if e != io.EOF {
		c.Conn.Close()
	}
	return 0, e
}

func (c *sudokuRecord) Write(p []byte) (int, error) {
	if c.method == "none" {
		return c.Conn.Write(p)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	frame := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(frame)
	n := 0
	d := &c.send
	for len(p) > 0 {
		if d.bytes >= c.rotateAfter || d.sequence == math.MaxUint64 {
			if d.epoch == math.MaxUint32 {
				c.Conn.Close()
				return n, errors.New("Sudoku key epoch exhausted")
			}
			d.epoch++
			d.bytes = 0
			d.sequence = 1
			d.aead = nil
		}
		if d.aead == nil {
			var e error
			d.aead, e = c.cipher(d, d.epoch)
			if e != nil {
				return n, e
			}
		}
		used := min(len(p), len(frame)-30)
		binary.BigEndian.PutUint16(frame[:2], uint16(used+28))
		header := frame[2:14]
		binary.BigEndian.PutUint32(header[:4], d.epoch)
		binary.BigEndian.PutUint64(header[4:], d.sequence)
		sealed := d.aead.Seal(frame[14:14], header, p[:used], header)
		if e := writeAll(c.Conn, frame[:14+len(sealed)]); e != nil {
			c.Conn.Close()
			return n, e
		}
		d.sequence++
		d.bytes += uint64(used)
		n += used
		p = p[used:]
	}
	return n, nil
}

func (c *sudokuRecord) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
