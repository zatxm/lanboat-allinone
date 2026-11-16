package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"encoding/binary"
	"errors"
	"io"
)

// RFC9147 uses its own HKDF namespace and record-number protection.
func dtls13Expand(s stCipherSuite, secret []byte, label string, context []byte, n int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	info = append(info, stVector([]byte("dtls13"+label), 1)...)
	info = append(info, stVector(context, 1)...)
	out, err := hkdf.Expand(s.newHash, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

type dtls13Epoch struct {
	key             quicKey
	epoch, sequence uint64
	window          packetWindow
}

func newDTLS13Epoch(s stCipherSuite, secret []byte, epoch uint64) (*dtls13Epoch, error) {
	e := &dtls13Epoch{epoch: epoch}
	e.key.secret = append([]byte(nil), secret...)
	e.key.suite = s.id
	key := dtls13Expand(s, secret, "key", nil, s.keySize)
	sn := dtls13Expand(s, secret, "sn", nil, s.keySize)
	defer clear(key)
	defer clear(sn)
	copy(e.key.iv[:], dtls13Expand(s, secret, "iv", nil, 12))
	var err error
	if s.id == 0x1303 {
		e.key.aead, err = newChaChaAEAD(key, false)
		e.key.hpChaCha = new([32]byte)
		copy(e.key.hpChaCha[:], sn)
	} else {
		var b cipher.Block
		b, err = aes.NewCipher(key)
		if err == nil {
			e.key.aead, err = cipher.NewGCM(b)
		}
		if err == nil {
			e.key.hp, err = aes.NewCipher(sn)
		}
	}
	return e, err
}

func (e *dtls13Epoch) seal(kind byte, data []byte) ([]byte, error) {
	// Conservative AES-GCM bound, also applied to ChaCha20; the tunnel renews on exhaustion.
	if len(data) > 16384 || e.sequence >= 1<<24 {
		return nil, errors.New("DTLS1.3 record limit")
	}
	header := []byte{0x2c | byte(e.epoch&3), byte(e.sequence >> 8), byte(e.sequence)}
	header = binary.BigEndian.AppendUint16(header, uint16(len(data)+1+e.key.aead.Overhead()))
	plain := make([]byte, len(data)+1)
	copy(plain, data)
	plain[len(data)] = kind
	wire := e.key.aead.Seal(header, e.key.nonce(e.sequence), plain, header)
	clear(plain)
	mask := e.key.mask(wire[5:])
	wire[1] ^= mask[0]
	wire[2] ^= mask[1]
	e.sequence++
	return wire, nil
}

func dtls13Sequence(truncated uint64, bits uint, next uint64) uint64 {
	span := uint64(1) << bits
	candidate := next & ^(span-1) | truncated
	if candidate+span/2 <= next && candidate < ^uint64(0)-span {
		candidate += span
	} else if candidate > next+span/2 && candidate >= span {
		candidate -= span
	}
	return candidate
}

// A duplicate is authenticated before it can trigger an ACK; unauthenticated
// sequence numbers must never move the replay window or acknowledge a flight.
func (e *dtls13Epoch) open(wire []byte) (kind byte, data []byte, seq uint64, duplicate bool, ok bool) {
	if len(wire) < 2 || wire[0]&0xf0 != 0x20 || uint64(wire[0]&3) != e.epoch&3 {
		return
	}
	n := 1
	if wire[0]&8 != 0 {
		n = 2
	}
	headerLen := 1 + n
	if wire[0]&4 != 0 {
		headerLen += 2
	}
	if len(wire) < headerLen+16 || len(wire) > headerLen+16384+1+e.key.aead.Overhead() {
		return
	}
	if wire[0]&4 != 0 && int(binary.BigEndian.Uint16(wire[1+n:])) != len(wire)-headerLen {
		return
	}
	var header [5]byte
	copy(header[:], wire[:headerLen])
	mask := e.key.mask(wire[headerLen:])
	for i := range n {
		header[1+i] ^= mask[i]
		seq = seq<<8 | uint64(header[1+i])
	}
	seq = dtls13Sequence(seq, uint(n*8), e.window.highest+1)
	if seq >= 1<<24 {
		return 0, nil, 0, false, false
	}
	plain, err := e.key.aead.Open(nil, e.key.nonce(seq), wire[headerLen:], header[:headerLen])
	if err != nil {
		return 0, nil, 0, false, false
	}
	at := len(plain) - 1
	for at >= 0 && plain[at] == 0 {
		at--
	}
	if at < 0 || at > 16384 {
		return 0, nil, 0, false, false
	}
	kind, data = plain[at], plain[:at]
	duplicate = !e.window.accept(seq)
	return kind, data, seq, duplicate, true
}

func dtls13RecordSize(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	if b[0]&0xe0 == 0x20 {
		if b[0]&0x10 != 0 {
			return 0
		} // CID is never negotiated.
		n := 2
		if b[0]&8 != 0 {
			n++
		}
		if b[0]&4 == 0 {
			if len(b) >= n+16 {
				return len(b)
			}
			return 0
		}
		if len(b) < n+2 {
			return 0
		}
		size := n + 2 + int(binary.BigEndian.Uint16(b[n:]))
		if size > len(b) || size < n+2+16 {
			return 0
		}
		return size
	}
	if len(b) < 13 || b[0] != 22 && b[0] != 21 && b[0] != 26 || binary.BigEndian.Uint16(b[3:5]) != 0 {
		return 0
	}
	size := 13 + int(binary.BigEndian.Uint16(b[11:]))
	if size > len(b) || size > 16384+13 {
		return 0
	}
	return size
}

func (d *dtls13) nextRecord() ([]byte, error) {
	for {
		if n := dtls13RecordSize(d.pending); n > 0 {
			b := d.pending[:n]
			d.pending = d.pending[n:]
			return b, nil
		}
		n, err := d.owner.conn.Read(d.buffer[:])
		if err != nil {
			return nil, err
		}
		d.pending = d.buffer[:n]
	}
}

func dtls13Write(conn io.Writer, wire []byte) error {
	n, err := conn.Write(wire)
	if err == nil && n != len(wire) {
		err = io.ErrShortWrite
	}
	return err
}
