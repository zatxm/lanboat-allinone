package native

import (
	"bufio"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"net"
	"strconv"
	"sync"
)

const tailscaleCapability = 121

// Tailscale's control channel uses Noise IK, not WireGuard's IKpsk2.
type tsNoiseHandshake struct {
	static, ephemeral *ecdh.PrivateKey
	ck, h             []byte
}

func tsNoiseInit(private *ecdh.PrivateKey, remote []byte) (*tsNoiseHandshake, []byte, error) {
	e, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	h := blake2s([]byte("Noise_IK_25519_ChaChaPoly_BLAKE2s"), nil, 32)
	s := &tsNoiseHandshake{static: private, ephemeral: e, ck: h, h: h}
	s.h = wgHashMix(s.h, []byte("Tailscale Control Protocol v"+strconv.Itoa(tailscaleCapability)))
	s.h = wgHashMix(s.h, remote)
	message := binary.BigEndian.AppendUint16(nil, tailscaleCapability)
	message = append(message, 1, 0, 96)
	message = append(message, e.PublicKey().Bytes()...)
	s.h = wgHashMix(s.h, e.PublicKey().Bytes())
	k, err := s.dh(e, remote)
	if err != nil {
		return nil, nil, err
	}
	body := wgEncrypt(k, private.PublicKey().Bytes(), s.h)
	s.h = wgHashMix(s.h, body)
	message = append(message, body...)
	k, err = s.dh(private, remote)
	if err != nil {
		return nil, nil, err
	}
	body = wgEncrypt(k, nil, s.h)
	s.h = wgHashMix(s.h, body)
	return s, append(message, body...), nil
}

func (s *tsNoiseHandshake) dh(private *ecdh.PrivateKey, public []byte) ([]byte, error) {
	shared, err := wgDH(private, public)
	if err != nil {
		return nil, err
	}
	keys := wgKDF(s.ck, shared, 2)
	s.ck = keys[0]
	return keys[1], nil
}

func (s *tsNoiseHandshake) finish(raw net.Conn, reader *bufio.Reader) (net.Conn, error) {
	var header [3]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 2 || binary.BigEndian.Uint16(header[1:]) != 48 {
		return nil, errors.New("Tailscale Noise handshake rejected")
	}
	var body [48]byte
	if _, err := io.ReadFull(reader, body[:]); err != nil {
		return nil, err
	}
	s.h = wgHashMix(s.h, body[:32])
	if _, err := s.dh(s.ephemeral, body[:32]); err != nil {
		return nil, err
	}
	k, err := s.dh(s.static, body[:32])
	if err != nil {
		return nil, err
	}
	if _, err = wgDecrypt(k, body[32:], s.h); err != nil {
		return nil, err
	}
	keys := wgKDF(s.ck, nil, 2)
	tx, _ := newChaChaAEAD(keys[0], false)
	rx, _ := newChaChaAEAD(keys[1], false)
	return &tsNoiseConn{Conn: raw, reader: reader, tx: tx, rx: rx}, nil
}

type tsNoiseConn struct {
	net.Conn
	reader            *bufio.Reader
	tx, rx            cipher.AEAD
	wmu, rmu          sync.Mutex
	wn, rn            uint64
	plain             []byte
	writeErr, readErr error
}

func (c *tsNoiseConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	count := 0
	for len(p) > 0 {
		if c.wn == ^uint64(0) {
			c.writeErr = errors.New("Tailscale Noise nonce exhausted")
			break
		}
		n := min(len(p), 4096-19)
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:], c.wn)
		c.wn++
		b := []byte{4, byte((n + 16) >> 8), byte(n + 16)}
		b = c.tx.Seal(b, nonce[:], p[:n], nil)
		if c.writeErr = writeAll(c.Conn, b); c.writeErr != nil {
			break
		}
		count += n
		p = p[n:]
	}
	return count, c.writeErr
}

func (c *tsNoiseConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	for len(c.plain) == 0 && c.readErr == nil {
		var header [3]byte
		if _, c.readErr = io.ReadFull(c.reader, header[:]); c.readErr != nil {
			break
		}
		n := int(binary.BigEndian.Uint16(header[1:]))
		if header[0] != 4 || n < 16 || n > 4093 || c.rn == ^uint64(0) {
			c.readErr = errors.New("invalid Tailscale Noise record")
			break
		}
		body := make([]byte, n)
		if _, c.readErr = io.ReadFull(c.reader, body); c.readErr != nil {
			break
		}
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:], c.rn)
		c.rn++
		c.plain, c.readErr = c.rx.Open(body[:0], nonce[:], body, nil)
	}
	if len(c.plain) == 0 {
		return 0, c.readErr
	}
	n := copy(p, c.plain)
	c.plain = c.plain[n:]
	return n, nil
}

// HSalsa20 and XSalsa20-Poly1305 implement NaCl box's wire format for DERP/disco.
func tsHSalsa(key []byte, nonce []byte) [32]byte {
	s := [16]uint32{0: 0x61707865, 5: 0x3320646e, 10: 0x79622d32, 15: 0x6b206574}
	for i := range 4 {
		s[1+i] = binary.LittleEndian.Uint32(key[i*4:])
		s[11+i] = binary.LittleEndian.Uint32(key[16+i*4:])
		s[6+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	quarter := func(a, b, c, d int) {
		s[b] ^= bits.RotateLeft32(s[a]+s[d], 7)
		s[c] ^= bits.RotateLeft32(s[b]+s[a], 9)
		s[d] ^= bits.RotateLeft32(s[c]+s[b], 13)
		s[a] ^= bits.RotateLeft32(s[d]+s[c], 18)
	}
	for range 10 {
		quarter(0, 4, 8, 12)
		quarter(5, 9, 13, 1)
		quarter(10, 14, 2, 6)
		quarter(15, 3, 7, 11)
		quarter(0, 1, 2, 3)
		quarter(5, 6, 7, 4)
		quarter(10, 11, 8, 9)
		quarter(15, 12, 13, 14)
	}
	var out [32]byte
	for i, v := range []uint32{s[0], s[5], s[10], s[15], s[6], s[7], s[8], s[9]} {
		binary.LittleEndian.PutUint32(out[i*4:], v)
	}
	return out
}

func tsBoxKey(private *ecdh.PrivateKey, public []byte) ([32]byte, error) {
	shared, err := wgDH(private, public)
	if err != nil {
		return [32]byte{}, err
	}
	return tsHSalsa(shared, make([]byte, 16)), nil
}

func tsSecretStream(key [32]byte, nonce []byte) (*salsaStream, polyState) {
	s := &salsaStream{key: tsHSalsa(key[:], nonce[:16])}
	copy(s.nonce[:], nonce[16:24])
	var first [32]byte
	s.XORKeyStream(first[:], first[:])
	return s, newPolyState(first[:])
}

func tsBoxSeal(key [32]byte, plain []byte) []byte {
	b := make([]byte, 40+len(plain))
	rand.Read(b[:24])
	s, mac := tsSecretStream(key, b[:24])
	s.XORKeyStream(b[40:], plain)
	mac.write(b[40:])
	tag := mac.sum()
	copy(b[24:40], tag[:])
	return b
}

func tsBoxOpen(key [32]byte, b []byte) ([]byte, error) {
	if len(b) < 40 {
		return nil, errors.New("short Tailscale NaCl box")
	}
	s, mac := tsSecretStream(key, b[:24])
	mac.write(b[40:])
	tag := mac.sum()
	if subtle.ConstantTimeCompare(tag[:], b[24:40]) != 1 {
		return nil, errors.New("Tailscale NaCl box authentication failed")
	}
	out := make([]byte, len(b)-40)
	s.XORKeyStream(out, b[40:])
	return out, nil
}
