package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// RFC3610 with the 12-byte nonce and 8/16-byte tags used by RFC6655.
type dtlsCCM struct {
	block cipher.Block
	tag   int
}

func newDTLSCCM(key []byte, tag int) (cipher.AEAD, error) {
	if tag != 8 && tag != 16 {
		return nil, errors.New("invalid DTLS CCM tag size")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &dtlsCCM{block: b, tag: tag}, nil
}

func (*dtlsCCM) NonceSize() int  { return 12 }
func (c *dtlsCCM) Overhead() int { return c.tag }

func (c *dtlsCCM) mac(nonce, plaintext, aad []byte) [16]byte {
	var state, counter, mask [16]byte
	state[0] = byte((c.tag-2)/2<<3) | 2 // L=3.
	if len(aad) != 0 {
		state[0] |= 64
	}
	copy(state[1:13], nonce)
	putUint24(state[13:], uint32(len(plaintext)))
	c.block.Encrypt(state[:], state[:])
	feed := func(b []byte) {
		for len(b) != 0 {
			n := min(16, len(b))
			for i, v := range b[:n] {
				state[i] ^= v
			}
			c.block.Encrypt(state[:], state[:])
			b = b[n:]
		}
	}
	if len(aad) != 0 {
		var first [16]byte
		n := 2
		switch {
		case uint64(len(aad)) < 0xff00:
			binary.BigEndian.PutUint16(first[:], uint16(len(aad)))
		case uint64(len(aad)) < 1<<32:
			first[0], first[1], n = 0xff, 0xfe, 6
			binary.BigEndian.PutUint32(first[2:], uint32(len(aad)))
		default:
			first[0], first[1], n = 0xff, 0xff, 10
			binary.BigEndian.PutUint64(first[2:], uint64(len(aad)))
		}
		used := copy(first[n:], aad)
		feed(first[:])
		feed(aad[used:])
	}
	feed(plaintext)
	counter[0] = 2
	copy(counter[1:13], nonce)
	c.block.Encrypt(mask[:], counter[:])
	for i := range state {
		state[i] ^= mask[i]
	}
	return state
}

func (c *dtlsCCM) crypt(dst, nonce, src []byte) {
	var counter, mask [16]byte
	counter[0] = 2
	copy(counter[1:13], nonce)
	for seq := uint32(1); len(src) != 0; seq++ {
		putUint24(counter[13:], seq)
		c.block.Encrypt(mask[:], counter[:])
		n := min(16, len(src))
		for i := range n {
			dst[i] = src[i] ^ mask[i]
		}
		dst, src = dst[n:], src[n:]
	}
}

func (c *dtlsCCM) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != 12 || len(plaintext) >= 1<<24 {
		panic("invalid DTLS CCM nonce or message size")
	}
	tag := c.mac(nonce, plaintext, aad)
	start := len(dst)
	dst = append(dst, plaintext...)
	c.crypt(dst[start:], nonce, dst[start:])
	return append(dst, tag[:c.tag]...)
}

func (c *dtlsCCM) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != 12 {
		panic("invalid DTLS CCM nonce size")
	}
	if len(ciphertext) < c.tag || len(ciphertext)-c.tag >= 1<<24 {
		return nil, errors.New("invalid DTLS CCM ciphertext size")
	}
	n, start := len(ciphertext)-c.tag, len(dst)
	var received [16]byte
	copy(received[:], ciphertext[n:])
	dst = append(dst, ciphertext[:n]...)
	plain := dst[start:]
	c.crypt(plain, nonce, plain)
	tag := c.mac(nonce, plain, aad)
	if subtle.ConstantTimeCompare(tag[:c.tag], received[:c.tag]) != 1 {
		clear(plain)
		return nil, errors.New("DTLS CCM authentication failed")
	}
	return dst, nil
}
