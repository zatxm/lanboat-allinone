package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"math/rand/v2"
	"testing"
)

func TestOCCBCMACOracle(t *testing.T) {
	for _, spec := range []struct {
		name string
		new  func() hash.Hash
	}{{"SHA1", sha1.New}, {"SHA256", sha256.New}, {"SHA384", sha512.New384}} {
		t.Run(spec.name, func(t *testing.T) {
			rng := rand.New(rand.NewPCG(0x123, 0x456))
			key, aad := make([]byte, spec.new().Size()), make([]byte, 13)
			for _, b := range [][]byte{key, aad} {
				for i := range b {
					b[i] = byte(rng.Uint32())
				}
			}
			m := newOCCBCMAC(key, len(key))
			for _, size := range []int{0, 1, 2, 20, 32, 48, 50, 51, 52, 63, 64, 100, 101, 102, 111, 112, 127, 128, 255, 256, 511, 512, 1280, 4096, 16383, 16384} {
				for padding := range 256 {
					plain := make([]byte, size+len(key)+padding+1)
					for i := range plain {
						plain[i] = byte(rng.Uint32())
					}
					h := hmac.New(spec.new, key)
					h.Write(aad)
					h.Write(plain[:size])
					expected := h.Sum(nil)
					got := m.sum(aad, plain, size)
					if !bytes.Equal(got[:len(key)], expected) {
						t.Fatal("HMAC mismatch", size, padding)
					}
				}
			}
		})
	}
}

func FuzzOCCBCMAC(f *testing.F) {
	f.Add([]byte("secret message"), byte(2), uint16(6))
	f.Fuzz(func(t *testing.T, plain []byte, algorithm byte, cut uint16) {
		if len(plain) > 16800 {
			return
		}
		h := []func() hash.Hash{sha1.New, sha256.New, sha512.New384}[int(algorithm)%3]
		key, aad := bytes.Repeat([]byte{7}, h().Size()), []byte("public header")
		n := int(cut) % (len(plain) + 1)
		mac := hmac.New(h, key)
		mac.Write(aad)
		mac.Write(plain[:n])
		m := newOCCBCMAC(key, len(key))
		got := m.sum(aad, plain, n)
		if !bytes.Equal(got[:len(key)], mac.Sum(nil)) {
			t.Fatal("constant-work HMAC differs from standard HMAC")
		}
	})
}
