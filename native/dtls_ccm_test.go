package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os/exec"
	"testing"
)

func TestDTLSCCMOracle(t *testing.T) {
	program := `import json,sys
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
rows=json.load(sys.stdin)
json.dump([AESCCM(bytes.fromhex(x['key']),tag_length=x['tag']).encrypt(bytes.fromhex(x['nonce']),bytes.fromhex(x['plain']),bytes.fromhex(x['aad'])).hex() for x in rows],sys.stdout)`
	type vector struct {
		Key   string `json:"key"`
		Nonce string `json:"nonce"`
		Plain string `json:"plain"`
		AAD   string `json:"aad"`
		Tag   int    `json:"tag"`
	}
	random := rand.NewChaCha8([32]byte{9, 3, 1})
	var rows []vector
	for _, keySize := range []int{16, 32} {
		for _, tag := range []int{8, 16} {
			for _, size := range []int{0, 1, 15, 16, 17, 255, 256, 1400, 16384, 65535} {
				for _, aadSize := range []int{0, 13, 14, 16, 17, 0xfeff, 0xff00, 65536} {
					key, nonce, plain, aad := make([]byte, keySize), make([]byte, 12), make([]byte, size), make([]byte, aadSize)
					for _, b := range [][]byte{key, nonce, plain, aad} {
						random.Read(b)
					}
					rows = append(rows, vector{hex.EncodeToString(key), hex.EncodeToString(nonce), hex.EncodeToString(plain), hex.EncodeToString(aad), tag})
				}
			}
		}
	}
	input, _ := json.Marshal(rows)
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("AES-CCM oracle: %v %s", err, output)
	}
	var expected []string
	if err = json.Unmarshal(output, &expected); err != nil || len(expected) != len(rows) {
		t.Fatal("oracle results", err)
	}
	for i, row := range rows {
		a, err := newDTLSCCM(unhex(t, row.Key), row.Tag)
		if err != nil {
			t.Fatal(err)
		}
		nonce, plain, aad := unhex(t, row.Nonce), unhex(t, row.Plain), unhex(t, row.AAD)
		buffer := make([]byte, len(plain), len(plain)+row.Tag)
		copy(buffer, plain)
		wire := a.Seal(buffer[:0], nonce, buffer, aad)
		if hex.EncodeToString(wire) != expected[i] {
			t.Fatalf("CCM differs from oracle at vector %d,tag %d,size %d,AAD %d", i, row.Tag, len(plain), len(aad))
		}
		guard := bytes.Repeat([]byte{0x5a}, 7)
		decoded, err := a.Open(bytes.Clone(guard), nonce, wire, aad)
		if err != nil || !bytes.Equal(decoded[:7], guard) || !bytes.Equal(decoded[7:], plain) {
			t.Fatal("CCM output prefix", i, err)
		}
		bad := bytes.Clone(wire)
		bad[len(bad)-1] ^= 1
		dst := bytes.Repeat([]byte{0x7b}, len(plain)+7)
		if got, err := a.Open(dst[:7], nonce, bad, aad); err == nil || got != nil || !bytes.Equal(dst[:7], bytes.Repeat([]byte{0x7b}, 7)) || !bytes.Equal(dst[7:], make([]byte, len(plain))) {
			t.Fatal("CCM invalid tag exposed plaintext", i, err)
		}
		decoded, err = a.Open(wire[:0], nonce, wire, aad)
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatal("CCM in-place decode", i, err)
		}
	}
}

func TestDTLSCCMBounds(t *testing.T) {
	for _, tag := range []int{0, 4, 7, 12, 17} {
		if _, err := newDTLSCCM(make([]byte, 16), tag); err == nil {
			t.Fatal("invalid tag accepted", tag)
		}
	}
	if _, err := newDTLSCCM(make([]byte, 17), 16); err == nil {
		t.Fatal("invalid key accepted")
	}
	a, _ := newDTLSCCM(make([]byte, 16), 16)
	for _, wire := range [][]byte{nil, make([]byte, 15)} {
		if _, err := a.Open(nil, make([]byte, 12), wire, nil); err == nil {
			t.Fatal("short ciphertext accepted")
		}
	}
	for _, f := range []func(){func() { a.Seal(nil, make([]byte, 13), nil, nil) }, func() { a.Open(nil, make([]byte, 11), nil, nil) }, func() { a.Seal(nil, make([]byte, 12), make([]byte, 1<<24), nil) }} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("invalid nonce or size did not panic")
				}
			}()
			f()
		}()
	}
}

func FuzzDTLSCCM(f *testing.F) {
	f.Add([]byte("payload"), []byte("header"), byte(16))
	f.Add([]byte{}, []byte{}, byte(8))
	f.Fuzz(func(t *testing.T, plain, aad []byte, tag byte) {
		if len(plain) > 16384 || len(aad) > 65536 {
			return
		}
		size := 8
		if tag&1 != 0 {
			size = 16
		}
		a, _ := newDTLSCCM(make([]byte, 16), size)
		nonce := make([]byte, 12)
		wire := a.Seal(nil, nonce, plain, aad)
		got, err := a.Open(nil, nonce, wire, aad)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatal("roundtrip", err)
		}
		wire[len(wire)-1] ^= 1
		if got, err = a.Open(nil, nonce, wire, aad); err == nil || got != nil {
			t.Fatal("forged tag accepted")
		}
	})
}
