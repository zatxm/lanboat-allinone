package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os/exec"
	"testing"
)

func unhex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPoly1305Vector(t *testing.T) {
	p := newPolyState(unhex(t, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))
	p.write([]byte("Cryptographic Forum Research Group"))
	tag := p.sum()
	if hex.EncodeToString(tag[:]) != "a8061dc1305136c6c22b8baf0c0127a9" {
		t.Fatalf("Poly1305 vector mismatch: %x", tag)
	}
}

func TestChaChaIndependentOracle(t *testing.T) {
	// The external program is a test oracle only and is never linked into the core.
	program := `import json,sys
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
rows=json.load(sys.stdin)
json.dump([ChaCha20Poly1305(bytes.fromhex(x['key'])).encrypt(bytes.fromhex(x['nonce']),bytes.fromhex(x['plain']),bytes.fromhex(x['aad'])).hex() for x in rows],sys.stdout)`
	type vector struct {
		Key   string `json:"key"`
		Nonce string `json:"nonce"`
		Plain string `json:"plain"`
		AAD   string `json:"aad"`
	}
	var rows []vector
	random := rand.NewChaCha8([32]byte{1, 2, 3})
	sizes := []int{16383, 16384, 16385, 65535, 65536}
	for i := range 512 {
		sizes = append(sizes, i)
	}
	for _, size := range sizes {
		key, nonce, plain, aad := make([]byte, 32), make([]byte, 12), make([]byte, size), make([]byte, size%73)
		for _, b := range [][]byte{key, nonce, plain, aad} {
			_, _ = random.Read(b)
		}
		rows = append(rows, vector{hex.EncodeToString(key), hex.EncodeToString(nonce), hex.EncodeToString(plain), hex.EncodeToString(aad)})
	}
	input, _ := json.Marshal(rows)
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("independent crypto oracle unavailable: %v %s", err, output)
	}
	var expected []string
	if err := json.Unmarshal(output, &expected); err != nil {
		t.Fatal(err)
	}
	for i, row := range rows {
		c, _ := newChaChaAEAD(unhex(t, row.Key), false)
		nonce, plain, aad := unhex(t, row.Nonce), unhex(t, row.Plain), unhex(t, row.AAD)
		got := c.Seal(nil, nonce, plain, aad)
		if hex.EncodeToString(got) != expected[i] {
			t.Fatalf("AEAD oracle mismatch at length %d", i)
		}
		bad := bytes.Clone(got)
		bad[len(bad)-1] ^= 1
		guard := bytes.Repeat([]byte{0x5a}, len(plain)+16)
		if _, err := c.Open(guard[:0], nonce, bad, aad); err == nil || !bytes.Equal(guard, bytes.Repeat([]byte{0x5a}, len(guard))) {
			t.Fatal("invalid tag exposed plaintext or changed output")
		}
		decoded, err := c.Open(got[:0], nonce, got, aad)
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatalf("in-place decode mismatch: %v", err)
		}
	}
}

func TestHChaChaPublishedVector(t *testing.T) {
	var key [32]byte
	copy(key[:], unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	got := hchacha(&key, unhex(t, "000000090000004a0000000031415927"))
	if hex.EncodeToString(got[:]) != "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc" {
		t.Fatalf("HChaCha vector mismatch: %x", got)
	}
}
