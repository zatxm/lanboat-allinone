package native

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestBlowfishKnownAnswer(t *testing.T) {
	b, e := newBlowfish(make([]byte, 8))
	if e != nil {
		t.Fatal(e)
	}
	out := make([]byte, 8)
	b.Encrypt(out, make([]byte, 8))
	if hex.EncodeToString(out) != "4ef997456198dd78" {
		t.Fatalf("ciphertext %x", out)
	}
	b.Decrypt(out, out)
	if !bytes.Equal(out, make([]byte, 8)) {
		t.Fatalf("plaintext %x", out)
	}
}

func TestBcryptPBKDFOracle(t *testing.T) {
	raw, e := os.ReadFile("testdata/bcrypt-pbkdf-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		Password, Salt, Key string
		Rounds, Size        int
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		p, _ := hex.DecodeString(v.Password)
		s, _ := hex.DecodeString(v.Salt)
		key, e := bcryptPBKDF(p, s, v.Rounds, v.Size)
		if e != nil || hex.EncodeToString(key) != v.Key {
			t.Fatalf("rounds=%d size=%d key=%x error=%v", v.Rounds, v.Size, key, e)
		}
	}
}
