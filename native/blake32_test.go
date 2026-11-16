package native

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestBlake3OfficialVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/blake3-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		InputLen int    `json:"input_len"`
		Hash     string `json:"hash"`
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		b := make([]byte, v.InputLen)
		for i := range b {
			b[i] = byte(i % 251)
		}
		got := blake3Sum(b)
		if hex.EncodeToString(got[:]) != v.Hash {
			t.Fatalf("length %d: %x != %s", len(b), got, v.Hash)
		}
	}
}

func TestBlake3DeriveOfficialVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/blake3-derive-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Context string `json:"context"`
		Cases   []struct {
			InputLen  int    `json:"input_len"`
			DeriveKey string `json:"derive_key"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Cases {
		data := make([]byte, v.InputLen)
		for i := range data {
			data[i] = byte(i % 251)
		}
		hash := blake3Derive(vectors.Context, data)
		if hex.EncodeToString(hash[:]) != v.DeriveKey {
			t.Fatalf("derive_key length%d: %x", v.InputLen, hash)
		}
	}
}
func TestBlake2sVectors(t *testing.T) {
	for _, v := range []struct {
		data, key, want string
		size            int
	}{
		{"", "", "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9", 32},
		{"abc", "", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982", 32},
	} {
		if got := hex.EncodeToString(blake2s([]byte(v.data), []byte(v.key), v.size)); got != v.want {
			t.Fatalf("%s: %s", v.data, got)
		}
	}
	raw, e := os.ReadFile("testdata/blake2s-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		N, Size   int
		Key, Hash string
	}
	if e = json.Unmarshal(raw, &vectors); e != nil {
		t.Fatal(e)
	}
	for _, v := range vectors {
		b := make([]byte, v.N)
		for i := range b {
			b[i] = byte(i % 251)
		}
		key, _ := hex.DecodeString(v.Key)
		if got := hex.EncodeToString(blake2s(b, key, v.Size)); got != v.Hash {
			t.Fatalf("n=%d,size=%d,key=%d: %s != %s", v.N, v.Size, len(key), got, v.Hash)
		}
	}
}
