package native

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

const sudokuMasterVector = "709aab5f030c9b8c322811d5c6545497c2136ce1e43b574e231562303de8f108"
const sudokuPublicVector = "6e5c05c3f7f5d45fcd2f6a5a7f4700f94ff51db376c128c581849feb71ccc58b"
const sudokuSplitVector = "b1ec294d5dba60a800e1ef8c3423d5a176093f0d8c432e01bc24895d6828140aac81776fc0b44c3c08e418eb702b5e0a4c0a2dd458f8284d67f0d8d2d4bfdd0e"

func TestSudokuPrivateVectors(t *testing.T) {
	for _, key := range []string{sudokuMasterVector, sudokuSplitVector, strings.ToUpper(sudokuSplitVector),
		"89acb9663cfd3bd04adf0001cc7000a8eb312903088b33a847d7e5cf102f1d0ad4c1e755e1717114bee50777d9dd3204d7e142dedcb023a6db3d7c602cb9d40e"} {
		public, err := RecoverSudokuPublicKey(key)
		if err != nil || public != sudokuPublicVector {
			t.Fatal("official public recovery vector", public, err)
		}
	}
	for _, test := range []struct{ key, public string }{
		{strings.Repeat("00", 32), "01" + strings.Repeat("00", 31)},
		{"01" + strings.Repeat("00", 31), "58" + strings.Repeat("66", 31)},
		{"ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010", "58" + strings.Repeat("66", 30) + "e6"},
	} {
		public, err := RecoverSudokuPublicKey(test.key)
		if err != nil || public != test.public {
			t.Fatal("scalar boundary", public, err)
		}
	}
	order := "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
	for _, key := range []string{"", strings.Repeat("0", 63), strings.Repeat("0", 65), strings.Repeat("0", 129),
		strings.Repeat("z", 64), order, strings.Repeat("ff", 32), order + sudokuMasterVector, sudokuMasterVector + order} {
		if _, err := RecoverSudokuPublicKey(key); err == nil {
			t.Fatal("invalid scalar accepted")
		}
		if _, err := SplitSudokuPrivateKey(key); err == nil {
			t.Fatal("invalid split input accepted")
		}
	}
}

func sudokuTestLE(b []byte) *big.Int {
	v := bytes.Clone(b)
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
	return new(big.Int).SetBytes(v)
}

func TestSudokuFieldArithmetic(t *testing.T) {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for i := range 512 {
		var ab, bb [32]byte
		rand.Read(ab[:])
		rand.Read(bb[:])
		ab[31] &= 127
		bb[31] &= 127
		if i < 20 {
			v := new(big.Int).Sub(p, big.NewInt(int64(i)))
			v.FillBytes(ab[:])
			for x, y := 0, 31; x < y; x, y = x+1, y-1 {
				ab[x], ab[y] = ab[y], ab[x]
			}
			bb = ab
		}
		a, b := sudokuFieldReduce(sudokuFieldDecode(ab)), sudokuFieldReduce(sudokuFieldDecode(bb))
		ai, bi := sudokuTestLE(ab[:]), sudokuTestLE(bb[:])
		for _, check := range []struct {
			value sudokuField
			want  *big.Int
		}{
			{a.add(b), new(big.Int).Add(ai, bi)}, {a.sub(b), new(big.Int).Sub(ai, bi)}, {a.mul(b), new(big.Int).Mul(ai, bi)},
		} {
			encoded := check.value.bytes()
			if sudokuTestLE(encoded[:]).Cmp(check.want.Mod(check.want, p)) != 0 {
				t.Fatal("field arithmetic", i)
			}
			for _, limb := range check.value {
				if limb > sudokuLimb {
					t.Fatal("unnormalized limb")
				}
			}
		}
		if ai.Sign() != 0 && new(big.Int).Mod(ai, p).Sign() != 0 {
			one := a.mul(a.inverse()).bytes()
			if one != [32]byte{1} {
				t.Fatal("inverse", i)
			}
		}
	}
}

func TestSudokuScalarAndPublicArithmetic(t *testing.T) {
	order := sudokuOrder.bytes()
	for i := range 128 {
		var input [64]byte
		rand.Read(input[:])
		if i == 0 {
			input = [64]byte{}
		}
		if i == 1 {
			for j := range input {
				input[j] = 255
			}
		}
		s := sudokuScalarUniform(input).bytes()
		want := sudokuTestLE(input[:])
		want.Mod(want, sudokuTestLE(order[:]))
		if sudokuTestLE(s[:]).Cmp(want) != 0 {
			t.Fatal("512-bit scalar reduction")
		}
	}
	seen := map[string]bool{}
	for range 64 {
		identity, err := GenerateSudokuKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		s, raw, err := sudokuParsePrivate(identity.PrivateKey)
		if err != nil || seen[identity.PublicKey] {
			t.Fatal("key generation", err)
		}
		seen[identity.PublicKey] = true
		parsed, _, err := sudokuParsePrivate(identity.SplitKey)
		if err != nil || s != parsed {
			t.Fatal("scalar split", err)
		}
		public, err := RecoverSudokuPublicKey(identity.SplitKey)
		if err != nil || public != identity.PublicKey {
			t.Fatal("point recovery", err)
		}
		split, err := SplitSudokuPrivateKey(identity.SplitKey)
		if err != nil || split == identity.SplitKey {
			t.Fatal("fresh split", err)
		}
		parsed, _, err = sudokuParsePrivate(split)
		if err != nil || s != parsed {
			t.Fatal("re-split changed master", err)
		}
		if len(raw) != 32 {
			t.Fatal("master size")
		}
	}
	// Compare against standard-library Ed25519 public derivation. Its seed hash
	// produces a clamped scalar; reduce it to the same prime-order subgroup.
	for range 64 {
		var seed [32]byte
		rand.Read(seed[:])
		h := sha512.Sum512(seed[:])
		h[0] &= 248
		h[31] = h[31]&63 | 64
		n := sudokuTestLE(h[:32])
		l := sudokuOrder.bytes()
		n.Mod(n, sudokuTestLE(l[:]))
		var encoded [32]byte
		n.FillBytes(encoded[:])
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			encoded[i], encoded[j] = encoded[j], encoded[i]
		}
		got, err := RecoverSudokuPublicKey(hex.EncodeToString(encoded[:]))
		want := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
		if err != nil || got != hex.EncodeToString(want) {
			t.Fatal("standard-library point comparison", got, err)
		}
	}
}
