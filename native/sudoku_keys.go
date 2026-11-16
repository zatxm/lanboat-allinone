package native

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
)

// Sudoku encodes canonical little-endian Edwards25519 scalars, not Ed25519
// seeds. Secret arithmetic below uses fixed loops and masked selection. The
// variable-time public-point verifier used by Tailnet Lock is unsuitable here.
type sudokuScalar [4]uint64

var sudokuOrder = sudokuScalar{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

func (s sudokuScalar) bytes() (b [32]byte) {
	for i, v := range s {
		binary.LittleEndian.PutUint64(b[i*8:], v)
	}
	return
}

func (s sudokuScalar) reduce() (sudokuScalar, uint64) {
	var d sudokuScalar
	var borrow uint64
	for i := range d {
		d[i], borrow = bits.Sub64(s[i], sudokuOrder[i], borrow)
	}
	mask := uint64(0) - borrow
	for i := range d {
		d[i] = d[i]&^mask | s[i]&mask
	}
	return d, borrow
}

func sudokuScalarFromBytes(b []byte) (sudokuScalar, error) {
	var s sudokuScalar
	for i := range s {
		s[i] = binary.LittleEndian.Uint64(b[i*8:])
	}
	if _, below := s.reduce(); below != 1 {
		return s, errors.New("noncanonical Sudoku private scalar")
	}
	return s, nil
}

func sudokuParsePrivate(key string) (sudokuScalar, []byte, error) {
	if len(key) != 64 && len(key) != 128 {
		return sudokuScalar{}, nil, errors.New("Sudoku private key must be64 or128 hexadecimal characters")
	}
	b, err := hex.DecodeString(key)
	if err != nil {
		return sudokuScalar{}, nil, errors.New("invalid Sudoku private key encoding")
	}
	s, err := sudokuScalarFromBytes(b[:32])
	if err == nil && len(b) == 64 {
		var k sudokuScalar
		k, err = sudokuScalarFromBytes(b[32:])
		var carry uint64
		for i := range s {
			s[i], carry = bits.Add64(s[i], k[i], carry)
		}
		s, _ = s.reduce()
	}
	return s, b, err
}

func sudokuRandomScalar() (sudokuScalar, error) {
	var b [64]byte
	if _, err := rand.Read(b[:]); err != nil {
		return sudokuScalar{}, err
	}
	s := sudokuScalarUniform(b)
	clear(b[:])
	return s, nil
}

func sudokuScalarUniform(b [64]byte) sudokuScalar {
	var s sudokuScalar
	// Reduce the uniform512-bit input modulo L without division or secret indices.
	for i := 511; i >= 0; i-- {
		carry := uint64(b[i/8] >> uint(i%8) & 1)
		for j := range s {
			s[j], carry = s[j]<<1|carry, s[j]>>63
		}
		s, _ = s.reduce()
	}
	return s
}

// SplitSudokuPrivateKey creates r||k with r+k equal to the master scalar modulo L.
// Both a master and an existing split key may be supplied.
func SplitSudokuPrivateKey(key string) (string, error) {
	s, raw, err := sudokuParsePrivate(key)
	clear(raw)
	if err != nil {
		return "", err
	}
	r, err := sudokuRandomScalar()
	if err != nil {
		return "", err
	}
	var k sudokuScalar
	var borrow uint64
	for i := range k {
		k[i], borrow = bits.Sub64(s[i], r[i], borrow)
	}
	mask, carry := uint64(0)-borrow, uint64(0)
	for i := range k {
		k[i], carry = bits.Add64(k[i], sudokuOrder[i]&mask, carry)
	}
	a, b := r.bytes(), k.bytes()
	return hex.EncodeToString(a[:]) + hex.EncodeToString(b[:]), nil
}

// RecoverSudokuPublicKey returns the compressed Edwards point [r+k]B or [x]B.
func RecoverSudokuPublicKey(key string) (string, error) {
	s, raw, err := sudokuParsePrivate(key)
	clear(raw)
	if err != nil {
		return "", err
	}
	b := sudokuPublic(s)
	return hex.EncodeToString(b[:]), nil
}

type SudokuKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	SplitKey   string `json:"split_key"`
}

func GenerateSudokuKeyPair() (SudokuKeyPair, error) {
	s, err := sudokuRandomScalar()
	for s == (sudokuScalar{}) && err == nil {
		s, err = sudokuRandomScalar()
	}
	if err != nil {
		return SudokuKeyPair{}, err
	}
	b := s.bytes()
	private := hex.EncodeToString(b[:])
	split, err := SplitSudokuPrivateKey(private)
	if err != nil {
		return SudokuKeyPair{}, err
	}
	public := sudokuPublic(s)
	return SudokuKeyPair{private, hex.EncodeToString(public[:]), split}, nil
}

// Seventeen radix2^15 limbs cover exactly255 bits. Products fit in uint64;
// 2^255 =19 modulo p permits reduction with three fixed carry passes.
type sudokuField [17]uint64

const sudokuLimb = uint64(1<<15 - 1)

func sudokuFieldReduce(a sudokuField) sudokuField {
	for range 3 {
		for i := 0; i < 16; i++ {
			a[i+1] += a[i] >> 15
			a[i] &= sudokuLimb
		}
		a[0] += 19 * (a[16] >> 15)
		a[16] &= sudokuLimb
	}
	var d sudokuField
	var borrow uint64
	for i := range d {
		p := sudokuLimb
		if i == 0 {
			p -= 18
		}
		x := a[i] - p - borrow
		borrow = x >> 63
		d[i] = x & sudokuLimb
	}
	mask := uint64(0) - borrow
	for i := range d {
		d[i] = d[i]&^mask | a[i]&mask
	}
	return d
}

func (a sudokuField) add(b sudokuField) sudokuField {
	for i := range a {
		a[i] += b[i]
	}
	return sudokuFieldReduce(a)
}

func (a sudokuField) sub(b sudokuField) sudokuField {
	for i := range a {
		p := sudokuLimb
		if i == 0 {
			p -= 18
		}
		a[i] += 2*p - b[i]
	}
	return sudokuFieldReduce(a)
}

func (a sudokuField) mul(b sudokuField) sudokuField {
	var product [33]uint64
	for i := range a {
		for j := range b {
			product[i+j] += a[i] * b[j]
		}
	}
	for i := 32; i >= 17; i-- {
		product[i-17] += 19 * product[i]
	}
	var c sudokuField
	copy(c[:], product[:17])
	return sudokuFieldReduce(c)
}

func (a sudokuField) inverse() sudokuField {
	r := sudokuField{1}
	// p-2 =2^255-21. Exponent bits are public and fixed.
	for i := 254; i >= 0; i-- {
		r = r.mul(r)
		if i >= 5 || 0x0b>>uint(i)&1 != 0 {
			r = r.mul(a)
		}
	}
	return r
}

func sudokuFieldDecode(b [32]byte) (a sudokuField) {
	for i := range 255 {
		a[i/15] |= uint64(b[i/8]>>uint(i%8)&1) << uint(i%15)
	}
	return
}

func (a sudokuField) bytes() (b [32]byte) {
	a = sudokuFieldReduce(a)
	for i := range 255 {
		b[i/8] |= byte(a[i/15]>>uint(i%15)&1) << uint(i%8)
	}
	return
}

type sudokuPoint struct{ x, y, z, t sudokuField }

var sudokuBase = func() sudokuPoint {
	// RFC8032 Edwards25519 base point: x positive/even, y=4/5.
	x := sudokuFieldDecode([32]byte{0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21})
	y := sudokuField{4}.mul(sudokuField{5}.inverse())
	return sudokuPoint{x, y, sudokuField{1}, x.mul(y)}
}()

var sudokuDoubleD = sudokuField{}.sub(sudokuFieldReduce(sudokuField{243330})).mul(sudokuFieldReduce(sudokuField{121666}).inverse())

func (p sudokuPoint) add(q sudokuPoint) sudokuPoint {
	a := p.y.sub(p.x).mul(q.y.sub(q.x))
	b := p.y.add(p.x).mul(q.y.add(q.x))
	c := p.t.mul(q.t).mul(sudokuDoubleD)
	d := p.z.mul(q.z)
	d = d.add(d)
	e, f, g, h := b.sub(a), d.sub(c), d.add(c), b.add(a)
	return sudokuPoint{e.mul(f), g.mul(h), f.mul(g), e.mul(h)}
}

func sudokuPublic(s sudokuScalar) [32]byte {
	p := sudokuPoint{y: sudokuField{1}, z: sudokuField{1}}
	for i := 255; i >= 0; i-- {
		p = p.add(p)
		q := p.add(sudokuBase)
		mask := uint64(0) - (s[i/64] >> uint(i%64) & 1)
		for j := range p.x {
			p.x[j] = p.x[j]&^mask | q.x[j]&mask
			p.y[j] = p.y[j]&^mask | q.y[j]&mask
			p.z[j] = p.z[j]&^mask | q.z[j]&mask
			p.t[j] = p.t[j]&^mask | q.t[j]&mask
		}
	}
	z := p.z.inverse()
	x, y := p.x.mul(z).bytes(), p.y.mul(z).bytes()
	y[31] |= (x[0] & 1) << 7
	return y
}
