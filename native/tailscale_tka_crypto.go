package native

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
)

// ZIP215 differs from Go's strict Ed25519 verification for noncanonical curve
// encodings and torsion. The normal case stays in the standard library. This
// public-data-only fallback evaluates the cofactored equation from ZIP215.
// It is never used to sign or manipulate private scalars.
var tsEdP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
var tsEdL, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
var tsEdD = tsEdMod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), tsEdP)))

type tsEdPoint struct{ x, y, z, t *big.Int }

func tsEdMod(x *big.Int) *big.Int    { return x.Mod(x, tsEdP) }
func tsEdAdd(a, b *big.Int) *big.Int { return tsEdMod(new(big.Int).Add(a, b)) }
func tsEdSub(a, b *big.Int) *big.Int { return tsEdMod(new(big.Int).Sub(a, b)) }
func tsEdMul(a, b *big.Int) *big.Int { return tsEdMod(new(big.Int).Mul(a, b)) }
func tsEdLE(b []byte) *big.Int {
	v := make([]byte, len(b))
	for i := range b {
		v[len(b)-i-1] = b[i]
	}
	return new(big.Int).SetBytes(v)
}
func tsEdIdentity() tsEdPoint {
	return tsEdPoint{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}
}
func tsEdDecode(b []byte) (tsEdPoint, bool) {
	if len(b) != 32 {
		return tsEdPoint{}, false
	}
	v := [32]byte(b)
	sign := v[31] >> 7
	v[31] &= 127
	y := tsEdMod(tsEdLE(v[:]))
	yy := tsEdMul(y, y)
	den := new(big.Int).ModInverse(tsEdAdd(tsEdMul(tsEdD, yy), big.NewInt(1)), tsEdP)
	if den == nil {
		return tsEdPoint{}, false
	}
	xx := tsEdMul(tsEdSub(yy, big.NewInt(1)), den)
	x := new(big.Int).ModSqrt(xx, tsEdP)
	if x == nil {
		return tsEdPoint{}, false
	}
	if x.Bit(0) != uint(sign) {
		x = tsEdSub(big.NewInt(0), x)
	}
	return tsEdPoint{x, y, big.NewInt(1), tsEdMul(x, y)}, true
}
func (p tsEdPoint) add(q tsEdPoint) tsEdPoint {
	a := tsEdMul(tsEdSub(p.y, p.x), tsEdSub(q.y, q.x))
	b := tsEdMul(tsEdAdd(p.y, p.x), tsEdAdd(q.y, q.x))
	c := tsEdMul(big.NewInt(2), tsEdMul(tsEdD, tsEdMul(p.t, q.t)))
	d := tsEdMul(big.NewInt(2), tsEdMul(p.z, q.z))
	e, f, g, h := tsEdSub(b, a), tsEdSub(d, c), tsEdAdd(d, c), tsEdAdd(b, a)
	return tsEdPoint{tsEdMul(e, f), tsEdMul(g, h), tsEdMul(f, g), tsEdMul(e, h)}
}
func (p tsEdPoint) scale(n *big.Int) tsEdPoint {
	r := tsEdIdentity()
	for i := n.BitLen() - 1; i >= 0; i-- {
		r = r.add(r)
		if n.Bit(i) == 1 {
			r = r.add(p)
		}
	}
	return r
}
func tsTKAVerify(key, message, sig []byte) bool {
	if len(key) != 32 || len(sig) != 64 {
		return false
	}
	if ed25519.Verify(ed25519.PublicKey(key), message, sig) {
		return true
	}
	s := tsEdLE(sig[32:])
	if s.Cmp(tsEdL) >= 0 {
		return false
	}
	a, ok := tsEdDecode(key)
	if !ok {
		return false
	}
	r, ok := tsEdDecode(sig[:32])
	if !ok {
		return false
	}
	h := sha512.New()
	h.Write(sig[:32])
	h.Write(key)
	h.Write(message)
	k := tsEdLE(h.Sum(nil))
	k.Mod(k, tsEdL)
	baseBytes := [32]byte{0x58}
	for i := 1; i < 32; i++ {
		baseBytes[i] = 0x66
	}
	base, _ := tsEdDecode(baseBytes[:])
	lhs, rhs := base.scale(s), r.add(a.scale(k))
	for range 3 {
		lhs = lhs.add(lhs)
		rhs = rhs.add(rhs)
	}
	return tsEdMul(lhs.x, rhs.z).Cmp(tsEdMul(rhs.x, lhs.z)) == 0 && tsEdMul(lhs.y, rhs.z).Cmp(tsEdMul(rhs.y, lhs.z)) == 0
}

// Argon2i v1.3 parameters fixed by the Tailnet Lock protocol, not by remote
// input: 16MiB, four lanes, four passes, 32 output bytes (RFC9106).
func tsTKADisablement(secret []byte) []byte {
	const lanes = 4
	const blocks = 16384
	const segment = blocks / lanes / 4
	const laneSize = blocks / lanes
	salt := []byte("tailscale network-lock disablement salt")
	var input []byte
	for _, v := range []uint32{lanes, 32, blocks, 4, 0x13, 1, uint32(len(secret))} {
		input = binary.LittleEndian.AppendUint32(input, v)
	}
	input = append(input, secret...)
	input = binary.LittleEndian.AppendUint32(input, uint32(len(salt)))
	input = append(input, salt...)
	input = append(input, make([]byte, 8)...)
	h := blake2b(input, 64)
	memory := make([]argonBlock, blocks)
	for lane := range lanes {
		for index := range 2 {
			seed := binary.LittleEndian.AppendUint32(append([]byte(nil), h...), uint32(index))
			seed = binary.LittleEndian.AppendUint32(seed, uint32(lane))
			expanded := argonHash(seed, 1024)
			for j := range 128 {
				memory[lane*laneSize+index][j] = binary.LittleEndian.Uint64(expanded[j*8:])
			}
		}
	}
	for pass := range 4 {
		for slice := range 4 {
			for lane := range lanes {
				addressInput := argonBlock{uint64(pass), uint64(lane), uint64(slice), blocks, 4, 1}
				var addresses argonBlock
				start := 0
				if pass == 0 && slice == 0 {
					start = 2
					addressInput[6]++
					addresses = argonCompress(argonBlock{}, argonCompress(argonBlock{}, addressInput))
				}
				for index := start; index < segment; index++ {
					if index%128 == 0 {
						addressInput[6]++
						addresses = argonCompress(argonBlock{}, argonCompress(argonBlock{}, addressInput))
					}
					random := addresses[index%128]
					other := int(random>>32) % lanes
					if pass == 0 && slice == 0 {
						other = lane
					}
					area := slice * segment
					if pass > 0 {
						area = laneSize - segment
					}
					if other == lane {
						area += index - 1
					} else if index == 0 {
						area--
					}
					rel := uint64(uint32(random))
					rel = rel * rel >> 32
					rel = uint64(area-1) - (uint64(area) * rel >> 32)
					base := 0
					if pass > 0 {
						base = (slice + 1) * segment % laneSize
					}
					reference := other*laneSize + (base+int(rel))%laneSize
					position := lane*laneSize + slice*segment + index
					previous := lane*laneSize + (slice*segment+index+laneSize-1)%laneSize
					mixed := argonCompress(memory[previous], memory[reference])
					if pass > 0 {
						for j := range mixed {
							mixed[j] ^= memory[position][j]
						}
					}
					memory[position] = mixed
				}
			}
		}
	}
	last := memory[laneSize-1]
	for lane := 1; lane < lanes; lane++ {
		for j := range last {
			last[j] ^= memory[(lane+1)*laneSize-1][j]
		}
	}
	data := make([]byte, 1024)
	for j, v := range last {
		binary.LittleEndian.PutUint64(data[j*8:], v)
	}
	clear(memory)
	return argonHash(data, 32)
}
