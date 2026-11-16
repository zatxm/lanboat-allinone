package native

import (
	"encoding/binary"
	"errors"
	"time"
)

type kcpRS struct {
	data, parity int
	rows         [][]byte
}

var kcpGF = func() [256][256]byte {
	var t [256][256]byte
	for a := range 256 {
		for b := range 256 {
			t[a][b] = finiteByte(byte(a), byte(b), 0x11d)
		}
	}
	return t
}()

func kcpInverse(a [][]byte) ([][]byte, error) {
	n := len(a)
	m := make([][]byte, n)
	for i := range n {
		m[i] = make([]byte, 2*n)
		copy(m[i], a[i])
		m[i][n+i] = 1
	}
	for col := range n {
		pivot := col
		for pivot < n && m[pivot][col] == 0 {
			pivot++
		}
		if pivot == n {
			return nil, errors.New("singular FEC matrix")
		}
		m[col], m[pivot] = m[pivot], m[col]
		v := m[col][col]
		inverse := byte(1)
		for range 254 {
			inverse = kcpGF[inverse][v]
		}
		for j := col; j < 2*n; j++ {
			m[col][j] = kcpGF[m[col][j]][inverse]
		}
		for i := range n {
			if i == col {
				continue
			}
			f := m[i][col]
			if f != 0 {
				for j := col; j < 2*n; j++ {
					m[i][j] ^= kcpGF[f][m[col][j]]
				}
			}
		}
	}
	for i := range n {
		m[i] = m[i][n:]
	}
	return m, nil
}

func newKCPRS(data, parity int) *kcpRS {
	if data == 0 || parity == 0 {
		return nil
	}
	v := make([][]byte, data+parity)
	for i := range v {
		v[i] = make([]byte, data)
		v[i][0] = 1
		for j := 1; j < data; j++ {
			v[i][j] = kcpGF[v[i][j-1]][byte(i)]
		}
	}
	inv, _ := kcpInverse(v[:data])
	r := &kcpRS{data: data, parity: parity, rows: make([][]byte, data+parity)}
	for i := range r.rows {
		r.rows[i] = make([]byte, data)
		for j := range data {
			for k := range data {
				r.rows[i][j] ^= kcpGF[v[i][k]][inv[k][j]]
			}
		}
	}
	return r
}

func kcpCombine(row []byte, shards [][]byte, size int) []byte {
	b := make([]byte, size)
	for i, f := range row {
		if f == 0 {
			continue
		}
		for j, v := range shards[i] {
			b[j] ^= kcpGF[f][v]
		}
	}
	return b
}

func (r *kcpRS) recover(shards [][]byte, size int) ([][]byte, error) {
	var rows, chosen [][]byte
	for i, b := range shards {
		if b != nil {
			rows = append(rows, r.rows[i])
			chosen = append(chosen, b)
			if len(rows) == r.data {
				break
			}
		}
	}
	if len(rows) < r.data {
		return nil, errors.New("insufficient FEC shards")
	}
	inv, err := kcpInverse(rows)
	if err != nil {
		return nil, err
	}
	recovered := make([][]byte, r.data)
	for i := range r.data {
		if shards[i] == nil {
			recovered[i] = kcpCombine(inv[i], chosen, size)
		}
	}
	return recovered, nil
}

type kcpFECGroup struct {
	at                 time.Time
	shards             [][]byte
	count, size, bytes int
}
type kcpFEC struct {
	r               *Runtime
	code            *kcpRS
	seq             uint32
	sending         [][]byte
	sendSize, bytes int
	groups          map[uint32]*kcpFECGroup
}

func newKCPFEC(r *Runtime, code *kcpRS) *kcpFEC {
	return &kcpFEC{r: r, code: code, groups: map[uint32]*kcpFECGroup{}}
}
func (f *kcpFEC) reserve(n int) bool {
	if f.bytes+n > 256<<10 {
		return false
	}
	if f.r.kcpFECBudget.Add(int64(n)) > 8<<20 {
		f.r.kcpFECBudget.Add(-int64(n))
		return false
	}
	f.bytes += n
	return true
}
func (f *kcpFEC) release(n int) { f.bytes -= n; f.r.kcpFECBudget.Add(-int64(n)) }
func (f *kcpFEC) clearSend() {
	for _, b := range f.sending {
		f.release(len(b))
	}
	f.sending = nil
	f.sendSize = 0
}
func (f *kcpFEC) drop(id uint32) {
	if g := f.groups[id]; g != nil {
		f.release(g.bytes)
		delete(f.groups, id)
	}
}
func (f *kcpFEC) close() {
	f.clearSend()
	for id := range f.groups {
		f.drop(id)
	}
}

func (f *kcpFEC) encode(b []byte) [][]byte {
	if f.code == nil {
		return [][]byte{b}
	}
	k, p := f.code.data, f.code.parity
	total := uint32(k + p)
	seq := f.seq
	index := int(seq % total)
	frame := make([]byte, 8+len(b))
	binary.LittleEndian.PutUint32(frame, seq)
	binary.LittleEndian.PutUint16(frame[4:], 0xf1)
	binary.LittleEndian.PutUint16(frame[6:], uint16(2+len(b)))
	copy(frame[8:], b)
	out := [][]byte{frame}
	f.seq++
	if index == 0 {
		f.clearSend()
	}
	if len(f.sending) == index && f.reserve(len(frame)-6) {
		f.sending = append(f.sending, append([]byte(nil), frame[6:]...))
		f.sendSize = max(f.sendSize, len(frame)-6)
	}
	if index == k-1 {
		if len(f.sending) == k {
			for i := range p {
				parity := make([]byte, 6, 6+f.sendSize)
				binary.LittleEndian.PutUint32(parity, f.seq+uint32(i))
				binary.LittleEndian.PutUint16(parity[4:], 0xf2)
				parity = append(parity, kcpCombine(f.code.rows[k+i], f.sending, f.sendSize)...)
				out = append(out, parity)
			}
		}
		f.seq += uint32(p)
		f.clearSend()
	}
	if f.seq >= (^uint32(0)/total)*total {
		f.seq = 0
	}
	return out
}

func (f *kcpFEC) decode(b []byte) [][]byte {
	if f.code == nil {
		return [][]byte{b}
	}
	if len(b) < 8 {
		return nil
	}
	k, total := f.code.data, f.code.data+f.code.parity
	seq, kind := binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:])
	index := int(seq % uint32(total))
	id := seq / uint32(total)
	if kind != 0xf1 && kind != 0xf2 || kind == 0xf1 && index >= k || kind == 0xf2 && index < k {
		return nil
	}
	payload := b[6:]
	var out [][]byte
	if kind == 0xf1 {
		n := int(binary.LittleEndian.Uint16(payload))
		if n < 26 || n > len(payload) {
			return nil
		}
		out = append(out, payload[2:n])
	}
	now := time.Now()
	for id, g := range f.groups {
		if now.Sub(g.at) > time.Second {
			f.drop(id)
		}
	}
	g := f.groups[id]
	if g == nil {
		if len(f.groups) >= 8 {
			var oldest uint32
			at := now
			for id, g := range f.groups {
				if g.at.Before(at) {
					oldest, at = id, g.at
				}
			}
			f.drop(oldest)
		}
		g = &kcpFECGroup{at: now, shards: make([][]byte, total)}
		f.groups[id] = g
	}
	if g.shards[index] != nil || !f.reserve(len(payload)) {
		return out
	}
	g.shards[index] = append([]byte(nil), payload...)
	g.count++
	g.bytes += len(payload)
	g.size = max(g.size, len(payload))
	if g.count >= k {
		missing := false
		for i := range k {
			missing = missing || g.shards[i] == nil
		}
		if missing {
			if recovered, err := f.code.recover(g.shards, g.size); err == nil {
				for _, b := range recovered {
					if len(b) >= 26 {
						n := int(binary.LittleEndian.Uint16(b))
						if n >= 26 && n <= len(b) {
							out = append(out, b[2:n])
						}
					}
				}
			}
		}
		f.drop(id)
	}
	return out
}
