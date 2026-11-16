package native

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	seedrand "math/rand"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
)

// Sudoku's table order is a wire convention. Geometry and clue searches are
// shared by every configured key; only the byte-to-grid permutation is private.
type sudokuGeometry struct {
	grids [][16]byte
	clues [][]uint16
	sets  [64][5]uint64
}

var sudokuGeometryOnce = sync.OnceValue(func() *sudokuGeometry {
	g := new(sudokuGeometry)
	var cells [16]byte
	var row, col, box [4]byte
	var visit func(int)
	visit = func(i int) {
		if i == 16 {
			g.grids = append(g.grids, cells)
			return
		}
		r, c, b := i/4, i%4, i/8*2+i%4/2
		available := ^(row[r] | col[c] | box[b]) & 15
		for available != 0 {
			v := bits.TrailingZeros8(available)
			mask := byte(1 << v)
			available &^= mask
			cells[i] = byte(v)
			row[r] |= mask
			col[c] |= mask
			box[b] |= mask
			visit(i + 1)
			row[r] &^= mask
			col[c] &^= mask
			box[b] &^= mask
		}
	}
	visit(0)
	g.clues = make([][]uint16, len(g.grids))
	for i, grid := range g.grids {
		for p, v := range grid {
			g.sets[int(v)*16+p][i/64] |= 1 << (i % 64)
		}
	}
	for mask := uint32(0); mask < 1<<16; mask++ {
		if bits.OnesCount32(mask) != 4 {
			continue
		}
		var count [256]uint16
		var signatures [288]byte
		for i, grid := range g.grids {
			var signature byte
			for m := mask; m != 0; m &= m - 1 {
				signature = signature<<2 | grid[bits.TrailingZeros32(m)]
			}
			signatures[i] = signature
			count[signature]++
		}
		for i, signature := range signatures {
			if count[signature] == 1 {
				g.clues[i] = append(g.clues[i], uint16(mask))
			}
		}
	}
	return g
})

type sudokuTable struct {
	geometry *sudokuGeometry
	order    [288]uint16
	rank     [288]uint16
}

func newSudokuTable(key string) *sudokuTable {
	t := &sudokuTable{geometry: sudokuGeometryOnce()}
	for i := range t.order {
		t.order[i] = uint16(i)
	}
	h := sha256.Sum256([]byte(key))
	rng := seedrand.New(seedrand.NewSource(int64(binary.BigEndian.Uint64(h[:8]))))
	rng.Shuffle(288, func(i, j int) { t.order[i], t.order[j] = t.order[j], t.order[i] })
	for i, v := range t.order {
		t.rank[v] = uint16(i)
	}
	return t
}

type sudokuLayout struct {
	encode  [64]byte
	decode  [256]int16 // -1 padding; -2 invalid hint-class byte
	packed  [256]int16
	padding []byte
	marker  byte
}

func newSudokuLayout(ascii bool, pattern string) (*sudokuLayout, error) {
	l := new(sudokuLayout)
	for i := range l.decode {
		l.decode[i], l.packed[i] = -1, -1
	}
	if ascii {
		for i := range 256 {
			if i&64 != 0 {
				l.decode[i] = -2
				l.packed[i] = int16(i & 63)
			}
		}
		for i := range 64 {
			l.encode[i] = byte(64 + i)
		}
		l.encode[63] = '\n'
		for i := 32; i < 64; i++ {
			l.padding = append(l.padding, byte(i))
		}
		l.marker = 63
	} else if pattern == "" {
		for i := range 64 {
			l.encode[i] = byte((i&48)<<1 | i&15)
		}
		for i := range 8 {
			l.padding = append(l.padding, byte(128+i), byte(16+i))
		}
		l.marker = 128
	} else {
		pattern = strings.ToLower(strings.ReplaceAll(pattern, " ", ""))
		if len(pattern) != 8 || strings.Count(pattern, "x") != 2 || strings.Count(pattern, "p") != 2 || strings.Count(pattern, "v") != 4 {
			return nil, errors.New("Sudoku custom_table needs 2X, 2P and 4V bits")
		}
		var x byte
		for i, c := range pattern {
			if c == 'x' {
				x |= 1 << (7 - i)
			}
		}
		for i := range 64 {
			v, p := 1, 3
			out := x
			for pos, c := range pattern {
				switch c {
				case 'p':
					out |= byte(i>>uint(4+v)&1) << uint(7-pos)
					v--
				case 'v':
					out |= byte(i>>uint(p)&1) << uint(7-pos)
					p--
				case 'x':
				default:
					return nil, errors.New("invalid Sudoku custom_table bit")
				}
			}
			l.encode[i] = out
		}
		for i := range 256 {
			if bits.OnesCount8(byte(i)&x) == 1 && bits.OnesCount8(byte(i)) >= 5 {
				l.padding = append(l.padding, byte(i))
			}
		}
		l.marker = l.padding[0]
	}
	for i, b := range l.encode {
		l.decode[b], l.packed[b] = int16(i), int16(i)
	}
	return l, nil
}

type sudokuCodec struct {
	net.Conn
	table                   *sudokuTable
	reader                  *bufio.Reader
	readLayout, writeLayout *sudokuLayout
	readPacked, writePacked bool
	padding                 int
	writePadding            []byte
	rmu, wmu                sync.Mutex
	readBits                uint32
	bitCount                uint
	clueCount               int
	candidates              [5]uint64
	failed                  error
}

var errSudokuBuffered = errors.New("Sudoku needs more wire bytes")

func (c *sudokuCodec) nextGroup(block bool) (int16, error) {
	for padding := 0; padding < 65536; padding++ {
		if !block && c.reader.Buffered() == 0 {
			return 0, errSudokuBuffered
		}
		b, e := c.reader.ReadByte()
		if e != nil {
			return 0, e
		}
		v := c.readLayout.decode[b]
		if c.readPacked {
			v = c.readLayout.packed[b]
			if b == c.readLayout.marker {
				c.bitCount, c.readBits = 0, 0
			}
		}
		if v == -2 {
			return 0, errors.New("invalid Sudoku hint")
		}
		if v >= 0 {
			return v, nil
		}
	}
	return 0, errors.New("excessive Sudoku padding")
}

func (c *sudokuCodec) readByte(block bool) (byte, error) {
	if c.readPacked {
		for c.bitCount < 8 {
			v, e := c.nextGroup(block)
			if e != nil {
				return 0, e
			}
			c.readBits = c.readBits<<6 | uint32(v)
			c.bitCount += 6
		}
		c.bitCount -= 8
		b := byte(c.readBits >> c.bitCount)
		c.readBits &= (1 << c.bitCount) - 1
		return b, nil
	}
	if c.clueCount == 0 {
		c.candidates = [5]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), (1 << 32) - 1}
	}
	for c.clueCount < 4 {
		v, e := c.nextGroup(block)
		if e != nil {
			if e == io.EOF && c.clueCount > 0 {
				e = io.ErrUnexpectedEOF
			}
			return 0, e
		}
		for i := range c.candidates {
			c.candidates[i] &= c.table.geometry.sets[v][i]
		}
		c.clueCount++
	}
	c.clueCount = 0
	found := -1
	for i, v := range c.candidates {
		if v != 0 {
			if found >= 0 || v&(v-1) != 0 {
				return 0, errors.New("ambiguous Sudoku clues")
			}
			found = i*64 + bits.TrailingZeros64(v)
		}
	}
	if found < 0 || c.table.rank[found] >= 256 {
		return 0, errors.New("invalid Sudoku clues")
	}
	return byte(c.table.rank[found]), nil
}

func (c *sudokuCodec) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.failed != nil {
		return 0, c.failed
	}
	n := 0
	for {
		b, e := c.readByte(n == 0)
		if e == errSudokuBuffered {
			return n, nil
		}
		if e != nil {
			c.failed = e
			return n, e
		}
		p[n] = b
		n++
		if n == len(p) || c.reader.Buffered() == 0 {
			return n, nil
		}
	}
}

func (c *sudokuCodec) pad(out []byte) []byte {
	if rand.IntN(100) >= c.padding {
		return out
	}
	return append(out, c.writePadding[rand.IntN(len(c.writePadding))])
}

func (c *sudokuCodec) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	out := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(out)
	written := 0
	queued := 0
	wire := out[:0]
	flush := func() error {
		if len(wire) == 0 {
			return nil
		}
		if err := writeAll(c.Conn, wire); err != nil {
			c.Conn.Close()
			return err
		}
		written += queued
		queued = 0
		wire = out[:0]
		return nil
	}
	for len(p) > 0 {
		n := min(len(p), 4096)
		// Preserve wire block boundaries while batching writes into the pooled
		// buffer;HTTP carriers otherwise need a full upload roundtrip per4KiB.
		if len(wire)+9*n+14 > len(out) {
			if err := flush(); err != nil {
				return written, err
			}
		}
		if c.writePacked {
			var value uint32
			var nbits uint
			for i, b := range p[:n] {
				if i < 14 {
					pad := c.writeLayout.padding[0]
					if pad == c.writeLayout.marker {
						pad = c.writeLayout.padding[1]
					}
					wire = append(wire, pad)
				}
				value = value<<8 | uint32(b)
				nbits += 8
				for nbits >= 6 {
					nbits -= 6
					wire = c.pad(wire)
					wire = append(wire, c.writeLayout.encode[(value>>nbits)&63])
				}
				value &= (1 << nbits) - 1
			}
			if nbits > 0 {
				wire = append(wire, c.writeLayout.encode[(value<<(6-nbits))&63], c.writeLayout.marker)
			}
		} else {
			for _, b := range p[:n] {
				grid := c.table.order[b]
				choices := c.table.geometry.clues[grid]
				mask := choices[rand.IntN(len(choices))]
				var clues [4]byte
				for i := range clues {
					pos := bits.TrailingZeros16(mask)
					mask &= mask - 1
					clues[i] = c.table.geometry.grids[grid][pos]*16 + byte(pos)
				}
				rand.Shuffle(4, func(i, j int) { clues[i], clues[j] = clues[j], clues[i] })
				wire = c.pad(wire)
				for _, v := range clues {
					wire = c.pad(wire)
					wire = append(wire, c.writeLayout.encode[v])
				}
			}
		}
		queued += n
		p = p[n:]
	}
	err := flush()
	return written, err
}

func (c *sudokuCodec) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
