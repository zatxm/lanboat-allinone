package native

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// Layouts share the keyed grid permutation. Only the wire alphabet changes;
// probing never publishes a session or consumes a replay-window entry.
func (o *SudokuOptions) acceptCodec(raw net.Conn) (*sudokuRecord, error) {
	candidates := o.acceptTables
	if len(candidates) == 0 {
		candidates = []*SudokuOptions{o}
	}
	if o.Reverse != nil && o.Reverse.Listen != "" {
		both := make([]*SudokuOptions, 0, len(candidates)*2)
		for _, variant := range candidates {
			packed := *variant
			packed.packedUplink = true
			both = append(both, variant, &packed)
		}
		candidates = both
	}
	if len(candidates) == 1 {
		return candidates[0].codec(raw, false), nil
	}
	candidates = append([]*SudokuOptions(nil), candidates...)
	reader := bufio.NewReaderSize(raw, 4096)
	prefix := make([]byte, 0, 4096)
	var chunk [4096]byte
	for {
		n, readErr := reader.Read(chunk[:min(len(chunk), 64<<10-len(prefix))])
		prefix = append(prefix, chunk[:n]...)
		if n == 0 {
			if readErr != nil {
				return nil, readErr
			}
			return nil, io.ErrNoProgress
		}
		pending := candidates[:0]
		for _, variant := range candidates {
			// Record authentication closes a failed input. Keep trial decoders
			// detached from the live connection until a layout is selected.
			probe := variant.codec(&sudokuHTTPHello{Conn: raw, input: bytes.NewReader(prefix)}, false)
			kind, hello, err := sudokuReadMessage(probe)
			if err == nil {
				now := time.Now().Unix()
				valid := kind == 1 && (len(hello) == 68 || len(hello) == 72)
				if valid {
					stamp := int64(binary.BigEndian.Uint64(hello[:8]))
					valid = stamp >= now-60 && stamp <= now+60
				}
				if valid && len(hello) == 72 {
					valid = binary.BigEndian.Uint32(hello[68:]) == variant.hint
				}
				if valid {
					wire := &bufferedConn{Conn: raw, reader: bufio.NewReader(io.MultiReader(bytes.NewReader(prefix), reader))}
					return variant.codec(wire, false), nil
				}
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				pending = append(pending, variant)
			}
		}
		candidates = pending
		if len(candidates) == 0 {
			return nil, errors.New("no matching Sudoku table")
		}
		if readErr != nil {
			return nil, readErr
		}
		if len(prefix) == 64<<10 {
			return nil, errors.New("Sudoku table probe exceeds64KiB")
		}
	}
}
