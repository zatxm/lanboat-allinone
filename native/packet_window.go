package native

// packetWindow tracks 8192 packet IDs; callers serialize access and commit only
// after authentication. Clearing exact bit ranges preserves partial edge words.
type packetWindow struct {
	highest uint64
	seen    [128]uint64
}

func (w *packetWindow) fresh(id uint64) bool {
	if id < w.highest && w.highest-id >= 8192 {
		return false
	}
	return id > w.highest || w.seen[(id/64)%128]&(uint64(1)<<(id%64)) == 0
}

func (w *packetWindow) accept(id uint64) bool {
	if !w.fresh(id) {
		return false
	}
	if id > w.highest {
		if id-w.highest >= 8192 {
			clear(w.seen[:])
		} else {
			for first := w.highest + 1; ; {
				last := min(id, first|63)
				mask := (^uint64(0) >> (63 - (last - first))) << (first % 64)
				w.seen[(first/64)%128] &^= mask
				if last == id {
					break
				}
				first = last + 1
			}
		}
		w.highest = id
	}
	w.seen[(id/64)%128] |= uint64(1) << (id % 64)
	return true
}
