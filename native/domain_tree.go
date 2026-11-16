package native

import (
	"encoding/binary"
	"sort"
	"strings"
)

// Build breadth-first edge arrays directly from sorted reversed keys. Only two
// layers of key ranges are retained; no per-character maps or heap nodes exist.
func buildDomainTree(domains, suffixes []string) *domainTree {
	if len(domains)+len(suffixes) == 0 {
		return nil
	}
	reverse := func(s string) string {
		r := []rune(canonicalDomain(s))
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r)
	}
	keys := make([]string, 0, len(domains)+len(suffixes))
	for _, v := range domains {
		keys = append(keys, reverse(v))
	}
	for _, v := range suffixes {
		marker := "\n"
		if strings.HasPrefix(v, ".") {
			marker = "\r"
		}
		keys = append(keys, reverse(v)+marker)
	}
	sort.Strings(keys)
	unique := keys[:0]
	for _, key := range keys {
		if len(unique) == 0 || unique[len(unique)-1] != key {
			unique = append(unique, key)
		}
	}
	keys = unique
	type span struct{ lo, hi int }
	layer := []span{{0, len(keys)}}
	depth := 0
	tree := &domainTree{}
	for len(layer) > 0 {
		next := make([]span, 0, len(layer))
		for _, group := range layer {
			node := len(tree.starts)
			tree.starts = append(tree.starts, uint32(len(tree.labels)))
			if node/64 == len(tree.leaves) {
				tree.leaves = append(tree.leaves, 0)
			}
			lo := group.lo
			if lo < group.hi && len(keys[lo]) == depth {
				tree.leaves[node/64] |= 1 << uint(node%64)
				lo++
			}
			for lo < group.hi {
				label := keys[lo][depth]
				hi := lo + 1
				for hi < group.hi && keys[hi][depth] == label {
					hi++
				}
				tree.labels = append(tree.labels, label)
				next = append(next, span{lo, hi})
				lo = hi
			}
		}
		layer = next
		depth++
	}
	tree.starts = append(tree.starts, uint32(len(tree.labels)))
	return tree
}
func appendSRSTree(b []byte, t *domainTree) []byte {
	b = append(b, 0)
	writeU64s := func(values []uint64) {
		b = binary.AppendUvarint(b, uint64(len(values)))
		for _, v := range values {
			b = binary.BigEndian.AppendUint64(b, v)
		}
	}
	writeU64s(t.leaves)
	nodes := len(t.starts) - 1
	bitmap := make([]uint64, (len(t.labels)+nodes+63)/64)
	bit := 0
	for node := range nodes {
		bit += int(t.starts[node+1] - t.starts[node])
		bitmap[bit/64] |= 1 << uint(bit%64)
		bit++
	}
	writeU64s(bitmap)
	b = binary.AppendUvarint(b, uint64(len(t.labels)))
	return append(b, t.labels...)
}
