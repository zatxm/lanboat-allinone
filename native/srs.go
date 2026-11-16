package native

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
)

type ipRange struct{ from, to netip.Addr }

func matchIPRanges(ranges []ipRange, host string, ips []netip.Addr) bool {
	match := func(ip netip.Addr) bool {
		ip = ip.Unmap()
		i := sort.Search(len(ranges), func(i int) bool { return ranges[i].to.Compare(ip) >= 0 })
		return i < len(ranges) && ranges[i].from.Compare(ip) <= 0
	}
	if ip, err := netip.ParseAddr(host); err == nil && match(ip) {
		return true
	}
	for _, ip := range ips {
		if match(ip) {
			return true
		}
	}
	return false
}

// Child identifiers are edge index + 1 in the breadth-first on-disk trie.
type domainTree struct {
	wildcard bool
	starts   []uint32
	labels   []byte
	leaves   []uint64
}

func (t *domainTree) leaf(node uint32) bool {
	return int(node>>6) < len(t.leaves) && t.leaves[node>>6]&(uint64(1)<<(node&63)) != 0
}
func (t *domainTree) edge(node uint32, label byte) (uint32, bool) {
	lo, hi := t.starts[node], t.starts[node+1]
	i := sort.Search(int(hi-lo), func(i int) bool { return t.labels[int(lo)+i] >= label })
	index := lo + uint32(i)
	return index + 1, index < hi && t.labels[index] == label
}
func (t *domainTree) match(host string) bool {
	runes := []rune(strings.ToLower(strings.TrimSuffix(host, ".")))
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	key := []byte(string(runes))
	if t.wildcard {
		return t.matchWildcard(key)
	}
	node := uint32(0)
	for _, label := range key {
		if _, ok := t.edge(node, '\r'); ok {
			return true
		}
		if child, ok := t.edge(node, '\n'); ok && label == '.' && t.leaf(child) {
			return true
		}
		child, ok := t.edge(node, label)
		if !ok {
			return false
		}
		node = child
	}
	if t.leaf(node) {
		return true
	}
	_, prefix := t.edge(node, '\r')
	_, root := t.edge(node, '\n')
	return prefix || root
}

type srsReader struct {
	*bytes.Reader
	remaining int
}

func (r *srsReader) count(max uint64) (int, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return 0, err
	}
	if n > max {
		return 0, errors.New("SRS collection exceeds limit")
	}
	return int(n), nil
}
func (r *srsReader) blob(max uint64) ([]byte, error) {
	n, err := r.count(max)
	if err != nil {
		return nil, err
	}
	if n > r.Len() {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, n)
	_, err = io.ReadFull(r, b)
	return b, err
}
func (r *srsReader) strings() ([]string, error) {
	n, err := r.count(1 << 20)
	if err != nil {
		return nil, err
	}
	var out []string
	for range n {
		b, e := r.blob(1 << 16)
		if e != nil {
			return nil, e
		}
		out = append(out, string(b))
	}
	return out, nil
}
func (r *srsReader) u16s() ([]uint16, error) {
	n, err := r.count(65536)
	if err != nil {
		return nil, err
	}
	if n > r.Len()/2 {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]uint16, n)
	err = binary.Read(r, binary.BigEndian, out)
	return out, err
}
func (r *srsReader) u64s() ([]uint64, error) {
	n, err := r.count(1 << 20)
	if err != nil {
		return nil, err
	}
	if n > r.Len()/8 {
		return nil, io.ErrUnexpectedEOF
	}
	out := make([]uint64, n)
	err = binary.Read(r, binary.BigEndian, out)
	return out, err
}
func (r *srsReader) tree() (*domainTree, error) {
	if version, err := r.ReadByte(); err != nil || version != 0 {
		return nil, errors.New("unsupported SRS domain encoding")
	}
	leaves, err := r.u64s()
	if err != nil {
		return nil, err
	}
	bitmap, err := r.u64s()
	if err != nil {
		return nil, err
	}
	labels, err := r.blob(8 << 20)
	if err != nil {
		return nil, err
	}
	nodes := len(labels) + 1
	if len(leaves) < (nodes+63)/64 {
		return nil, errors.New("SRS leaf bitmap is truncated")
	}
	starts := make([]uint32, nodes+1)
	edge, bit := 0, 0
	for node := range nodes {
		if edge < node {
			return nil, errors.New("SRS trie has cyclic edges")
		}
		starts[node] = uint32(edge)
		start := edge
		for {
			if bit >= len(bitmap)*64 {
				return nil, errors.New("truncated SRS trie bitmap")
			}
			stop := bitmap[bit/64]&(uint64(1)<<uint(bit%64)) != 0
			bit++
			if stop {
				break
			}
			if edge >= len(labels) || edge > start && labels[edge] <= labels[edge-1] {
				return nil, errors.New("invalid SRS trie edges")
			}
			edge++
		}
		if edge < node {
			return nil, errors.New("SRS trie references an ancestor")
		}
	}
	starts[nodes] = uint32(edge)
	if edge != len(labels) {
		return nil, errors.New("SRS trie edge count mismatch")
	}
	for ; bit < len(bitmap)*64; bit++ {
		if bitmap[bit/64]&(uint64(1)<<uint(bit%64)) != 0 {
			return nil, errors.New("extra SRS trie delimiters")
		}
	}
	return &domainTree{starts: starts, labels: labels, leaves: leaves, wildcard: false}, nil
}
func (r *srsReader) ipRanges() ([]ipRange, error) {
	version, err := r.ReadByte()
	if err != nil || version != 1 {
		return nil, errors.New("unsupported SRS IP encoding")
	}
	var count uint64
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > 1<<20 || count > uint64(r.Len()/10) {
		return nil, errors.New("invalid SRS IP range count")
	}
	readIP := func() (netip.Addr, error) {
		b, e := r.blob(16)
		if e != nil {
			return netip.Addr{}, e
		}
		ip, ok := netip.AddrFromSlice(b)
		if !ok {
			return ip, errors.New("invalid SRS IP size")
		}
		return ip.Unmap(), nil
	}
	out := make([]ipRange, int(count))
	for i := range out {
		a, e := readIP()
		if e != nil {
			return nil, e
		}
		b, e := readIP()
		if e != nil {
			return nil, e
		}
		if a.BitLen() != b.BitLen() || a.Compare(b) > 0 || i > 0 && out[i-1].to.Compare(a) >= 0 {
			return nil, errors.New("invalid SRS IP range order")
		}
		out[i] = ipRange{a, b}
	}
	return out, nil
}
func readSRS(data []byte) ([]Rule, error) {
	if len(data) < 6 || string(data[:3]) != "SRS" || data[3] < 1 || data[3] > 5 {
		return nil, errors.New("unsupported SRS header/version")
	}
	compressed := bytes.NewReader(data[4:])
	z, err := zlib.NewReader(compressed)
	if err != nil {
		return nil, err
	}
	defer z.Close()
	plain, err := io.ReadAll(io.LimitReader(z, (128<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(plain) > 128<<20 || compressed.Len() != 0 {
		return nil, errors.New("SRS exceeds size limit or has trailing data")
	}
	r := &srsReader{Reader: bytes.NewReader(plain), remaining: 1 << 20}
	count, err := r.count(1 << 20)
	if err != nil {
		return nil, err
	}
	var rules []Rule
	for range count {
		rule, err := r.rule(0)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing SRS rule data")
	}
	return rules, nil
}
func (r *srsReader) rule(depth int) (Rule, error) {
	var rule Rule
	if depth > 64 || r.remaining == 0 {
		return rule, errors.New("SRS rule nesting/count exceeds limit")
	}
	r.remaining--
	typ, err := r.ReadByte()
	if err != nil {
		return rule, err
	}
	if typ == 1 {
		mode, err := r.ReadByte()
		if err != nil || mode > 1 {
			return rule, errors.New("invalid SRS logical mode")
		}
		rule.Type = "logical"
		rule.Mode = "and"
		if mode == 1 {
			rule.Mode = "or"
		}
		count, err := r.count(1 << 20)
		if err != nil || count == 0 {
			return rule, errors.New("invalid SRS logical child count")
		}
		for range count {
			child, err := r.rule(depth + 1)
			if err != nil {
				return rule, err
			}
			rule.Rules = append(rule.Rules, child)
		}
		flag, err := r.ReadByte()
		if err != nil || flag > 1 {
			return rule, errors.New("invalid SRS invert flag")
		}
		rule.Invert = flag == 1
		return rule, nil
	}
	if typ != 0 {
		return rule, errors.New("unknown SRS rule type")
	}
	seen := map[byte]bool{}
	for {
		item, err := r.ReadByte()
		if err != nil {
			return rule, err
		}
		if seen[item] {
			return rule, errors.New("duplicate SRS condition")
		}
		seen[item] = true
		switch item {
		case 0:
			rule.QueryType, err = r.u16s()
		case 1:
			rule.Network, err = r.strings()
		case 2:
			rule.domains, err = r.tree()
		case 3:
			rule.DomainKeyword, err = r.strings()
		case 4:
			rule.DomainRegex, err = r.strings()
		case 5:
			rule.sourceRanges, err = r.ipRanges()
		case 6:
			rule.ipRanges, err = r.ipRanges()
		case 7:
			rule.SourcePort, err = r.u16s()
		case 8:
			rule.SourcePortRange, err = r.strings()
		case 9:
			rule.Port, err = r.u16s()
		case 10:
			rule.PortRange, err = r.strings()

		case 11:
			rule.ProcessName, err = r.strings()
		case 12:
			rule.ProcessPath, err = r.strings()
		case 13:
			rule.PackageName, err = r.strings()
		case 14:
			rule.WiFiSSID, err = r.strings()
		case 15:
			rule.WiFiBSSID, err = r.strings()
		case 16:
			rule.domains, err = r.tree()
			if rule.domains != nil {
				rule.domains.wildcard = true
			}
		case 17:
			rule.ProcessPathRegex, err = r.strings()
		case 18:
			var n int
			n, err = r.count(16)
			for range n {
				var b byte
				b, err = r.ReadByte()
				if err != nil {
					break
				}
				if int(b) >= len(srsNetworkTypes) {
					err = errors.New("invalid SRS network type")
					break
				}
				rule.NetworkType = append(rule.NetworkType, srsNetworkTypes[b])
			}
		case 19:
			rule.NetworkIsExpensive = true
		case 20:
			rule.NetworkIsConstrained = true
		case 21:
			var n int
			n, err = r.count(16)
			rule.NetworkInterfaceAddress = map[string][]string{}
			for range n {
				var b byte
				b, err = r.ReadByte()
				if err != nil {
					break
				}
				if int(b) >= len(srsNetworkTypes) {
					err = errors.New("invalid SRS interface type")
					break
				}
				var prefixes []string
				prefixes, err = r.prefixes()
				if err != nil {
					break
				}
				rule.NetworkInterfaceAddress[srsNetworkTypes[b]] = prefixes
			}
		case 22:
			rule.DefaultInterfaceAddress, err = r.prefixes()
		case 23:
			rule.PackageNameRegex, err = r.strings()
		case 255:
			flag, e := r.ReadByte()
			if e != nil || flag > 1 {
				return rule, errors.New("invalid SRS invert flag")
			}
			rule.Invert = flag == 1
			return rule, nil
		default:
			return rule, fmt.Errorf("SRS condition %d is not implemented", item)
		}
		if err != nil {
			return rule, err
		}
	}
}

var srsNetworkTypes = []string{"wifi", "cellular", "ethernet", "other"}

func (r *srsReader) prefixes() ([]string, error) {
	n, e := r.count(1 << 20)
	if e != nil {
		return nil, e
	}
	out := make([]string, 0, n)
	for range n {
		b, e := r.blob(16)
		if e != nil {
			return nil, e
		}
		ip, ok := netip.AddrFromSlice(b)
		if !ok {
			return nil, errors.New("invalid SRS interface IP")
		}
		bits, e := r.ReadByte()
		if e != nil || int(bits) > ip.BitLen() {
			return nil, errors.New("invalid SRS interface prefix")
		}
		out = append(out, netip.PrefixFrom(ip, int(bits)).String())
	}
	return out, nil
}

func (t *domainTree) matchWildcard(key []byte) bool {
	type state struct {
		node uint32
		pos  int
	}
	seen := map[state]bool{}
	var visit func(uint32, int) bool
	visit = func(node uint32, pos int) bool {
		k := state{node, pos}
		if seen[k] {
			return false
		}
		seen[k] = true
		if _, ok := t.edge(node, '\r'); ok {
			return true
		}
		if ch, ok := t.edge(node, '\n'); ok && t.leaf(ch) && (pos == len(key) || key[pos] == '.') {
			return true
		}
		if pos == len(key) && t.leaf(node) {
			return true
		}
		if ch, ok := t.edge(node, '*'); ok {
			for i := pos; i <= len(key); i++ {
				if visit(ch, i) {
					return true
				}
			}
		}
		if pos < len(key) {
			if ch, ok := t.edge(node, key[pos]); ok {
				return visit(ch, pos+1)
			}
		}
		return false
	}
	return visit(0, 0)
}
