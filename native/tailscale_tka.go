package native

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"slices"
)

var errTSTailnetLock = errors.New("Tailscale Tailnet Lock verification failed")
var tsTKAEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// All accepted authority history is pinned to the original checkpoint. The
// control server can distribute signed changes, but cannot replace this root.
type tsTKAStored struct {
	Messages      [][]byte
	Head          string
	SelfSignature []byte
}
type tsTKAKey struct {
	public []byte
	votes  uint64
	meta   tsCBOR
}
type tsTKAState struct {
	keys     map[string]tsTKAKey
	disable  [][]byte
	id1, id2 uint64
}
type tsTKAUpdate struct {
	wire         tsCBOR
	raw          []byte
	hash, parent string
	kind, weight uint64
	state        *tsTKAState
	children     []*tsTKAUpdate
}
type tsTKA struct {
	root, head *tsTKAUpdate
	updates    map[string]*tsTKAUpdate
	bytes      int
}

func tsTKAHash(b []byte) string { return tsTKAEncoding.EncodeToString(blake2s(b, nil, 32)) }
func tsTKAValidHash(s string) bool {
	b, e := tsTKAEncoding.DecodeString(s)
	return e == nil && len(b) == 32
}
func tsTKAMeta(m tsCBOR) bool {
	size := 0
	for k, v := range m {
		key, ok := k.(string)
		value, ok2 := v.(string)
		if !ok || !ok2 {
			return false
		}
		size += len(key) + len(value)
	}
	return size <= 512
}
func tsTKAReadKey(m tsCBOR) (tsTKAKey, error) {
	k := tsTKAKey{public: m.bytes(3), votes: m.num(2), meta: m.object(12)}
	_, votes := m[uint64(2)].(uint64)
	if !m.only(1, 2, 3, 12) || m.num(1) != 1 || len(k.public) != 32 || !votes || k.votes > 4096 || !tsTKAMeta(k.meta) {
		return k, errTSTailnetLock
	}
	return k, nil
}
func tsTKAReadState(m tsCBOR) (*tsTKAState, error) {
	if m == nil || !m.only(1, 2, 3, 4, 5) || m[uint64(1)] != nil {
		return nil, errTSTailnetLock
	}
	for _, k := range []uint64{4, 5} {
		if v, ok := m[k]; ok {
			if _, valid := v.(uint64); !valid {
				return nil, errTSTailnetLock
			}
		}
	}
	keys, disable := m.array(3), m.array(2)
	if len(keys) == 0 || len(keys) > 512 || len(disable) == 0 || len(disable) > 32 {
		return nil, errTSTailnetLock
	}
	s := &tsTKAState{keys: map[string]tsTKAKey{}, id1: m.num(4), id2: m.num(5)}
	for _, v := range keys {
		obj, ok := v.(tsCBOR)
		if !ok {
			return nil, errTSTailnetLock
		}
		k, e := tsTKAReadKey(obj)
		if e != nil {
			return nil, e
		}
		id := string(k.public)
		if _, ok := s.keys[id]; ok {
			return nil, errTSTailnetLock
		}
		s.keys[id] = k
	}
	seen := map[string]bool{}
	for _, v := range disable {
		b, ok := v.([]byte)
		if !ok || len(b) != 32 || seen[string(b)] {
			return nil, errTSTailnetLock
		}
		seen[string(b)] = true
		s.disable = append(s.disable, b)
	}
	return s, nil
}
func tsTKAReadUpdate(b []byte) (*tsTKAUpdate, error) {
	m, e := tsCBORDecode(b)
	if e != nil || !m.only(1, 2, 3, 4, 5, 6, 7, 23) || m.num(1) == 0 {
		return nil, errTSTailnetLock
	}
	parent := m.bytes(2)
	if len(parent) != 0 && len(parent) != 32 {
		return nil, errTSTailnetLock
	}
	a := &tsTKAUpdate{wire: m, raw: tsCBOREncode(nil, m), kind: m.num(1)}
	a.hash = tsTKAHash(a.raw)
	if len(parent) > 0 {
		a.parent = tsTKAEncoding.EncodeToString(parent)
	}
	fields := []uint64{1, 2, 23}
	switch a.kind {
	case 1:
		fields = append(fields, 3)
		_, e = tsTKAReadKey(m.object(3))
	case 2:
		fields = append(fields, 4)
		if len(m.bytes(4)) != 32 {
			e = errTSTailnetLock
		}
	case 4:
		fields = append(fields, 4, 6, 7)
		if len(m.bytes(4)) != 32 || m[uint64(6)] == nil && m[uint64(7)] == nil {
			e = errTSTailnetLock
		}
		if v, ok := m[uint64(6)]; ok {
			n, valid := v.(uint64)
			if !valid || n > 4096 {
				e = errTSTailnetLock
			}
		}
		if v, ok := m[uint64(7)]; ok {
			obj, valid := v.(tsCBOR)
			if !valid || !tsTKAMeta(obj) {
				e = errTSTailnetLock
			}
		}
	case 5:
		fields = append(fields, 5)
		a.state, e = tsTKAReadState(m.object(5))
	default: // Future additive message kinds have no effect on existing state.
		fields = []uint64{1, 2, 3, 4, 5, 6, 7, 23}
	}
	if e != nil || !m.only(fields...) {
		return nil, errTSTailnetLock
	}
	return a, nil
}
func (a *tsTKAUpdate) verify(s *tsTKAState) error {
	entries := a.wire.array(23)
	if len(entries) == 0 || len(entries) > 512 {
		return errTSTailnetLock
	}
	digest := blake2s(tsTKAUnsigned(a.wire, 23), nil, 32)
	seen := map[string]bool{}
	valid := false
	for _, entry := range entries {
		m, ok := entry.(tsCBOR)
		if !ok || !m.only(1, 2) || len(m.bytes(1)) != 32 || len(m.bytes(2)) != 64 {
			return errTSTailnetLock
		}
		id := string(m.bytes(1))
		if seen[id] {
			return errTSTailnetLock
		}
		seen[id] = true
		k, ok := s.keys[id]
		if !ok {
			continue
		}
		if !tsTKAVerify(k.public, digest, m.bytes(2)) {
			return errTSTailnetLock
		}
		valid = true
		a.weight += k.votes
	}
	if !valid {
		return errTSTailnetLock
	}
	return nil
}
func (a *tsTKAUpdate) apply(parent *tsTKAState) error {
	if e := a.verify(parent); e != nil {
		return e
	}
	if a.kind == 5 {
		if a.state.id1 != parent.id1 || a.state.id2 != parent.id2 {
			return errTSTailnetLock
		}
		return nil
	}
	if a.kind != 1 && a.kind != 2 && a.kind != 4 {
		a.state = parent
		return nil
	}
	s := *parent
	s.keys = make(map[string]tsTKAKey, len(parent.keys))
	for id, k := range parent.keys {
		s.keys[id] = k
	}
	id := string(a.wire.bytes(4))
	switch a.kind {
	case 1:
		k, e := tsTKAReadKey(a.wire.object(3))
		if e != nil {
			return e
		}
		if _, exists := s.keys[string(k.public)]; exists || len(s.keys) >= 512 {
			return errTSTailnetLock
		}
		s.keys[string(k.public)] = k
	case 2:
		if _, exists := s.keys[id]; !exists {
			return errTSTailnetLock
		}
		delete(s.keys, id)
	case 4:
		k, exists := s.keys[id]
		if !exists {
			return errTSTailnetLock
		}
		if n, ok := a.wire[uint64(6)].(uint64); ok {
			k.votes = n
		}
		if m, ok := a.wire[uint64(7)].(tsCBOR); ok {
			k.meta = m
		}
		s.keys[id] = k
	}
	a.state = &s
	return nil
}

func (t *tsTKA) obsolete(wire []byte) [][]byte {
	m, e := tsCBORDecode(wire)
	if e != nil {
		return nil
	}
	var result [][]byte
	for m.num(1) == 2 {
		m = m.object(5)
		if key := m.bytes(2); len(key) == 34 && string(key[:2]) == "np" {
			result = append(result, key[2:])
		}
	}
	return result
}
func tsTKABootstrap(raw []byte) (*tsTKA, error) {
	a, e := tsTKAReadUpdate(raw)
	if e != nil || a.kind != 5 {
		return nil, errTSTailnetLock
	}
	// The initial checkpoint is TOFU. A valid signature from one of its keys is
	// required, and subsequent checkpoints must descend from this pinned root.
	if e = a.verify(a.state); e != nil {
		return nil, e
	}
	return &tsTKA{root: a, head: a, updates: map[string]*tsTKAUpdate{a.hash: a}, bytes: len(a.raw)}, nil
}
func (t *tsTKA) add(raws [][]byte) error {
	if len(raws) > 4096 {
		return errTSTailnetLock
	}
	pending := map[string]*tsTKAUpdate{}
	size := t.bytes
	for _, raw := range raws {
		a, e := tsTKAReadUpdate(raw)
		if e != nil {
			return e
		}
		if t.updates[a.hash] != nil || pending[a.hash] != nil {
			continue
		}
		size += len(a.raw)
		pending[a.hash] = a
	}
	if len(t.updates)+len(pending) > 8192 || size > 16<<20 {
		return errors.New("Tailnet Lock history exceeds local storage limit")
	}
	// Validate the entire batch before publishing any changes; RPC order is not
	// trusted. Each branch is verified against its own parent state.
	accepted := map[string]*tsTKAUpdate{}
	order := make([]*tsTKAUpdate, 0, len(pending))
	for len(pending) > 0 {
		progress := false
		for hash, a := range pending {
			parent := t.updates[a.parent]
			if parent == nil {
				parent = accepted[a.parent]
			}
			if parent == nil {
				continue
			}
			if e := a.apply(parent.state); e != nil {
				return e
			}
			accepted[hash] = a
			order = append(order, a)
			delete(pending, hash)
			progress = true
		}
		if !progress {
			return errors.New("Tailnet Lock update has an unknown parent")
		}
	}
	for _, a := range order {
		t.updates[a.hash] = a
		p := t.updates[a.parent]
		p.children = append(p.children, a)
	}
	t.bytes = size
	current := t.root
	for len(current.children) > 0 {
		best := current.children[0]
		for _, a := range current.children[1:] {
			if a.weight > best.weight || a.weight == best.weight && (a.kind == 2 && best.kind != 2 || (a.kind == 2) == (best.kind == 2) && tsTKALessHash(a.hash, best.hash)) {
				best = a
			}
		}
		current = best
	}
	t.head = current
	return nil
}
func (t *tsTKA) stored(self []byte) *tsTKAStored {
	stored := &tsTKAStored{Head: t.head.hash, SelfSignature: self, Messages: [][]byte{t.root.raw}}
	hashes := make([]string, 0, len(t.updates)-1)
	for h := range t.updates {
		if h != t.root.hash {
			hashes = append(hashes, h)
		}
	}
	slices.Sort(hashes)
	for _, h := range hashes {
		stored.Messages = append(stored.Messages, t.updates[h].raw)
	}
	return stored
}
func tsTKARestore(s *tsTKAStored) (*tsTKA, error) {
	if s == nil {
		return nil, nil
	}
	if len(s.Messages) == 0 {
		return nil, errTSTailnetLock
	}
	t, e := tsTKABootstrap(s.Messages[0])
	if e == nil {
		e = t.add(s.Messages[1:])
	}
	if e != nil {
		return nil, e
	}
	if t.head.hash != s.Head {
		return nil, errTSTailnetLock
	}
	return t, nil
}
func (t *tsTKA) nodeAuthorized(key, wire []byte) bool {
	if len(key) == 32 {
		key = append([]byte("np"), key...)
	}
	m, e := tsCBORDecode(wire)
	if e != nil || m.num(1) == 3 {
		return false
	}
	return t.signature(m, key, 0)
}
func (t *tsTKA) signature(m tsCBOR, node []byte, depth int) bool {
	if depth > 15 || !m.only(1, 2, 3, 4, 5, 6) || len(m.bytes(4)) != 64 {
		return false
	}
	kind := m.num(1)
	if kind != 3 && (len(node) != 34 || string(node[:2]) != "np" || !bytes.Equal(node, m.bytes(2))) {
		return false
	}
	if v, exists := m[uint64(6)]; exists {
		b, ok := v.([]byte)
		if !ok || len(b) != 32 {
			return false
		}
	}
	digest := blake2s(tsTKAUnsigned(m, 4), nil, 32)
	switch kind {
	case 1, 3:
		if m[uint64(5)] != nil || len(m.bytes(3)) != 32 {
			return false
		}
		if kind == 3 && len(m.bytes(6)) != 32 {
			return false
		}
		k, ok := t.head.state.keys[string(m.bytes(3))]
		return ok && tsTKAVerify(k.public, digest, m.bytes(4))
	case 2:
		nested := m.object(5)
		if nested == nil {
			return false
		}
		wrapping := nested
		for i := 0; i < 16 && len(wrapping.bytes(6)) == 0 && wrapping.num(1) == 2; i++ {
			wrapping = wrapping.object(5)
		}
		return len(wrapping.bytes(6)) == 32 && tsTKAVerify(wrapping.bytes(6), digest, m.bytes(4)) && t.signature(nested, nested.bytes(2), depth+1)
	}
	return false
}
func (c *tailscaleClient) lockKey() ed25519.PrivateKey {
	h := hmac.New(sha256.New, c.machine.Bytes())
	h.Write([]byte("lanboat/tailscale/tailnet-lock-ed25519/v1"))
	return ed25519.NewKeyFromSeed(h.Sum(nil))
}
func (c *tailscaleClient) lockPublic() string {
	return "nlpub:" + hex.EncodeToString(c.lockKey().Public().(ed25519.PublicKey))
}
func (c *tailscaleClient) rotateLockSignature(old []byte) ([]byte, error) {
	nested, e := tsCBORDecode(old)
	if e != nil {
		return nil, e
	}
	pub := c.lockKey().Public().(ed25519.PublicKey)
	if nested.num(1) == 2 && bytes.Equal(nested.bytes(6), pub) {
		nested = nested.object(5)
	}
	if nested == nil {
		return nil, errTSTailnetLock
	}
	wrapping := nested
	for i := 0; i < 16 && len(wrapping.bytes(6)) == 0 && wrapping.num(1) == 2; i++ {
		wrapping = wrapping.object(5)
	}
	if !bytes.Equal(wrapping.bytes(6), pub) {
		return nil, errors.New("Tailnet Lock rotation key does not match local identity")
	}
	m := tsCBOR{uint64(1): uint64(2), uint64(2): append([]byte("np"), c.nodeKey.PublicKey().Bytes()...), uint64(5): nested, uint64(6): []byte(pub)}
	digest := blake2s(tsCBOREncode(nil, m), nil, 32)
	m[uint64(4)] = ed25519.Sign(c.lockKey(), digest)
	return tsCBOREncode(nil, m), nil
}

func tsTKALessHash(a, b string) bool {
	x, _ := tsTKAEncoding.DecodeString(a)
	y, _ := tsTKAEncoding.DecodeString(b)
	return bytes.Compare(x, y) < 0
}
