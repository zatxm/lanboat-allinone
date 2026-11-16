package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"sync"
)

// Provisional code points from draft-ietf-masque-http-datagram-compression-02.
const (
	masqueTemplateAssign uint64 = 0x3ee3143f + iota
	masqueTemplateACK
	masqueTemplateClose
	masqueDerivedAssign
	masqueDerivedACK
	masqueDerivedClose
	masqueChecksumAssign
	masqueChecksumACK
	masqueChecksumClose
)
const masqueContextBudget = 4 << 20

var errMasqueContext = errors.New("invalid MASQUE processing context")

type masqueStaticSegment struct {
	offset int
	data   []byte
}
type masqueProcessingContext struct {
	id, next, kind               uint64
	segments                     []masqueStaticSegment
	fields                       uint16
	checksumField, checksumStart int
	acked, closed                bool
	charge                       int64
	used                         uint64
}
type masqueContextPlan struct {
	segments                     []masqueStaticSegment
	fields                       uint16
	checksum                     bool
	checksumField, checksumStart int
}
type masqueChecksumContextKey struct {
	field, start int
	next         uint64
}
type masqueContextACK struct{ kind, id uint64 }
type masqueContexts struct {
	acks               chan masqueContextACK
	mu, sendMu         sync.Mutex
	session            *masqueSession
	local, peer        masqueContextCapabilities
	ip, server, closed bool
	entries            map[uint64]*masqueProcessingContext
	derived            map[uint16]*masqueProcessingContext
	templates          []*masqueProcessingContext
	checksums          map[masqueChecksumContextKey]*masqueProcessingContext
	next, epoch        uint64
	budget             int64
}

func (f *masqueFlow) negotiateContexts(protocol, header string, server bool) {
	if header == "" {
		return
	}
	peer, err := parseMasqueContextCapabilities(header)
	if err != nil {
		return
	}
	state := &masqueContexts{acks: make(chan masqueContextACK, 128), session: f.session, local: masqueLocalContexts(protocol), peer: peer, ip: protocol == "connect-ip", server: server, entries: map[uint64]*masqueProcessingContext{}}
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.contexts.Store(state)
	f.mu.Unlock()
	if !f.session.goWork(func() {
		for {
			select {
			case ack := <-state.acks:
				if f.capsule(ack.kind, quicVar(nil, ack.id)) != nil {
					return
				}
			case <-f.done:
				return
			case <-f.session.done:
				return
			}
		}
	}) {
		f.Close()
	}
}
func (s *masqueContexts) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.session.contextBytes.Add(-s.budget)
	s.budget = 0
	s.entries = nil
	s.derived = nil
	s.templates = nil
	s.checksums = nil
}
func (s *masqueContexts) localID(id uint64) bool { return id%2 == 1 == s.server }
func (s *masqueContexts) plan(c *masqueProcessingContext) (masqueContextPlan, bool) {
	var p masqueContextPlan
	var kinds uint8
	for depth := 0; c != nil; depth++ {
		if depth == 3 || c.closed {
			return p, false
		}
		bit := uint8(1 << ((c.kind - masqueTemplateAssign) / 3))
		if kinds&bit != 0 {
			return p, false
		}
		kinds |= bit
		switch c.kind {
		case masqueTemplateAssign:
			p.segments = c.segments
		case masqueDerivedAssign:
			p.fields = c.fields
		case masqueChecksumAssign:
			p.checksum = true
			p.checksumField, p.checksumStart = c.checksumField, c.checksumStart
		default:
			return p, false
		}
		if c.next == 0 {
			break
		}
		parent, ok := s.entries[c.next]
		if !ok || s.localID(c.id) != s.localID(parent.id) {
			return p, false
		}
		c = parent
	}
	if p.checksum && p.fields&uint16(1<<5|1<<6|1<<7|1<<8) != 0 {
		return p, false
	}
	return p, true
}
func (s *masqueContexts) install(c *masqueProcessingContext, local bool) error {
	if s.closed {
		return net.ErrClosed
	}
	if c.id == 0 || s.localID(c.id) != local || len(s.entries) >= 4096 {
		return errMasqueContext
	}
	if _, seen := s.entries[c.id]; seen {
		return errMasqueContext
	}
	if c.next != 0 {
		parent, ok := s.entries[c.next]
		if !ok || parent.closed || s.localID(c.id) != s.localID(parent.id) {
			return errMasqueContext
		}
	}
	if _, ok := s.plan(c); !ok {
		return errMasqueContext
	}
	templates, active := 0, 0
	for _, e := range s.entries {
		if e.closed || s.localID(e.id) != local {
			continue
		}
		active++
		if e.kind == masqueTemplateAssign {
			templates++
		}
	}
	caps := s.local
	if local {
		caps = s.peer
	}
	if active >= 128 || c.kind == masqueTemplateAssign && templates >= caps.templates {
		return errMasqueContext
	}
	charge := int64(128 + len(c.segments)*32)
	for _, seg := range c.segments {
		charge += int64(len(seg.data))
	}
	if s.session.contextBytes.Add(charge) > masqueContextBudget {
		s.session.contextBytes.Add(-charge)
		return errors.New("MASQUE context capacity exhausted")
	}
	c.charge = charge
	s.budget += charge
	s.entries[c.id] = c
	if local && c.kind == masqueTemplateAssign {
		s.templates = append(s.templates, c)
	}
	return nil
}
func (s *masqueContexts) retire(c *masqueProcessingContext) {
	if c.closed {
		return
	}
	defer func() {
		s.templates = slices.DeleteFunc(s.templates, func(e *masqueProcessingContext) bool { return e.closed })
	}()
	if s.localID(c.id) && c.kind == masqueTemplateAssign {
		// Locally generated templates are leaves; retiring one does not scan old context IDs.
		c.closed = true
		c.segments = nil
		s.budget -= c.charge - 128
		s.session.contextBytes.Add(-(c.charge - 128))
		c.charge = 128
		return
	}
	for _, e := range s.entries {
		if e.closed {
			continue
		}
		for next, depth := e, 0; next != nil && depth < 3; depth++ {
			if next.id == c.id {
				e.closed = true
				e.segments = nil
				s.budget -= e.charge - 128
				s.session.contextBytes.Add(-(e.charge - 128))
				e.charge = 128
				break
			}
			next = s.entries[next.next]
		}
	}
}
func (s *masqueContexts) handle(f *masqueFlow, kind uint64, data []byte) error {
	r := quicReader(data)
	id, err := r.v()
	if err != nil || id == 0 {
		return errMasqueContext
	}
	group := (kind - masqueTemplateAssign) / 3
	action := (kind - masqueTemplateAssign) % 3
	if group > 2 {
		return errMasqueContext
	}
	assign := masqueTemplateAssign + 3*group
	s.mu.Lock()
	if action != 0 {
		c, ok := s.entries[id]
		if !ok || c.kind != assign || len(r) != 0 || action == 1 && !s.localID(id) {
			s.mu.Unlock()
			return errMasqueContext
		}
		if action == 1 {
			c.acked = true
		} else {
			s.retire(c)
		}
		s.mu.Unlock()
		return nil
	}
	next, err := r.v()
	if err != nil {
		s.mu.Unlock()
		return errMasqueContext
	}
	c := &masqueProcessingContext{id: id, next: next, kind: kind}
	switch kind {
	case masqueTemplateAssign:
		for len(r) > 0 {
			offset, e := r.v()
			if e != nil {
				err = e
				break
			}
			n, e := r.v()
			if e != nil || n > uint64(len(r)) || offset > uint64(s.local.mtu) || n > uint64(s.local.mtu)-offset {
				err = errMasqueContext
				break
			}
			if len(c.segments) >= s.local.segments || len(c.segments) > 0 && int(offset) <= c.segments[len(c.segments)-1].offset+len(c.segments[len(c.segments)-1].data) {
				err = errMasqueContext
				break
			}
			c.segments = append(c.segments, masqueStaticSegment{int(offset), bytes.Clone(r[:n])})
			r = r[n:]
		}
		if len(c.segments) == 0 || s.local.templates == 0 {
			err = errMasqueContext
		}
	case masqueDerivedAssign:
		for len(r) > 0 {
			field, e := r.v()
			if e != nil || field >= 9 || s.local.derived&(1<<field) == 0 || c.fields&(1<<field) != 0 {
				err = errMasqueContext
				break
			}
			c.fields |= 1 << field
		}
		if c.fields == 0 {
			err = errMasqueContext
		}
	case masqueChecksumAssign:
		field, e := r.v()
		if e != nil {
			err = e
			break
		}
		start, e := r.v()
		if e != nil || len(r) != 0 || !s.local.checksum || start == 0 || start > uint64(s.local.mtu) || field+2 > uint64(s.local.mtu) {
			err = errMasqueContext
			break
		}
		c.checksumField, c.checksumStart = int(field), int(start)
	}
	if err == nil {
		err = s.install(c, false)
	}
	s.mu.Unlock()
	if err != nil {
		return errMasqueContext
	}
	// The reader must keep consuming while both peers write; a synchronous ACK can deadlock HTTP flow control.
	select {
	case s.acks <- masqueContextACK{kind + 1, id}:
		return nil
	case <-f.done:
		return net.ErrClosed
	case <-f.session.done:
		return net.ErrClosed
	}
}
func (s *masqueContexts) decode(id uint64, b []byte) ([]byte, bool) {
	if id == 0 {
		return b, len(b) <= s.local.mtu
	}
	s.mu.Lock()
	c, ok := s.entries[id]
	var plan masqueContextPlan
	if ok && !s.localID(id) {
		plan, ok = s.plan(c)
	} else {
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return nil, false
	}
	total := len(b)
	for _, seg := range plan.segments {
		total += len(seg.data)
	}
	if total > s.local.mtu {
		return nil, false
	}
	reconstructed := b
	if len(plan.segments) != 0 {
		reconstructed = make([]byte, total)
		input, at := 0, 0
		for _, seg := range plan.segments {
			gap := seg.offset - at
			if gap < 0 || input+gap > len(b) || seg.offset+len(seg.data) > total {
				return nil, false
			}
			copy(reconstructed[at:seg.offset], b[input:input+gap])
			copy(reconstructed[seg.offset:], seg.data)
			input += gap
			at = seg.offset + len(seg.data)
		}
		if total-at != len(b)-input {
			return nil, false
		}
		copy(reconstructed[at:], b[input:])
	}
	reconstructed, ok = masqueInsertDerived(reconstructed, plan.fields, s.local.mtu)
	if !ok {
		return nil, false
	}
	if plan.checksum {
		if plan.fields == 0 && len(plan.segments) == 0 {
			reconstructed = bytes.Clone(reconstructed)
		}
		if !masqueCompleteChecksum(reconstructed, plan.checksumField, plan.checksumStart, s.ip) {
			return nil, false
		}
	}
	return reconstructed, true
}

func masqueContextWire(c *masqueProcessingContext) []byte {
	b := quicVar(nil, c.id)
	b = quicVar(b, c.next)
	switch c.kind {
	case masqueTemplateAssign:
		for _, seg := range c.segments {
			b = quicVar(b, uint64(seg.offset))
			b = quicVar(b, uint64(len(seg.data)))
			b = append(b, seg.data...)
		}
	case masqueDerivedAssign:
		for bit := uint16(0); bit < 9; bit++ {
			if c.fields&(1<<bit) != 0 {
				b = quicVar(b, uint64(bit))
			}
		}
	case masqueChecksumAssign:
		b = quicVar(b, uint64(c.checksumField))
		b = quicVar(b, uint64(c.checksumStart))
	}
	return b
}
func (s *masqueContexts) create(c *masqueProcessingContext) bool {
	s.next += 2
	if s.next >= 1<<62 {
		return false
	}
	c.id = s.next
	if s.server {
		c.id--
	}
	return s.install(c, true) == nil
}
func masqueStaticFields(b []byte, holes []masqueDerivedField) []masqueStaticSegment {
	l, _, ok := masquePacketFields(b, 0)
	if !ok {
		return nil
	}
	ranges := [][2]int{{0, 1}, {8, 2}, {12, 8}}
	if l.version == 6 {
		ranges = [][2]int{{0, 1}, {6, 34}}
	}
	if masqueTransportOffset(b, &l) {
		ranges = append(ranges, [2]int{l.transport, 4})
	}
	var segments []masqueStaticSegment
	for _, span := range ranges {
		at, n := span[0], span[1]
		for _, hole := range holes {
			if hole.offset+2 <= span[0] {
				at -= 2
			}
		}
		if len(segments) > 0 && segments[len(segments)-1].offset+len(segments[len(segments)-1].data) == at {
			last := &segments[len(segments)-1]
			last.data = append(last.data, b[span[0]:span[0]+n]...)
		} else {
			segments = append(segments, masqueStaticSegment{at, bytes.Clone(b[span[0] : span[0]+n])})
		}
	}
	return segments
}
func masqueTemplateMatches(b []byte, c *masqueProcessingContext) bool {
	for _, seg := range c.segments {
		if seg.offset+len(seg.data) > len(b) || !bytes.Equal(seg.data, b[seg.offset:seg.offset+len(seg.data)]) {
			return false
		}
	}
	return true
}
func masqueTemplateRemove(b []byte, segments []masqueStaticSegment) []byte {
	total := len(b)
	for _, seg := range segments {
		total -= len(seg.data)
	}
	out := make([]byte, 0, total)
	at := 0
	for _, seg := range segments {
		out = append(out, b[at:seg.offset]...)
		at = seg.offset + len(seg.data)
	}
	return append(out, b[at:]...)
}
func (s *masqueContexts) encode(f *masqueFlow, b []byte) (uint64, []byte, error) {
	if len(b) > s.peer.mtu {
		return 0, nil, errors.New("MASQUE peer reconstruction MTU exceeded")
	}
	if !s.ip || s.peer.templates == 0 && s.peer.derived == 0 && !s.peer.checksum {
		return 0, b, nil
	}
	compact, mask, holes := masqueRemoveDerived(b, s.peer.derived)
	type capsule struct {
		kind uint64
		data []byte
	}
	var assignments []capsule
	var retired *masqueProcessingContext
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	var derived *masqueProcessingContext
	if mask != 0 {
		derived = s.derived[mask]
		if derived == nil || derived.closed {
			derived = &masqueProcessingContext{kind: masqueDerivedAssign, fields: mask}
			if s.create(derived) {
				if s.derived == nil {
					s.derived = map[uint16]*masqueProcessingContext{}
				}
				s.derived[mask] = derived
				assignments = append(assignments, capsule{derived.kind, masqueContextWire(derived)})
			} else {
				derived = nil
			}
		}
	}
	next := uint64(0)
	if derived != nil {
		next = derived.id
	}
	parent := derived
	partial := uint16(0)
	checksumField := 0
	if s.peer.checksum && mask&uint16(1<<5|1<<6|1<<7|1<<8) == 0 && (mask == 0 || derived != nil) {
		field, start, value, ok := masquePartialChecksum(b)
		if ok {
			key := masqueChecksumContextKey{field, start, next}
			offload := s.checksums[key]
			if offload == nil || offload.closed {
				offload = &masqueProcessingContext{kind: masqueChecksumAssign, next: next, checksumField: field, checksumStart: start}
				if s.create(offload) {
					if s.checksums == nil {
						s.checksums = map[masqueChecksumContextKey]*masqueProcessingContext{}
					}
					s.checksums[key] = offload
					assignments = append(assignments, capsule{offload.kind, masqueContextWire(offload)})
				} else {
					offload = nil
				}
			}
			if offload != nil {
				parent = offload
				next = offload.id
				partial = value
				checksumField = field
			}
		}
	}
	var selected *masqueProcessingContext
	if mask == 0 || derived != nil {
		for _, c := range s.templates {
			if !c.closed && c.next == next && masqueTemplateMatches(compact, c) {
				selected = c
				break
			}
		}
		if selected == nil && s.peer.templates > 0 {
			segments := masqueStaticFields(b, holes)
			if len(segments) > 0 && (s.peer.segments == 0 || len(segments) <= s.peer.segments) {
				count := 0
				var oldest *masqueProcessingContext
				for _, c := range s.templates {
					if !c.closed {
						count++
						if oldest == nil || c.used < oldest.used {
							oldest = c
						}
					}
				}
				if count >= min(s.peer.templates, 32) && oldest != nil {
					s.retire(oldest)
					retired = oldest
				}
				c := &masqueProcessingContext{kind: masqueTemplateAssign, next: next, segments: segments}
				if s.create(c) {
					selected = c
					assignments = append(assignments, capsule{c.kind, masqueContextWire(c)})
				}
			}
		}
	}
	// Capsules are ordered, but QUIC datagrams can overtake them; wait for acknowledgement before use.
	if selected != nil && !selected.acked {
		selected = nil
	}
	if selected == nil && parent != nil && parent.acked {
		selected = parent
	}
	if selected == nil && derived != nil && derived.acked {
		selected = derived
	}
	if selected != nil {
		s.epoch++
		selected.used = s.epoch
	}
	var id uint64
	offload := false
	var segments []masqueStaticSegment
	if selected != nil {
		id = selected.id
		segments = selected.segments
		plan, ok := s.plan(selected)
		offload = ok && plan.checksum
	}
	s.mu.Unlock()
	if retired != nil {
		if err := f.capsule(retired.kind+2, quicVar(nil, retired.id)); err != nil {
			return 0, nil, err
		}
	}
	for _, c := range assignments {
		if err := f.capsule(c.kind, c.data); err != nil {
			return 0, nil, err
		}
	}
	if selected == nil {
		return 0, b, nil
	}
	if offload {
		compact = bytes.Clone(compact)
		offset := checksumField
		for _, hole := range holes {
			if hole.offset < checksumField {
				offset -= 2
			}
		}
		binary.BigEndian.PutUint16(compact[offset:], partial)
	}
	if len(segments) != 0 {
		return id, masqueTemplateRemove(compact, segments), nil
	}
	return id, compact, nil
}

func masqueKnownContextCapsule(kind uint64) bool {
	return kind >= masqueTemplateAssign && kind <= masqueChecksumClose
}
