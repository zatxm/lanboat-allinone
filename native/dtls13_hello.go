package native

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"slices"
)

type dtls13Identity struct{ identity, binder []byte }
type dtls13Hello struct {
	group                          uint16
	random, session, cookie, share []byte
	suites                         []uint16
	identities                     []dtls13Identity
	truncated                      int
	invariant                      [32]byte
}

func parseDTLS13Hello(body []byte) (*dtls13Hello, error) {
	if len(body) > 16384 {
		return nil, errors.New("DTLS1.3 ClientHello limit")
	}
	p := stCursor{data: body}
	h := new(dtls13Hello)
	if p.number(2) != 0xfefd {
		return nil, errors.New("invalid DTLS1.3 legacy version")
	}
	h.random = p.take(32)
	h.session = p.vector(1)
	if len(h.session) > 32 || len(p.vector(1)) != 0 {
		return nil, errors.New("invalid DTLS1.3 legacy fields")
	}
	suites := p.vector(2)
	if len(suites) == 0 || len(suites)%2 != 0 || !bytes.Equal(p.vector(1), []byte{0}) {
		return nil, errors.New("invalid DTLS1.3 cipher offer")
	}
	for len(suites) > 0 {
		h.suites = append(h.suites, binary.BigEndian.Uint16(suites))
		suites = suites[2:]
	}
	fixed := len(body) - len(p.data)
	extBytes := p.vector(2)
	if err := p.end(); err != nil {
		return nil, err
	}
	ext, err := stExtensions(extBytes)
	if err != nil {
		return nil, err
	}
	versions := stCursor{data: ext[43]}
	v := versions.vector(1)
	found := false
	for len(v) >= 2 {
		found = found || binary.BigEndian.Uint16(v) == 0xfefc
		v = v[2:]
	}
	if !found || len(v) != 0 || versions.end() != nil {
		return nil, errors.New("DTLS1.3 not offered")
	}
	modes := stCursor{data: ext[45]}
	if !bytes.Contains(modes.vector(1), []byte{1}) || modes.end() != nil {
		return nil, errors.New("DTLS1.3 requires PSK-DHE")
	}
	groups := stCursor{data: ext[10]}
	groupBytes := groups.vector(2)
	if groups.end() != nil || len(groupBytes) == 0 || len(groupBytes)%2 != 0 {
		return nil, errors.New("invalid DTLS1.3 supported groups")
	}
	var offeredGroups []uint16
	for len(groupBytes) > 0 {
		offeredGroups = append(offeredGroups, binary.BigEndian.Uint16(groupBytes))
		groupBytes = groupBytes[2:]
	}
	shares := stCursor{data: ext[51]}
	shares = stCursor{data: shares.vector(2), err: shares.err}
	seenGroups := map[int]bool{}
	for len(shares.data) > 0 && shares.err == nil {
		group := shares.number(2)
		key := shares.vector(2)
		if seenGroups[group] || !slices.Contains(offeredGroups, uint16(group)) {
			return nil, errors.New("duplicate DTLS1.3 key share")
		}
		seenGroups[group] = true
		if group == 29 || group == 23 || group == 24 || group == 25 {
			curve, _ := stCurve(tls.CurveID(group))
			if _, err := curve.NewPublicKey(key); err != nil {
				return nil, errors.New("invalid DTLS1.3 key share")
			}
			if h.group == 0 || group == 29 {
				h.share = key
				h.group = uint16(group)
			}
		}
	}
	if shares.end() != nil || h.group == 0 {
		return nil, errors.New("DTLS1.3 requires a supported ECDHE share")
	}
	if cookie, ok := ext[44]; ok {
		c := stCursor{data: cookie}
		h.cookie = c.vector(2)
		if c.end() != nil || len(h.cookie) == 0 || len(h.cookie) > 256 {
			return nil, errors.New("invalid DTLS1.3 cookie")
		}
	}
	psk, ok := ext[41]
	if !ok || len(psk) < 4 || len(extBytes) < len(psk)+4 || !bytes.Equal(extBytes[len(extBytes)-len(psk)-4:], stExtension(nil, 41, psk)) {
		return nil, errors.New("DTLS1.3 PSK must be the last extension")
	}
	q := stCursor{data: psk}
	ids := stCursor{data: q.vector(2), err: q.err}
	for len(ids.data) > 0 && ids.err == nil {
		id := ids.vector(2)
		ids.take(4)
		if len(id) == 0 || len(id) > 256 || len(h.identities) >= 4 {
			return nil, errors.New("invalid DTLS1.3 PSK identities")
		}
		h.identities = append(h.identities, dtls13Identity{identity: id})
	}
	h.truncated = len(body) - len(q.data)
	binders := stCursor{data: q.vector(2), err: q.err}
	for i := 0; len(binders.data) > 0 && binders.err == nil; i++ {
		b := binders.vector(1)
		if i >= len(h.identities) || len(b) != 32 && len(b) != 48 {
			return nil, errors.New("invalid DTLS1.3 binders")
		}
		h.identities[i].binder = b
	}
	if len(h.identities) == 0 || slices.ContainsFunc(h.identities, func(i dtls13Identity) bool { return i.binder == nil }) || ids.end() != nil || binders.end() != nil || q.end() != nil {
		return nil, errors.New("invalid DTLS1.3 PSK vectors")
	}
	invariant := bytes.Clone(body[:fixed])
	for remaining := extBytes; len(remaining) > 0; {
		kind, n := binary.BigEndian.Uint16(remaining), int(binary.BigEndian.Uint16(remaining[2:]))
		if kind != 41 && kind != 44 && kind != 42 && kind != 21 {
			invariant = append(invariant, remaining[:4+n]...)
		}
		remaining = remaining[4+n:]
	}
	h.invariant = sha256.Sum256(invariant)
	return h, nil
}

func dtls13Hash(s stCipherSuite, b []byte) []byte { h := s.newHash(); h.Write(b); return h.Sum(nil) }
func dtls13Derive(s stCipherSuite, secret []byte, label string, transcript []byte) []byte {
	return dtls13Expand(s, secret, label, dtls13Hash(s, transcript), s.hash.Size())
}
func dtls13Finished(s stCipherSuite, secret, transcript []byte) []byte {
	k := dtls13Expand(s, secret, "finished", nil, s.hash.Size())
	defer clear(k)
	mac := hmac.New(s.newHash, k)
	mac.Write(dtls13Hash(s, transcript))
	return mac.Sum(nil)
}
func dtls13Binder(s stCipherSuite, psk, transcript []byte) []byte {
	early := s.extract(nil, psk)
	key := dtls13Derive(s, early, "ext binder", nil)
	defer clear(early)
	defer clear(key)
	return dtls13Finished(s, key, transcript)
}

func (d *dtls13) clientHello(cookie []byte) ([]byte, error) {
	if d.private == nil {
		var err error
		d.private, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		rand.Read(d.random[:])
	}
	b := append([]byte{0xfe, 0xfd}, d.random[:]...)
	b = append(b, 0, 0) // legacy session and cookie are empty.
	var suites []byte
	for _, s := range d.owner.suites {
		suites = binary.BigEndian.AppendUint16(suites, s)
	}
	b = append(b, stVector(suites, 2)...)
	b = append(b, 1, 0)
	ext := stExtension(nil, 43, []byte{2, 0xfe, 0xfc})
	ext = stExtension(ext, 10, []byte{0, 2, 0, 29})
	ext = stExtension(ext, 45, []byte{1, 1})
	share := append([]byte{0, 29}, stVector(d.private.PublicKey().Bytes(), 2)...)
	ext = stExtension(ext, 51, stVector(share, 2))
	if len(cookie) > 0 {
		ext = stExtension(ext, 44, stVector(cookie, 2))
	}
	var identities, binders []byte
	var hashes []stCipherSuite
	for _, id := range d.owner.suites {
		s, _ := stSuite(id)
		if d.retried && s.hash != d.suite.hash {
			continue
		}
		if slices.ContainsFunc(hashes, func(o stCipherSuite) bool { return s.hash == o.hash }) {
			continue
		}
		hashes = append(hashes, s)
		identities = append(identities, stVector(d.identity, 2)...)
		identities = binary.BigEndian.AppendUint32(identities, 0)
		binders = append(binders, stVector(make([]byte, s.hash.Size()), 1)...)
	}
	d.offered = hashes
	psk := append(stVector(identities, 2), stVector(binders, 2)...)
	ext = stExtension(ext, 41, psk)
	b = append(b, stVector(ext, 2)...)
	truncated := len(b) - len(binders) - 2
	msg := stMessage(1, b)
	at := truncated + 2
	for _, s := range hashes {
		transcript := append(bytes.Clone(d.transcript), msg[:4+truncated]...)
		binder := dtls13Binder(s, d.owner.psk, transcript)
		copy(b[at+1:], binder)
		at += len(binder) + 1
	}
	return b, nil
}

func dtls13ServerHello(random, session []byte, suite uint16, share []byte, group uint16, identity int, cookie []byte) []byte {
	b := append([]byte{0xfe, 0xfd}, random...)
	b = append(b, stVector(session, 1)...)
	b = binary.BigEndian.AppendUint16(b, suite)
	b = append(b, 0)
	ext := stExtension(nil, 43, []byte{0xfe, 0xfc})
	if cookie != nil {
		ext = stExtension(ext, 44, stVector(cookie, 2))
	} else {
		ext = stExtension(ext, 51, append(binary.BigEndian.AppendUint16(nil, group), stVector(share, 2)...))
		ext = stExtension(ext, 41, binary.BigEndian.AppendUint16(nil, uint16(identity)))
	}
	return append(b, stVector(ext, 2)...)
}
