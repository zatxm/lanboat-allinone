package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"
)

const quicVersion = 1
const quicVersion2 = 0x6b3343cf
const quicMSS = 1200

// The default stream window lets one stream reach about 1MiB per RTT while a
// stalled stream can hold at most a quarter of the connection window.
const quicStreamWindow = 1 << 20
const quicConnWindow = 4 << 20

type quicReader []byte

func (r *quicReader) v() (uint64, error) {
	if len(*r) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := 1 << ((*r)[0] >> 6)
	if len(*r) < n {
		return 0, io.ErrUnexpectedEOF
	}
	v := uint64((*r)[0] & 63)
	for _, b := range (*r)[1:n] {
		v = v<<8 | uint64(b)
	}
	*r = (*r)[n:]
	return v, nil
}
func (r *quicReader) take(n uint64) ([]byte, error) {
	if n > uint64(len(*r)) {
		return nil, io.ErrUnexpectedEOF
	}
	b := (*r)[:int(n)]
	*r = (*r)[int(n):]
	return b, nil
}
func quicVar(b []byte, v uint64) []byte {
	switch {
	case v < 64:
		return append(b, byte(v))
	case v < 16384:
		return binary.BigEndian.AppendUint16(b, uint16(v)|0x4000)
	case v < 1<<30:
		return binary.BigEndian.AppendUint32(b, uint32(v)|0x80000000)
	default:
		return binary.BigEndian.AppendUint64(b, v|0xc000000000000000)
	}
}
func quicString(b []byte, s string) []byte { return append(quicVar(b, uint64(len(s))), s...) }
func (r *quicReader) text(limit int) (string, error) {
	n, e := r.v()
	if e != nil {
		return "", e
	}
	if n > uint64(limit) {
		return "", errors.New("QUIC string exceeds limit")
	}
	b, e := r.take(n)
	return string(b), e
}
func quicLabel(h func() hash.Hash, secret []byte, label string, n int) []byte {
	info := binary.BigEndian.AppendUint16(nil, uint16(n))
	full := "tls13 " + label
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)
	out, err := hkdf.Expand(h, secret, string(info), n)
	if err != nil {
		panic(err)
	}
	return out
}

type quicKey struct {
	aead     cipher.AEAD
	hp       cipher.Block
	hpChaCha *[32]byte
	iv       [12]byte
	secret   []byte
	suite    uint16
}

func newQUICKey(secret []byte, suite uint16) (*quicKey, error) {
	return newQUICKeyLabels(secret, suite, "quic")
}
func newQUICKeyLabels(secret []byte, suite uint16, label string) (*quicKey, error) {
	if suite != tls.TLS_AES_128_GCM_SHA256 && suite != tls.TLS_AES_256_GCM_SHA384 && suite != tls.TLS_CHACHA20_POLY1305_SHA256 {
		return nil, errors.New("unsupported QUIC cipher suite")
	}
	h, size := sha256.New, 16
	if suite == tls.TLS_AES_256_GCM_SHA384 {
		h, size = sha512.New384, 32
	}
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		size = 32
	}
	key := quicLabel(h, secret, label+" key", size)
	hp := quicLabel(h, secret, label+" hp", size)
	k := &quicKey{secret: append([]byte{}, secret...), suite: suite}
	copy(k.iv[:], quicLabel(h, secret, label+" iv", 12))
	var err error
	if suite == tls.TLS_CHACHA20_POLY1305_SHA256 {
		k.aead, err = newChaChaAEAD(key, false)
		k.hpChaCha = new([32]byte)
		copy(k.hpChaCha[:], hp)
	} else {
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			k.aead, err = cipher.NewGCM(block)
		}
		if err == nil {
			k.hp, err = aes.NewCipher(hp)
		}
	}
	return k, err
}
func (k *quicKey) next() (*quicKey, error) {
	h := sha256.New
	if k.suite == tls.TLS_AES_256_GCM_SHA384 {
		h = sha512.New384
	}
	n, err := newQUICKey(quicLabel(h, k.secret, "quic ku", h().Size()), k.suite)
	if err == nil {
		n.hp = k.hp
		n.hpChaCha = k.hpChaCha
	}
	return n, err
}
func (k *quicKey) nonce(pn uint64) []byte {
	var iv [12]byte
	return k.nonceTo(&iv, pn)
}
func (k *quicKey) nonceTo(iv *[12]byte, pn uint64) []byte {
	*iv = k.iv
	v := binary.BigEndian.Uint64(iv[4:]) ^ pn
	binary.BigEndian.PutUint64(iv[4:], v)
	return iv[:]
}
func (k *quicKey) mask(sample []byte) [16]byte {
	var out [16]byte
	return k.maskTo(&out, sample)
}
func (k *quicKey) maskTo(out *[16]byte, sample []byte) [16]byte {
	if k.hpChaCha != nil {
		b := chachaBlock(k.hpChaCha, sample[4:16], binary.LittleEndian.Uint32(sample))
		copy(out[:], b[:16])
	} else {
		k.hp.Encrypt(out[:], sample[:16])
	}
	return *out
}

// quicScratchLimit bounds the packet buffers a connection keeps between packets.
const quicScratchLimit = 4096

// quicScratch holds reusable packet buffers for one QUIC connection. Interface
// calls into cipher.AEAD/Block make stack buffers escape, so per-packet nonce,
// mask and output storage live here instead. It is owned by the connection's
// run goroutine; returned packets are valid only until the next seal/open.
type quicScratch struct {
	nonce      [12]byte
	mask       [16]byte
	seal, open []byte
}

func (s *quicScratch) buffer(owned *[]byte, size int) []byte {
	if cap(*owned) >= size {
		return (*owned)[:0]
	}
	b := make([]byte, 0, max(size, 2048))
	if cap(b) <= quicScratchLimit {
		*owned = b
	}
	return b
}
func quicInitialKeys(dcid []byte, server bool) (read, write *quicKey, err error) {
	return quicInitialKeysVersion(dcid, server, quicVersion)
}
func quicInitialKeysVersion(dcid []byte, server bool, version uint32) (read, write *quicKey, err error) {
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	label := "quic"
	if version == quicVersion2 {
		salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
		label = "quicv2"
	} else if version != quicVersion {
		return nil, nil, errors.New("unsupported QUIC version")
	}
	m := hmac.New(sha256.New, salt)
	m.Write(dcid)
	secret := m.Sum(nil)
	client, err := newQUICKeyLabels(quicLabel(sha256.New, secret, "client in", 32), tls.TLS_AES_128_GCM_SHA256, label)
	if err != nil {
		return nil, nil, err
	}
	remote, err := newQUICKeyLabels(quicLabel(sha256.New, secret, "server in", 32), tls.TLS_AES_128_GCM_SHA256, label)
	if server {
		return client, remote, err
	}
	return remote, client, err
}

type quicHeader struct {
	level             int
	pnOffset, end     int
	dcid, scid, token []byte
	retry, boolLong   bool
}

func parseQUICHeader(b []byte) (quicHeader, error) {
	h, err := parseQUICHeaderVersion(b, quicVersion)
	if err == nil && h.level == 3 {
		return h, errors.New("QUIC 0-RTT not enabled")
	}
	return h, err
}
func parseQUICHeaderVersion(b []byte, version uint32) (quicHeader, error) {
	h := quicHeader{end: len(b)}
	if len(b) < 1 || b[0]&0x40 == 0 {
		return h, errors.New("invalid QUIC fixed bit")
	}
	if b[0]&0x80 == 0 {
		if len(b) < 9+4+16 {
			return h, io.ErrUnexpectedEOF
		}
		h.level = 2
		h.dcid = b[1:9]
		h.pnOffset = 9
		return h, nil
	}
	h.boolLong = true
	if len(b) < 7 {
		return h, io.ErrUnexpectedEOF
	}
	if (version != quicVersion && version != quicVersion2) || binary.BigEndian.Uint32(b[1:5]) != version {
		return h, errors.New("unsupported QUIC version")
	}
	pos := 5
	n := int(b[pos])
	pos++
	if n > 20 || pos+n+1 > len(b) {
		return h, io.ErrUnexpectedEOF
	}
	h.dcid = b[pos : pos+n]
	pos += n
	n = int(b[pos])
	pos++
	if n > 20 || pos+n > len(b) {
		return h, io.ErrUnexpectedEOF
	}
	h.scid = b[pos : pos+n]
	pos += n
	kind := (b[0] >> 4) & 3
	if version == quicVersion2 {
		kind = (kind + 3) & 3
	}
	if kind == 3 {
		if len(b) < pos+16 {
			return h, io.ErrUnexpectedEOF
		}
		h.retry = true
		h.token = b[pos : len(b)-16]
		return h, nil
	}
	h.level = 0
	if kind == 1 {
		h.level = 3
	}
	if kind == 2 {
		h.level = 1
	}
	r := quicReader(b[pos:])
	if kind == 0 {
		n, e := r.v()
		if e != nil {
			return h, e
		}
		token, e := r.take(n)
		if e != nil {
			return h, e
		}
		h.token = token
	}
	payloadLen, e := r.v()
	if e != nil {
		return h, e
	}
	h.pnOffset = len(b) - len(r)
	if payloadLen > uint64(len(r)) || payloadLen < 20 {
		return h, io.ErrUnexpectedEOF
	}
	h.end = h.pnOffset + int(payloadLen)
	return h, nil
}
func quicPacketNumber(truncated uint64, n int, largest int64) uint64 {
	expected := uint64(largest + 1)
	window := uint64(1) << (uint(n) * 8)
	half := window / 2
	candidate := (expected &^ (window - 1)) | truncated
	if candidate+half <= expected && candidate+window < 1<<62 {
		candidate += window
	} else if candidate > expected+half && candidate >= window {
		candidate -= window
	}
	return candidate
}
func openQUICPacket(b []byte, h quicHeader, k *quicKey, largest int64) ([]byte, uint64, byte, error) {
	return new(quicScratch).openPacket(b, h, k, largest)
}

// openPacket leaves b unchanged so callers can retry other keys.
func (s *quicScratch) openPacket(b []byte, h quicHeader, k *quicKey, largest int64) ([]byte, uint64, byte, error) {
	if h.pnOffset+4+16 > h.end {
		return nil, 0, 0, io.ErrUnexpectedEOF
	}
	mask := k.maskTo(&s.mask, b[h.pnOffset+4:h.pnOffset+20])
	first := b[0]
	bits := byte(0x1f)
	if h.boolLong {
		bits = 15
	}
	first ^= mask[0] & bits
	n := int(first&3) + 1
	if h.pnOffset+n+16 > h.end {
		return nil, 0, 0, io.ErrUnexpectedEOF
	}
	headerLen := h.pnOffset + n
	// The unprotected header is followed by the plaintext in the same buffer.
	header := append(s.buffer(&s.open, h.end), b[:headerLen]...)
	header[0] = first
	var truncated uint64
	for i := range n {
		header[h.pnOffset+i] ^= mask[1+i]
		truncated = truncated<<8 | uint64(header[h.pnOffset+i])
	}
	pn := quicPacketNumber(truncated, n, largest)
	plain, err := k.aead.Open(header[headerLen:], k.nonceTo(&s.nonce, pn), b[headerLen:h.end], header)
	if err == nil && (h.boolLong && first&12 != 0 || !h.boolLong && first&24 != 0) {
		err = errors.New("QUIC reserved bits are nonzero")
	}
	return plain, pn, first, err
}
func sealQUICPacket(payload, dcid, scid, token []byte, level int, pn uint64, phase bool, k *quicKey, initial ...int) []byte {
	return new(quicScratch).sealPacket(payload, dcid, scid, token, level, pn, phase, k, initial...)
}
func (s *quicScratch) sealPacket(payload, dcid, scid, token []byte, level int, pn uint64, phase bool, k *quicKey, initial ...int) []byte {
	var header []byte
	if level == 2 {
		first := byte(0x43)
		if phase {
			first |= 4
		}
		header = append(s.buffer(&s.seal, 1+len(dcid)+4+len(payload)+16), first)
		header = append(header, dcid...)
	} else {
		first := byte(0xc3)
		if level == 1 {
			first = 0xe3
		}
		size := 6 + len(dcid) + 1 + len(scid) + 8 + len(token) + 8 + 4 + max(len(payload), 1200) + 16
		if len(initial) > 0 {
			size = max(size, initial[0]+64)
		}
		header = append(s.buffer(&s.seal, size), first, 0, 0, 0, 1, byte(len(dcid)))
		header = append(header, dcid...)
		header = append(header, byte(len(scid)))
		header = append(header, scid...)
		if level == 0 {
			header = quicVar(header, uint64(len(token)))
			header = append(header, token...)
		}
		// Initial datagrams always meet the protocol's 1200-byte minimum.
		if level == 0 {
			minimum := 1200
			if len(initial) > 0 && initial[0] > minimum {
				minimum = initial[0]
			}
			padding := max(0, minimum-(len(header)+2+4+16+len(payload)))
			payload = append(payload, make([]byte, padding)...)
		}
		header = quicVar(header, uint64(4+16+len(payload)))
	}
	pnOffset := len(header)
	header = binary.BigEndian.AppendUint32(header, uint32(pn))
	out := k.aead.Seal(header, k.nonceTo(&s.nonce, pn), payload, header)
	if cap(out) > cap(s.seal) && cap(out) <= quicScratchLimit {
		s.seal = out[:0]
	}
	mask := k.maskTo(&s.mask, out[pnOffset+4:pnOffset+20])
	bits := byte(0x1f)
	if level != 2 {
		bits = 15
	}
	out[0] ^= mask[0] & bits
	for i := range 4 {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out
}
func quicRetryTag(odcid, packet []byte) []byte {
	key := []byte{0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e}
	nonce := []byte{0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	pseudo := append([]byte{byte(len(odcid))}, odcid...)
	pseudo = append(pseudo, packet...)
	return aead.Seal(nil, nonce, nil, pseudo)
}
func appendQUICParam(b []byte, id, value uint64) []byte {
	v := quicVar(nil, value)
	b = quicVar(b, id)
	b = quicVar(b, uint64(len(v)))
	return append(b, v...)
}
func appendQUICBytes(b []byte, id uint64, value []byte) []byte {
	b = quicVar(b, id)
	b = quicVar(b, uint64(len(value)))
	return append(b, value...)
}
func quicParameters(cid, odcid, retryCID []byte, server bool, mtu ...int) []byte {
	o := quicOptions{}
	if len(mtu) > 0 {
		o.receiveMTU = mtu[0]
	}
	return quicConnectionParameters(cid, odcid, retryCID, server, o.defaults())
}
func quicConnectionParameters(cid, odcid, retryCID []byte, server bool, o quicOptions) []byte {
	var b []byte
	size := o.receiveMTU
	datagram := min(1400, size-64)
	if o.datagramLimit != 0 {
		datagram = min(datagram, o.datagramLimit)
	}
	for _, p := range [][2]uint64{{1, uint64(o.idleTimeout / time.Millisecond)}, {3, uint64(size)}, {4, o.connectionWindow}, {5, o.streamWindow}, {6, o.streamWindow}, {7, o.streamWindow}, {8, o.streams}, {9, 16}, {10, 0}, {11, 25}, {14, 2}, {32, uint64(datagram)}} {
		b = appendQUICParam(b, p[0], p[1])
	}
	b = appendQUICBytes(b, 12, nil)
	b = appendQUICBytes(b, 15, cid)
	if server {
		b = appendQUICBytes(b, 0, odcid)
		if len(retryCID) > 0 {
			b = appendQUICBytes(b, 16, retryCID)
		}
	}
	return b
}

type quicPeerParams struct {
	maxUDPPayload                                                   uint64
	maxData, bidiLocal, bidiRemote, uni, maxBi, maxUni, maxDatagram uint64
	ackExponent                                                     uint
	maxAckDelay, idle                                               time.Duration
}

func parseQUICParameters(data, cid, odcid, retryCID []byte, server bool) (quicPeerParams, error) {
	p := quicPeerParams{maxUDPPayload: 65527, ackExponent: 3, maxAckDelay: 25 * time.Millisecond}
	r := quicReader(data)
	seen := map[uint64]bool{}
	if len(r) > 65535 {
		return p, errors.New("QUIC transport parameters exceed limit")
	}
	for len(r) > 0 {
		id, err := r.v()
		if err != nil {
			return p, err
		}
		n, err := r.v()
		if err != nil {
			return p, err
		}
		b, err := r.take(n)
		if err != nil {
			return p, err
		}
		if seen[id] {
			return p, errors.New("duplicate QUIC transport parameter")
		}
		seen[id] = true
		switch id {
		case 0, 15, 16:
			expected := cid
			if id == 0 {
				if server {
					return p, errors.New("client sent server-only QUIC parameter")
				}
				expected = odcid
			}
			if id == 16 {
				expected = retryCID
			}
			if !bytes.Equal(b, expected) {
				return p, errors.New("QUIC connection ID parameter mismatch")
			}
		case 12:
			if n != 0 {
				return p, errors.New("invalid disable_active_migration")
			}
		case 2:
			if server || n != 16 {
				return p, errors.New("invalid stateless reset token")
			}
		case 13:
			if server {
				return p, errors.New("client sent preferred address")
			}
		case 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 14, 32:
			v := quicReader(b)
			value, err := v.v()
			if err != nil || len(v) != 0 {
				return p, errors.New("invalid QUIC parameter integer")
			}
			switch id {
			case 1:
				if value > 0 {
					p.idle = time.Duration(min(value, uint64((1<<63-1)/time.Millisecond))) * time.Millisecond
				}
			case 3:
				p.maxUDPPayload = value
				if value < 1200 {
					return p, errors.New("QUIC maximum datagram below 1200")
				}
			case 4:
				p.maxData = value
			case 5:
				p.bidiLocal = value
			case 6:
				p.bidiRemote = value
			case 7:
				p.uni = value
			case 8:
				if value > 1<<60 {
					return p, errors.New("invalid QUIC stream limit")
				}
				p.maxBi = value
			case 9:
				if value > 1<<60 {
					return p, errors.New("invalid QUIC stream limit")
				}
				p.maxUni = value
			case 10:
				if value > 20 {
					return p, errors.New("invalid QUIC ACK exponent")
				}
				p.ackExponent = uint(value)
			case 11:
				if value >= 1<<14 {
					return p, errors.New("invalid QUIC ACK delay")
				}
				p.maxAckDelay = time.Duration(value) * time.Millisecond
			case 14:
				if value < 2 {
					return p, errors.New("invalid QUIC connection ID limit")
				}
			case 32:
				p.maxDatagram = value
			}
		}
	}
	if !seen[15] || !server && (!seen[0] || len(retryCID) > 0 && !seen[16]) {
		return p, errors.New("missing QUIC connection ID parameter")
	}
	return p, nil
}
