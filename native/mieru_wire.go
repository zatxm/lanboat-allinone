package native

import (
	"bytes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
	"sync"
	"time"
)

type mieruUser struct {
	name  string
	hash  [32]byte
	mu    sync.Mutex
	epoch int64
	keys  [3]cipher.AEAD
}

func newMieruUser(name, password string) *mieruUser {
	return &mieruUser{name: name, hash: sha256.Sum256([]byte(password + "\x00" + name))}
}
func (u *mieruUser) ciphers() [3]cipher.AEAD {
	u.mu.Lock()
	defer u.mu.Unlock()
	epoch := time.Now().Round(2 * time.Minute).Unix()
	if u.keys[1] == nil || epoch != u.epoch {
		for i := range 3 {
			salt := sha256.Sum256(binary.BigEndian.AppendUint64(nil, uint64(epoch+int64(i-1)*120)))
			key, _ := pbkdf2.Key(sha256.New, string(u.hash[:]), salt[:], 64, 32)
			u.keys[i], _ = newChaChaAEAD(key, true)
		}
		u.epoch = epoch
	}
	return u.keys
}
func mieruNonce(name string, hint bool) [24]byte {
	var n [24]byte
	rand.Read(n[:])
	if hint {
		h := sha256.Sum256(append([]byte(name), n[:16]...))
		copy(n[20:], h[:4])
	}
	return n
}
func mieruIncrement(n *[24]byte) error {
	for i := 23; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			return nil
		}
	}
	return errors.New("Mieru nonce exhausted")
}

type mieruFrame struct {
	kind             byte
	id, seq, ack     uint32
	window           uint16
	fragment, status byte
	mode, rotation   byte
	mask             uint32
	original         int
	body             []byte
	sent             time.Time
	tries            int
}

func (f mieruFrame) metadata(prefix, suffix int, wireLength int) [32]byte {
	var b [32]byte
	b[0] = f.kind
	binary.BigEndian.PutUint32(b[2:], uint32(time.Now().Unix()/60))
	binary.BigEndian.PutUint32(b[6:], f.id)
	binary.BigEndian.PutUint32(b[10:], f.seq)
	if f.kind <= 5 {
		b[14] = f.status
		binary.BigEndian.PutUint16(b[15:], uint16(len(f.body)))
		b[17] = byte(suffix)
	} else {
		b[1] = f.mode
		binary.BigEndian.PutUint32(b[14:], f.ack)
		binary.BigEndian.PutUint16(b[18:], f.window)
		b[20] = f.fragment
		b[21] = byte(prefix)
		binary.BigEndian.PutUint16(b[22:], uint16(wireLength))
		b[24] = byte(suffix)
		binary.BigEndian.PutUint32(b[25:], f.mask)
		binary.BigEndian.PutUint16(b[29:], uint16(len(f.body)))
		b[31] = f.rotation
	}
	return b
}
func mieruParseHeader(b []byte) (f mieruFrame, prefix, length, suffix int, e error) {
	if len(b) != 32 {
		return f, 0, 0, 0, io.ErrUnexpectedEOF
	}
	f.kind = b[0]
	f.id = binary.BigEndian.Uint32(b[6:])
	f.seq = binary.BigEndian.Uint32(b[10:])
	stamp := int64(binary.BigEndian.Uint32(b[2:]))
	now := time.Now().Unix() / 60
	if stamp < now-1 || stamp > now+1 || f.id == 0 || f.kind < 2 || f.kind > 11 || f.seq == ^uint32(0) {
		return f, 0, 0, 0, errors.New("invalid Mieru metadata")
	}
	if f.kind <= 5 {
		f.status = b[14]
		length = int(binary.BigEndian.Uint16(b[15:]))
		suffix = int(b[17])
		if length > 1024 {
			return f, 0, 0, 0, errors.New("Mieru control payload exceeds limit")
		}
	} else {
		f.ack = binary.BigEndian.Uint32(b[14:])
		f.window = binary.BigEndian.Uint16(b[18:])
		f.fragment = b[20]
		prefix = int(b[21])
		length = int(binary.BigEndian.Uint16(b[22:]))
		suffix = int(b[24])
		f.mode = b[1]
		f.mask = binary.BigEndian.Uint32(b[25:])
		f.rotation = b[31]
		if f.kind >= 10 {
			original := int(binary.BigEndian.Uint16(b[29:]))
			if e = mieruLowEntropySize(f.mode, f.mask, f.rotation, length, original); e != nil {
				return f, 0, 0, 0, e
			}
			f.original = original
		} else if length > 32768 {
			return f, 0, 0, 0, errors.New("Mieru data payload exceeds limit")
		}
		if (f.kind == 8 || f.kind == 9) && length != 0 {
			return f, 0, 0, 0, errors.New("Mieru ACK has payload")
		}
	}
	return
}
func mieruLowEntropySize(mode byte, mask uint32, rotation byte, encoded, original int) error {
	if mode < 1 || mode > 4 || bits.OnesCount32(mask) != 12+4*int(mode) || rotation&15 != 0 && rotation&240 != 0 || original < 1 || original > 32768 || encoded != ((original+int(mode)+2)/(int(mode)+3))*8 {
		return errors.New("invalid Mieru low entropy metadata")
	}
	return nil
}
func mieruMask(mask uint32, rotation byte, chunk int) uint64 {
	m := uint64(mask)<<32 | uint64(mask)
	shift := int(rotation & 15)
	if rotation&240 != 0 {
		shift = -int(rotation >> 4)
	}
	return bits.RotateLeft64(m, -chunk*shift)
}
func mieruLowEntropy(data []byte, mode byte, mask uint32, rotation byte, original int, encode bool) ([]byte, error) {
	capacity := int(mode) + 3
	encoded := ((original + capacity - 1) / capacity) * 8
	if e := mieruLowEntropySize(mode, mask, rotation, encoded, original); e != nil {
		return nil, e
	}
	if encode {
		out := make([]byte, encoded)
		for i := 0; i < encoded/8; i++ {
			var src uint64
			start := i * capacity
			for _, v := range data[start:min(original, start+capacity)] {
				src = src<<8 | uint64(v)
			}
			m := mieruMask(mask, rotation, i)
			var word uint64
			bit := 0
			for position := 0; position < 64; position++ {
				if m>>position&1 != 0 {
					word |= (src >> bit & 1) << position
					bit++
				}
			}
			binary.BigEndian.PutUint64(out[i*8:], word)
		}
		return out, nil
	}
	if len(data) != encoded {
		return nil, errors.New("truncated Mieru low entropy payload")
	}
	out := make([]byte, 0, original)
	ones := false
	for i := 0; i < encoded/8; i++ {
		word := binary.BigEndian.Uint64(data[i*8:])
		m := mieruMask(mask, rotation, i)
		active := m
		n := min(capacity, original-len(out))
		for bits.OnesCount64(active) > n*8 {
			active &^= uint64(1) << (63 - bits.LeadingZeros64(active))
		}
		padding := word &^ active
		if i == 0 {
			ones = padding == ^active
		}
		if padding != 0 && !ones || ones && padding != ^active {
			return nil, errors.New("inconsistent Mieru low entropy padding")
		}
		var src uint64
		bit := 0
		for position := 0; position < 64; position++ {
			if m>>position&1 != 0 {
				src |= (word >> position & 1) << bit
				bit++
			}
		}
		for j := n - 1; j >= 0; j-- {
			out = append(out, byte(src>>(8*j)))
		}
	}
	return out, nil
}

type mieruCodec struct {
	key         cipher.AEAD
	user        *mieruUser
	nonce       [24]byte
	initialized bool
	buffer      []byte
	pattern     *mieruPattern
	mtu         int
	keyEpoch    int64
}

func (c *mieruCodec) read(r io.Reader, users []*mieruUser, replay *replayWindow) (mieruFrame, error) {
	var f mieruFrame
	if !c.initialized {
		if _, e := io.ReadFull(r, c.nonce[:]); e != nil {
			return f, e
		}
	} else if e := mieruIncrement(&c.nonce); e != nil {
		return f, e
	}
	var encrypted [48]byte
	if _, e := io.ReadFull(r, encrypted[:]); e != nil {
		return f, e
	}
	var plain []byte
	var e error
	if c.key == nil {
		c.user, c.key, plain, e = mieruDiscover(users, c.nonce[:], encrypted[:])
	} else {
		plain, e = c.key.Open(nil, c.nonce[:], encrypted[:], nil)
	}
	if e != nil {
		return f, e
	}
	first := !c.initialized
	c.initialized = true
	f, prefix, length, suffix, e := mieruParseHeader(plain)
	if e != nil {
		return f, e
	}
	if prefix != 0 {
		if _, e = io.CopyN(io.Discard, r, int64(prefix)); e != nil {
			return f, e
		}
	}
	if length > 0 {
		payload := make([]byte, length+16)
		if _, e = io.ReadFull(r, payload); e != nil {
			return f, e
		}
		if f.kind >= 10 {
			original := f.original
			raw, e := mieruLowEntropy(payload[:length], f.mode, f.mask, f.rotation, original, false)
			if e != nil {
				return f, e
			}
			payload = append(raw, payload[length:]...)
		}
		if e = mieruIncrement(&c.nonce); e != nil {
			return f, e
		}
		f.body, e = c.key.Open(payload[:0], c.nonce[:], payload, nil)
		if e != nil {
			return f, e
		}
	}
	if _, e = io.CopyN(io.Discard, r, int64(suffix)); e != nil {
		return f, e
	}
	if first && replay != nil {
		if e = replay.claimFor("mieru:"+string(c.user.hash[:])+string(encrypted[:]), 4*time.Minute); e != nil {
			return f, e
		}
	}
	return f, nil
}
func mieruDiscover(users []*mieruUser, nonce, encrypted []byte) (*mieruUser, cipher.AEAD, []byte, error) {
	for pass := 0; pass < 2; pass++ {
		for _, u := range users {
			hint := sha256.Sum256(append([]byte(u.name), nonce[:16]...))
			matched := bytes.Equal(hint[:4], nonce[20:24])
			if matched != (pass == 0) {
				continue
			}
			keys := u.ciphers()
			for _, i := range []int{1, 0, 2} {
				if plain, e := keys[i].Open(nil, nonce, encrypted, nil); e == nil {
					return u, keys[i], plain, nil
				}
			}
		}
	}
	return nil, nil, nil, errors.New("Mieru authentication rejected")
}
func (c *mieruCodec) encode(f mieruFrame, packet, hint bool) ([]byte, error) {
	first := !c.initialized || packet
	if first {
		c.nonce = mieruNonce(c.user.name, false)
		if c.pattern != nil && (!c.initialized || c.pattern.allPackets) {
			c.pattern.nonce(&c.nonce)
		}
		if hint {
			h := sha256.Sum256(append([]byte(c.user.name), c.nonce[:16]...))
			copy(c.nonce[20:], h[:4])
		}
	} else if e := mieruIncrement(&c.nonce); e != nil {
		return nil, e
	}
	c.initialized = true
	prefix, suffix := 0, 0
	var random [2]byte
	rand.Read(random[:])
	middle, end := 15, 31
	if c.pattern != nil {
		middle, end = c.pattern.middle, c.pattern.end
	}
	suffix = int(random[1]) % (end + 1)
	if f.kind > 5 {
		prefix = int(random[0]) % (middle + 1)
	}
	body := f.body
	wireLength := len(body)
	if f.kind >= 10 {
		f.mode = max(f.mode, 1)
		if f.mask == 0 {
			f.mask = ^uint32(0)
			for bits.OnesCount32(f.mask) > 12+4*int(f.mode) {
				selected := mieruRandom(bits.OnesCount32(f.mask))
				available := f.mask
				for range selected {
					available &= available - 1
				}
				f.mask &^= uint32(1) << bits.TrailingZeros32(available)
			}
		}
		wireLength = ((len(body) + int(f.mode) + 2) / (int(f.mode) + 3)) * 8
	}
	if packet && c.mtu > 0 {
		room := c.mtu - 72 - wireLength
		if len(body) > 0 {
			room -= 16
		}
		if room < 0 {
			return nil, errors.New("Mieru frame exceeds MTU")
		}
		prefix = min(prefix, room)
		suffix = min(suffix, room-prefix)
	}
	meta := f.metadata(prefix, suffix, wireLength)
	c.buffer = c.buffer[:0]
	if first {
		c.buffer = append(c.buffer, c.nonce[:]...)
	}
	c.buffer = c.key.Seal(c.buffer, c.nonce[:], meta[:], nil)
	offset := len(c.buffer)
	c.buffer = append(c.buffer, make([]byte, prefix)...)
	rand.Read(c.buffer[offset:])
	if len(body) > 0 {
		if !packet {
			if e := mieruIncrement(&c.nonce); e != nil {
				return nil, e
			}
		}
		if f.kind < 10 {
			c.buffer = c.key.Seal(c.buffer, c.nonce[:], body, nil)
		} else {
			payload := c.key.Seal(nil, c.nonce[:], body, nil)
			raw, e := mieruLowEntropy(payload[:len(body)], f.mode, f.mask, f.rotation, len(body), true)
			if e != nil {
				return nil, e
			}
			payload = append(raw, payload[len(body):]...)
			c.buffer = append(c.buffer, payload...)
		}
	}
	offset = len(c.buffer)
	c.buffer = append(c.buffer, make([]byte, suffix)...)
	rand.Read(c.buffer[offset:])
	return c.buffer, nil
}
func mieruDecodePacket(packet []byte, users []*mieruUser, known cipher.AEAD) (mieruFrame, *mieruUser, cipher.AEAD, error) {
	var f mieruFrame
	if len(packet) < 72 {
		return f, nil, nil, io.ErrUnexpectedEOF
	}
	nonce := packet[:24]
	var user *mieruUser
	key := known
	var plain []byte
	var e error
	if key != nil {
		plain, e = key.Open(nil, nonce, packet[24:72], nil)
	}
	if plain == nil {
		user, key, plain, e = mieruDiscover(users, nonce, packet[24:72])
	}
	if e != nil {
		return f, nil, nil, e
	}
	f, prefix, length, suffix, e := mieruParseHeader(plain)
	if e != nil {
		return f, nil, nil, e
	}
	end := 72 + prefix + length
	if length > 0 {
		end += 16
	}
	if end+suffix != len(packet) {
		return f, nil, nil, errors.New("invalid Mieru packet length")
	}
	if length > 0 {
		body := packet[72+prefix : end]
		if f.kind >= 10 {
			raw, e := mieruLowEntropy(body[:length], f.mode, f.mask, f.rotation, f.original, false)
			if e != nil {
				return f, nil, nil, e
			}
			body = append(raw, body[length:]...)
		}
		f.body, e = key.Open(nil, nonce, body, nil)
		if e != nil {
			return f, nil, nil, e
		}
	}
	return f, user, key, nil
}
