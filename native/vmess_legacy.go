package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"sync"
)

// Inbound users use sing-box's alterId; retain Lanboat's earlier spelling.
func (u *User) UnmarshalJSON(raw []byte) error {
	type fields User
	var value struct {
		fields
		Canonical *int `json:"alterId"`
		Alias     *int `json:"alter_id"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&value); err != nil {
		return err
	}
	if value.Canonical != nil && value.Alias != nil && *value.Canonical != *value.Alias {
		return errors.New("conflicting alterId and alter_id")
	}
	*u = User(value.fields)
	if value.Canonical != nil {
		u.AlterID = *value.Canonical
	}
	if value.Alias != nil {
		u.AlterID = *value.Alias
	}
	return nil
}

func vmessLegacyID(id [16]byte) [16]byte {
	return md5.Sum(append(id[:], "16167dc8-16b6-4e6d-b8bb-65dd68113a81"...))
}

func vmessLegacyIV(stamp int64) [16]byte {
	var repeated [32]byte
	for offset := 0; offset < len(repeated); offset += 8 {
		binary.BigEndian.PutUint64(repeated[offset:], uint64(stamp))
	}
	return md5.Sum(repeated[:])
}

func writeVMessLegacy(c io.Writer, user vmessUser, plain []byte, stamp int64) error {
	id := vmessLegacyID(user.id)
	mac := hmac.New(md5.New, id[:])
	var clock [8]byte
	binary.BigEndian.PutUint64(clock[:], uint64(stamp))
	_, _ = mac.Write(clock[:])
	header := mac.Sum(make([]byte, 0, 16+len(plain)))
	iv := vmessLegacyIV(stamp)
	block, _ := aes.NewCipher(user.command[:])
	start := len(header)
	header = append(header, plain...)
	cipher.NewCFBEncrypter(block, iv[:]).XORKeyStream(header[start:], header[start:])
	return writeAll(c, header)
}

type vmessLegacyToken struct {
	user  int
	stamp int64
}
type vmessLegacySigner struct {
	user int
	mac  hash.Hash
}
type vmessLegacyIndex struct {
	mu      sync.Mutex
	signers []vmessLegacySigner
	tokens  map[[16]byte]vmessLegacyToken
	slots   [241][][16]byte
	newest  int64
}

func newVMessLegacyIndex(users []vmessUser) *vmessLegacyIndex {
	var index *vmessLegacyIndex
	for i, u := range users {
		if !u.legacy {
			continue
		}
		if index == nil {
			index = &vmessLegacyIndex{tokens: make(map[[16]byte]vmessLegacyToken)}
		}
		// Modern compatible implementations use one derived identity regardless of count.
		for _, id := range [][16]byte{u.id, vmessLegacyID(u.id)} {
			index.signers = append(index.signers, vmessLegacySigner{user: i, mac: hmac.New(md5.New, id[:])})
		}
	}
	return index
}

func (index *vmessLegacyIndex) lookup(auth [16]byte, now int64) (vmessLegacyToken, bool) {
	if index == nil {
		return vmessLegacyToken{}, false
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	start, end := index.newest+1, now+120
	if index.newest == 0 || end < index.newest || end-index.newest >= int64(len(index.slots)) {
		clear(index.tokens)
		for i := range index.slots {
			index.slots[i] = index.slots[i][:0]
		}
		start = now - 120
	}
	for stamp := start; stamp <= end; stamp++ {
		var clock [8]byte
		slot := &index.slots[uint64(stamp)%uint64(len(index.slots))]
		for _, token := range *slot {
			delete(index.tokens, token)
		}
		*slot = (*slot)[:0]
		binary.BigEndian.PutUint64(clock[:], uint64(stamp))
		for _, signer := range index.signers {
			signer.mac.Reset()
			_, _ = signer.mac.Write(clock[:])
			var token [16]byte
			signer.mac.Sum(token[:0])
			index.tokens[token] = vmessLegacyToken{user: signer.user, stamp: stamp}
			*slot = append(*slot, token)
		}
	}
	index.newest = end
	token, ok := index.tokens[auth]
	return token, ok
}

func (r *Runtime) readVMessLegacy(c io.Reader, tag string, auth [16]byte, now int64) (vmessRequest, error) {
	token, ok := r.vmessLegacy[tag].lookup(auth, now)
	if !ok {
		return vmessRequest{}, errors.New("VMess authentication rejected")
	}
	user := r.vmessUsers["in:"+tag][token.user]
	iv := vmessLegacyIV(token.stamp)
	block, _ := aes.NewCipher(user.command[:])
	reader := &cipher.StreamReader{S: cipher.NewCFBDecrypter(block, iv[:]), R: c}
	header := make([]byte, 38, 320)
	if _, err := io.ReadFull(reader, header); err != nil {
		return vmessRequest{}, err
	}
	if header[0] != 1 || header[37] < 1 || header[37] > 3 {
		return vmessRequest{}, errors.New("invalid VMess legacy instruction")
	}
	read := func(n int) error {
		start := len(header)
		header = header[:start+n]
		_, err := io.ReadFull(reader, header[start:])
		return err
	}
	if header[37] != 3 {
		if err := read(3); err != nil {
			return vmessRequest{}, err
		}
		size := 0
		switch header[40] {
		case 1:
			size = 4
		case 3:
			size = 16
		case 2:
			if err := read(1); err != nil {
				return vmessRequest{}, err
			}
			size = int(header[41])
		default:
			return vmessRequest{}, errors.New("invalid VMess legacy address")
		}
		if err := read(size); err != nil {
			return vmessRequest{}, err
		}
	}
	if err := read(int(header[35]>>4) + 4); err != nil {
		return vmessRequest{}, err
	}
	q, err := parseVMessPlaintext(header)
	if err != nil {
		return q, err
	}
	q.legacy = true
	var nonce [32]byte
	copy(nonce[:16], q.iv[:])
	copy(nonce[16:], q.key[:])
	if err := r.replay.add(&ssKey{master: user.command[:]}, nonce[:]); err != nil {
		return q, errors.New("VMess authentication replay")
	}
	return q, nil
}

func vmessLegacyResponse(q vmessRequest, b []byte, encrypt bool) {
	key, iv := vmessResponseKeys(q)
	block, _ := aes.NewCipher(key[:])
	var stream cipher.Stream
	if encrypt {
		stream = cipher.NewCFBEncrypter(block, iv[:])
	} else {
		stream = cipher.NewCFBDecrypter(block, iv[:])
	}
	stream.XORKeyStream(b, b)
}

func readVMessLegacyResponse(c io.Reader, q vmessRequest) error {
	var header [4]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	vmessLegacyResponse(q, header[:], false)
	if header[0] != q.response || header[2] != 0 || header[3] != 0 {
		return errors.New("VMess response authentication failed")
	}
	return nil
}
