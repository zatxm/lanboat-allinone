package native

import (
	"bytes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"sync"
	"time"
)

type wgHash struct{ b []byte }

func (w *wgHash) Write(b []byte) (int, error) { w.b = append(w.b, b...); return len(b), nil }
func (w *wgHash) Sum(b []byte) []byte         { return append(b, blake2s(w.b, nil, 32)...) }
func (w *wgHash) Reset()                      { w.b = w.b[:0] }
func (*wgHash) Size() int                     { return 32 }
func (*wgHash) BlockSize() int                { return 64 }
func wgHMAC(key, data []byte) []byte {
	h := hmac.New(func() hash.Hash { return &wgHash{} }, key)
	h.Write(data)
	return h.Sum(nil)
}
func wgKDF(key, data []byte, n int) [][]byte {
	prk := wgHMAC(key, data)
	out := make([][]byte, n)
	var prev []byte
	for i := range out {
		prev = wgHMAC(prk, append(append([]byte{}, prev...), byte(i+1)))
		out[i] = prev
	}
	return out
}
func wgHashMix(h, data []byte) []byte {
	return blake2s(append(append([]byte{}, h...), data...), nil, 32)
}
func wgDH(key *ecdh.PrivateKey, pub []byte) ([]byte, error) {
	p, e := ecdh.X25519().NewPublicKey(pub)
	if e != nil {
		return nil, e
	}
	return key.ECDH(p)
}
func wgKey(raw string) ([]byte, error) {
	b, e := base64.StdEncoding.DecodeString(raw)
	if e != nil || len(b) != 32 {
		return nil, errors.New("WireGuard keys must contain 32 base64-encoded bytes")
	}
	var zero [32]byte
	if subtle.ConstantTimeCompare(zero[:], b) == 1 {
		return nil, errors.New("WireGuard key cannot be zero")
	}
	return b, nil
}
func wgNoiseHash(remote []byte) (ck, h []byte) {
	ck = blake2s([]byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"), nil, 32)
	h = wgHashMix(ck, []byte("WireGuard v1 zx2c4 Jason@zx2c4.com"))
	h = wgHashMix(h, remote)
	return
}
func wgEncrypt(key, plain, aad []byte) []byte {
	a, _ := newChaChaAEAD(key, false)
	return a.Seal(nil, make([]byte, 12), plain, aad)
}
func wgDecrypt(key, body, aad []byte) ([]byte, error) {
	a, _ := newChaChaAEAD(key, false)
	return a.Open(nil, make([]byte, 12), body, aad)
}
func wgMAC1(message, pub []byte) []byte {
	return blake2s(message, blake2s(append([]byte("mac1----"), pub...), nil, 32), 16)
}
func wgTimestamp(now time.Time) []byte {
	b := binary.BigEndian.AppendUint64(nil, uint64(now.Unix())+0x400000000000000a)
	return binary.BigEndian.AppendUint32(b, uint32(now.Nanosecond()))
}
func wgIndex() uint32 {
	var b [4]byte
	for {
		rand.Read(b[:])
		if n := binary.LittleEndian.Uint32(b[:]); n != 0 {
			return n
		}
	}
}

type wgHandshake struct {
	private, ephemeral          *ecdh.PrivateKey
	remote, psk, ck, h, message []byte
	retryCookie                 []byte
	index                       uint32
	at                          time.Time
}
type wgTransport struct {
	mu                      sync.Mutex
	send, receive           []byte
	local, remote           uint32
	counter                 uint64
	window                  packetWindow
	at                      time.Time
	confirmed               bool
	rekeyAfter, rejectAfter time.Duration
	// Per-direction ciphers and nonce scratch reused across packets; guarded by mu.
	sendAEAD, receiveAEAD   cipher.AEAD
	sendNonce, receiveNonce [12]byte
}

func wgInitiate(private *ecdh.PrivateKey, remote, psk []byte) (*wgHandshake, error) {
	return wgInitiateKind(private, remote, psk, 1)
}
func wgInitiateKind(private *ecdh.PrivateKey, remote, psk []byte, kind uint32) (*wgHandshake, error) {
	ephemeral, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	s := &wgHandshake{private: private, ephemeral: ephemeral, remote: remote, psk: psk, index: wgIndex(), at: time.Now()}
	s.ck, s.h = wgNoiseHash(remote)
	pub := ephemeral.PublicKey().Bytes()
	s.ck = wgKDF(s.ck, pub, 1)[0]
	s.h = wgHashMix(s.h, pub)
	dh, e := wgDH(ephemeral, remote)
	if e != nil {
		return nil, e
	}
	k := wgKDF(s.ck, dh, 2)
	s.ck = k[0]
	static := wgEncrypt(k[1], private.PublicKey().Bytes(), s.h)
	s.h = wgHashMix(s.h, static)
	dh, e = wgDH(private, remote)
	if e != nil {
		return nil, e
	}
	k = wgKDF(s.ck, dh, 2)
	s.ck = k[0]
	stamp := wgEncrypt(k[1], wgTimestamp(s.at), s.h)
	s.h = wgHashMix(s.h, stamp)
	b := binary.LittleEndian.AppendUint32(nil, kind)
	b = binary.LittleEndian.AppendUint32(b, s.index)
	b = append(b, pub...)
	b = append(b, static...)
	b = append(b, stamp...)
	b = append(b, wgMAC1(b, remote)...)
	b = append(b, make([]byte, 16)...)
	s.message = b
	return s, nil
}
func wgReadInitiation(private *ecdh.PrivateKey, b []byte) (remote, stamp, ck, h []byte, err error) {
	return wgReadInitiationKind(private, b, 1)
}
func wgReadInitiationKind(private *ecdh.PrivateKey, b []byte, kind uint32) (remote, stamp, ck, h []byte, err error) {
	if len(b) != 148 || binary.LittleEndian.Uint32(b) != kind {
		err = errors.New("invalid WireGuard initiation")
		return
	}
	if subtle.ConstantTimeCompare(wgMAC1(b[:116], private.PublicKey().Bytes()), b[116:132]) != 1 {
		err = errors.New("invalid WireGuard MAC1")
		return
	}
	ck, h = wgNoiseHash(private.PublicKey().Bytes())
	ephemeral := b[8:40]
	ck = wgKDF(ck, ephemeral, 1)[0]
	h = wgHashMix(h, ephemeral)
	dh, e := wgDH(private, ephemeral)
	if e != nil {
		err = e
		return
	}
	k := wgKDF(ck, dh, 2)
	ck = k[0]
	remote, err = wgDecrypt(k[1], b[40:88], h)
	if err != nil {
		return
	}
	h = wgHashMix(h, b[40:88])
	dh, err = wgDH(private, remote)
	if err != nil {
		return
	}
	k = wgKDF(ck, dh, 2)
	ck = k[0]
	stamp, err = wgDecrypt(k[1], b[88:116], h)
	h = wgHashMix(h, b[88:116])
	return
}
func wgRespond(private *ecdh.PrivateKey, remote, psk, ck, h, init []byte) ([]byte, *wgTransport, error) {
	return wgRespondKind(private, remote, psk, ck, h, init, 2)
}
func wgRespondKind(private *ecdh.PrivateKey, remote, psk, ck, h, init []byte, kind uint32) ([]byte, *wgTransport, error) {
	ephemeral, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	pub := ephemeral.PublicKey().Bytes()
	ck = wgKDF(ck, pub, 1)[0]
	h = wgHashMix(h, pub)
	dh, e := wgDH(ephemeral, init[8:40])
	if e != nil {
		return nil, nil, e
	}
	ck = wgKDF(ck, dh, 1)[0]
	dh, e = wgDH(ephemeral, remote)
	if e != nil {
		return nil, nil, e
	}
	ck = wgKDF(ck, dh, 1)[0]
	k := wgKDF(ck, psk, 3)
	ck = k[0]
	h = wgHashMix(h, k[1])
	empty := wgEncrypt(k[2], nil, h)
	keys := wgKDF(ck, nil, 2)
	t := &wgTransport{send: keys[1], receive: keys[0], local: wgIndex(), remote: binary.LittleEndian.Uint32(init[4:]), at: time.Now()}
	b := binary.LittleEndian.AppendUint32(nil, kind)
	b = binary.LittleEndian.AppendUint32(b, t.local)
	b = binary.LittleEndian.AppendUint32(b, t.remote)
	b = append(b, pub...)
	b = append(b, empty...)
	b = append(b, wgMAC1(b, remote)...)
	b = append(b, make([]byte, 16)...)
	return b, t, nil
}
func (s *wgHandshake) response(b []byte) (*wgTransport, error) {
	return s.responseKind(b, 2)
}
func (s *wgHandshake) responseKind(b []byte, kind uint32) (*wgTransport, error) {
	if len(b) != 92 || binary.LittleEndian.Uint32(b) != kind || binary.LittleEndian.Uint32(b[8:]) != s.index {
		return nil, errors.New("invalid WireGuard response")
	}
	if subtle.ConstantTimeCompare(wgMAC1(b[:60], s.private.PublicKey().Bytes()), b[60:76]) != 1 {
		return nil, errors.New("invalid WireGuard response MAC1")
	}
	ck, h := append([]byte{}, s.ck...), append([]byte{}, s.h...)
	pub := b[12:44]
	ck = wgKDF(ck, pub, 1)[0]
	h = wgHashMix(h, pub)
	dh, e := wgDH(s.ephemeral, pub)
	if e != nil {
		return nil, e
	}
	ck = wgKDF(ck, dh, 1)[0]
	dh, e = wgDH(s.private, pub)
	if e != nil {
		return nil, e
	}
	ck = wgKDF(ck, dh, 1)[0]
	k := wgKDF(ck, s.psk, 3)
	ck = k[0]
	h = wgHashMix(h, k[1])
	if _, e = wgDecrypt(k[2], b[44:60], h); e != nil {
		return nil, e
	}
	keys := wgKDF(ck, nil, 2)
	return &wgTransport{send: keys[0], receive: keys[1], local: s.index, remote: binary.LittleEndian.Uint32(b[4:]), at: time.Now(), confirmed: true}, nil
}
func (s *wgHandshake) cookie(b []byte) error {
	return s.cookieKind(b, 3)
}
func (s *wgHandshake) cookieKind(b []byte, kind uint32) error {
	if len(b) != 64 || binary.LittleEndian.Uint32(b) != kind || binary.LittleEndian.Uint32(b[4:]) != s.index {
		return errors.New("invalid WireGuard cookie")
	}
	key := blake2s(append([]byte("cookie--"), s.remote...), nil, 32)
	a, _ := newChaChaAEAD(key, true)
	cookie, e := a.Open(nil, b[8:32], b[32:], s.message[116:132])
	if e != nil {
		return e
	}
	copy(s.message[132:], blake2s(s.message[:132], cookie, 16))
	s.retryCookie = append(s.retryCookie[:0], cookie...)
	return nil
}
func (t *wgTransport) seal(packet []byte) ([]byte, error) {
	return t.sealPrefixed(packet, 4, 0, 0)
}
func (t *wgTransport) sealPrefixed(packet []byte, kind uint32, prefix, suffix int) ([]byte, error) {
	return t.sealPadded(packet, kind, prefix, suffix, -1)
}
func (t *wgTransport) lifetime() time.Duration {
	if t.rejectAfter != 0 {
		return t.rejectAfter
	}
	return 180 * time.Second
}
func (t *wgTransport) refreshTime() time.Duration {
	if t.rekeyAfter != 0 {
		return t.rekeyAfter
	}
	return 120 * time.Second
}
func (t *wgTransport) sealPadded(packet []byte, kind uint32, prefix, suffix, padding int) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.at) > t.lifetime() || t.counter >= 1<<60 {
		return nil, errors.New("WireGuard transport key expired")
	}
	if padding < 0 {
		padding = ((len(packet) + 15) &^ 15) - len(packet)
	}
	if t.sendAEAD == nil {
		t.sendAEAD, _ = newChaChaAEAD(t.send, false)
	}
	b := make([]byte, prefix, prefix+32+len(packet)+padding+suffix)
	rand.Read(b)
	b = binary.LittleEndian.AppendUint32(b, kind)
	b = binary.LittleEndian.AppendUint32(b, t.remote)
	b = binary.LittleEndian.AppendUint64(b, t.counter)
	binary.LittleEndian.PutUint64(t.sendNonce[4:], t.counter)
	t.counter++
	// Seal the padded plaintext in place after the header.
	header := len(b)
	b = append(append(b, packet...), make([]byte, padding)...)
	return t.sendAEAD.Seal(b[:header], t.sendNonce[:], b[header:], nil), nil
}
func (t *wgTransport) open(b []byte) ([]byte, error) {
	return t.openKind(b, 4)
}
func (t *wgTransport) openKind(b []byte, kind uint32) ([]byte, error) {
	if len(b) < 32 || binary.LittleEndian.Uint32(b) != kind || binary.LittleEndian.Uint32(b[4:]) != t.local {
		return nil, errors.New("invalid WireGuard data header")
	}
	counter := binary.LittleEndian.Uint64(b[8:])
	t.mu.Lock()
	defer t.mu.Unlock()
	if time.Since(t.at) > t.lifetime() || counter >= 1<<60 {
		return nil, errors.New("expired or stale WireGuard packet")
	}
	if !t.window.fresh(counter) {
		return nil, errors.New("replayed WireGuard packet")
	}
	if t.receiveAEAD == nil {
		t.receiveAEAD, _ = newChaChaAEAD(t.receive, false)
	}
	binary.LittleEndian.PutUint64(t.receiveNonce[4:], counter)
	plain, e := t.receiveAEAD.Open(nil, t.receiveNonce[:], b[16:], nil)
	if e != nil {
		return nil, e
	}
	t.window.accept(counter)
	t.confirmed = true
	if len(plain) == 0 {
		return plain, nil
	}
	if plain[0] == 0 {
		for _, b := range plain {
			if b != 0 {
				return nil, errors.New("invalid WireGuard keepalive padding")
			}
		}
		return nil, nil
	}
	p, e := parseTunPacket(plain)
	if e != nil {
		return nil, e
	}
	return p.data, nil
}
func wgEqualTimestamp(a, b []byte) bool {
	return len(a) == 12 && len(b) == 12 && bytes.Compare(a, b) <= 0
}
