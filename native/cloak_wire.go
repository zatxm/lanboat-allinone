package native

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const cloakWireLimit = 16640

func cloakGCM(key []byte) cipher.AEAD {
	block, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(block)
	return a
}

type cloakCodec struct {
	key  [32]byte
	aead cipher.AEAD
}
type cloakFrame struct {
	id     uint32
	seq    uint64
	close  byte
	body   []byte
	charge int
}

func newCloakCodec(key [32]byte, method byte) (*cloakCodec, error) {
	c := &cloakCodec{key: key}
	switch method {
	case 0:
	case 1:
		c.aead = cloakGCM(key[:])
	case 3:
		c.aead = cloakGCM(key[:16])
	case 2:
		c.aead, _ = newChaChaAEAD(key[:], false)
	default:
		return nil, errors.New("unknown Cloak encryption")
	}
	return c, nil
}
func (c *cloakCodec) seal(f cloakFrame) []byte {
	extra := 8
	if c.aead != nil {
		extra = 16
	}
	pad := 0
	if f.seq < 5 {
		var b [1]byte
		rand.Read(b[:])
		pad = int(b[0]) % (256 - extra)
	}
	b := make([]byte, 14+len(f.body)+pad, 14+len(f.body)+pad+extra)
	binary.BigEndian.PutUint32(b, f.id)
	binary.BigEndian.PutUint64(b[4:], f.seq)
	b[12], b[13] = f.close, byte(extra+pad)
	copy(b[14:], f.body)
	rand.Read(b[14+len(f.body):])
	if c.aead != nil {
		b = c.aead.Seal(b[:14], b[:12], b[14:], nil)
	} else {
		n := len(b)
		b = append(b, make([]byte, 8)...)
		rand.Read(b[n:])
	}
	stream := salsaStream{key: c.key}
	copy(stream.nonce[:], b[len(b)-8:])
	stream.XORKeyStream(b[:14], b[:14])
	return b
}
func (c *cloakCodec) open(b []byte) (cloakFrame, error) {
	var f cloakFrame
	if len(b) < 22 || len(b) > cloakWireLimit {
		return f, errors.New("invalid Cloak frame length")
	}
	stream := salsaStream{key: c.key}
	copy(stream.nonce[:], b[len(b)-8:])
	stream.XORKeyStream(b[:14], b[:14])
	extra := int(b[13])
	minimum := 8
	if c.aead != nil {
		minimum = 16
	}
	if extra < minimum || extra > len(b)-14 {
		return f, errors.New("invalid Cloak padding")
	}
	f = cloakFrame{id: binary.BigEndian.Uint32(b), seq: binary.BigEndian.Uint64(b[4:]), close: b[12]}
	if f.close > 2 {
		return f, errors.New("invalid Cloak closing flag")
	}
	data := b[14:]
	if c.aead != nil {
		var e error
		data, e = c.aead.Open(data[:0], b[:12], data, nil)
		if e != nil {
			return f, e
		}
	}
	size := len(b) - 14 - extra
	if size > len(data) {
		return f, errors.New("invalid Cloak payload size")
	}
	f.body = data[:size]
	return f, nil
}
func (o *cloakOptions) auth(id uint32) (public, encrypted, shared []byte, err error) {
	peer, e := ecdh.X25519().NewPublicKey(o.public)
	if e != nil {
		err = e
		return
	}
	key, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		err = e
		return
	}
	shared, err = key.ECDH(peer)
	if err != nil {
		return
	}
	public = key.PublicKey().Bytes()
	plain := make([]byte, 48)
	copy(plain, o.uid[:])
	copy(plain[16:28], o.proxy)
	plain[28] = o.encryption
	binary.BigEndian.PutUint64(plain[29:], uint64(time.Now().Unix()))
	binary.BigEndian.PutUint32(plain[37:], id)
	encrypted = cloakGCM(shared).Seal(nil, public[:12], plain, nil)
	return
}

type cloakIdentity struct {
	id     uint32
	method byte
	shared []byte
}

func (o *cloakOptions) authenticate(public, encrypted []byte) (cloakIdentity, error) {
	var identity cloakIdentity
	if len(public) != 32 || len(encrypted) != 64 {
		return identity, errors.New("invalid Cloak authentication size")
	}
	key, e := ecdh.X25519().NewPrivateKey(o.private)
	if e != nil {
		return identity, e
	}
	peer, e := ecdh.X25519().NewPublicKey(public)
	if e != nil {
		return identity, e
	}
	shared, e := key.ECDH(peer)
	if e != nil {
		return identity, e
	}
	plain, e := cloakGCM(shared).Open(nil, public[:12], encrypted, nil)
	if e != nil || len(plain) != 48 {
		return identity, errors.New("Cloak authentication failed")
	}
	stamp := int64(binary.BigEndian.Uint64(plain[29:]))
	now := time.Now().Unix()
	if stamp < now-180 || stamp > now+180 || subtle.ConstantTimeCompare(plain[:16], o.uid[:]) != 1 || strings.TrimRight(string(plain[16:28]), "\x00") != o.proxy || plain[28] > 3 || plain[41] != 0 {
		return identity, errors.New("Cloak credential,time,method or mode rejected")
	}
	identity.id = binary.BigEndian.Uint32(plain[37:])
	identity.method = plain[28]
	identity.shared = shared
	return identity, nil
}
func cloakClientHello(browser, host string, public, encrypted []byte) []byte {
	b := append([]byte{3, 3}, public...)
	b = append(b, 32)
	b = append(b, encrypted[:32]...)
	suites := []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	if browser == "firefox" {
		suites = []uint16{0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	}
	var cipherBytes []byte
	for _, v := range suites {
		cipherBytes = binary.BigEndian.AppendUint16(cipherBytes, v)
	}
	b = append(b, stVector(cipherBytes, 2)...)
	b = append(b, 1, 0)
	var extensions []byte
	if host != "" && net.ParseIP(host) == nil {
		extensions = stExtension(extensions, 0, stVector(append([]byte{0}, stVector([]byte(host), 2)...), 2))
	}
	extensions = stExtension(extensions, 23, nil)
	extensions = stExtension(extensions, 65281, []byte{0})
	extensions = stExtension(extensions, 10, []byte{0, 6, 0, 29, 0, 23, 0, 24})
	extensions = stExtension(extensions, 11, []byte{1, 0})
	extensions = stExtension(extensions, 35, nil)
	extensions = stExtension(extensions, 16, []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'})
	keyshare := append([]byte{0, 29, 0, 32}, encrypted[32:]...)
	extensions = stExtension(extensions, 51, stVector(keyshare, 2))
	extensions = stExtension(extensions, 43, []byte{4, 3, 4, 3, 3})
	extensions = stExtension(extensions, 13, []byte{0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1})
	extensions = stExtension(extensions, 45, []byte{1, 1})
	if browser == "firefox" {
		extensions = stExtension(extensions, 28, []byte{0x40, 1})
	} else if browser == "safari" {
		extensions = stExtension(extensions, 18, nil)
	} else {
		extensions = stExtension(extensions, 27, []byte{2, 0, 2})
	}
	if n := 512 - (4 + len(b) + 2 + len(extensions) + 4); n > 0 {
		extensions = stExtension(extensions, 21, make([]byte, n))
	}
	hello := stMessage(1, append(b, stVector(extensions, 2)...))
	wire := shadowFrame(22, hello)
	wire[2] = 1
	return wire
}
func cloakHelloFields(hello []byte, server bool) (public, session, share []byte, err error) {
	if len(hello) < 71 || hello[0] != 1 && !server || hello[0] != 2 && server || int(hello[1])<<16|int(hello[2])<<8|int(hello[3]) != len(hello)-4 || hello[38] != 32 {
		err = errors.New("invalid Cloak TLS hello")
		return
	}
	public, session = hello[6:38], hello[39:71]
	pos := 71
	if server {
		pos += 3
	} else {
		if len(hello) < pos+2 {
			err = io.ErrUnexpectedEOF
			return
		}
		n := int(binary.BigEndian.Uint16(hello[pos:]))
		pos += 2 + n
		if pos >= len(hello) {
			err = io.ErrUnexpectedEOF
			return
		}
		pos += 1 + int(hello[pos])
	}
	if pos+2 > len(hello) {
		err = io.ErrUnexpectedEOF
		return
	}
	n := int(binary.BigEndian.Uint16(hello[pos:]))
	pos += 2
	if n != len(hello)-pos {
		err = errors.New("invalid Cloak TLS extension size")
		return
	}
	ext, e := stExtensions(hello[pos:])
	if e != nil {
		err = e
		return
	}
	data := ext[51]
	if server {
		if len(data) != 36 || binary.BigEndian.Uint16(data) != 29 || binary.BigEndian.Uint16(data[2:]) != 32 {
			err = errors.New("missing Cloak server key share")
			return
		}
		share = data[4:]
		return
	}
	if len(data) < 2 || int(binary.BigEndian.Uint16(data)) != len(data)-2 {
		err = errors.New("invalid Cloak key share vector")
		return
	}
	data = data[2:]
	for len(data) > 0 {
		if len(data) < 4 {
			err = io.ErrUnexpectedEOF
			return
		}
		group, size := binary.BigEndian.Uint16(data), int(binary.BigEndian.Uint16(data[2:]))
		data = data[4:]
		if size > len(data) {
			err = io.ErrUnexpectedEOF
			return
		}
		if group == 29 {
			if size != 32 || share != nil {
				err = errors.New("invalid Cloak client key share")
				return
			}
			share = data[:size]
		}
		data = data[size:]
	}
	if share == nil {
		err = errors.New("missing Cloak X25519 key share")
	}
	return
}
func cloakReply(key [32]byte, shared []byte) []byte {
	nonce := make([]byte, 12)
	rand.Read(nonce)
	return cloakGCM(shared).Seal(nonce, nonce, key[:], nil)
}
func cloakReplyKey(reply, shared []byte) (key [32]byte, err error) {
	if len(reply) != 60 {
		err = errors.New("Cloak reply must contain60 bytes")
		return
	}
	var plain []byte
	plain, err = cloakGCM(shared).Open(nil, reply[:12], reply[12:], nil)
	if err == nil {
		if len(plain) != 32 {
			err = errors.New("invalid Cloak session key")
		} else {
			copy(key[:], plain)
		}
	}
	return
}
func cloakServerHello(session, reply []byte) []byte {
	b := append([]byte{3, 3}, reply[:32]...)
	b = append(b, 32)
	b = append(b, session...)
	b = append(b, 0x13, 1, 0)
	share := append([]byte{0, 29, 0, 32}, reply[32:]...)
	pad := make([]byte, 4)
	rand.Read(pad)
	share = append(share, pad...)
	ext := stExtension(nil, 51, share)
	ext = stExtension(ext, 43, []byte{3, 4})
	b = append(b, stVector(ext, 2)...)
	wire := shadowFrame(22, stMessage(2, b))
	wire = append(wire, shadowFrame(20, []byte{1})...)
	certificate := make([]byte, 128+int(reply[0]))
	rand.Read(certificate)
	return append(wire, shadowFrame(23, certificate)...)
}
func cloakDirectReply(conn net.Conn, session, shared []byte) ([32]byte, error) {
	var key [32]byte
	buffer := make([]byte, 5+shadowRecordLimit)
	record, e := shadowReadRecord(conn, buffer)
	if e != nil {
		return key, e
	}
	if record[0] != 22 {
		return key, errors.New("Cloak expected ServerHello")
	}
	random, sid, share, e := cloakHelloFields(record[5:], true)
	if e != nil {
		return key, e
	}
	if subtle.ConstantTimeCompare(sid, session) != 1 {
		return key, errors.New("Cloak session identifier mismatch")
	}
	reply := append(append([]byte(nil), random...), share[:28]...)
	key, e = cloakReplyKey(reply, shared)
	if e != nil {
		return key, fmt.Errorf("Cloak server authentication: %w", e)
	}
	for _, kind := range []byte{20, 23} {
		record, e = shadowReadRecord(conn, buffer)
		if e != nil {
			return key, e
		}
		if record[0] != kind {
			return key, errors.New("invalid Cloak handshake flight")
		}
	}
	return key, nil
}
