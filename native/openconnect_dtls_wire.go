package native

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// OpenConnect's modern PSK channel, independently encoded from RFC6347/5487.
// The PSK comes from the authenticated CSTP TLS exporter, never the password.
type ocDTLS struct {
	resume               *ocDTLSResume
	v13                  *dtls13
	previous             *ocDTLS
	secret               *[32]byte
	baseEpoch            uint16
	secureRenegotiation  bool
	clientVerify         [12]byte
	serverVerify         [12]byte
	generation           atomic.Uint64
	queued               [][]byte
	queuedBytes          int
	earlyCCS             bool
	conn                 net.Conn
	client               bool
	psk, appID           []byte
	clientRandom         [32]byte
	serverRandom         [32]byte
	suite                uint16
	suites               []uint16
	ems, etm, ccs        bool
	newHash              func() hash.Hash
	transcript           []byte
	master               []byte
	readKey, writeKey    cipher.AEAD
	cbc                  *ocDTLSCBC
	readIV, writeIV      [12]byte
	failures             uint32
	writeMu              sync.Mutex
	writeEpoch           uint16
	writeSeq             uint64
	window               packetWindow
	sendNext, recvNext   uint16
	stage                int
	fragments            map[uint16]*ocDTLSFragment
	pending              []byte
	buffer               [18432]byte
	plain, writeBuffer   []byte
	appBuffer            []byte
	flight, peerFinished []byte
	lastFlight           time.Time
	readDeadline         time.Time
	ready                atomic.Bool
	lastReceive          atomic.Int64
	sent, received       atomic.Uint64
}

type ocDTLSFragment struct {
	kind byte
	data []byte
	seen []bool
	n    int
}

func putUint24(b []byte, n uint32) { b[0], b[1], b[2] = byte(n>>16), byte(n>>8), byte(n) }
func readUint24(b []byte) uint32   { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }

func ocDTLSHandshakeMessage(kind byte, seq uint16, body []byte) []byte {
	b := make([]byte, 12, 12+len(body))
	b[0] = kind
	putUint24(b[1:4], uint32(len(body)))
	binary.BigEndian.PutUint16(b[4:6], seq)
	putUint24(b[9:12], uint32(len(body)))
	return append(b, body...)
}

func ocDTLSRecordHeader(kind byte, epoch uint16, seq uint64, size int) []byte {
	b := make([]byte, 13, 13+size)
	b[0], b[1], b[2] = kind, 0xfe, 0xfd
	binary.BigEndian.PutUint64(b[3:11], uint64(epoch)<<48|seq)
	binary.BigEndian.PutUint16(b[11:], uint16(size))
	return b
}

func ocDTLSClientHello(b []byte) (appid, cookie, random []byte, suites []uint16, ext ocDTLSExtensionFlags, err error) {
	return ocDTLSParseHello(b, 0xfefd)
}

func ocDTLSParseHello(b []byte, version uint16) (appid, cookie, random []byte, suites []uint16, ext ocDTLSExtensionFlags, err error) {
	bad := errors.New("invalid DTLS ClientHello")
	if len(b) < 38 || binary.BigEndian.Uint16(b) != version || b[34] > 32 || len(b) < 36+int(b[34]) {
		err = bad
		return
	}
	random, appid = b[2:34], b[35:35+int(b[34])]
	b = b[35+int(b[34]):]
	n := int(b[0])
	if len(b) < n+3 {
		err = bad
		return
	}
	cookie, b = b[1:n+1], b[n+1:]
	n = int(binary.BigEndian.Uint16(b))
	if n == 0 || n%2 != 0 || len(b) < n+3 {
		err = bad
		return
	}
	for i := 2; i < n+2; i += 2 {
		suites = append(suites, binary.BigEndian.Uint16(b[i:]))
	}
	b = b[n+2:]
	n = int(b[0])
	if n == 0 || len(b) < n+1 || !bytes.Contains(b[1:n+1], []byte{0}) {
		err = bad
		return
	}
	ext, err = ocDTLSExtensions(b[n+1:])
	return
}

type ocDTLSExtensionFlags struct {
	ems, etm      bool
	renegotiation []byte
}

func ocDTLSExtensions(b []byte) (ocDTLSExtensionFlags, error) {
	var ext ocDTLSExtensionFlags
	if len(b) == 0 {
		return ext, nil
	}
	if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
		return ext, errors.New("invalid DTLS extensions")
	}
	seen := map[uint16]bool{}
	for b = b[2:]; len(b) != 0; {
		if len(b) < 4 || int(binary.BigEndian.Uint16(b[2:])) > len(b)-4 {
			return ext, errors.New("short DTLS extension")
		}
		kind, size := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if seen[kind] || (kind == 23 || kind == 22) && size != 0 {
			return ext, errors.New("invalid DTLS extension")
		}
		seen[kind] = true
		if kind == 0xff01 {
			if size < 1 || int(b[4]) != size-1 || size > 25 {
				return ext, errors.New("invalid DTLS renegotiation binding")
			}
			ext.renegotiation = b[5 : 4+size]
		}
		ext.ems, ext.etm = ext.ems || kind == 23, ext.etm || kind == 22
		b = b[4+size:]
	}
	return ext, nil
}

func ocDTLSAppendExtensions(b []byte, ems, etm bool, binding ...[]byte) []byte {
	var verify []byte
	if len(binding) != 0 {
		verify = binding[0]
	}
	ext := []byte{0xff, 1, 0, byte(1 + len(verify)), byte(len(verify))}
	ext = append(ext, verify...)
	if ems {
		ext = append(ext, 0, 23, 0, 0)
	}
	if etm {
		ext = append(ext, 0, 22, 0, 0)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(ext)))
	return append(b, ext...)
}

func (d *ocDTLS) hello(cookie []byte) []byte {
	if d.resume != nil {
		return d.resumeHello(cookie)
	}
	b := append([]byte{0xfe, 0xfd}, d.clientRandom[:]...)
	id := d.appID
	if d.previous != nil {
		id = nil
	}
	b = append(b, byte(len(id)))
	b = append(b, id...)
	b = append(b, byte(len(cookie)))
	b = append(b, cookie...)
	suites := d.cipherIDs()
	b = binary.BigEndian.AppendUint16(b, uint16(len(suites)*2))
	for _, suite := range suites {
		b = binary.BigEndian.AppendUint16(b, suite)
	}
	var verify []byte
	if d.previous != nil {
		verify = d.previous.clientVerify[:]
	}
	return ocDTLSAppendExtensions(append(b, 1, 0), true, slices.ContainsFunc(suites, ocDTLSIsCBC), verify)
}

func (d *ocDTLS) hash(b []byte) []byte {
	h := d.newHash()
	h.Write(b)
	return h.Sum(nil)
}

func ocDTLSPRF(h func() hash.Hash, secret []byte, label string, seed []byte, size int) []byte {
	input := append([]byte(label), seed...)
	mac := func(b []byte) []byte { m := hmac.New(h, secret); m.Write(b); return m.Sum(nil) }
	a, result := mac(input), make([]byte, 0, size+64)
	for len(result) < size {
		result = append(result, mac(append(append([]byte(nil), a...), input...))...)
		a = mac(a)
	}
	return result[:size]
}

func (d *ocDTLS) keys() error {
	if d.resume != nil {
		return d.resumeKeys()
	}
	keySize, ivSize, macSize := 16, 4, 0
	var newMAC func() hash.Hash
	d.newHash = sha256.New
	switch d.suite {
	case 0xa8, 0xc0a4, 0xc0a8:
	case 0xa9:
		keySize, d.newHash = 32, sha512.New384
	case 0xc0a5, 0xc0a9:
		keySize = 32
	case 0xccab:
		keySize, ivSize = 32, 12
	case 0x008c, 0x008d, 0x00ae, 0x00af:
		keySize, newMAC = ocDTLSCBCSpec(d.suite)
		ivSize, macSize = 0, newMAC().Size()
		if d.suite == 0x00af {
			d.newHash = sha512.New384
		}
	default:
		return errors.New("DTLS requires a supported PSK suite")
	}
	premaster := make([]byte, 68)
	binary.BigEndian.PutUint16(premaster, 32)
	binary.BigEndian.PutUint16(premaster[34:], 32)
	copy(premaster[36:], d.psk)
	label, seed := "master secret", append(append([]byte(nil), d.clientRandom[:]...), d.serverRandom[:]...)
	if d.ems {
		label, seed = "extended master secret", d.hash(d.transcript)
	}
	d.master = ocDTLSPRF(d.newHash, premaster, label, seed, 48)
	seed = append(append([]byte(nil), d.serverRandom[:]...), d.clientRandom[:]...)
	block := ocDTLSPRF(d.newHash, d.master, "key expansion", seed, (macSize+keySize+ivSize)*2)
	defer clear(premaster)
	defer clear(block)
	if newMAC != nil {
		d.cbcKeys(block, keySize, newMAC)
		return nil
	}
	makeKey := func(key []byte) cipher.AEAD {
		if d.suite == 0xccab {
			a, _ := newChaChaAEAD(key, false)
			return a
		}
		if d.suite >= 0xc0a4 && d.suite <= 0xc0a9 {
			tag := 16
			if d.suite >= 0xc0a8 {
				tag = 8
			}
			a, _ := newDTLSCCM(key, tag)
			return a
		}
		b, _ := aes.NewCipher(key)
		a, _ := cipher.NewGCM(b)
		return a
	}
	d.writeKey, d.readKey = makeKey(block[:keySize]), makeKey(block[keySize:keySize*2])
	clear(d.writeIV[:])
	clear(d.readIV[:])
	copy(d.writeIV[:ivSize], block[keySize*2:keySize*2+ivSize])
	copy(d.readIV[:ivSize], block[keySize*2+ivSize:])
	if !d.client {
		d.writeKey, d.readKey = d.readKey, d.writeKey
		d.writeIV, d.readIV = d.readIV, d.writeIV
	}
	return nil
}

func (d *ocDTLS) record(kind byte, data []byte) ([]byte, error) {
	if d.previous != nil && d.writeEpoch == d.baseEpoch {
		return d.previous.record(kind, data)
	}
	if len(data) > 16384 || d.writeSeq >= 1<<48 || d.writeEpoch != 0 && d.writeSeq >= d.recordLimit() {
		return nil, errors.New("DTLS record limit")
	}
	b := append(d.writeBuffer[:0], make([]byte, 13)...)
	b[0] = kind
	binary.BigEndian.PutUint16(b[1:3], d.recordVersion())
	binary.BigEndian.PutUint64(b[3:11], uint64(d.writeEpoch)<<48|d.writeSeq)
	binary.BigEndian.PutUint16(b[11:], uint16(len(data)))
	d.writeSeq++
	if d.writeEpoch == 0 {
		b = append(b, data...)
		d.writeBuffer = b[:0]
		return b, nil
	}
	if d.cbc != nil {
		return d.sealCBC(b, data)
	}
	nonce := d.writeIV
	var aad [13]byte
	copy(aad[:8], b[3:11])
	copy(aad[8:11], b[:3])
	binary.BigEndian.PutUint16(aad[11:], uint16(len(data)))
	if d.suite == 0xccab {
		for i, value := range b[3:11] {
			nonce[4+i] ^= value
		}
	} else {
		copy(nonce[4:], b[3:11])
		b = append(b, nonce[4:]...)
	}
	b = d.writeKey.Seal(b, nonce[:], data, aad[:])
	binary.BigEndian.PutUint16(b[11:], uint16(len(b)-13))
	d.writeBuffer = b[:0]
	return b, nil
}

func (d *ocDTLS) open(b []byte) (byte, []byte, bool) {
	if len(b) < 13 || !d.acceptVersion(binary.BigEndian.Uint16(b[1:3])) || int(binary.BigEndian.Uint16(b[11:])) != len(b)-13 {
		return 0, nil, false
	}
	id := binary.BigEndian.Uint64(b[3:11])
	epoch, seq := id>>48, id&((1<<48)-1)
	if d.previous != nil && epoch == uint64(d.baseEpoch) {
		return d.previous.open(b)
	}
	if epoch == 0 {
		if d.baseEpoch != 0 || d.ready.Load() || b[0] != 22 && b[0] != 20 && b[0] != 21 {
			return 0, nil, false
		}
		return b[0], b[13:], true
	}
	if epoch != uint64(d.baseEpoch)+1 || binary.BigEndian.Uint16(b[1:3]) != d.recordVersion() || d.readKey == nil && d.cbc == nil || !d.ccs || seq >= d.recordLimit() || !d.window.fresh(seq) || d.failures >= 1<<16 {
		return 0, nil, false
	}
	if d.cbc != nil {
		data, ok := d.openCBC(b)
		if !ok {
			d.failures++
			return 0, nil, false
		}
		d.window.accept(seq)
		return b[0], data, true
	}
	explicit, tag := 8, d.readKey.Overhead()
	if d.suite == 0xccab {
		explicit = 0
	}
	n := len(b) - 13 - explicit - tag
	if n < 0 || n > 16384 {
		return 0, nil, false
	}
	nonce := d.readIV
	if explicit == 0 {
		for i, value := range b[3:11] {
			nonce[4+i] ^= value
		}
	} else {
		copy(nonce[4:], b[13:21])
	}
	var aad [13]byte
	copy(aad[:8], b[3:11])
	copy(aad[8:11], b[:3])
	binary.BigEndian.PutUint16(aad[11:], uint16(n))
	data, err := d.readKey.Open(d.plain[:0], nonce[:], b[13+explicit:], aad[:])
	if err != nil {
		d.failures++
		return 0, nil, false
	}
	d.plain = data
	d.window.accept(seq)
	return b[0], data, true
}

func (d *ocDTLS) nextRecord() ([]byte, error) {
	for {
		if len(d.pending) >= 13 {
			n := 13 + int(binary.BigEndian.Uint16(d.pending[11:]))
			if n <= len(d.pending) {
				b := d.pending[:n]
				d.pending = d.pending[n:]
				return b, nil
			}
		}
		b := d.buffer[:]
		n, err := d.conn.Read(b)
		if err != nil {
			return nil, err
		}
		d.pending = b[:n]
	}
}

func (d *ocDTLS) addHandshake(kind byte, body []byte, hashMessage bool) error {
	m := ocDTLSHandshakeMessage(kind, d.sendNext, body)
	d.sendNext++
	if hashMessage {
		d.appendTranscript(m)
	}
	b, err := d.record(22, m)
	d.flight = append(d.flight, b...)
	return err
}

func (d *ocDTLS) finished(client bool) []byte {
	label := "server finished"
	if client {
		label = "client finished"
	}
	if d.resume != nil && d.resume.version == 0x0100 {
		return ocDTLSLegacyFinished(d.master, label, d.transcript)
	}
	return ocDTLSPRF(d.newHash, d.master, label, d.hash(d.transcript), 12)
}

func (d *ocDTLS) changeCipher() error {
	body := []byte{1}
	if d.resume != nil && d.resume.version == 0x0100 {
		body = binary.BigEndian.AppendUint16(body, d.sendNext)
		d.sendNext++
	}
	b, err := d.record(20, body)
	if err != nil {
		return err
	}
	d.flight = append(d.flight, b...)
	d.writeEpoch, d.writeSeq = d.baseEpoch+1, 0
	return nil
}

func (d *ocDTLS) transmit() error {
	d.lastFlight = time.Now()
	n, err := d.conn.Write(d.flight)
	if err == nil && n != len(d.flight) {
		err = io.ErrShortWrite
	}
	return err
}

func (d *ocDTLS) handshake(ctx context.Context) error {
	if d.v13 != nil {
		d.v13.init(d)
		return d.v13.handshake(ctx)
	}
	return d.handshakeFrom(ctx, nil)
}

func (d *ocDTLS) handshakeFrom(ctx context.Context, first []byte) error {
	defer clear(d.psk)
	defer func() { clear(d.master) }()
	if d.resume != nil {
		defer clear(d.resume.master[:])
		if len(d.appID) != 32 || d.resume.version != 0x0100 && d.resume.version != 0xfefd || d.resume.suite == 0 {
			return errors.New("invalid DTLS resumed binding")
		}
	} else if len(d.psk) != 32 || len(d.appID) < 16 || len(d.appID) > 32 {
		return errors.New("invalid DTLS PSK binding")
	}
	if d.resume == nil && d.secret == nil {
		d.secret = new([32]byte)
		copy(d.secret[:], d.psk)
	}
	defer func() {
		if !d.ready.Load() && d.previous == nil && d.secret != nil {
			clear(d.secret[:])
		}
	}()
	d.fragments = map[uint16]*ocDTLSFragment{}
	if len(first) != 0 {
		if d.client {
			if len(first) != 12 || first[0] != 0 || readUint24(first[1:4]) != 0 || binary.BigEndian.Uint16(first[4:6]) != 0 || readUint24(first[6:9]) != 0 || readUint24(first[9:12]) != 0 {
				return errors.New("invalid DTLS HelloRequest")
			}
			d.recvNext = 1
		} else if err := d.handshakes(first, d.baseEpoch); err != nil {
			return err
		}
	}
	if d.client {
		rand.Read(d.clientRandom[:])
		if err := d.addHandshake(1, d.hello(nil), true); err != nil {
			return err
		}
		if err := d.transmit(); err != nil {
			return err
		}
	} else if d.previous != nil && len(first) == 0 {
		if err := d.addHandshake(0, nil, false); err != nil {
			return err
		}
		if err := d.transmit(); err != nil {
			return err
		}
	}
	for !d.ready.Load() {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline := time.Now().Add(time.Second)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		d.conn.SetReadDeadline(deadline)
		wire, err := d.nextRecord()
		if err != nil {
			if os.IsTimeout(err) && ctx.Err() == nil {
				if len(d.flight) != 0 {
					if err = d.transmit(); err != nil {
						return err
					}
				}
				continue
			}
			return err
		}
		kind, data, ok := d.open(wire)
		if !ok {
			continue
		}
		switch kind {
		case 20:
			if d.resume != nil {
				if err := d.resumeCCS(data); err != nil {
					return err
				}
				continue
			}
			if !bytes.Equal(data, []byte{1}) {
				return errors.New("invalid DTLS cipher transition")
			}
			if d.readKey == nil && d.cbc == nil {
				d.earlyCCS = true
				continue
			}
			if binary.BigEndian.Uint16(wire[3:5]) == d.baseEpoch {
				d.ccs = true
			}
		case 21:
			return errors.New("DTLS peer rejected handshake")
		case 22:
			if err := d.handshakes(data, binary.BigEndian.Uint16(wire[3:5])); err != nil {
				return err
			}
			if d.ready.Load() {
				d.peerFinished = append([]byte(nil), wire...)
			}
		case 23:
			if d.previous == nil {
				continue
			}
			if !d.ccs && len(data) != 0 && len(d.queued) < 128 && d.queuedBytes+len(data) <= 256<<10 {
				d.queued = append(d.queued, bytes.Clone(data))
				d.queuedBytes += len(data)
			}
		default:
			return errors.New("DTLS application data before authentication")
		}
	}
	d.lastReceive.Store(time.Now().UnixNano())
	d.conn.SetReadDeadline(time.Time{})
	d.transcript, d.fragments = nil, nil
	return nil
}

func (d *ocDTLS) handshakes(b []byte, epoch uint16) error {
	for len(b) != 0 {
		if len(b) < 12 {
			return errors.New("short DTLS handshake")
		}
		size, offset, length := int(readUint24(b[1:4])), int(readUint24(b[6:9])), int(readUint24(b[9:12]))
		seq, kind := binary.BigEndian.Uint16(b[4:6]), b[0]
		if size > 8192 || length > len(b)-12 || offset+length > size || kind == 20 && epoch != d.baseEpoch+1 || kind != 20 && epoch != d.baseEpoch {
			return errors.New("invalid DTLS handshake fragment")
		}
		if seq < d.recvNext {
			if time.Since(d.lastFlight) >= 200*time.Millisecond && len(d.flight) != 0 {
				if err := d.transmit(); err != nil {
					return err
				}
			}
			b = b[12+length:]
			continue
		}
		if seq-d.recvNext > 4 || len(d.fragments) >= 8 && d.fragments[seq] == nil {
			return errors.New("DTLS handshake queue limit")
		}
		f := d.fragments[seq]
		if f == nil {
			f = &ocDTLSFragment{kind: kind, data: make([]byte, size), seen: make([]bool, size)}
			d.fragments[seq] = f
		}
		if f.kind != kind || len(f.data) != size {
			return errors.New("conflicting DTLS handshake")
		}
		for i, value := range b[12 : 12+length] {
			at := offset + i
			if f.seen[at] && f.data[at] != value {
				return errors.New("conflicting DTLS fragment overlap")
			}
			if !f.seen[at] {
				f.n++
			}
			f.seen[at], f.data[at] = true, value
		}
		b = b[12+length:]
		for f := d.fragments[d.recvNext]; f != nil && f.n == len(f.data); f = d.fragments[d.recvNext] {
			delete(d.fragments, d.recvNext)
			message := ocDTLSHandshakeMessage(f.kind, d.recvNext, f.data)
			d.recvNext++
			if err := d.message(f.kind, f.data, message); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *ocDTLS) message(kind byte, body, message []byte) error {
	if d.resume != nil {
		return d.resumeMessage(kind, body, message)
	}
	bad := errors.New("unexpected DTLS PSK handshake")
	if d.client {
		switch {
		case kind == 0 && d.stage == 0 && d.previous != nil:
			if len(body) != 0 {
				return bad
			}
			return nil
		case kind == 3 && d.stage == 0:
			if len(body) < 3 || len(body) != 3+int(body[2]) || body[2] == 0 || d.sendNext != 1 {
				return bad
			}
			d.flight, d.transcript = nil, nil
			if err := d.addHandshake(1, d.hello(body[3:]), true); err != nil {
				return err
			}
			return d.transmit()
		case kind == 2 && d.stage == 0:
			if len(body) < 38 || binary.BigEndian.Uint16(body) != 0xfefd || int(body[34]) > 32 || len(body) < 38+int(body[34]) {
				return bad
			}
			copy(d.serverRandom[:], body[2:34])
			body = body[35+int(body[34]):]
			d.suite = binary.BigEndian.Uint16(body)
			if body[2] != 0 || !slices.Contains(d.cipherIDs(), d.suite) {
				return bad
			}
			ext, err := ocDTLSExtensions(body[3:])
			if err != nil {
				return err
			}
			if ext.etm && !ocDTLSIsCBC(d.suite) {
				return bad
			}
			if err := d.verifyRenegotiation(ext, nil); err != nil {
				return err
			}
			d.ems, d.etm = ext.ems, ext.etm
			d.stage = 1
		case kind == 12 && d.stage == 1:
			if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
				return bad
			}
			d.stage = 2
		case kind == 14 && (d.stage == 1 || d.stage == 2):
			if len(body) != 0 {
				return bad
			}
			d.transcript = append(d.transcript, message...)
			d.flight = nil
			if err := d.addHandshake(16, []byte{0, 3, 'p', 's', 'k'}, true); err != nil {
				return err
			}
			if err := d.keys(); err != nil {
				return err
			}
			if d.earlyCCS {
				d.ccs = true
			}
			if err := d.changeCipher(); err != nil {
				return err
			}
			copy(d.clientVerify[:], d.finished(true))
			if err := d.addHandshake(20, d.clientVerify[:], true); err != nil {
				return err
			}
			d.stage = 3
			return d.transmit()
		case kind == 20 && d.stage == 3 && d.ccs:
			if !hmac.Equal(body, d.finished(false)) {
				return errors.New("DTLS server Finished authentication failed")
			}
			copy(d.serverVerify[:], body)
			d.ready.Store(true)
			return nil
		default:
			return bad
		}
	} else {
		switch {
		case kind == 1 && d.stage == 0:
			id, _, random, suites, ext, err := ocDTLSClientHello(body)
			if err != nil || d.previous == nil && !bytes.Equal(id, d.appID) {
				return bad
			}
			if err := d.verifyRenegotiation(ext, suites); err != nil {
				return err
			}
			for _, suite := range d.cipherIDs() {
				if slices.Contains(suites, suite) {
					d.suite = suite
					break
				}
			}
			if d.suite == 0 {
				return bad
			}
			copy(d.clientRandom[:], random)
			rand.Read(d.serverRandom[:])
			d.ems, d.etm = ext.ems, ext.etm && ocDTLSIsCBC(d.suite)
			d.transcript = append(d.transcript, message...)
			hello := append([]byte{0xfe, 0xfd}, d.serverRandom[:]...)
			hello = binary.BigEndian.AppendUint16(append(hello, 0), d.suite)
			hello = append(hello, 0)
			var verify []byte
			if d.previous != nil {
				verify = append(bytes.Clone(d.previous.clientVerify[:]), d.previous.serverVerify[:]...)
			}
			hello = ocDTLSAppendExtensions(hello, d.ems, d.etm, verify)
			d.flight = nil
			if err := d.addHandshake(2, hello, true); err != nil {
				return err
			}
			if err := d.addHandshake(14, nil, true); err != nil {
				return err
			}
			d.stage = 1
			return d.transmit()
		case kind == 16 && d.stage == 1:
			if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 || len(body) > 258 {
				return bad
			}
			d.transcript = append(d.transcript, message...)
			d.stage = 2
			if err := d.keys(); err != nil {
				return err
			}
			if d.earlyCCS {
				d.ccs = true
			}
			return nil
		case kind == 20 && d.stage == 2 && d.ccs:
			if !hmac.Equal(body, d.finished(true)) {
				return errors.New("DTLS client Finished authentication failed")
			}
			copy(d.clientVerify[:], body)
			d.transcript = append(d.transcript, message...)
			d.flight = nil
			if err := d.changeCipher(); err != nil {
				return err
			}
			copy(d.serverVerify[:], d.finished(false))
			if err := d.addHandshake(20, d.serverVerify[:], true); err != nil {
				return err
			}
			if err := d.transmit(); err != nil {
				return err
			}
			d.ready.Store(true)
			return nil
		default:
			return bad
		}
	}
	d.transcript = append(d.transcript, message...)
	return nil
}

func (d *ocDTLS) write(kind byte, payload []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if !d.ready.Load() {
		return net.ErrClosed
	}
	if d.v13 != nil {
		return d.v13.write(kind, payload)
	}
	data := append(d.appBuffer[:0], kind)
	data = append(data, payload...)
	d.appBuffer = data
	b, err := d.record(23, data)
	if err != nil {
		d.ready.Store(false)
		d.conn.Close()
		return err
	}
	n, err := d.conn.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err == nil && kind == 0 {
		d.sent.Add(1)
	}
	if err != nil {
		d.ready.Store(false)
		d.conn.Close()
	}
	return err
}

func (d *ocDTLS) read() (byte, []byte, error) {
	if d.v13 != nil {
		return d.v13.read()
	}
	for {
		if len(d.queued) != 0 {
			data := d.queued[0]
			d.queuedBytes -= len(data)
			d.queued[0] = nil
			d.queued = d.queued[1:]
			if data[0] == 0 {
				d.received.Add(1)
			}
			return data[0], data[1:], nil
		}
		if d.failures >= 1<<16 {
			return 0, nil, errors.New("DTLS authentication failure limit")
		}
		b, err := d.nextRecord()
		if err != nil {
			return 0, nil, err
		}
		kind, data, ok := d.open(b)
		if !ok {
			if (d.resume != nil && d.client || d.resume == nil && !d.client) && bytes.Equal(b, d.peerFinished) {
				d.writeMu.Lock()
				if time.Since(d.lastFlight) >= 200*time.Millisecond {
					_ = d.transmit()
				}
				d.writeMu.Unlock()
			}
			continue
		}
		if kind == 21 {
			return 0, nil, io.EOF
		}
		if kind == 22 && d.resume != nil {
			return 0, nil, errors.New("resumed DTLS requires a new tunnel for rekey")
		}
		if kind == 22 && len(data) >= 12 && ((d.client && data[0] == 0) || (!d.client && data[0] == 1)) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := d.renegotiate(ctx, data)
			cancel()
			if err != nil {
				return 0, nil, err
			}
			continue
		}
		if kind != 23 || len(data) == 0 {
			continue
		}
		d.lastReceive.Store(time.Now().UnixNano())
		if data[0] == 0 {
			d.received.Add(1)
		}
		return data[0], data[1:], nil
	}
}
