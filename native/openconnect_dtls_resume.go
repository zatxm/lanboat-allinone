package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"slices"
)

// Cisco's abbreviated handshake authenticates a fresh key sent inside CSTP TLS.
// It is enabled explicitly; it never downgrades the default exporter-PSK channel.
type ocDTLSResume struct {
	version uint16
	suite   uint16
	master  [48]byte
	ccsSeq  uint16
}

var ocDTLSResumeSuites = [...]ocDTLSSuite{
	{"AES128-SHA", 0x002f}, {"AES256-SHA", 0x0035},
	{"DHE-RSA-AES128-SHA", 0x0033}, {"DHE-RSA-AES256-SHA", 0x0039},
	{"DES-CBC3-SHA", 0x000a},
	{"AES128-GCM-SHA256", 0x009c}, {"AES256-GCM-SHA384", 0x009d},
	{"ECDHE-RSA-AES128-GCM-SHA256", 0xc02f}, {"ECDHE-RSA-AES256-GCM-SHA384", 0xc030},
	{"OC2-DTLS1_2-CHACHA20-POLY1305", 0xccab},
}

func ocDTLSResumeName(id uint16) string {
	for _, s := range ocDTLSResumeSuites {
		if s.id == id {
			return s.name
		}
	}
	return ""
}
func (o OpenConnectOptions) dtlsResume() bool {
	return o.DTLSMode == "resume" || o.DTLSVersion == "0.9"
}
func (o OpenConnectOptions) resumeVersion() uint16 {
	if o.DTLSVersion == "0.9" {
		return 0x0100
	}
	return 0xfefd
}
func (o OpenConnectOptions) resumeCipherIDs() ([]uint16, error) {
	names := o.DTLSCipherSuites
	if names == nil {
		if o.DTLSVersion == "0.9" {
			return []uint16{0x002f, 0x0035}, nil
		}
		return []uint16{0x009c, 0x009d, 0xc02f, 0xc030}, nil
	}
	if len(names) == 0 || len(names) > len(ocDTLSResumeSuites) {
		return nil, errors.New("invalid DTLS resumption suite count")
	}
	var ids []uint16
	for _, name := range names {
		at := slices.IndexFunc(ocDTLSResumeSuites[:], func(s ocDTLSSuite) bool { return s.name == name })
		if at < 0 || slices.Contains(ids, ocDTLSResumeSuites[at].id) || o.DTLSVersion == "0.9" && at > 4 || o.DTLSVersion != "0.9" && at == 4 {
			return nil, errors.New("unknown, duplicate or incompatible DTLS resumption suite")
		}
		ids = append(ids, ocDTLSResumeSuites[at].id)
	}
	return ids, nil
}
func (d *ocDTLS) recordVersion() uint16 {
	if d.resume != nil {
		return d.resume.version
	}
	return 0xfefd
}
func (d *ocDTLS) acceptVersion(v uint16) bool {
	return v == d.recordVersion() || d.resume == nil && v == 0xfeff
}
func (d *ocDTLS) appendTranscript(m []byte) {
	if d.resume != nil && d.resume.version == 0x0100 {
		m = m[12:]
	}
	d.transcript = append(d.transcript, m...)
}
func ocDTLSLegacyPRF(secret []byte, label string, seed []byte, n int) []byte {
	half := (len(secret) + 1) / 2
	out := ocDTLSPRF(md5.New, secret[:half], label, seed, n)
	other := ocDTLSPRF(sha1.New, secret[len(secret)-half:], label, seed, n)
	for i := range out {
		out[i] ^= other[i]
	}
	clear(other)
	return out
}
func ocDTLSLegacyFinished(master []byte, label string, transcript []byte) []byte {
	m, s := md5.Sum(transcript), sha1.Sum(transcript)
	return ocDTLSLegacyPRF(master, label, append(m[:], s[:]...), 12)
}
func (d *ocDTLS) resumeKeys() error {
	d.suite = d.resume.suite
	d.master = bytes.Clone(d.resume.master[:])
	d.newHash = sha256.New
	keySize := 16
	switch d.suite {
	case 0x002f, 0x0033, 0x009c, 0xc02f:
	case 0x0035, 0x0039:
		keySize = 32
	case 0x000a:
		keySize = 24
	case 0x009d, 0xc030:
		keySize, d.newHash = 32, sha512.New384
	case 0xccab:
		keySize = 32
	default:
		return errors.New("invalid DTLS resumption cipher")
	}
	macSize, ivSize := 0, 4
	if d.suite == 0xccab {
		ivSize = 12
	}
	cbc := d.suite == 0x002f || d.suite == 0x0033 || d.suite == 0x0035 || d.suite == 0x0039 || d.suite == 0x000a
	if cbc {
		macSize, ivSize = sha1.Size, 0
	}
	seed := append(bytes.Clone(d.serverRandom[:]), d.clientRandom[:]...)
	n := (macSize + keySize + ivSize) * 2
	var block []byte
	if d.resume.version == 0x0100 {
		block = ocDTLSLegacyPRF(d.master, "key expansion", seed, n)
	} else {
		block = ocDTLSPRF(d.newHash, d.master, "key expansion", seed, n)
	}
	defer clear(block)
	if cbc {
		d.cbcKeys(block, keySize, sha1.New)
		return nil
	}
	makeKey := func(key []byte) cipher.AEAD {
		if d.suite == 0xccab {
			a, _ := newChaChaAEAD(key, false)
			return a
		}
		b, _ := aes.NewCipher(key)
		a, _ := cipher.NewGCM(b)
		return a
	}
	d.writeKey, d.readKey = makeKey(block[:keySize]), makeKey(block[keySize:keySize*2])
	copy(d.writeIV[:ivSize], block[keySize*2:keySize*2+ivSize])
	copy(d.readIV[:ivSize], block[keySize*2+ivSize:])
	if !d.client {
		d.writeKey, d.readKey = d.readKey, d.writeKey
		d.writeIV, d.readIV = d.readIV, d.writeIV
	}
	return nil
}
func (d *ocDTLS) resumeHello(cookie []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, d.resume.version)
	b = append(b, d.clientRandom[:]...)
	b = append(append(b, 32), d.appID...)
	b = append(append(b, byte(len(cookie))), cookie...)
	b = binary.BigEndian.AppendUint16(b, 2)
	b = binary.BigEndian.AppendUint16(b, d.resume.suite)
	return ocDTLSAppendExtensions(append(b, 1, 0), false, false, []byte{})
}
func (d *ocDTLS) resumeCCS(data []byte) error {
	if d.resume.version == 0x0100 {
		if len(data) != 3 || data[0] != 1 {
			return errors.New("invalid DTLS0.9 cipher transition")
		}
		seq := binary.BigEndian.Uint16(data[1:])
		if d.earlyCCS || d.ccs {
			if seq != d.resume.ccsSeq {
				return errors.New("conflicting DTLS0.9 cipher transition")
			}
			return nil
		}
		if !(d.stage == 1 && seq == d.recvNext || d.stage == 0 && seq == d.recvNext+1) {
			return errors.New("invalid DTLS0.9 cipher sequence")
		}
		d.resume.ccsSeq = seq
	} else if !bytes.Equal(data, []byte{1}) {
		return errors.New("invalid DTLS cipher transition")
	}
	d.earlyCCS = true
	d.syncResumeCCS()
	return nil
}
func (d *ocDTLS) syncResumeCCS() {
	if !d.earlyCCS || d.readKey == nil && d.cbc == nil {
		return
	}
	if d.resume.version == 0x0100 && !d.ccs {
		if d.recvNext != d.resume.ccsSeq {
			return
		}
		d.recvNext++
	}
	d.ccs = true
}
func (d *ocDTLS) resumeMessage(kind byte, body, message []byte) error {
	bad := errors.New("unexpected DTLS resumption handshake")
	if d.client {
		switch {
		case kind == 3 && d.stage == 0 && d.sendNext == 1:
			if len(body) < 3 || len(body) != 3+int(body[2]) || body[2] == 0 {
				return bad
			}
			if d.resume.version != 0x0100 {
				d.transcript = nil
			} else {
				d.appendTranscript(message)
			}
			d.flight = nil
			if err := d.addHandshake(1, d.hello(body[3:]), true); err != nil {
				return err
			}
			return d.transmit()
		case kind == 2 && d.stage == 0:
			if len(body) < 70 || binary.BigEndian.Uint16(body) != d.resume.version || body[34] != 32 || !bytes.Equal(body[35:67], d.appID) || binary.BigEndian.Uint16(body[67:69]) != d.resume.suite || body[69] != 0 {
				return bad
			}
			ext, err := ocDTLSExtensions(body[70:])
			if err != nil {
				return err
			}
			if ext.ems || ext.etm || len(ext.renegotiation) != 0 {
				return bad
			}
			copy(d.serverRandom[:], body[2:34])
			d.appendTranscript(message)
			if err = d.keys(); err != nil {
				return err
			}
			d.stage = 1
			d.syncResumeCCS()
			return nil
		case kind == 20 && d.stage == 1 && d.ccs:
			if !hmac.Equal(body, d.finished(false)) {
				return errors.New("DTLS resumed server Finished authentication failed")
			}
			d.appendTranscript(message)
			d.flight = nil
			if err := d.changeCipher(); err != nil {
				return err
			}
			if err := d.addHandshake(20, d.finished(true), true); err != nil {
				return err
			}
			if err := d.transmit(); err != nil {
				return err
			}
			d.ready.Store(true)
			return nil
		}
	} else {
		switch {
		case kind == 1 && d.stage == 0:
			id, _, random, suites, ext, err := ocDTLSParseHello(body, d.resume.version)
			if err != nil || !bytes.Equal(id, d.appID) || !slices.Contains(suites, d.resume.suite) || len(ext.renegotiation) != 0 {
				return bad
			}
			copy(d.clientRandom[:], random)
			rand.Read(d.serverRandom[:])
			d.appendTranscript(message)
			hello := binary.BigEndian.AppendUint16(nil, d.resume.version)
			hello = append(hello, d.serverRandom[:]...)
			hello = append(append(hello, 32), d.appID...)
			hello = binary.BigEndian.AppendUint16(hello, d.resume.suite)
			hello = append(hello, 0)
			if ext.renegotiation != nil || slices.Contains(suites, 0x00ff) {
				hello = ocDTLSAppendExtensions(hello, false, false, []byte{})
			}
			d.flight = nil
			if err = d.addHandshake(2, hello, true); err != nil {
				return err
			}
			if err = d.keys(); err != nil {
				return err
			}
			d.stage = 1
			d.syncResumeCCS()
			if err = d.changeCipher(); err != nil {
				return err
			}
			if err = d.addHandshake(20, d.finished(false), true); err != nil {
				return err
			}
			return d.transmit()
		case kind == 20 && d.stage == 1 && d.ccs:
			if !hmac.Equal(body, d.finished(true)) {
				return errors.New("DTLS resumed client Finished authentication failed")
			}
			d.ready.Store(true)
			return nil
		}
	}
	return bad
}
