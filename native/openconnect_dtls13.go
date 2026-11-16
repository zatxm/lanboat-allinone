package native

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"slices"
	"time"
)

func (l *ocDTLSListener) dtls13CookieMAC(from net.Addr, id, random, claims []byte) []byte {
	mac := hmac.New(sha256.New, l.secret[:])
	mac.Write([]byte(from.String()))
	mac.Write(id)
	mac.Write(random)
	mac.Write(claims)
	return mac.Sum(nil)[:16]
}

// Verify the source before allocating peer state or doing ECDHE. The cookie
// carries the authenticated first-ClientHello hash for the stateless HRR transcript.
func (l *ocDTLSListener) accept13(wire []byte, from net.Addr) ([]byte, *dtls13) {
	h, err := parseDTLS13Hello(wire[25:])
	if err != nil {
		return nil, nil
	}
	var id, identity []byte
	var suite stCipherSuite
	for _, cipherID := range l.suites {
		if !slices.Contains(h.suites, cipherID) {
			continue
		}
		candidate, _ := stSuite(cipherID)
		for _, psk := range h.identities {
			decoded, e := hex.DecodeString(string(psk.identity))
			if e != nil || len(decoded) < 16 || len(decoded) > 32 || len(psk.binder) != candidate.hash.Size() {
				continue
			}
			l.mu.Lock()
			known := l.bindings[string(decoded)] != nil
			l.mu.Unlock()
			if known {
				id, identity, suite = decoded, psk.identity, candidate
				break
			}
		}
		if id != nil {
			break
		}
	}
	if id == nil {
		return nil, nil
	}
	cookie := h.cookie
	now := time.Now().Unix()
	seq := binary.BigEndian.Uint16(wire[17:19])
	if len(cookie) == 0 {
		if seq != 0 {
			return nil, nil
		}
		cookie = binary.BigEndian.AppendUint64(nil, uint64(now))
		cookie = binary.BigEndian.AppendUint16(cookie, suite.id)
		cookie = append(cookie, dtls13Hash(suite, stMessage(1, wire[25:]))...)
		cookie = append(cookie, h.invariant[:]...)
		cookie = append(cookie, l.dtls13CookieMAC(from, id, h.random, cookie)...)
		body := dtls13ServerHello(stRetryRandom, h.session, suite.id, nil, 0, 0, cookie)
		msg := ocDTLSHandshakeMessage(2, 0, body)
		_, _ = l.packet.WriteTo(append(ocDTLSRecordHeader(22, 0, 0, len(msg)), msg...), from)
		return nil, nil
	}
	if seq != 1 || len(cookie) != 10+suite.hash.Size()+32+16 || binary.BigEndian.Uint16(cookie[8:]) != suite.id {
		return nil, nil
	}
	if !hmac.Equal(h.invariant[:], cookie[10+suite.hash.Size():len(cookie)-16]) {
		return nil, nil
	}
	created := int64(binary.BigEndian.Uint64(cookie))
	if created > now || now-created > 120 || !hmac.Equal(cookie[len(cookie)-16:], l.dtls13CookieMAC(from, id, h.random, cookie[:len(cookie)-16])) {
		return nil, nil
	}
	retry := dtls13ServerHello(stRetryRandom, h.session, suite.id, nil, 0, 0, cookie)
	transcript := append(stMessage(254, cookie[10:10+suite.hash.Size()]), stMessage(2, retry)...)
	return bytes.Clone(id), &dtls13{identity: bytes.Clone(identity), suite: suite, transcript: transcript, retried: true, sendNext: 1, recvNext: 1, plainSequence: 1}
}
