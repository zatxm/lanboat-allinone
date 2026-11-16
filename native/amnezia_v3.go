package native

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

type wgV3 struct {
	key                                                             *[32]byte
	addition, rekey, retry, reject, keepalive, attempts, persistent wgMagic
	trailers, disableCookies                                        bool
}

func wgOptionRange(name string, raw WGHeaderRange, maximum uint32) (wgMagic, error) {
	if raw == "" || raw == "(off)" {
		return wgMagic{}, nil
	}
	r, err := parseWGMagic(raw, 0)
	if err != nil || r.high > maximum || r.low == 0 && r.high != 0 {
		return wgMagic{}, fmt.Errorf("invalid AmneziaWG %s range (maximum%d)", name, maximum)
	}
	return r, nil
}
func (r wgMagic) pick(fallback uint32) uint32 {
	if r.high == 0 {
		return fallback
	}
	return wgRandomRange(r.low, r.high)
}
func (v *wgV3) configure(o *AmneziaWGOptions, prefix [4]int, mtu int) error {
	if o.HeaderProtectionKey != "" {
		key, err := wgKey(o.HeaderProtectionKey)
		if err != nil {
			return fmt.Errorf("AmneziaWG header_protection_key: %w", err)
		}
		for _, n := range prefix {
			if n < 12 {
				return errors.New("AmneziaWG header protection requires s1-s4>=12")
			}
		}
		v.key = new([32]byte)
		copy(v.key[:], key)
	}
	for _, item := range []struct {
		name  string
		raw   WGHeaderRange
		limit uint32
		dst   *wgMagic
	}{
		{"content_padding_addition", o.ContentPaddingAddition, 65507, &v.addition},
		{"rekey_after_time", o.RekeyAfterTime, 86400, &v.rekey},
		{"rekey_timeout", o.RekeyTimeout, 86400, &v.retry},
		{"reject_after_time", o.RejectAfterTime, 86400, &v.reject},
		{"keepalive_timeout", o.KeepaliveTimeout, 86400, &v.keepalive},
		{"max_handshake_attempts", o.MaxHandshakeAttempts, 1024, &v.attempts},
		{"persistent_keepalive_interval", o.PersistentKeepalive, 65535, &v.persistent},
	} {
		r, err := wgOptionRange(item.name, item.raw, item.limit)
		if err != nil {
			return err
		}
		*item.dst = r
	}
	if mtu+32+prefix[3]+int(v.addition.high) > 65507 {
		return errors.New("AmneziaWG MTU plus content padding exceeds UDP capacity")
	}
	rekeyMax, rejectMin := v.rekey.high, v.reject.low
	if rekeyMax == 0 {
		rekeyMax = 120
	}
	if rejectMin == 0 {
		rejectMin = 180
	}
	if rekeyMax >= rejectMin {
		return errors.New("AmneziaWG rekey_after_time must precede reject_after_time")
	}
	v.trailers, v.disableCookies = o.RandomTrailers, o.DisableCookies
	return nil
}

// Header protection starts ChaCha20 at block zero; AEAD payload encryption starts at one.
func wgHeaderXOR(body []byte, key *[32]byte, nonce []byte) {
	for counter := uint32(0); len(body) > 0; counter++ {
		block := chachaBlock(key, nonce, counter)
		n := min(len(body), len(block))
		for i := range n {
			body[i] ^= block[i]
		}
		body = body[n:]
	}
}
func (p *wgPeer) v3() wgV3 {
	if p.obfs != nil {
		return p.obfs.v3
	}
	return wgV3{}
}
func (p *wgPeer) transportTimers(t *wgTransport) {
	v := p.v3()
	t.rekeyAfter = time.Duration(v.rekey.pick(120)) * time.Second
	t.rejectAfter = time.Duration(v.reject.pick(180)) * time.Second
}
func (p *wgPeer) traversalLocked(now time.Time) {
	v := p.v3()
	interval := v.persistent.pick(uint32(p.keepalive / time.Second))
	if interval > 0 {
		p.nextKeepalive = now.Add(time.Duration(interval) * time.Second)
	}
}
func (p *wgPeer) contentPadding(size int) int {
	v := p.v3()
	window := max(500, p.udpWindow)
	space := max(0, min(window, 65507)-size)
	if v.addition.high != 0 {
		return min(space, int(v.addition.pick(0)))
	}
	if v.trailers {
		if space == 0 {
			return 0
		}
		return int(wgRandomRange(0, uint32(space-1)))
	}
	return -1
}

// Under load, cookies validate return reachability before another expensive Noise exchange.
func (l *wgListener) allowInitiation(b []byte, remote net.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.After(l.until) {
		l.tokens, l.cookieTokens, l.until = 20, 20, now.Add(time.Second)
	}
	if l.tokens > 0 {
		l.tokens--
		return true
	}
	if l.obfs != nil && l.obfs.v3.disableCookies || len(b) != 148 || l.cookieTokens == 0 {
		return false
	}
	if subtle.ConstantTimeCompare(wgMAC1(b[:116], l.private.PublicKey().Bytes()), b[116:132]) != 1 {
		return false
	}
	if now.Sub(l.cookieAt) > 120*time.Second {
		rand.Read(l.cookieSecret[:])
		l.cookieAt = now
	}
	address, ok := remote.(*net.UDPAddr)
	if !ok {
		return false
	}
	source := append([]byte(nil), address.IP.To4()...)
	if source == nil {
		source = append(source, address.IP.To16()...)
	}
	source = binary.BigEndian.AppendUint16(source, uint16(address.Port))
	cookie := blake2s(source, l.cookieSecret[:], 16)
	if subtle.ConstantTimeCompare(blake2s(b[:132], cookie, 16), b[132:]) == 1 {
		l.cookieTokens--
		return true
	}
	l.cookieTokens--
	reply := binary.LittleEndian.AppendUint32(nil, l.obfs.header(3))
	reply = append(reply, b[4:8]...)
	nonce := make([]byte, 24)
	rand.Read(nonce)
	reply = append(reply, nonce...)
	key := blake2s(append([]byte("cookie--"), l.private.PublicKey().Bytes()...), nil, 32)
	a, _ := newChaChaAEAD(key, true)
	reply = a.Seal(reply, nonce, cookie, b[116:132])
	l.writePacket(l.obfs.wrap(3, reply), remote)
	return false
}
