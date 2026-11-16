package native

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"slices"
	"strings"
)

var browserProfiles = []string{"chrome100", "chrome110", "chrome120", "chrome140", "chrome150", "firefox109", "firefox117", "firefox120", "firefox148", "random"}

func browserShuffle[T any](v []T) {
	for i := len(v) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			panic(err)
		}
		j := int(n.Int64())
		v[i], v[j] = v[j], v[i]
	}
}

func (h *stClientHello) initModernBrowser(name string) error {
	if !slices.Contains(browserProfiles, name) {
		return errors.New("unknown browser profile")
	}
	h.browser = name
	var entropy [5]byte
	rand.Read(entropy[:])
	for i, b := range entropy {
		v := uint16(b&15)*16 + 10
		h.grease[i] = v<<8 | v
	}
	if h.grease[0] == h.grease[1] {
		h.grease[1] ^= 0x1010
	}
	chrome := strings.HasPrefix(name, "chrome")
	h.groups = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384}
	h.suites = []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
	if chrome {
		h.suites = append([]uint16{h.grease[2]}, h.suites...)
		h.extensions = []uint16{0x0a0a, 0, 23, 0xff01, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 0x1a1a, 21}
		if name == "chrome120" {
			h.extensions = slices.Insert(h.extensions, 16, 0xfe0d)
		}
		if name == "chrome140" || name == "chrome150" {
			h.groups = append([]tls.CurveID{tls.X25519MLKEM768}, h.groups...)
			h.extensions = []uint16{0x0a0a, 0, 23, 0xff01, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17613, 0xfe0d, 0x1a1a}
			if name == "chrome150" {
				h.extensions = slices.Insert(h.extensions, 17, 51764)
			}
		}
		if name != "chrome100" {
			end := len(h.extensions) - 1
			if h.extensions[end] == 21 {
				end--
			}
			browserShuffle(h.extensions[1:end])
		}
	} else {
		h.suites = []uint16{0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035}
		h.groups = append(h.groups, tls.CurveP521, tls.CurveID(256), tls.CurveID(257))
		h.extensions = []uint16{0, 23, 0xff01, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28, 21}
		if name == "firefox120" || name == "random" {
			h.extensions[len(h.extensions)-1] = 0xfe0d
		}
		if name == "firefox148" {
			h.groups = append([]tls.CurveID{tls.X25519MLKEM768}, h.groups...)
			h.extensions = []uint16{0, 23, 0xff01, 10, 11, 35, 16, 5, 34, 18, 51, 43, 13, 45, 28, 27, 0xfe0d}
		}
		if name == "random" {
			h.groups = append([]tls.CurveID{tls.X25519MLKEM768}, h.groups...)
			browserShuffle(h.suites)
			browserShuffle(h.extensions)
		}
	}
	if err := h.share(h.groups[0]); err != nil {
		return err
	}
	if !chrome {
		if h.kem != nil {
			h.fallback = h.key
		}
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		h.additional = map[tls.CurveID]*ecdh.PrivateKey{tls.CurveP256: key}
	}
	if slices.Contains(h.extensions, 0xfe0d) {
		payload := 239
		if chrome {
			payload = 144 + int(entropy[0]&3)*32
		}
		h.echGrease = append([]byte{0, 0, 1, 0, 1, entropy[1]}, stVector(make([]byte, 32), 2)...)
		h.echGrease = append(h.echGrease, stVector(make([]byte, payload), 2)...)
		rand.Read(h.echGrease[8:40])
		rand.Read(h.echGrease[42:])
	}
	return nil
}

func (h *stClientHello) hasShare(group tls.CurveID) bool {
	return group == h.group || group == tls.X25519 && h.kem != nil && slices.Contains(h.groups, group) || h.additional[group] != nil
}

func (h *stClientHello) modernBrowserHello(cookie []byte) ([]byte, error) {
	chrome := strings.HasPrefix(h.browser, "chrome")
	var ext []byte
	retry := len(h.serverHello) >= 38 && bytes.Equal(h.serverHello[6:38], stRetryRandom)
	for _, id := range h.extensions {
		var value []byte
		switch id {
		case 0x0a0a:
			id = h.grease[0]
		case 0x1a1a:
			id = h.grease[1]
			value = []byte{0}
		case 0:
			name := strings.TrimSuffix(h.config.ServerName, ".")
			if name == "" || net.ParseIP(name) != nil {
				continue
			}
			value = stVector(append([]byte{0}, stVector([]byte(name), 2)...), 2)
		case 10:
			var groups []byte
			if chrome {
				groups = browserWords(h.grease[3])
			}
			for _, g := range h.groups {
				groups = append(groups, browserWords(uint16(g))...)
			}
			value = stVector(groups, 2)
		case 11:
			value = []byte{1, 0}
		case 0xff01:
			value = []byte{0}
		case 16:
			if len(h.config.NextProtos) == 0 {
				continue
			}
			var list []byte
			for _, p := range h.config.NextProtos {
				if len(p) == 0 || len(p) > 255 {
					return nil, errors.New("invalid browser ALPN")
				}
				list = append(list, stVector([]byte(p), 1)...)
			}
			value = stVector(list, 2)
		case 5:
			value = []byte{1, 0, 0, 0, 0}
		case 13:
			value = stVector(browserWords(browserSignatures(h.browser)...), 2)
		case 34:
			value = stVector(browserWords(0x0403, 0x0503, 0x0603, 0x0203), 2)
		case 51:
			var shares []byte
			if chrome && !retry {
				shares = append(browserWords(h.grease[3]), 0, 1, 0)
			}
			var public []byte
			if h.ffdhe != nil {
				public = h.ffdhe.public
			} else {
				public = h.key.PublicKey().Bytes()
			}
			if h.kem != nil {
				public = append(h.kem.EncapsulationKey().Bytes(), public...)
			}
			shares = append(shares, browserWords(uint16(h.group))...)
			shares = append(shares, stVector(public, 2)...)
			if h.kem != nil && !retry {
				shares = append(shares, browserWords(uint16(tls.X25519))...)
				shares = append(shares, stVector(h.fallback.PublicKey().Bytes(), 2)...)
			}
			if key := h.additional[tls.CurveP256]; key != nil && !retry {
				shares = append(shares, browserWords(uint16(tls.CurveP256))...)
				shares = append(shares, stVector(key.PublicKey().Bytes(), 2)...)
			}
			value = stVector(shares, 2)
		case 43:
			var versions []byte
			if chrome {
				versions = browserWords(h.grease[4])
			}
			for _, v := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
				if (h.config.MinVersion == 0 || v >= h.config.MinVersion) && (h.config.MaxVersion == 0 || v <= h.config.MaxVersion) {
					versions = append(versions, browserWords(v)...)
				}
			}
			value = stVector(versions, 1)
		case 45:
			value = []byte{1, 1}
		case 27:
			value = []byte{2, 0, 2}
			if !chrome {
				value = []byte{6, 0, 1, 0, 2, 0, 3}
			}
		case 28:
			value = browserWords(16385)
		case 17513, 17613:
			if !slices.Contains(h.config.NextProtos, "h2") {
				continue
			}
			value = []byte{0, 3, 2, 'h', '2'}
		case 51764:
			value = []byte{0, 0}
		case 0xfe0d:
			value = h.echGrease
		case 21:
			continue
		}
		ext = stExtension(ext, id, value)
	}
	if cookie != nil {
		ext = stExtension(ext, 44, cookie)
	}
	body := append([]byte{3, 3}, h.random...)
	body = append(body, stVector(h.session, 1)...)
	body = append(body, stVector(browserWords(h.suites...), 2)...)
	body = append(body, 1, 0)
	if slices.Contains(h.extensions, 21) {
		n := 4 + len(body) + 2 + len(ext)
		if n > 255 && n < 512 {
			ext = stExtension(ext, 21, make([]byte, max(1, 512-n-4)))
		}
	}
	return stMessage(1, append(body, stVector(ext, 2)...)), nil
}

func browserCompressionOffered(profile string, algorithm uint16) bool {
	if strings.HasPrefix(profile, "chrome") {
		return algorithm == 2
	}
	if profile == "firefox148" {
		return algorithm >= 1 && algorithm <= 3
	}
	return algorithm == 1 && strings.HasPrefix(profile, "safari") && profile != "safari15_3"
}

func browserRecordLimit(value []byte, tls13 bool) (int, error) {
	if len(value) != 2 {
		return 0, errors.New("invalid TLS record size limit")
	}
	n := int(binary.BigEndian.Uint16(value))
	upper := 16384
	if tls13 {
		upper++
	}
	if n < 64 || n > upper {
		return 0, errors.New("invalid TLS record size limit")
	}
	if tls13 {
		n--
	}
	return n, nil
}
