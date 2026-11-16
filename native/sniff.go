package native

import (
	"bytes"
	"encoding/binary"
	"net"
	"slices"
	"strings"
)

func sniffPacket(network string, b []byte, enabled []string) (protocol, domain string) {
	protocol, domain, _ = sniffPacketInfo(network, b, enabled)
	return
}
func sniffPacketInfo(network string, b []byte, enabled []string) (protocol, domain, client string) {
	allow := func(p string) bool { return len(enabled) == 0 || slices.Contains(enabled, p) }
	if len(b) == 0 {
		return
	}
	b = b[:min(len(b), sniffLimit)]
	if network == "tcp" {
		if allow("http") {
			line, headers, ok := bytes.Cut(b, []byte("\r\n"))
			parts := strings.Fields(string(line))
			if ok && bytes.Contains(b, []byte("\r\n\r\n")) && len(parts) == 3 && strings.HasPrefix(parts[2], "HTTP/") {
				for len(headers) > 0 {
					h, rest, _ := bytes.Cut(headers, []byte("\r\n"))
					if len(h) == 0 {
						break
					}
					headers = rest
					key, value, ok := bytes.Cut(h, []byte(":"))
					if ok && bytes.EqualFold(key, []byte("host")) {
						domain = string(bytes.TrimSpace(value))
						if host, _, e := net.SplitHostPort(domain); e == nil {
							domain = host
						}
						break
					}
				}
				return "http", canonicalDomain(domain), ""
			}
		}
		if allow("tls") {
			if name, ok, _ := sniffTLS(b); ok {
				return "tls", name, ""
			}
		}
		if allow("ssh") {
			if name, ok, _ := sniffSSH(b); ok {
				return "ssh", "", name
			}
		}
		if allow("rdp") && len(b) >= 7 && b[0] == 3 && b[1] == 0 && b[5] == 0xe0 {
			return "rdp", "", ""
		}
		if allow("bittorrent") && bytes.HasPrefix(b, []byte("\x13BitTorrent protocol")) {
			return "bittorrent", "", ""
		}
		if allow("dns") && len(b) > 14 && int(binary.BigEndian.Uint16(b)) <= len(b)-2 {
			if h, _, _, e := dnsQuestion(b[2:]); e == nil {
				return "dns", h, ""
			}
		}
	} else {
		if allow("dns") {
			if h, _, _, e := dnsQuestion(b); e == nil {
				return "dns", h, ""
			}
		}
		if allow("stun") && len(b) >= 20 && b[0]&0xc0 == 0 && binary.BigEndian.Uint32(b[4:8]) == 0x2112a442 {
			return "stun", "", ""
		}
		if allow("ntp") && len(b) >= 48 && (b[0]&7 == 3 || b[0]&7 == 4) && b[0]>>3&7 >= 2 && b[0]>>3&7 <= 4 {
			return "ntp", "", ""
		}
		if allow("dtls") && len(b) >= 13 && b[0] >= 20 && b[0] <= 23 && b[1] == 0xfe {
			return "dtls", "", ""
		}
		if allow("quic") {
			host, client, ok, more := sniffQUICInfo(b)
			if ok || more {
				return "quic", host, client
			}
		}
	}
	return
}
func sniffClientHello(b []byte) (string, bool) {
	host, _, ok := clientHelloSNI(b)
	return host, ok
}

const sniffLimit = 64 << 10

// Only recognizable incomplete handshakes wait; opaque and server-first traffic passes through.
func sniffNeedsMore(network string, b []byte, enabled []string) bool {
	if network != "tcp" && network != "udp" || len(b) == 0 || len(b) >= sniffLimit {
		return false
	}
	allow := func(p string) bool { return len(enabled) == 0 || slices.Contains(enabled, p) }
	if network == "udp" {
		if allow("quic") {
			_, _, more := sniffQUICData(b)
			return more
		}
		return false
	}
	if allow("tls") {
		if _, _, more := sniffTLS(b); more {
			return true
		}
	}
	if allow("ssh") {
		if _, _, more := sniffSSH(b); more {
			return true
		}
	}
	if allow("http") && !bytes.Contains(b, []byte("\r\n\r\n")) {
		for _, method := range []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "} {
			if bytes.HasPrefix(b, []byte(method)) || bytes.HasPrefix([]byte(method), b) {
				return true
			}
		}
	}
	return false
}

func sniffSSH(b []byte) (client string, complete, more bool) {
	if len(b) < 4 {
		return "", false, len(b) > 0 && bytes.HasPrefix([]byte("SSH-"), b)
	}
	if !bytes.HasPrefix(b, []byte("SSH-")) {
		return "", false, false
	}
	end := bytes.IndexByte(b, '\n')
	if end < 0 {
		if len(b) >= 255 {
			return "", false, false
		}
		end = len(b)
		more = true
	} else if end >= 255 {
		return "", false, false
	}
	line := bytes.TrimSuffix(b[:end], []byte{'\r'})
	for _, c := range line {
		if c < 32 || c >= 127 {
			return "", false, false
		}
	}
	if more {
		return "", false, true
	}
	version, name, ok := bytes.Cut(line[4:], []byte{'-'})
	if !ok || !bytes.Equal(version, []byte("2.0")) && !bytes.Equal(version, []byte("1.99")) {
		return "", false, false
	}
	software, _, _ := bytes.Cut(name, []byte{' '})
	if len(software) == 0 || bytes.IndexByte(software, '-') >= 0 {
		return "", false, false
	}
	// Keep the full advertised name, including comments, for compatible client rules.
	return string(bytes.TrimSpace(name)), true, false
}

func sniffTLS(b []byte) (host string, complete, more bool) {
	var hello []byte
	for records := 0; len(b) > 0 && records < 128; records++ {
		if b[0] != 22 || len(b) > 1 && b[1] != 3 || len(b) > 2 && b[2] > 4 {
			return "", false, false
		}
		if len(b) < 5 {
			return "", false, true
		}
		n := int(binary.BigEndian.Uint16(b[3:5]))
		if n == 0 || n > 16384 || len(hello)+n > sniffLimit {
			return "", false, false
		}
		if len(b) < 5+n {
			return "", false, true
		}
		part := b[5 : 5+n]
		if hello == nil && len(part) >= 4 && 4+(int(part[1])<<16|int(part[2])<<8|int(part[3])) <= len(part) {
			host, complete = sniffClientHello(part)
			return
		}
		hello = append(hello, part...)
		if len(hello) > 0 && hello[0] != 1 {
			return "", false, false
		}
		if len(hello) >= 4 {
			want := 4 + (int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3]))
			if want > sniffLimit {
				return "", false, false
			}
			if len(hello) >= want {
				host, complete = sniffClientHello(hello)
				return
			}
		}
		b = b[5+n:]
	}
	return "", false, len(b) == 0 && len(hello) > 0
}
func clientHelloSNI(b []byte) (string, int, bool) {
	if len(b) < 4 || b[0] != 1 {
		return "", 0, false
	}
	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length > len(b)-4 {
		return "", 0, false
	}
	b = b[4 : 4+length]
	take := func(n int) bool {
		if n > len(b) {
			return false
		}
		b = b[n:]
		return true
	}
	if !take(34) || len(b) < 1 {
		return "", 0, false
	}
	n := int(b[0])
	if !take(1+n) || len(b) < 2 {
		return "", 0, false
	}
	n = int(binary.BigEndian.Uint16(b))
	if !take(2+n) || len(b) < 1 {
		return "", 0, false
	}
	n = int(b[0])
	if !take(1 + n) {
		return "", 0, false
	}
	if len(b) == 0 {
		return "", 0, true
	}
	if len(b) < 2 {
		return "", 0, false
	}
	n = int(binary.BigEndian.Uint16(b))
	if n > len(b)-2 {
		return "", 0, false
	}
	b = b[2 : 2+n]
	for len(b) >= 4 {
		kind, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		b = b[4:]
		if n > len(b) {
			return "", 0, false
		}
		v := b[:n]
		b = b[n:]
		if kind != 0 {
			continue
		}
		if len(v) < 2 || int(binary.BigEndian.Uint16(v)) != len(v)-2 {
			return "", 0, false
		}
		v = v[2:]
		for len(v) >= 3 {
			kind, n := v[0], int(binary.BigEndian.Uint16(v[1:]))
			v = v[3:]
			if n > len(v) {
				return "", 0, false
			}
			if kind == 0 {
				host := string(v[:n])
				if strings.ContainsAny(host, "\x00 /\r\n") {
					return "", 0, false
				}
				return canonicalDomain(host), 4 + length - len(b) - len(v), true
			}
			v = v[n:]
		}
	}
	return "", 0, true
}
func sniffQUICData(b []byte) (string, bool, bool) {
	host, _, ok, more := sniffQUICInfo(b)
	return host, ok, more
}
func sniffQUICInfo(b []byte) (string, string, bool, bool) {
	if len(b) < 5 || len(b) > sniffLimit {
		return "", "", false, false
	}
	var crypto quicBuffer
	var dcid []byte
	var key *quicKey
	version := binary.BigEndian.Uint32(b[1:5])
	largest := int64(-1)
	var style quicClientFrames
	var seen [32]uint64
	seenCount := 0
	for packets := 0; len(b) > 0; packets++ {
		if packets >= 32 {
			return "", "", false, false
		}
		if len(b) >= 5 && b[0]&0x80 != 0 && binary.BigEndian.Uint32(b[1:5]) != version {
			return "", "", false, false
		}
		h, err := parseQUICHeaderVersion(b, version)
		if err != nil || !h.boolLong || h.retry {
			if packets > 0 {
				break
			}
			return "", "", false, false
		}
		if h.level != 0 {
			if key == nil || !bytes.Equal(dcid, h.dcid) {
				return "", "", false, false
			}
			b = bytes.TrimLeft(b[h.end:], "\x00")
			continue
		}
		if key == nil {
			dcid = h.dcid
			key, _, err = quicInitialKeysVersion(dcid, true, version)
			if err != nil {
				return "", "", false, false
			}
		} else if !bytes.Equal(dcid, h.dcid) {
			return "", "", false, false
		}
		plain, pn, _, err := openQUICPacket(b, h, key, largest)
		if err != nil {
			return "", "", false, false
		}
		largest = max(largest, int64(pn))
		duplicate := slices.Contains(seen[:seenCount], pn)
		if !duplicate {
			seen[seenCount] = pn
			seenCount++
		}
		var packetStyle quicClientFrames
		r := quicReader(plain)
		for len(r) > 0 {
			kind, err := r.v()
			if err != nil {
				return "", "", false, false
			}
			packetStyle.add(kind)
			switch kind {
			case 0, 1:
			case 2, 3:
				if !sniffQUICACK(&r, kind == 3) {
					return "", "", false, false
				}
			case 6:
				off, err := r.v()
				if err != nil {
					return "", "", false, false
				}
				n, err := r.v()
				if err != nil || off > sniffLimit || n > sniffLimit-off {
					return "", "", false, false
				}
				data, err := r.take(n)
				if err != nil || crypto.put(off, data) != nil {
					return "", "", false, false
				}
			case 28:
				return "", "", true, false
			default:
				return "", "", false, false
			}
		}
		if !duplicate {
			style.merge(packetStyle)
		}
		b = bytes.TrimLeft(b[h.end:], "\x00")
	}
	hello, more := sniffQUICHello(crypto)
	if hello == nil {
		return "", "", false, more
	}
	host, ok := sniffClientHello(hello)
	if !ok {
		return "", "", false, false
	}
	return host, classifyQUICClient(style, hello), true, false
}

func sniffQUICACK(r *quicReader, ecn bool) bool {
	largest, err := r.v()
	if err != nil {
		return false
	}
	if _, err = r.v(); err != nil {
		return false
	}
	count, err := r.v()
	if err != nil || count > 256 {
		return false
	}
	first, err := r.v()
	if err != nil || first > largest {
		return false
	}
	low := largest - first
	for range count {
		gap, err := r.v()
		if err != nil || gap+2 > low {
			return false
		}
		high := low - gap - 2
		n, err := r.v()
		if err != nil || n > high {
			return false
		}
		low = high - n
	}
	if ecn {
		for range 3 {
			if _, err := r.v(); err != nil {
				return false
			}
		}
	}
	return true
}
