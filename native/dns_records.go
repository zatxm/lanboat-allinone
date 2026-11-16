package native

import (
	"encoding/binary"
	"errors"
	"strings"
)

type dnsRecord struct {
	name      string
	typ       uint16
	class     uint16
	ttl       uint32
	data      []byte
	ttlOffset int
}

var dnsTypeNames = map[string]uint16{
	"A": 1, "NS": 2, "MD": 3, "MF": 4, "CNAME": 5, "SOA": 6, "MB": 7, "MG": 8, "MR": 9,
	"NULL": 10, "WKS": 11, "PTR": 12, "HINFO": 13, "MINFO": 14, "MX": 15, "TXT": 16, "RP": 17,
	"AFSDB": 18, "X25": 19, "ISDN": 20, "RT": 21, "SIG": 24, "KEY": 25, "PX": 26, "AAAA": 28,
	"LOC": 29, "SRV": 33, "NAPTR": 35, "KX": 36, "CERT": 37, "DNAME": 39, "OPT": 41,
	"DS": 43, "SSHFP": 44, "IPSECKEY": 45, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48,
	"DHCID": 49, "NSEC3": 50, "NSEC3PARAM": 51, "TLSA": 52, "SMIMEA": 53,
	"CDS": 59, "CDNSKEY": 60, "OPENPGPKEY": 61, "CSYNC": 62, "ZONEMD": 63, "SVCB": 64, "HTTPS": 65,
	"SPF": 99, "LP": 107, "EUI48": 108, "EUI64": 109, "URI": 256, "CAA": 257, "DLV": 32769,
}
var dnsRCodes = map[string]byte{"": 0, "NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "NOTIMP": 4, "REFUSED": 5}

func dnsAppendName(b []byte, name string) ([]byte, error) {
	if strings.Contains(name, `\`) {
		return dnsAppendEscapedName(b, name)
	}
	if name == "." || name == "" {
		return append(b, 0), nil
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return nil, errors.New("DNS name too long")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, errors.New("invalid DNS label")
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}
func dnsRecords(b []byte) ([3][]dnsRecord, error) {
	var sections [3][]dnsRecord
	if len(b) < 12 {
		return sections, errors.New("short DNS message")
	}
	pos := 12
	for range int(binary.BigEndian.Uint16(b[4:6])) {
		_, end, e := dnsName(b, pos)
		if e != nil || end+4 > len(b) {
			return sections, errors.New("invalid DNS question")
		}
		pos = end + 4
	}
	for section := range 3 {
		n := int(binary.BigEndian.Uint16(b[6+2*section:]))
		if n > 4096 {
			return sections, errors.New("too many DNS RRs")
		}
		for range n {
			name, end, e := dnsName(b, pos)
			if e != nil || end+10 > len(b) {
				return sections, errors.New("invalid DNS RR")
			}
			typ := binary.BigEndian.Uint16(b[end:])
			length := int(binary.BigEndian.Uint16(b[end+8:]))
			dataStart := end + 10
			pos = dataStart + length
			if pos > len(b) {
				return sections, errors.New("truncated DNS RR")
			}
			data := append([]byte(nil), b[dataStart:pos]...)
			// Expand names before comparing records from different compression layouts.
			prefix, count, tail := 0, 0, 0
			switch typ {
			case 2, 3, 4, 5, 7, 8, 9, 12, 39:
				count = 1
			case 15, 18, 21, 36, 107:
				prefix, count = 2, 1
			case 33:
				prefix, count = 6, 1
			case 6:
				count, tail = 2, 20
			case 14, 17:
				count = 2
			case 26:
				prefix, count = 2, 2
			case 24, 46:
				prefix, count, tail = 18, 1, -1
			case 47:
				count, tail = 1, -1
			case 35:
				prefix = 4
				for range 3 {
					if prefix >= len(data) {
						return sections, errors.New("short NAPTR string")
					}
					prefix += 1 + int(data[prefix])
				}
				count = 1
			}
			if count > 0 {
				if prefix > len(data) {
					return sections, errors.New("short name RR")
				}
				data = data[:prefix:prefix]
				off := dataStart + prefix
				for range count {
					host, next, err := dnsName(b, off)
					if err != nil || next > pos {
						return sections, errors.New("invalid RR name boundary")
					}
					data, e = dnsAppendName(data, host)
					off = next
				}
				if tail >= 0 && off+tail != pos {
					return sections, errors.New("invalid name RR length")
				}
				data = append(data, b[off:pos]...)
			}
			if e != nil {
				return sections, e
			}
			sections[section] = append(sections[section], dnsRecord{name: name, typ: typ, class: binary.BigEndian.Uint16(b[end+2:]), ttl: binary.BigEndian.Uint32(b[end+4:]), data: data, ttlOffset: end + 4})
		}
	}
	if pos != len(b) {
		return sections, errors.New("trailing DNS data")
	}
	return sections, nil
}
func predefinedDNS(query []byte, o DNSRule) ([]byte, error) {
	_, end, _, e := dnsQuestion(query)
	if e != nil {
		return nil, e
	}
	code, ok := dnsRCodes[strings.ToUpper(o.RCode)]
	if !ok {
		return nil, errors.New("unknown DNS rcode")
	}
	out := dnsResponse(query, end, nil, 0, code)
	for section, items := range [][]string{o.Answer, o.NS, o.Extra} {
		if len(items) > 4096 {
			return nil, errors.New("too many DNS RRs in one section")
		}
		for _, text := range items {
			rr, e := parseTextRecord(text)
			if e != nil {
				return nil, e
			}
			out, e = dnsAppendName(out, rr.name)
			if e != nil {
				return nil, e
			}
			if len(out)+10+len(rr.data) > 65535 {
				return nil, errors.New("DNS response too large")
			}
			out = binary.BigEndian.AppendUint16(out, rr.typ)
			out = binary.BigEndian.AppendUint16(out, rr.class)
			out = binary.BigEndian.AppendUint32(out, rr.ttl)
			out = binary.BigEndian.AppendUint16(out, uint16(len(rr.data)))
			out = append(out, rr.data...)
		}
		binary.BigEndian.PutUint16(out[6+section*2:], uint16(len(items)))
	}
	return out, nil
}
