package native

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

var svcbKeys = map[string]uint16{"mandatory": 0, "alpn": 1, "no-default-alpn": 2, "port": 3, "ipv4hint": 4, "ech": 5, "ipv6hint": 6, "dohpath": 7, "ohttp": 8}

func svcbKey(name string) (uint16, error) {
	if n, ok := svcbKeys[name]; ok {
		return n, nil
	}
	if strings.HasPrefix(name, "key") {
		n, err := strconv.ParseUint(name[3:], 10, 16)
		return uint16(n), err
	}
	return 0, errors.New("unknown SVCB parameter key")
}

func svcbUnescape(value string) (string, error) {
	var b []byte
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			if value[i] == '"' {
				return "", errors.New("unescaped SVCB quote")
			}
			b = append(b, value[i])
			continue
		}
		i++
		if i == len(value) {
			return "", errors.New("trailing SVCB escape")
		}
		if value[i] >= '0' && value[i] <= '9' {
			if i+3 > len(value) {
				return "", errors.New("short SVCB decimal escape")
			}
			n, err := strconv.ParseUint(value[i:i+3], 10, 8)
			if err != nil {
				return "", errors.New("invalid SVCB decimal escape")
			}
			b = append(b, byte(n))
			i += 2
		} else {
			b = append(b, value[i])
		}
	}
	return string(b), nil
}

func svcbList(value string) ([]string, error) {
	var list []string
	var item []byte
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			if i == len(value) || (value[i] != ',' && value[i] != '\\') {
				return nil, errors.New("invalid SVCB list escape")
			}
			item = append(item, value[i])
		} else if value[i] == ',' {
			list = append(list, string(item))
			item = item[:0]
		} else {
			item = append(item, value[i])
		}
	}
	list = append(list, string(item))
	return list, nil
}

func validateSVCBParams(params map[uint16][]byte) error {
	for key, b := range params {
		switch key {
		case 0:
			if len(b) == 0 || len(b)%2 != 0 {
				return errors.New("invalid mandatory SVCB value")
			}
			last := uint16(0)
			for len(b) > 0 {
				id := binary.BigEndian.Uint16(b)
				b = b[2:]
				_, present := params[id]
				if id <= last || !present {
					return errors.New("invalid mandatory SVCB list")
				}
				last = id
			}
		case 1:
			if len(b) == 0 {
				return errors.New("empty SVCB ALPN")
			}
			for len(b) > 0 {
				n := int(b[0])
				if n == 0 || n+1 > len(b) {
					return errors.New("invalid SVCB ALPN wire value")
				}
				b = b[n+1:]
			}
		case 2, 8:
			if len(b) != 0 {
				return errors.New("invalid SVCB flag")
			}
		case 3:
			if len(b) != 2 {
				return errors.New("invalid SVCB port")
			}
		case 4:
			if len(b) == 0 || len(b)%4 != 0 {
				return errors.New("invalid SVCB IPv4 hints")
			}
		case 5:
			if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
				return errors.New("invalid SVCB ECH list length")
			}
		case 6:
			if len(b) == 0 || len(b)%16 != 0 {
				return errors.New("invalid SVCB IPv6 hints")
			}
		}
	}
	if _, flag := params[2]; flag && len(params[1]) == 0 {
		return errors.New("no-default-alpn requires alpn")
	}
	return nil
}

func encodeSVCB(values []string) ([]byte, error) {
	if len(values) < 2 {
		return nil, errors.New("SVCB requires priority and target")
	}
	priority, err := strconv.ParseUint(values[0], 10, 16)
	if err != nil {
		return nil, err
	}
	data, err := dnsAppendName(binary.BigEndian.AppendUint16(nil, uint16(priority)), canonicalDomain(values[1]))
	if err != nil {
		return nil, err
	}
	params := make(map[uint16][]byte)
	var keys []uint16
	for i := 2; i < len(values); i++ {
		name, value, hasValue := strings.Cut(values[i], "=")
		if strings.HasPrefix(value, "\"") {
			for !strings.HasSuffix(value, "\"") && i+1 < len(values) {
				i++
				value += " " + values[i]
			}
			if len(value) < 2 || !strings.HasSuffix(value, "\"") {
				return nil, errors.New("unterminated SVCB quote")
			}
			value = value[1 : len(value)-1]
		}
		value, err = svcbUnescape(value)
		if err != nil {
			return nil, err
		}
		key, err := svcbKey(name)
		if err != nil {
			return nil, err
		}
		if _, exists := params[key]; exists {
			return nil, errors.New("duplicate SVCB parameter")
		}
		var b []byte
		if strings.HasPrefix(name, "key") {
			b = []byte(value)
		} else {
			switch key {
			case 0:
				var mandatory []uint16
				for _, name := range strings.Split(value, ",") {
					id, e := svcbKey(name)
					if e != nil || id == 0 || slices.Contains(mandatory, id) {
						return nil, errors.New("invalid SVCB mandatory list")
					}
					mandatory = append(mandatory, id)
				}
				slices.Sort(mandatory)
				for _, id := range mandatory {
					b = binary.BigEndian.AppendUint16(b, id)
				}
			case 1:
				list, err := svcbList(value)
				if err != nil {
					return nil, err
				}
				for _, alpn := range list {
					if len(alpn) == 0 || len(alpn) > 255 {
						return nil, errors.New("invalid SVCB ALPN")
					}
					b = append(append(b, byte(len(alpn))), alpn...)
				}
			case 2, 8:
				if value != "" {
					return nil, errors.New("SVCB flag value must be empty")
				}
			case 3:
				n, err := strconv.ParseUint(value, 10, 16)
				if err != nil {
					return nil, err
				}
				b = binary.BigEndian.AppendUint16(nil, uint16(n))
			case 4, 6:
				for _, text := range strings.Split(value, ",") {
					ip, err := netip.ParseAddr(text)
					if err != nil || key == 4 != ip.Is4() || ip.Is4In6() || ip.Zone() != "" {
						return nil, errors.New("invalid SVCB address hint")
					}
					b = append(b, ip.AsSlice()...)
				}
			case 5:
				b, err = base64.StdEncoding.Strict().DecodeString(value)
				if err != nil || len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
					return nil, errors.New("invalid SVCB ECHConfigList encoding")
				}
			default:
				b = []byte(value)
			}
		}
		if !hasValue && key != 2 && key != 8 || len(b) > 65535 {
			return nil, errors.New("invalid SVCB parameter value")
		}
		keys = append(keys, key)
		params[key] = b
	}
	if err := validateSVCBParams(params); err != nil {
		return nil, err
	}
	slices.Sort(keys)
	for _, key := range keys {
		data = binary.BigEndian.AppendUint16(data, key)
		data = binary.BigEndian.AppendUint16(data, uint16(len(params[key])))
		data = append(data, params[key]...)
	}
	if len(data) > 65535 {
		return nil, errors.New("SVCB record exceeds65535 bytes")
	}
	return data, nil
}
