package native

import "errors"

func dnsAppendEscapedName(b []byte, name string) ([]byte, error) {
	start, label := len(b), len(b)
	b = append(b, 0)
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '.' {
			if len(b)-label-1 == 0 {
				return nil, errors.New("empty DNS label")
			}
			b[label] = byte(len(b) - label - 1)
			label = len(b)
			b = append(b, 0)
			continue
		}
		if c == '\\' {
			i++
			if i == len(name) {
				return nil, errors.New("trailing DNS name escape")
			}
			c = name[i]
			if c >= '0' && c <= '9' {
				if i+2 >= len(name) || name[i+1] < '0' || name[i+1] > '9' || name[i+2] < '0' || name[i+2] > '9' {
					return nil, errors.New("invalid DNS name decimal escape")
				}
				n := int(c-'0')*100 + int(name[i+1]-'0')*10 + int(name[i+2]-'0')
				if n > 255 {
					return nil, errors.New("DNS name decimal escape exceeds255")
				}
				c, i = byte(n), i+2
			}
		}
		b = append(b, c)
		if len(b)-label-1 > 63 || len(b)-start > 254 {
			return nil, errors.New("DNS name too long")
		}
	}
	if len(b)-label-1 != 0 {
		b[label] = byte(len(b) - label - 1)
		b = append(b, 0)
	}
	return b, nil
}

func dnsEscapeLabel(b []byte) string {
	for _, c := range b {
		if c <= 32 || c >= 127 || c == '.' || c == '\\' {
			out := make([]byte, 0, len(b)+3)
			for _, c := range b {
				switch {
				case c <= 32 || c >= 127:
					out = append(out, '\\', '0'+c/100, '0'+c/10%10, '0'+c%10)
				case c == '.', c == '\\':
					out = append(out, '\\', c)
				default:
					out = append(out, c)
				}
			}
			return string(out)
		}
	}
	return string(b)
}
