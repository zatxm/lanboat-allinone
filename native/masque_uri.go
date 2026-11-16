package native

import (
	"context"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// RFC9484 allows simple and form-query expansions, not the other URI operators.
// Compile once at configuration time; packets never run the URI matcher.
type masqueURITemplate struct {
	pattern  *regexp.Regexp
	wildcard string
}

func compileMasqueURI(text string) (*masqueURITemplate, error) {
	if text == "" {
		text = "/.well-known/masque/ip/{target}/{ipproto}/"
	}
	invalid := errors.New("invalid MASQUE URI template: use a relative path with target/ipproto simple or query expressions")
	if len(text) > 2048 || !strings.HasPrefix(text, "/") || strings.HasPrefix(text, "//") {
		return nil, invalid
	}
	for _, b := range []byte(text) {
		if b < 0x21 || b > 0x7e || b == '#' {
			return nil, invalid
		}
	}
	var pattern, expanded strings.Builder
	pattern.WriteString("^")
	for len(text) != 0 {
		i := strings.IndexByte(text, '{')
		if i < 0 {
			i = len(text)
		}
		literal := text[:i]
		if strings.ContainsRune(literal, '}') {
			return nil, invalid
		}
		pattern.WriteString(regexp.QuoteMeta(literal))
		expanded.WriteString(literal)
		text = text[i:]
		if text == "" {
			break
		}
		end := strings.IndexByte(text, '}')
		if end < 0 {
			return nil, invalid
		}
		expression := text[1:end]
		text = text[end+1:]
		operator := byte(0)
		if strings.HasPrefix(expression, "?") || strings.HasPrefix(expression, "&") {
			operator, expression = expression[0], expression[1:]
		}
		vars := strings.Split(expression, ",")
		if len(vars) > 2 {
			return nil, invalid
		}
		for index, name := range vars {
			if name != "target" && name != "ipproto" || index > 0 && name == vars[0] {
				return nil, invalid
			}
		}
		capture := func(name string) string { return "(?P<" + name + ">[^/?&#,]+)" }
		if operator == 0 {
			for index, name := range vars {
				if index != 0 {
					pattern.WriteByte(',')
					expanded.WriteByte(',')
				}
				pattern.WriteString(capture(name))
				expanded.WriteByte('*')
			}
			continue
		}
		// Both variables are optional. Enumerate the three nonempty subsets so
		// an omitted first variable still starts its query with ? rather than &.
		pattern.WriteString("(?:")
		for subset := 1; subset < 1<<len(vars); subset++ {
			if subset != 1 {
				pattern.WriteByte('|')
			}
			separator := operator
			for index, name := range vars {
				if subset&(1<<index) != 0 {
					pattern.WriteString(regexp.QuoteMeta(string(separator) + name + "="))
					pattern.WriteString(capture(name))
					separator = '&'
				}
			}
		}
		pattern.WriteString(")?")
		for index, name := range vars {
			separator := operator
			if index != 0 {
				separator = '&'
			}
			expanded.WriteByte(separator)
			expanded.WriteString(name + "=*")
		}
	}
	pattern.WriteByte('$')
	path := expanded.String()
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path == "" {
		return nil, invalid
	}
	if _, err := url.PathUnescape(path); err != nil {
		return nil, invalid
	}
	re, err := regexp.Compile(pattern.String())
	if err != nil {
		return nil, invalid
	}
	return &masqueURITemplate{pattern: re, wildcard: path}, nil
}

type masqueScope struct {
	target   string
	prefix   netip.Prefix
	protocol uint16 // 256 means any; protocol zero is not the wildcard.
}

func (t *masqueURITemplate) match(path string) (masqueScope, int) {
	scope := masqueScope{protocol: 256}
	if len(path) > 2048 {
		return scope, 400
	}
	values := t.pattern.FindStringSubmatch(path)
	if values == nil {
		return scope, 404
	}
	seen := map[string]string{}
	for index, name := range t.pattern.SubexpNames() {
		if name == "" || values[index] == "" {
			continue
		}
		raw := values[index]
		value, err := url.PathUnescape(raw)
		if err != nil {
			return scope, 400
		}
		if old, ok := seen[name]; ok && old != value {
			return scope, 400
		}
		seen[name] = value
		if value == "*" {
			continue
		}
		if name == "ipproto" {
			if len(value) > 3 || strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
				return scope, 400
			}
			n, err := strconv.ParseUint(value, 10, 8)
			// Scoping to extension headers is explicitly optional in RFC9484.
			if err != nil || slices.Contains([]uint64{0, 43, 44, 50, 51, 60, 135, 139, 140}, n) {
				return scope, 400
			}
			scope.protocol = uint16(n)
			continue
		}
		if strings.Contains(raw, ":") {
			return scope, 400 // IPv6 colons must be percent-encoded.
		}
		if ip, err := netip.ParseAddr(value); err == nil && ip.Zone() == "" && !ip.Is4In6() {
			scope.prefix = netip.PrefixFrom(ip, ip.BitLen())
		} else if prefix, err := netip.ParsePrefix(value); err == nil && prefix == prefix.Masked() && !prefix.Addr().Is4In6() && prefix.Addr().Zone() == "" {
			scope.prefix = prefix
		} else {
			if len(value) > 253 || strings.ContainsAny(value, ":/%") {
				return scope, 400
			}
			for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
				if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' || strings.IndexFunc(label, func(r rune) bool {
					return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
				}) >= 0 {
					return scope, 400
				}
			}
			scope.target = value
		}
	}
	return scope, 0
}

func (s masqueScope) allowsProtocol(protocol byte) bool {
	return s.protocol == 256 || s.protocol == uint16(protocol) || protocol == 1 || protocol == 58
}

func (s masqueScope) routes(ctx context.Context, r *Runtime, allowed []netip.Prefix, assigned []string) ([]netip.Prefix, error) {
	var targets []netip.Prefix
	if s.prefix.IsValid() {
		targets = []netip.Prefix{s.prefix}
	} else if s.target != "" {
		ips, err := r.resolver.lookupReal(ctx, s.target)
		if err != nil {
			return nil, err
		}
		if len(ips) > 128 {
			return nil, errors.New("too many MASQUE target addresses")
		}
		for _, ip := range ips {
			if ip.Zone() == "" && !ip.Is4In6() {
				targets = append(targets, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	} else {
		targets = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	if len(allowed) == 0 {
		allowed = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	families := map[bool]bool{true: true, false: true}
	if len(assigned) != 0 {
		clear(families)
		for _, value := range assigned {
			prefix, _ := netip.ParsePrefix(value)
			families[prefix.Addr().Is4()] = true
		}
	}
	var result []netip.Prefix
	for _, target := range targets {
		if !families[target.Addr().Is4()] {
			continue
		}
		for _, prefix := range allowed {
			if !target.Overlaps(prefix) {
				continue
			}
			match := target
			if prefix.Bits() > match.Bits() {
				match = prefix
			}
			if !slices.Contains(result, match) {
				if len(result) == 128 {
					return nil, errors.New("too many MASQUE scoped routes")
				}
				result = append(result, match)
			}
		}
	}
	if len(result) == 0 {
		return nil, ErrRejected
	}
	return result, nil
}
