package native

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// ConvertAdGuard compiles domain filters. Unsupported URL paths and modifiers
// are ignored, matching the documented domain-only AdGuard rule-set contract.
func ConvertAdGuard(data []byte) ([]Rule, error) {
	if len(data) > 64<<20 {
		return nil, errors.New("AdGuard input exceeds64MiB")
	}
	lines := strings.Split(string(data), "\n")
	onlyDomains := true
	var domains []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue
		}
		if validRuleDomain(line) {
			domains = append(domains, canonicalDomain(line))
		} else {
			onlyDomains = false
		}
	}
	if onlyDomains {
		return []Rule{{Domain: domains}}, nil
	}
	var normal, important, exceptions, importantExceptions []Rule
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "0.0.0.0" {
			for _, domain := range fields[1:] {
				if validRuleDomain(domain) {
					normal = append(normal, Rule{Domain: []string{canonicalDomain(domain)}})
				}
			}
			continue
		}
		exception := strings.HasPrefix(line, "@@")
		line = strings.TrimPrefix(line, "@@")
		isImportant := false
		if i := strings.LastIndexByte(line, '$'); i >= 0 {
			modifiers := strings.Split(line[i+1:], ",")
			supported := true
			for _, m := range modifiers {
				switch m {
				case "important":
					isImportant = true
				case "dnsrewrite=0.0.0.0":
				default:
					supported = false
				}
			}
			if !supported {
				continue
			}
			line = line[:i]
		}
		var rule Rule
		if len(line) >= 2 && line[0] == '/' && line[len(line)-1] == '/' {
			expression := line[1 : len(line)-1]
			if _, e := regexp.Compile(expression); e != nil {
				return nil, e
			}
			rule.DomainRegex = []string{expression}
		} else {
			line = strings.TrimPrefix(strings.TrimPrefix(line, "|https://"), "|http://")
			line = strings.TrimPrefix(strings.TrimPrefix(line, "https://"), "http://")
			suffix := strings.HasPrefix(line, "||")
			start := strings.HasPrefix(line, "|")
			line = strings.TrimLeft(line, "|")
			end := strings.HasSuffix(line, "|") || strings.HasSuffix(line, "^")
			line = strings.TrimRight(line, "|^")
			if strings.ContainsAny(line, "/:?# ") || line == "" {
				continue
			}
			expression := regexp.QuoteMeta(canonicalDomain(line))
			expression = strings.ReplaceAll(expression, `\*`, ".*")
			expression = strings.ReplaceAll(expression, `\^`, `(?:\.|$)`)
			if suffix {
				expression = `(?:^|\.)` + expression
			} else if start {
				expression = "^" + expression
			}
			if end {
				expression += "$"
			}
			rule.DomainRegex = []string{expression}
		}
		switch {
		case exception && isImportant:
			importantExceptions = append(importantExceptions, rule)
		case exception:
			exceptions = append(exceptions, rule)
		case isImportant:
			important = append(important, rule)
		default:
			normal = append(normal, rule)
		}
	}
	union := func(items []Rule) Rule {
		if len(items) == 1 {
			return items[0]
		}
		return Rule{Type: "logical", Mode: "or", Rules: items}
	}
	filter := func(items, except []Rule) (Rule, bool) {
		if len(items) == 0 {
			return Rule{}, false
		}
		base := union(items)
		if len(except) > 0 {
			ex := union(except)
			ex.Invert = true
			base = Rule{Type: "logical", Mode: "and", Rules: []Rule{base, ex}}
		}
		return base, true
	}
	var result []Rule
	if v, ok := filter(normal, append(exceptions, importantExceptions...)); ok {
		result = append(result, v)
	}
	if v, ok := filter(important, importantExceptions); ok {
		result = append(result, v)
	}
	return result, nil
}
func validRuleDomain(s string) bool {
	if len(s) == 0 || len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// CompileRuleSet emits SRS v5 using the public binary format; no engine code is linked.
func CompileRuleSet(data []byte, format string) ([]byte, error) {
	var items []Rule
	var e error
	if format == "adguard" {
		items, e = ConvertAdGuard(data)
	} else {
		items, e = parseRuleSet(data, "source")
	}
	if e != nil {
		return nil, e
	}
	if _, e = compileRuleSet(items); e != nil {
		return nil, e
	}
	b := binary.AppendUvarint(nil, uint64(len(items)))
	for _, rule := range items {
		part, e := encodeSRSRule(rule)
		if e != nil {
			return nil, e
		}
		b = append(b, part...)
	}
	out := bytes.NewBuffer([]byte{'S', 'R', 'S', 5})
	z := zlib.NewWriter(out)
	if _, e = z.Write(b); e != nil {
		return nil, e
	}
	if e = z.Close(); e != nil {
		return nil, e
	}
	return out.Bytes(), nil
}
func encodeSRSRule(o Rule) ([]byte, error) {
	if o.Type == "logical" {
		mode := byte(0)
		if o.Mode == "or" {
			mode = 1
		}
		b := binary.AppendUvarint([]byte{1, mode}, uint64(len(o.Rules)))
		for _, child := range o.Rules {
			part, e := encodeSRSRule(child)
			if e != nil {
				return nil, e
			}
			b = append(b, part...)
		}
		return append(b, boolByte(o.Invert)), nil
	}
	b := []byte{0}
	stringItem := func(id byte, values []string) {
		if len(values) == 0 {
			return
		}
		b = append(b, id)
		b = binary.AppendUvarint(b, uint64(len(values)))
		for _, v := range values {
			b = binary.AppendUvarint(b, uint64(len(v)))
			b = append(b, v...)
		}
	}
	u16Item := func(id byte, values []uint16) {
		if len(values) == 0 {
			return
		}
		b = append(b, id)
		b = binary.AppendUvarint(b, uint64(len(values)))
		for _, v := range values {
			b = binary.BigEndian.AppendUint16(b, v)
		}
	}

	u16Item(0, o.QueryType)
	stringItem(1, o.Network)
	stringItem(3, o.DomainKeyword)
	if tree := buildDomainTree(o.Domain, o.DomainSuffix); tree != nil {
		b = appendSRSTree(append(b, 2), tree)
	}
	stringItem(4, o.DomainRegex)
	for _, field := range []struct {
		id     byte
		values []string
	}{{5, o.SourceIPCIDR}, {6, o.IPCIDR}} {
		if len(field.values) == 0 {
			continue
		}
		var ranges []ipRange
		for _, v := range field.values {
			p, e := netip.ParsePrefix(v)
			if e != nil {
				return nil, e
			}
			from := p.Masked().Addr()
			raw := append([]byte(nil), from.AsSlice()...)
			for i := p.Bits(); i < from.BitLen(); i++ {
				raw[i/8] |= 1 << uint(7-i%8)
			}
			to, _ := netip.AddrFromSlice(raw)
			ranges = append(ranges, ipRange{from, to})
		}
		sort.Slice(ranges, func(i, j int) bool { return ranges[i].from.Compare(ranges[j].from) < 0 })
		merged := ranges[:0]
		for _, r := range ranges {
			if len(merged) > 0 && merged[len(merged)-1].to.Next().Compare(r.from) >= 0 {
				if r.to.Compare(merged[len(merged)-1].to) > 0 {
					merged[len(merged)-1].to = r.to
				}
			} else {
				merged = append(merged, r)
			}
		}
		b = append(b, field.id, 1)
		b = binary.BigEndian.AppendUint64(b, uint64(len(merged)))
		for _, r := range merged {
			for _, ip := range []netip.Addr{r.from, r.to} {
				raw := ip.AsSlice()
				b = binary.AppendUvarint(b, uint64(len(raw)))
				b = append(b, raw...)
			}
		}
	}
	u16Item(7, o.SourcePort)
	stringItem(8, o.SourcePortRange)
	u16Item(9, o.Port)
	stringItem(10, o.PortRange)
	stringItem(11, o.ProcessName)
	stringItem(12, o.ProcessPath)
	stringItem(13, o.PackageName)
	stringItem(14, o.WiFiSSID)
	stringItem(15, o.WiFiBSSID)
	stringItem(17, o.ProcessPathRegex)
	networkID := func(v string) (byte, error) {
		for i, s := range srsNetworkTypes {
			if v == s {
				return byte(i), nil
			}
		}
		return 0, fmt.Errorf("invalid network_type %q", v)
	}
	if len(o.NetworkType) > 0 {
		b = append(b, 18)
		b = binary.AppendUvarint(b, uint64(len(o.NetworkType)))
		for _, v := range o.NetworkType {
			id, e := networkID(v)
			if e != nil {
				return nil, e
			}
			b = append(b, id)
		}
	}
	if o.NetworkIsExpensive {
		b = append(b, 19)
	}
	if o.NetworkIsConstrained {
		b = append(b, 20)
	}
	prefixes := func(values []string) error {
		b = binary.AppendUvarint(b, uint64(len(values)))
		for _, v := range values {
			p, e := netip.ParsePrefix(v)
			if e != nil {
				return e
			}
			raw := p.Addr().AsSlice()
			b = binary.AppendUvarint(b, uint64(len(raw)))
			b = append(b, raw...)
			b = append(b, byte(p.Bits()))
		}
		return nil
	}
	if len(o.NetworkInterfaceAddress) > 0 {
		b = append(b, 21)
		b = binary.AppendUvarint(b, uint64(len(o.NetworkInterfaceAddress)))
		keys := make([]string, 0, len(o.NetworkInterfaceAddress))
		for k := range o.NetworkInterfaceAddress {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			id, e := networkID(k)
			if e != nil {
				return nil, e
			}
			b = append(b, id)
			if e = prefixes(o.NetworkInterfaceAddress[k]); e != nil {
				return nil, e
			}
		}
	}
	if len(o.DefaultInterfaceAddress) > 0 {
		b = append(b, 22)
		if e := prefixes(o.DefaultInterfaceAddress); e != nil {
			return nil, e
		}
	}
	stringItem(23, o.PackageNameRegex)
	// Reject conditions without a headless SRS representation instead of dropping them.
	raw, _ := json.Marshal(o)
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	allowed := map[string]bool{}
	for _, k := range strings.Fields("type mode rules domain domain_suffix domain_keyword domain_regex source_ip_cidr ip_cidr source_port source_port_range port port_range process_name process_path process_path_regex package_name package_name_regex network network_type network_is_expensive network_is_constrained network_interface_address default_interface_address wifi_ssid wifi_bssid invert query_type") {
		allowed[k] = true
	}
	for k := range fields {
		if !allowed[k] {
			return nil, fmt.Errorf("field %q is not a headless SRS condition", k)
		}
	}
	return append(b, 255, boolByte(o.Invert)), nil
}
func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// DecodeRuleSet returns the source form of a binary rule set.
func DecodeRuleSet(data []byte) ([]byte, error) {
	rules, err := parseRuleSet(data, "binary")
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"version": 4, "rules": rules})
}

func MatchRuleSet(data []byte, target string) (bool, error) {
	items, err := parseRuleSet(data, "binary")
	if err != nil {
		return false, err
	}
	snapshot, err := compileRuleSet(items)
	if err != nil {
		return false, err
	}
	q := request{network: "tcp", address: net.JoinHostPort(target, "0")}
	if ip, err := netip.ParseAddr(target); err == nil {
		q.ips = []netip.Addr{ip}
	}
	for _, rule := range snapshot.rules {
		if rule.evaluate(q) == matchYes {
			return true, nil
		}
	}
	return false, nil
}
