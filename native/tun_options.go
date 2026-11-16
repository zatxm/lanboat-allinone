package native

import (
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
)

type FirewallMark uint32

func (m *FirewallMark) UnmarshalJSON(b []byte) error {
	var text string
	if len(b) > 0 && b[0] == '"' {
		if e := json.Unmarshal(b, &text); e != nil {
			return e
		}
	} else {
		text = string(b)
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(text), "0x") {
		base = 0
	}
	v, e := strconv.ParseUint(text, base, 32)
	if e == nil {
		*m = FirewallMark(v)
	}
	return e
}
func (in Inbound) redirectMarks() (input, output, reset, tproxy uint32) {
	input, output, reset, tproxy = uint32(in.AutoRedirectInputMark), uint32(in.AutoRedirectOutputMark), uint32(in.AutoRedirectResetMark), uint32(in.AutoRedirectTProxyMark)
	if input == 0 {
		input = 0x2023
	}
	if output == 0 {
		output = 0x2024
	}
	if reset == 0 {
		reset = 0x2025
	}
	if tproxy == 0 {
		tproxy = 0x2026
	}
	return
}
func (in Inbound) queueNumber() uint16 {
	if in.AutoRedirectNFQueue != nil {
		return *in.AutoRedirectNFQueue
	}
	return 100
}
func (in Inbound) linuxTUNOptions() bool {
	return in.AutoRedirect || in.MultiQueue || in.IPRoute2TableIndex != 0 || in.IPRoute2RuleIndex != 0 || in.AutoRedirectInputMark != 0 || in.AutoRedirectOutputMark != 0 || in.AutoRedirectResetMark != 0 || in.AutoRedirectTProxyMark != 0 || in.AutoRedirectNFQueue != nil || in.AutoRedirectFallbackRuleIndex != 0 || in.ExcludeMPTCP || len(in.IncludeInterface)+len(in.ExcludeInterface)+len(in.IncludeUID)+len(in.ExcludeUID)+len(in.IncludeUIDRange)+len(in.ExcludeUIDRange)+len(in.IncludeMACAddress)+len(in.ExcludeMACAddress) > 0
}
func uidRanges(ids []uint32, values []string) ([][2]uint32, error) {
	out := make([][2]uint32, 0, len(ids)+len(values))
	for _, id := range ids {
		out = append(out, [2]uint32{id, id})
	}
	for _, v := range values {
		a, b, ok := strings.Cut(v, ":")
		if !ok {
			return nil, errors.New("UID range must be start:end")
		}
		first, e := strconv.ParseUint(a, 10, 32)
		if e != nil {
			return nil, e
		}
		last, e := strconv.ParseUint(b, 10, 32)
		if e != nil || first > last {
			return nil, errors.New("invalid UID range")
		}
		out = append(out, [2]uint32{uint32(first), uint32(last)})
	}

	slices.SortFunc(out, func(a, b [2]uint32) int {
		if a[0] < b[0] {
			return -1
		}
		if a[0] > b[0] {
			return 1
		}
		return 0
	})
	merged := out[:0]
	for _, v := range out {
		if len(merged) > 0 {
			last := &merged[len(merged)-1]
			if uint64(v[0]) <= uint64(last[1])+1 {
				last[1] = max(last[1], v[1])
				continue
			}
		}
		merged = append(merged, v)
	}
	return merged, nil
}
func (in Inbound) validateRedirect() error {
	table, priority := in.IPRoute2TableIndex, in.IPRoute2RuleIndex
	if table == 0 {
		table = 2022
	}
	if priority == 0 {
		priority = 9000
	}
	if table >= 253 && table <= 255 || in.AutoRedirect && (table == ^uint32(0) || table+1 >= 253 && table+1 <= 255) {
		return errors.New("TUN requires a private routing table")
	}
	count := uint64(4+len(in.ExcludeUID)+len(in.ExcludeUIDRange)+2*len(in.ExcludeInterface)) + uint64(len(in.IncludeUID)+len(in.IncludeUIDRange)+1)*uint64(len(in.IncludeInterface)+1)
	if uint64(priority)+count > uint64(^uint32(0)) || in.AutoRedirect && priority < 2 {
		return errors.New("TUN policy priority range overflows")
	}
	if in.AutoRedirectFallbackRuleIndex != 0 && (in.AutoRedirectFallbackRuleIndex == priority || in.AutoRedirectFallbackRuleIndex == priority-1) {
		return errors.New("TUN fallback priority conflicts with redirect rules")
	}

	if in.AutoRedirect {
		i, o, r, t := in.redirectMarks()
		if i == o || i == r || i == t || o == r || o == t || r == t {
			return errors.New("auto_redirect marks must be distinct")
		}
	} else if in.AutoRedirectInputMark != 0 || in.AutoRedirectOutputMark != 0 || in.AutoRedirectResetMark != 0 || in.AutoRedirectTProxyMark != 0 || in.AutoRedirectNFQueue != nil || in.AutoRedirectFallbackRuleIndex != 0 || in.ExcludeMPTCP || len(in.IncludeMACAddress)+len(in.ExcludeMACAddress) > 0 {
		return errors.New("redirect options require auto_redirect")
	}
	if len(in.IncludeInterface) > 0 && len(in.ExcludeInterface) > 0 {
		return errors.New("include_interface conflicts with exclude_interface")
	}
	if len(in.IncludeMACAddress) > 0 && len(in.ExcludeMACAddress) > 0 {
		return errors.New("include_mac_address conflicts with exclude_mac_address")
	}
	if !in.AutoRoute && len(in.IncludeInterface)+len(in.ExcludeInterface)+len(in.IncludeUID)+len(in.ExcludeUID)+len(in.IncludeUIDRange)+len(in.ExcludeUIDRange) > 0 {
		return errors.New("TUN routing filters require auto_route")
	}
	for _, v := range append(append([]string{}, in.IncludeInterface...), in.ExcludeInterface...) {
		if len(v) == 0 || len(v) > 15 || strings.ContainsAny(v, "\x00/\n\r\t ") {
			return errors.New("invalid routing interface name")
		}
	}
	for _, v := range append(append([]string{}, in.IncludeMACAddress...), in.ExcludeMACAddress...) {
		mac, e := net.ParseMAC(v)
		if e != nil || len(mac) != 6 {
			return errors.New("invalid TUN MAC address")
		}
	}
	if _, e := uidRanges(in.IncludeUID, in.IncludeUIDRange); e != nil {
		return e
	}
	if _, e := uidRanges(in.ExcludeUID, in.ExcludeUIDRange); e != nil {
		return e
	}
	if (len(in.IncludeUID)+len(in.IncludeUIDRange)+1)*(len(in.IncludeInterface)+1) > 65536 {
		return errors.New("too many TUN policy combinations")
	}
	return nil
}

// Queue verdicts must use temporary marks: the following route chain must see
// a mark change so Linux recalculates an OUTPUT packet's already chosen route.
func (in Inbound) redirectVerdictMarks() (input, output, reset uint32) {
	a, b, c, d := in.redirectMarks()
	v := uint32(0x4c420100)
	next := func() uint32 {
		for v == a || v == b || v == c || v == d {
			v++
		}
		out := v
		v++
		return out
	}
	return next(), next(), next()
}
