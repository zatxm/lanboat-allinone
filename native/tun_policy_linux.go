//go:build linux

package native

import "encoding/binary"

func tunBareRule(table, priority uint32, family byte) []byte {
	body := []byte{family, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	body = append(body, nlU32(15, table)...)
	return append(body, nlU32(6, priority)...)
}
func tunPolicyRules(in Inbound, table, priority, protect uint32, family byte, name string) [][]byte {
	if in.AutoRedirect {
		input, _, _, _ := in.redirectMarks()
		selected := tunRule(table, priority, input, family)
		binary.NativeEndian.PutUint32(selected[8:], 0)
		fallback := in.AutoRedirectFallbackRuleIndex
		if fallback == 0 {
			fallback = 32768
		}
		return [][]byte{selected, tunRule(table, fallback, protect, family)}
	}
	include, _ := uidRanges(in.IncludeUID, in.IncludeUIDRange)
	exclude, _ := uidRanges(in.ExcludeUID, in.ExcludeUIDRange)
	type filter struct {
		uid    *[2]uint32
		iface  string
		output bool
	}
	exclusions := []filter{{iface: name}}
	for i := range exclude {
		exclusions = append(exclusions, filter{uid: &exclude[i]})
	}
	for _, name := range in.ExcludeInterface {
		exclusions = append(exclusions, filter{iface: name})
		if !in.StrictRoute {
			exclusions = append(exclusions, filter{iface: name, output: true})
		}
	}
	var selected []filter
	if len(include) == 0 {
		include = [][2]uint32{{0, ^uint32(0)}}
	}
	ifaces := in.IncludeInterface
	if len(ifaces) == 0 {
		ifaces = []string{""}
	}
	for i := range include {
		for _, name := range ifaces {
			f := filter{iface: name}
			if len(in.IncludeUID)+len(in.IncludeUIDRange) > 0 {
				f.uid = &include[i]
			}
			selected = append(selected, f)
		}
	}
	appendFilters := func(body []byte, f filter) []byte {
		if f.uid != nil {
			b := make([]byte, 8)
			binary.NativeEndian.PutUint32(b, f.uid[0])
			binary.NativeEndian.PutUint32(b[4:], f.uid[1])
			body = append(body, nlAttribute(20, b)...)
		}
		if f.iface != "" {
			kind := uint16(3)
			if f.output {
				kind = 17
			}
			body = append(body, nlAttribute(kind, append([]byte(f.iface), 0))...)
		}
		return body
	}
	controlRules := 0
	if family == 10 {
		controlRules = 1
	}
	target := priority + uint32(1+controlRules+len(exclusions)+len(selected))
	protectRule := tunRule(0, priority, protect, family)
	binary.NativeEndian.PutUint32(protectRule[8:], 0)
	protectRule[7] = 2
	protectRule = append(protectRule, nlU32(4, target)...)
	out := [][]byte{protectRule}
	if controlRules > 0 {
		body := tunBareRule(254, priority+1, family)
		body = append(body, nlU32(14, 0)...)
		body = append(body, nlAttribute(22, []byte{58})...)
		out = append(out, body)
	}
	// Inverting a FIB rule inverts every predicate, including UID/interface. Keep
	// the protect-mark escape separate from the positive routing predicates.
	for _, f := range exclusions {
		body := tunBareRule(0, priority+uint32(len(out)), family)
		body[7] = 2
		body = append(body, nlU32(4, target)...)
		out = append(out, appendFilters(body, f))
	}
	for _, f := range selected {
		out = append(out, appendFilters(tunBareRule(table, priority+uint32(len(out)), family), f))
	}
	return append(out, tunBareRule(254, target, family))
}
