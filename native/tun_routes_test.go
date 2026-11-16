package native

import (
	"errors"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
)

func TestTUNRouteReplacementRollback(t *testing.T) {
	for _, failure := range []string{"add", "remove", ""} {
		t.Run(failure, func(t *testing.T) {
			old, next := netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32")
			kernel := map[netip.Prefix]bool{old: true}
			state := &tunRouteState{current: map[netip.Prefix]bool{old: true}, add: func(p netip.Prefix) error {
				if failure == "add" && p == next {
					return errors.New("add failure")
				}
				kernel[p] = true
				return nil
			}, remove: func(p netip.Prefix) error {
				if failure == "remove" && p == old {
					return errors.New("remove failure")
				}
				delete(kernel, p)
				return nil
			}}
			e := state.replace([]netip.Prefix{next, next})
			if failure != "" {
				if e == nil || !reflect.DeepEqual(kernel, map[netip.Prefix]bool{old: true}) || !reflect.DeepEqual(state.current, kernel) {
					t.Fatal(e, kernel, state.current)
				}
			} else {
				if e != nil || !reflect.DeepEqual(kernel, map[netip.Prefix]bool{next: true}) {
					t.Fatal(e, kernel)
				}
				if e = state.replace(nil); e != nil || len(kernel) > 0 {
					t.Fatal(e, kernel)
				}
			}
		})
	}
}
func TestTUNRedirectOptionValidation(t *testing.T) {
	good := []string{
		`{"inbounds":[{"type":"tun","auto_route":true,"auto_redirect":true,"auto_redirect_input_mark":"0x1234","auto_redirect_output_mark":12345,"auto_redirect_nfqueue":0,"exclude_mptcp":true,"include_uid":[0],"include_uid_range":["1000:2000"],"include_interface":["eth0"],"include_mac_address":["00:11:22:33:44:55"]}]}`,
		`{"inbounds":[{"type":"tun","auto_route":true,"exclude_uid_range":["2:3"],"exclude_interface":["lo"]}]}`,
	}
	if runtime.GOOS == "linux" {
		for _, s := range good {
			if _, e := Parse([]byte(s)); e != nil {
				t.Fatal(e)
			}
		}
	}
	bad := []string{`"auto_redirect_input_mark":-1`, `"auto_redirect_input_mark":"0x100000000"`, `"auto_redirect_input_mark":"x"`, `"auto_redirect_input_mark":"0x2024"`, `"include_uid_range":["2:1"]`, `"iproute2_table_index":254`, `"iproute2_table_index":4294967295`, `"iproute2_rule_index":4294967295`, `"iproute2_rule_index":1`, `"auto_redirect_iproute2_fallback_rule_index":9000`, `"include_uid_range":["2"]`, `"include_interface":["bad name"]`, `"include_mac_address":["x"]`, `"include_interface":["eth0"],"exclude_interface":["eth1"]`, `"include_mac_address":["00:11:22:33:44:55"],"exclude_mac_address":["00:11:22:33:44:66"]`}
	for _, s := range bad {
		if _, e := Parse([]byte(`{"inbounds":[{"type":"tun","auto_route":true,"auto_redirect":true,` + s + `}]}`)); e == nil {
			t.Fatal("invalid options accepted", s)
		}
	}
}

func TestTUNUIDRangeCoalescing(t *testing.T) {
	ranges, e := uidRanges([]uint32{1, 2, 1, 9}, []string{"0:3", "8:10", "10:10"})
	if e != nil || !reflect.DeepEqual(ranges, [][2]uint32{{0, 3}, {8, 10}}) {
		t.Fatal(ranges, e)
	}
}
