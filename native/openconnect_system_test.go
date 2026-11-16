package native

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestOpenConnectSystemRetryBoundary(t *testing.T) {
	for name, item := range map[string]struct {
		err  error
		want bool
	}{
		"connection-refused": {&net.OpError{Op: "dial", Err: errors.New("connection refused")}, true},
		"DNS":                {&net.DNSError{Err: "lookup failed"}, true},
		"wrapped-dial":       {fmt.Errorf("endpoint: %w", &net.OpError{Op: "dial", Err: io.EOF}), true},
		"read-after-auth":    {&net.OpError{Op: "read", Err: io.EOF}, false},
		"HTTP401":            {ocHTTPError(401), false},
		"TLS-verification":   {errors.New("certificate verification failed"), false},
		"interface-conflict": {errors.New("interface already exists"), false},
	} {
		t.Run(name, func(t *testing.T) {
			if ocSystemRetryable(item.err) != item.want {
				t.Fatal(item.err)
			}
		})
	}
}

func TestOpenConnectSplitRoutes(t *testing.T) {
	h := http.Header{"X-CSTP-Split-Include": {"192.0.2.42/255.255.255.0", "2001:db8::42/64,192.0.2.0/24"}, "X-CSTP-Split-Exclude-IP6": {"2001:db8::7/128"}, "X-CSTP-Split-Exclude": {"192.0.2.99/32"}}
	include, exclude, err := ocParseRoutes(h)
	if err != nil || !slices.Equal(include, []string{"192.0.2.0/24", "2001:db8::/64"}) || !slices.Equal(exclude, []string{"192.0.2.99/32", "2001:db8::7/128"}) {
		t.Fatal(include, exclude, err)
	}
	for _, value := range []string{"", ", \t", "bad", "192.0.2.0/255.0.255.0", "::ffff:192.0.2.0/120", "192.0.2.0/33", "ff02::/16", "192.0.2.0/24\r\nHost:evil", strings.Repeat("192.0.2.0/24,", 129)} {
		t.Run(value, func(t *testing.T) {
			if _, _, err := ocParseRoutes(http.Header{"X-Cstp-Split-Include": {value}}); err == nil {
				t.Fatal("invalid route accepted")
			}
		})
	}
}

func TestOpenConnectSystemRoutePlan(t *testing.T) {
	tunnel := &ocTunnel{local: []netip.Addr{netip.MustParseAddr("10.44.0.2"), netip.MustParseAddr("fd44::2")}}
	for _, split := range []bool{false, true} {
		h := http.Header{"X-Cstp-Split-Exclude": {"192.0.2.99/32", "2001:db8::99/128"}}
		if split {
			h.Set("X-Cstp-Split-Include", "192.0.2.0/24,2001:db8::/64")
		}
		in, err := tunnel.systemConfig(Outbound{Tag: "proxy"}, h, 1280)
		if err != nil || !slices.Equal(in.Address, []string{"10.44.0.2/32", "fd44::2/128"}) {
			t.Fatal(in, err)
		}
		plan := (&tunTunnel{local4: tunnel.local[0], local6: tunnel.local[1]}).routePlan(in)
		for address, want := range map[string]bool{"192.0.2.42": true, "2001:db8::42": true, "192.0.2.99": false, "2001:db8::99": false, "203.0.113.4": !split, "2001:db8:1::4": !split} {
			if slices.ContainsFunc(plan, func(p netip.Prefix) bool { return p.Contains(netip.MustParseAddr(address)) }) != want {
				t.Fatal(split, address, plan)
			}
		}
	}
	if _, err := tunnel.systemConfig(Outbound{}, nil, 1200); err == nil {
		t.Fatal("invalid IPv6 MTU accepted")
	}
}

func TestOpenConnectSystemOptions(t *testing.T) {
	valid := `{"outbounds":[{"type":"openconnect","tag":"vpn","server":"127.0.0.1","server_port":443,"username":"u","password":"p","tls":{"enabled":true},"system":true}]}`
	if _, err := Parse([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(valid, `"system":true`, `"name":"oc0"`, 1),
		strings.Replace(valid, `"system":true`, `"system":true,"name":"../x"`, 1),
		strings.Replace(valid, `"system":true`, `"split_include":["192.0.2.0/24"]`, 1),
		strings.Replace(valid, `"type":"openconnect"`, `"type":"http"`, 1),
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("invalid system options accepted", raw)
		}
	}
}

func FuzzOpenConnectSplitRoutes(f *testing.F) {
	for _, seed := range []string{"192.0.2.0/255.255.255.0", "2001:db8::/32", "0.0.0.0/0,::/0", "", "255.255.255.255/32"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		include, exclude, err := ocParseRoutes(http.Header{"X-Cstp-Split-Include": {value}})
		if err == nil {
			_ = tunRoutePrefixes(Inbound{Address: []string{"10.44.0.2/32", "fd44::2/128"}, RouteAddress: include, RouteExcludeAddress: exclude, DNSMode: "disabled"})
		}
	})
}
