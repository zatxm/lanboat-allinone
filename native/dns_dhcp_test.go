package native

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
)

func dhcpTestQuery(t testing.TB) []byte {
	t.Helper()
	b, err := dhcpDiscover(net.HardwareAddr{2, 0, 0, 0, 0, 1})
	if err != nil {
		t.Fatal(err)
	}
	copy(b[4:8], []byte{1, 2, 3, 4})
	return b
}

func dhcpTestOffer(query []byte, options ...byte) []byte {
	b := bytes.Clone(query[:240])
	b[0] = 2
	return append(b, options...)
}

func TestDHCPConfiguration(t *testing.T) {
	for _, extra := range []string{``, `,"interface":""`, `,"interface":"Ethernet 2"`, `,"interface":"eth0","detour":"direct"`} {
		if _, err := Parse([]byte(`{"dns":{"servers":[{"type":"dhcp","tag":"lan"` + extra + `}]}}`)); err != nil {
			t.Fatal(extra, err)
		}
	}
	for _, extra := range []string{`,"interface":["a","b"]`, `,"interface":"bad/name"`, `,"interface":"` + strings.Repeat("x", 129) + `"`, `,"server":"192.0.2.53"`, `,"server_port":53`, `,"tls":{"enabled":true}`, `,"predefined":{"test.local":["192.0.2.1"]}`} {
		if _, err := Parse([]byte(`{"dns":{"servers":[{"type":"dhcp","tag":"lan"` + extra + `}]}}`)); err == nil {
			t.Fatal("accepted", extra)
		}
	}
	if _, err := Parse([]byte(`{"dns":{"servers":[{"type":"dhcp","tag":"lan"}]},"route":{"rules":[{"dns_server_address":{"lan":"192.0.2.0/24"},"action":"reject"}]}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestDHCPOffer(t *testing.T) {
	q := dhcpTestQuery(t)
	base := []byte{53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 4, 192, 0, 2, 53}
	search := []byte{4, 'c', 'o', 'r', 'p', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 3, 'l', 'a', 'b', 192, 5}
	options := append(bytes.Clone(base), 119, byte(len(search)))
	options = append(options, search...)
	options = append(options, 255)
	b := dhcpTestOffer(q, options...)
	state, err := dhcpOffer(q, b)
	if err != nil || fmt.Sprint(state.servers) != "[192.0.2.53]" || fmt.Sprint(state.domains) != "[corp.example lab.example]" {
		t.Fatal(state, err)
	}
	// Long options concatenate in main,file,sname order (RFC3396/option52).
	overloaded := dhcpTestOffer(q, 53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 2, 192, 0, 52, 1, 3, 255)
	copy(overloaded[108:236], []byte{6, 2, 2, 53, 15, 5, 'c', 'o', 'r', 'p', '.', 255})
	copy(overloaded[44:108], []byte{15, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 255})
	state, err = dhcpOffer(q, overloaded)
	if err != nil || fmt.Sprint(state.servers) != "[192.0.2.53]" || fmt.Sprint(state.domains) != "[corp.example]" {
		t.Fatal(state, err)
	}
	for name, change := range map[string]func([]byte){
		"opcode": func(b []byte) { b[0] = 1 }, "hardware": func(b []byte) { b[1] = 2 }, "hlen": func(b []byte) { b[2] = 17 }, "xid": func(b []byte) { b[4] ^= 1 }, "client": func(b []byte) { b[28] ^= 1 }, "cookie": func(b []byte) { b[236] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := bytes.Clone(b)
			change(bad)
			if _, err := dhcpOffer(q, bad); err == nil {
				t.Fatal("bad identity accepted")
			}
		})
	}
	for _, opts := range [][]byte{
		{53, 1, 5, 54, 4, 192, 0, 2, 1, 6, 4, 192, 0, 2, 53, 255}, // ACK is not a response to DISCOVER.
		{53, 1, 2, 6, 4, 192, 0, 2, 53, 255},                      // Missing server id.
		{53, 1, 2, 54, 4, 224, 0, 0, 1, 6, 4, 192, 0, 2, 53, 255},
		{53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 3, 192, 0, 2, 255},
		{53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 4, 0, 0, 0, 0, 255},
		{53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 4, 255, 255, 255, 255, 255},
		append(bytes.Clone(base), 119, 2, 192, 0, 255), // Compression loop.
		append(bytes.Clone(base), 119, 3, 1, 0, 0, 255),
		append(bytes.Clone(base), 52, 1, 4, 255),
		append(bytes.Clone(base), 53, 1, 2, 255),
		append(bytes.Clone(base), 99, 10, 1),
		base,
	} {
		if _, err := dhcpOffer(q, dhcpTestOffer(q, opts...)); err == nil {
			t.Fatal("malformed offer accepted", opts)
		}
	}
	if _, err := dhcpOffer(q, make([]byte, 8192)); err == nil {
		t.Fatal("unbounded offer accepted")
	}
}

func FuzzDHCPOffer(f *testing.F) {
	q := dhcpTestQuery(f)
	f.Add(dhcpTestOffer(q, 53, 1, 2, 54, 4, 192, 0, 2, 1, 6, 4, 192, 0, 2, 53, 255))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if state, err := dhcpOffer(q, b); err == nil {
			if len(state.servers) == 0 || len(state.servers) > 64 {
				t.Fatal(state)
			}
			for _, ip := range state.servers {
				if !ip.Is4() || !ip.IsGlobalUnicast() {
					t.Fatal(ip)
				}
			}
		}
	})
}
