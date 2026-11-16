package native

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestMDNSConfiguration(t *testing.T) {
	for _, value := range []string{``, `,"interface":[]`, `,"interface":"eth0"`, `,"interface":["Ethernet 2","wlan0"]`} {
		if _, err := Parse([]byte(`{"dns":{"servers":[{"type":"mdns","tag":"lan"` + value + `}]}}`)); err != nil {
			t.Fatal(value, err)
		}
	}
	for _, value := range []string{`,"interface":""`, `,"interface":["a","a"]`, `,"interface":"bad/name"`, `,"server":"127.0.0.1"`, `,"server_port":5353`, `,"detour":"direct"`, `,"domain_resolver":"lan"`, `,"tls":{"enabled":true}`, `,"predefined":{"x.local":["127.0.0.1"]}`, `,"path":"/"`, `,"interface":"` + strings.Repeat("x", 129) + `"`} {
		if _, err := Parse([]byte(`{"dns":{"servers":[{"type":"mdns","tag":"lan"` + value + `}]}}`)); err == nil {
			t.Fatal("accepted", value)
		}
	}
	if _, err := Parse([]byte(`{"dns":{"servers":[{"type":"udp","tag":"lan","server":"127.0.0.1","interface":"eth0"}]}}`)); err == nil {
		t.Fatal("interface accepted by an unrelated DNS transport")
	}
}

func mdnsTestReply(t testing.TB, query []byte, answer ...string) []byte {
	t.Helper()
	reply, err := predefinedDNS(query, DNSRule{Answer: answer})
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

func TestMDNSReply(t *testing.T) {
	for _, tc := range []struct {
		typ    uint16
		answer string
	}{
		{1, "device.local. 120 IN A 192.0.2.7"},
		{28, "device.local. 120 IN AAAA 2001:db8::7"},
		{12, "device.local. 120 IN PTR printer.local."},
		{16, `device.local. 120 IN TXT "lanboat service"`},
		{33, "device.local. 120 IN SRV 0 0 443 server.local."},
		{255, "device.local. 120 IN A 192.0.2.7"},
		{1, "device.local. 120 IN CNAME server.local."},
	} {
		t.Run(fmt.Sprint(tc.typ), func(t *testing.T) {
			query, _ := makeDNSQuery("device.local", tc.typ)
			reply := mdnsTestReply(t, query, tc.answer)
			if err := mdnsReply(query, reply); err != nil {
				t.Fatal(err)
			}
			sections, _ := dnsRecords(reply)
			if len(sections[0]) != 1 || sections[0][0].ttl != 10 {
				t.Fatal("legacy TTL was not bounded", sections)
			}
		})
	}
	query, _ := makeDNSQuery("device.local", 1)
	valid := mdnsTestReply(t, query, "device.local. 0 IN A 192.0.2.7")
	if err := mdnsReply(query, valid); err != nil {
		t.Fatal("goodbye TTL0 rejected", err)
	}
	mutations := map[string]func([]byte){
		"identity": func(b []byte) { b[0] ^= 1 },
		"query":    func(b []byte) { b[2] &^= 128 },
		"opcode":   func(b []byte) { b[2] |= 8 },
		"truncated": func(b []byte) {
			b[2] |= 2
		},
		"rcode": func(b []byte) { b[3] |= 2 },
		"wrong-question": func(b []byte) {
			b[13] = 'x'
		},
		"cache-flush": func(b []byte) {
			_, end, _, _ := dnsQuestion(query)
			b[end+4] |= 128
		},
		"class": func(b []byte) {
			_, end, _, _ := dnsQuestion(query)
			b[end+5] = 3
		},
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			b := bytes.Clone(valid)
			change(b)
			if err := mdnsReply(query, b); err == nil {
				t.Fatal("forged response accepted")
			}
		})
	}
	for _, reply := range [][]byte{valid[:len(valid)-1], append(bytes.Clone(valid), 0), mdnsTestReply(t, query), mdnsTestReply(t, query, "unrelated.local. 10 IN A 192.0.2.1")} {
		if mdnsReply(query, reply) == nil {
			t.Fatal("invalid response accepted")
		}
	}
}

func TestMDNSLinkPolicy(t *testing.T) {
	p := mdnsPath{local: netip.MustParseAddr("192.0.2.1"), prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	for _, ip := range []string{"192.0.2.7", "::ffff:192.0.2.7"} {
		if !p.onLink(netip.MustParseAddr(ip)) {
			t.Fatal("local responder rejected", ip)
		}
	}
	for _, ip := range []string{"198.51.100.7", "0.0.0.0", "224.0.0.251", "::1"} {
		if p.onLink(netip.MustParseAddr(ip)) {
			t.Fatal("off-link responder accepted", ip)
		}
	}
	p.local, p.prefixes = netip.MustParseAddr("2001:db8::1"), []netip.Prefix{netip.MustParsePrefix("2001:db8::/64")}
	if !p.onLink(netip.MustParseAddr("fe80::1%eth0")) || !p.onLink(netip.MustParseAddr("2001:db8::7")) || p.onLink(netip.MustParseAddr("2001:db8:1::7")) {
		t.Fatal("IPv6 scope validation")
	}
}

func FuzzMDNSReply(f *testing.F) {
	query, _ := makeDNSQuery("device.local", 1)
	query[0], query[1] = 0x12, 0x34
	f.Add(mdnsTestReply(f, query, "device.local. 120 IN A 192.0.2.7"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, reply []byte) {
		if mdnsReply(query, reply) == nil {
			sections, err := dnsRecords(reply)
			if err != nil {
				t.Fatal(err)
			}
			for _, section := range sections {
				for _, rr := range section {
					if rr.typ != 41 && binary.BigEndian.Uint32(reply[rr.ttlOffset:]) > 10 {
						t.Fatal("unbounded TTL")
					}
				}
			}
		}
	})
}
