package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type dnsTextFixture struct {
	Text       string `json:"text"`
	Type       uint16 `json:"type"`
	Class      uint16 `json:"class"`
	TTL        uint32 `json:"ttl"`
	Data       string `json:"data"`
	Compressed string `json:"compressed"`
}

func dnsTextFixtures(t testing.TB) []dnsTextFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/dns-text-records.json")
	if err != nil {
		t.Fatal(err)
	}
	var values []dnsTextFixture
	if err = json.Unmarshal(b, &values); err != nil {
		t.Fatal(err)
	}
	return values
}

func TestDNSTextReferenceRecords(t *testing.T) {
	for _, fixture := range dnsTextFixtures(t) {
		t.Run(fmt.Sprint(fixture.Type), func(t *testing.T) {
			rr, err := parseTextRecord(fixture.Text)
			if err != nil {
				t.Fatal(fixture.Text, err)
			}
			if rr.typ != fixture.Type || rr.class != fixture.Class || rr.ttl != fixture.TTL || hex.EncodeToString(rr.data) != fixture.Data {
				t.Fatalf("reference mismatch: %+v want:%+v data:%x", rr, fixture, rr.data)
			}
			wire, err := hex.DecodeString(fixture.Compressed)
			if err != nil {
				t.Fatal(err)
			}
			sections, err := dnsRecords(wire)
			if err != nil || len(sections[0]) != 1 {
				t.Fatal(err, sections)
			}
			got := sections[0][0]
			if rr.name != got.name || rr.typ != got.typ || rr.class != got.class || !bytes.Equal(rr.data, got.data) {
				t.Fatalf("compressed reference mismatch: %+v vs %+v", rr, got)
			}
			q, _ := makeDNSQuery("rr.test", fixture.Type)
			for _, section := range []string{"answer", "ns", "extra"} {
				o := DNSRule{}
				index := 0
				switch section {
				case "answer":
					o.Answer = []string{fixture.Text}
				case "ns":
					o.NS, index = []string{fixture.Text}, 1
				case "extra":
					o.Extra, index = []string{fixture.Text}, 2
				}
				reply, err := predefinedDNS(q, o)
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := dnsRecords(reply)
				if err != nil || len(parsed[index]) != 1 {
					t.Fatal(err)
				}
				got = parsed[index][0]
				if got.class != rr.class || !bytes.Equal(got.data, rr.data) {
					t.Fatal("predefined changed RDATA or class")
				}
			}
		})
	}
}

func TestDNSTextEscapesAndBounds(t *testing.T) {
	rr, err := parseTextRecord("rr.test. IN 1w2d3h4m5s TXT (\n\"hello\\032world\" ; comment\n\"\\000\\255\\\"\\\\\"\n)")
	if err != nil || rr.ttl != 788645 || !bytes.Equal(rr.data, []byte{11, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 4, 0, 255, '"', '\\'}) {
		t.Fatal(rr, err)
	}
	for _, s := range []string{
		`rr.test. TXT "unterminated`, `rr.test. TXT ( "a"`, `rr.test. TXT "a" )`,
		`rr.test. TXT (( "a" ))`, `rr.test. TXT "a"junk`, `rr.test. TXT "\999"`, `rr.test. TXT "\12"`,
		`rr.test. TXT trailing\`, `rr.test. 999999999w TXT "a"`, `rr.test. IN IN A 192.0.2.1`,
		`rr.test. 1 2 A 192.0.2.1`, `rr.test. CLASS65536 TXT "a"`, `rr.test. CLASS A 192.0.2.1`,
		`rr.test. A ::ffff:192.0.2.1`, `rr.test. AAAA fe80::1%eth0`, `rr.test. CAA 256 issue "x"`,
		`rr.test. CAA 0 "" "x"`, `rr.test. CAA 0 invalid-tag "x"`, `rr.test. MX 65536 mail.test.`,
		`rr.test. TLSA 256 0 0 AA`, `rr.test. DS 1 8 2 nothex`, `rr.test. DNSKEY 256 3 13 notbase64`,
		`rr.test. TYPE65536 \# 0`, `rr.test. TYPE65280 \# 1 aabb`, `rr.test. TYPE65280 \# 1 ax`,
		`rr.test. NAPTR 1 2 "S" "SIP" "a"`, `rr.test. RRSIG A 13 2 60 20261301000000 20260101000000 1 rr.test. AQID`,
		`rr.test. RRSIG A 13 2 60 22000101000000 20260101000000 1 rr.test. AQID`,
		`rr.test. NSEC3 1 0 1 xyz 0410610 A`, `rr.test. NSEC3 1 0 1 - invalid! A`,
		`rr.test. NSEC3PARAM 1 0 1 - extra`, `rr.test. EUI48 00-11`, `rr.test. SOA ns.test. host.test. 1 1bad 2 3 4`,
		"rr.test. TXT \"" + strings.Repeat("x", 256) + "\"",
	} {
		if _, err := parseTextRecord(s); err == nil {
			t.Fatalf("invalid record accepted: %s", s)
		}
	}
	rr, err = parseTextRecord(`rr.test. TYPE65280 \# 65535 ` + strings.Repeat("AB", 65535))
	if err != nil || len(rr.data) != 65535 {
		t.Fatal("maximum RDATA rejected", err)
	}
	q, _ := makeDNSQuery("rr.test", 65280)
	if _, err = predefinedDNS(q, DNSRule{Answer: []string{`rr.test. TYPE65280 \# 65535 ` + strings.Repeat("AB", 65535)}}); err == nil {
		t.Fatal("oversized DNS message accepted")
	}
}

func TestDNSTextRecordPolicyAndCache(t *testing.T) {
	answer := []string{`rr.test. 60 IN CAA 0 issue "example.com"`, `rr.test. 60 IN TYPE65280 \# 4 DEADBEEF`}
	upstream := dnsTestUpstream(t, "records", func(ctx context.Context, q []byte) []byte {
		b, err := predefinedDNS(q, DNSRule{Answer: answer})
		if err != nil {
			t.Error(err)
		}
		return b
	})
	cfg := Config{DNS: DNSConfig{Servers: []DNSServer{upstream}, Rules: []DNSRule{
		{Rule: Rule{Action: "evaluate"}, Server: "records", Tag: "checked"},
		{Rule: Rule{MatchResponse: "checked", ResponseAnswer: []string{answer[0]}, Action: "respond"}},
		{Rule: Rule{Action: "reject"}},
	}}}
	r := newTestRuntime(t, cfg)
	q, _ := makeDNSQuery("rr.test", 257)
	for range 2 {
		reply, err := r.ExchangeDNS(context.Background(), q, "")
		if err != nil || reply[3]&15 != 0 {
			t.Fatal(err, reply)
		}
		sections, err := dnsRecords(reply)
		if err != nil || len(sections[0]) != 2 {
			t.Fatal(err)
		}
	}
	cfg.DNS.Rules[1].ResponseAnswer = []string{`rr.test. 60 CH CAA 0 issue "example.com"`}
	r = newTestRuntime(t, cfg)
	reply, err := r.ExchangeDNS(context.Background(), q, "")
	if err == nil && reply[3]&15 != 5 {
		t.Fatal("response matcher ignored RR class", err, reply)
	}
}

func TestDNSRecordNameBoundaries(t *testing.T) {
	q, _ := makeDNSQuery("rr.test", 2)
	for _, typ := range []uint16{2, 5, 12, 15, 17, 33, 35, 39, 46, 47} {
		b := dnsResponse(q, len(q)-4, nil, 0, 0)
		binary.BigEndian.PutUint16(b[6:], 1)
		b = append(b, 0xc0, 0x0c)
		b = binary.BigEndian.AppendUint16(b, typ)
		b = append(b, 0, 1, 0, 0, 0, 60, 0, 0)
		if _, err := dnsRecords(b); err == nil {
			t.Fatal("empty name RDATA accepted", typ)
		}
	}
}

func TestDNSNameEscapes(t *testing.T) {
	for n := range 256 {
		wire := []byte{1, byte(n), 4, 't', 'e', 's', 't', 0}
		name, end, err := dnsName(wire, 0)
		if err != nil || end != len(wire) {
			t.Fatal(n, name, err)
		}
		encoded, err := dnsAppendName(nil, name)
		want := bytes.Clone(wire)
		if n >= 'A' && n <= 'Z' {
			want[1] += 'a' - 'A'
		}
		if err != nil || !bytes.Equal(encoded, want) {
			t.Fatal(n, name, err, encoded)
		}
		q, err := makeDNSQuery(name, 1)
		if err != nil {
			t.Fatal(err)
		}
		if host, _, _, err := dnsQuestion(q); err != nil || host != name {
			t.Fatal(n, host, name, err)
		}
	}
	for _, name := range []string{`a\999.test`, `a\12.test`, `a\`, `a..b\046test`, strings.Repeat(`\097`, 64) + ".test"} {
		if _, err := dnsAppendName(nil, name); err == nil {
			t.Fatal("invalid escaped name accepted", name)
		}
	}
}

func TestDNSTextQueryTypes(t *testing.T) {
	for _, fixture := range dnsTextFixtures(t) {
		t.Run(fmt.Sprint(fixture.Type), func(t *testing.T) {
			name := fmt.Sprintf("TYPE%d", fixture.Type)
			for text, typ := range dnsTypeNames {
				if typ == fixture.Type {
					name = text
					break
				}
			}
			encoded, _ := json.Marshal([]any{name, fixture.Type, fmt.Sprintf("TYPE%d", fixture.Type)})
			var values queryTypes
			if err := json.Unmarshal(encoded, &values); err != nil {
				t.Fatal(err)
			}
			if len(values) != 3 || values[0] != fixture.Type || values[1] != fixture.Type || values[2] != fixture.Type {
				t.Fatal(name, values)
			}
		})
	}
	var values queryTypes
	if err := json.Unmarshal([]byte(`"ANY"`), &values); err != nil || len(values) != 1 || values[0] != 255 {
		t.Fatal(values, err)
	}
	for _, text := range []string{`"TYPE65536"`, `"unknown"`, `-1`, `65536`} {
		if json.Unmarshal([]byte(text), new(queryTypes)) == nil {
			t.Fatal("invalid query type accepted", text)
		}
	}
}

func TestDNSTextNetworkReference(t *testing.T) {
	fixtures := dnsTextFixtures(t)
	var answers []string
	for _, fixture := range fixtures {
		answers = append(answers, fixture.Text)
	}
	for _, side := range []string{"native", "official"} {
		t.Run(side, func(t *testing.T) {
			port := unusedPort(t)
			config := Config{Inbounds: []Inbound{
				{Type: "mixed", Tag: "control", Listen: "127.0.0.1", ListenPort: unusedPort(t)},
				{Type: "direct", Tag: "dns", Listen: "127.0.0.1", ListenPort: port},
			}, Route: Route{Rules: []Rule{{Inbound: []string{"dns"}, Action: "hijack-dns"}}},
				DNS: DNSConfig{Rules: []DNSRule{{Rule: Rule{Action: "predefined"}, Answer: answers}}}}
			if side == "native" {
				newTestRuntime(t, config)
			} else {
				shadowReference(t, config)
			}
			for _, transport := range []string{"udp", "tcp"} {
				t.Run(transport, func(t *testing.T) {
					r, err := newResolver(DNSConfig{Servers: []DNSServer{{Tag: "test", Type: transport, Server: "127.0.0.1", ServerPort: port}}})
					if err != nil {
						t.Fatal(err)
					}
					defer r.Close()
					q, _ := makeDNSQuery("rr.test", 257)
					q[11] = 1
					q = append(q, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					reply, err := r.exchange(ctx, q)
					if err != nil {
						t.Fatal(err)
					}
					sections, err := dnsRecords(reply)
					if err != nil || len(sections[0]) != len(fixtures) {
						t.Fatal("network answer count", len(sections[0]), err)
					}
					for i, got := range sections[0] {
						want, err := parseTextRecord(fixtures[i].Text)
						if err != nil || want.name != got.name || want.typ != got.typ || want.class != got.class || !bytes.Equal(want.data, got.data) {
							t.Fatalf("network record%d: %+v vs %+v (%v)", i, want, got, err)
						}
					}
				})
			}
		})
	}
}

func FuzzDNSTextRecord(f *testing.F) {
	for _, fixture := range dnsTextFixtures(f) {
		f.Add(fixture.Text)
	}
	for _, s := range []string{`rr.test. TXT "\999"`, `rr.test. CAA 0 issue "a"`, `rr.test. TYPE65280 \# 0`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		rr, err := parseTextRecord(text)
		if err != nil {
			return
		}
		if len(rr.data) > 65535 {
			t.Fatal("RDATA length overflow")
		}
		q, _ := makeDNSQuery("fuzz.test", 1)
		reply, err := predefinedDNS(q, DNSRule{Answer: []string{text}})
		if err == nil && !strings.Contains(text, `\#`) {
			sections, err := dnsRecords(reply)
			if err != nil || len(sections[0]) != 1 {
				t.Fatal("encoded record failed to decode", err)
			}
		}
	})
}

func FuzzDNSRecords(f *testing.F) {
	for _, fixture := range dnsTextFixtures(f) {
		b, err := hex.DecodeString(fixture.Compressed)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte{0, 0, 0x81, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		sections, err := dnsRecords(b)
		if err != nil {
			return
		}
		for i, section := range sections {
			if len(section) != int(binary.BigEndian.Uint16(b[6+2*i:])) {
				t.Fatal("record count changed")
			}
			for _, rr := range section {
				if rr.ttlOffset < 0 || rr.ttlOffset+4 > len(b) {
					t.Fatal("TTL offset escaped message")
				}
			}
		}
	})
}
