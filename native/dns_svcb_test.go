package native

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"strings"
	"testing"
)

func TestDNSSVCBText(t *testing.T) {
	config, _ := testECHPair(t)
	block, _ := pem.Decode([]byte(config))
	for _, typ := range []string{"SVCB", "HTTPS"} {
		text := `ech.test. 123 IN ` + typ + ` 1 . ipv6hint=2001:db8::1 port=8443 alpn="h2,h3" ech=` + base64.StdEncoding.EncodeToString(block.Bytes) + ` mandatory=ech,alpn ipv4hint=192.0.2.1 no-default-alpn dohpath="/dns-query{?dns}" key123=opaque`
		rr, err := parseTextRecord(text)
		if err != nil {
			t.Fatal(err)
		}
		s, err := parseSVCB(rr.data)
		if err != nil || s.priority != 1 || s.target != "" || len(s.params) != 9 || !s.echUsable() {
			t.Fatalf("SVCB: %+v,%v", s, err)
		}
		if binary.BigEndian.Uint16(s.params[3]) != 8443 || len(s.params[4]) != 4 || len(s.params[6]) != 16 || string(s.params[7]) != "/dns-query{?dns}" {
			t.Fatal("wrong SVCB values")
		}
	}
	for _, value := range []string{
		`1 . alpn=h2 alpn=h3`, `1 . mandatory=ech`, `1 . mandatory=mandatory`, `1 . no-default-alpn`, `1 . no-default-alpn=bad`,
		`1 . alpn=`, `1 . ipv4hint=::1`, `1 . ipv6hint=192.0.2.1`, `1 . ipv6hint=fe80::1%eth0`, `1 . port=65536`, `1 . ech=invalid`,
		`65536 .`, `1 bad..name`, `1 . unknown=foo`, `1 . key99999=foo`, `1 . dohpath="broken`,
	} {
		if _, err := parseTextRecord("ech.test. HTTPS " + value); err == nil {
			t.Fatalf("invalid SVCB accepted: %s", value)
		}
	}
	if _, err := parseSVCB([]byte{0, 1, 0xc0, 0}); err == nil {
		t.Fatal("compressed SVCB target accepted")
	}
	rr, err := parseTextRecord(`ech.test. HTTPS 1 . alpn="h2\\,test,h3" key123="hello\032world"`)
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseSVCB(rr.data)
	if err != nil || string(s.params[123]) != "hello world" || string(s.params[1][1:8]) != "h2,test" {
		t.Fatalf("SVCB escapes: %+v,%v", s, err)
	}
	rr, err = parseTextRecord(`ech.test. HTTPS 1 . key1="\002h2"`)
	if err != nil {
		t.Fatal(err)
	}
	s, err = parseSVCB(rr.data)
	if err != nil || string(s.params[1]) != "\x02h2" {
		t.Fatal("opaque numbered-key encoding", err)
	}
	if _, err := parseTextRecord("ech.test. HTTPS 1 . key123=" + strings.Repeat("x", 65536)); err == nil {
		t.Fatal("oversized SVCB accepted")
	}
}
