package native

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func browserProfileShape(t *testing.T, record []byte, profile string) ([]byte, []string) {
	t.Helper()
	if len(record) < 9 || record[0] != 22 || record[1] != 3 || record[2] != 1 {
		t.Fatal("invalid record prefix")
	}
	p := stCursor{data: record[9:]}
	version := p.number(2)
	p.take(32)
	sid := p.vector(1)
	suites := bytes.Clone(p.vector(2))
	compression := bytes.Clone(p.vector(1))
	ext := stCursor{data: p.vector(2)}
	if version != 0x0303 || len(sid) != 32 || p.end() != nil {
		t.Fatal("invalid hello")
	}
	grease := func(w uint16) bool { return w&0x0f0f == 0x0a0a && byte(w) == byte(w>>8) }
	normalize := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			if grease(binary.BigEndian.Uint16(b[i:])) {
				b[i], b[i+1] = 0x0a, 0x0a
			}
		}
	}
	normalize(suites)
	var order []string
	var normalized []string
	for len(ext.data) > 0 && ext.err == nil {
		id := uint16(ext.number(2))
		value := bytes.Clone(ext.vector(2))
		label := fmt.Sprintf("%04x", id)
		if grease(id) {
			label = "grease"
		}
		switch id {
		case 10, 13:
			normalize(value[2:])
		case 43:
			normalize(value[1:])
		case 21:
			if !bytes.Equal(value, make([]byte, len(value))) {
				t.Fatal("nonzero padding")
			}
			continue
		case 51:
			q := stCursor{data: value}
			shares := stCursor{data: q.vector(2)}
			value = nil
			for len(shares.data) > 0 && shares.err == nil {
				group := uint16(shares.number(2))
				public := shares.vector(2)
				if grease(group) {
					group = 0x0a0a
				}
				value = binary.BigEndian.AppendUint16(value, group)
				value = binary.BigEndian.AppendUint16(value, uint16(len(public)))
			}
			if q.end() != nil || shares.end() != nil {
				t.Fatal("invalid shares")
			}
		case 0xfe0d:
			q := stCursor{data: value}
			kind, kdf, aead := q.number(1), q.number(2), q.number(2)
			q.take(1)
			enc, payload := q.vector(2), q.vector(2)
			if q.end() != nil || kind != 0 || kdf != 1 || (aead != 1 && aead != 3) || len(enc) != 32 {
				t.Fatal("invalid GREASE ECH")
			}
			if strings.HasPrefix(profile, "chrome") {
				if !slices.Contains([]int{144, 176, 208, 240}, len(payload)) {
					t.Fatal("Chrome ECH padding", len(payload))
				}
			} else if len(payload) != 239 {
				t.Fatal("Firefox ECH padding", len(payload))
			}
			value = []byte{0, 0, 1} // GREASE HPKE suite and length vary between connections.
		}
		order = append(order, label)
		normalized = append(normalized, fmt.Sprintf("%s:%x", label, value))
	}
	if ext.end() != nil {
		t.Fatal("invalid extensions")
	}
	if strings.HasPrefix(profile, "chrome") && profile != "chrome100" {
		slices.Sort(normalized)
	}
	return append(append(suites, compression...), []byte(strings.Join(normalized, ";"))...), order
}

func TestBrowserVersionProfiles(t *testing.T) {
	for _, profile := range browserProfiles {
		if profile == "random" {
			continue
		}
		t.Run(profile, func(t *testing.T) {
			fixture, err := os.ReadFile(filepath.Join("testdata", "browser", profile+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var capture struct{ Record string }
			if err = json.Unmarshal(fixture, &capture); err != nil {
				t.Fatal(err)
			}
			wire, err := base64.StdEncoding.DecodeString(capture.Record)
			if err != nil {
				t.Fatal(err)
			}
			want, wantOrder := browserProfileShape(t, wire, profile)
			for range 5 {
				h, err := newSTHello(&tls.Config{ServerName: "fingerprint.example", NextProtos: []string{"h2", "http/1.1"}})
				if err != nil {
					t.Fatal(err)
				}
				if err = h.initBrowser(profile); err != nil {
					t.Fatal(err)
				}
				msg, err := h.marshal("", nil, false)
				if err != nil {
					t.Fatal(err)
				}
				record := shadowFrame(22, msg)
				record[2] = 1
				got, order := browserProfileShape(t, record, profile)
				if !bytes.Equal(got, want) {
					t.Fatalf("profile differs\ngot %s\nwant %s", got, want)
				}
				if !(strings.HasPrefix(profile, "chrome") && profile != "chrome100") && !reflect.DeepEqual(order, wantOrder) {
					t.Fatalf("extension order %v / %v", order, wantOrder)
				}
			}
		})
	}
}

func TestBrowserFFDHE(t *testing.T) {
	for _, id := range []tls.CurveID{256, 257} {
		t.Run(id.String(), func(t *testing.T) {
			a, err := newBrowserFFDHE(id)
			if err != nil {
				t.Fatal(err)
			}
			b, err := newBrowserFFDHE(id)
			if err != nil {
				t.Fatal(err)
			}
			primeBytes := make([]byte, len(a.group.modulus)*8)
			for i, v := range a.group.modulus {
				binary.BigEndian.PutUint64(primeBytes[len(primeBytes)-(i+1)*8:], v)
			}
			p := new(big.Int).SetBytes(primeBytes)
			want := new(big.Int).Exp(big.NewInt(2), new(big.Int).SetBytes(a.private), p).FillBytes(make([]byte, len(primeBytes)))
			if !bytes.Equal(a.public, want) {
				t.Fatal("public key differs from arithmetic oracle")
			}
			aa, err := a.shared(b.public)
			if err != nil {
				t.Fatal(err)
			}
			bb, err := b.shared(a.public)
			if err != nil || !bytes.Equal(aa, bb) {
				t.Fatal("DH differs", err)
			}
			for range 16 {
				base, _ := rand.Int(rand.Reader, p)
				exponent := make([]byte, 48)
				rand.Read(exponent)
				got := a.group.power(base.FillBytes(make([]byte, len(primeBytes))), exponent)
				want := new(big.Int).Exp(base, new(big.Int).SetBytes(exponent), p).FillBytes(make([]byte, len(primeBytes)))
				if !bytes.Equal(got, want) {
					t.Fatal("modular power differs")
				}
			}
			for _, v := range []*big.Int{big.NewInt(0), big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1)), p} {
				key, err := newBrowserFFDHE(id)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = key.shared(v.FillBytes(make([]byte, len(primeBytes)))); err == nil {
					t.Fatal("invalid public accepted")
				}
			}
		})
	}
}

func TestBrowserModernEntropy(t *testing.T) {
	var firstOrder []uint16
	changed := false
	for i := range 16 {
		h, err := newSTHello(&tls.Config{ServerName: "example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if err = h.initBrowser("Chrome150"); err != nil {
			t.Fatal(err)
		}
		if h.browser != "chrome150" || bytes.Equal(h.key.PublicKey().Bytes(), h.fallback.PublicKey().Bytes()) {
			t.Fatal("Chrome hybrid shares must use independent classical keys")
		}
		if i == 0 {
			firstOrder = slices.Clone(h.extensions)
		} else if !reflect.DeepEqual(firstOrder, h.extensions) {
			changed = true
		}
	}
	if !changed {
		t.Fatal("Chrome extension order was fixed")
	}
	for _, name := range []string{"Firefox148", "Random"} {
		h, err := newSTHello(new(tls.Config))
		if err != nil {
			t.Fatal(err)
		}
		if err = h.initBrowser(name); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(h.key.PublicKey().Bytes(), h.fallback.PublicKey().Bytes()) || h.additional[tls.CurveP256] == nil {
			t.Fatal("Firefox hybrid/classical/P256 shares")
		}
	}
	for name, want := range map[string]string{"Chrome": "chrome150", "Firefox": "firefox148", "Random": "random"} {
		options := TLSOptions{Enabled: true, UTLS: &BrowserTLSOptions{Enabled: true, Fingerprint: name}}
		if err := options.validateBrowser(false); err != nil {
			t.Fatal(err)
		}
		h, err := newSTHello(new(tls.Config))
		if err != nil {
			t.Fatal(err)
		}
		if err = h.initBrowser(name); err != nil || h.browser != want {
			t.Fatal(name, h.browser, err)
		}
	}
}
