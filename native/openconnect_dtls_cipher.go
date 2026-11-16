package native

import (
	"errors"
	"net/http"
	"slices"
	"strings"
)

type ocDTLSSuite struct {
	name string
	id   uint16
}

var ocDTLSSuites = [...]ocDTLSSuite{
	{"PSK-AES128-GCM-SHA256", 0x00a8},
	{"PSK-AES256-GCM-SHA384", 0x00a9},
	{"PSK-CHACHA20-POLY1305", 0xccab},
	{"PSK-AES128-CCM", 0xc0a4},
	{"PSK-AES256-CCM", 0xc0a5},
	{"PSK-AES128-CCM8", 0xc0a8},
	{"PSK-AES256-CCM8", 0xc0a9},
	{"PSK-AES128-CBC-SHA", 0x008c},
	{"PSK-AES256-CBC-SHA", 0x008d},
	{"PSK-AES128-CBC-SHA256", 0x00ae},
	{"PSK-AES256-CBC-SHA384", 0x00af},
}

var ocDTLSDefaults = []uint16{0x00a8, 0x00a9, 0xccab, 0xc0a4, 0xc0a5}

func ocDTLSCipherIDs(names []string) ([]uint16, error) {
	if names == nil {
		return ocDTLSDefaults, nil
	}
	if len(names) == 0 || len(names) > len(ocDTLSSuites) {
		return nil, errors.New("OpenConnect dtls_cipher_suites requires 1-11 suites")
	}
	ids := make([]uint16, 0, len(names))
	for _, name := range names {
		at := slices.IndexFunc(ocDTLSSuites[:], func(s ocDTLSSuite) bool { return s.name == name })
		if at < 0 || slices.Contains(ids, ocDTLSSuites[at].id) {
			return nil, errors.New("unknown or duplicate OpenConnect DTLS cipher suite")
		}
		ids = append(ids, ocDTLSSuites[at].id)
	}
	return ids, nil
}

func (d *ocDTLS) cipherIDs() []uint16 {
	if d.suites == nil {
		return ocDTLSDefaults
	}
	return d.suites
}

func (d *ocDTLS) recordLimit() uint64 {
	if d.resume != nil && d.resume.suite == 0x000a {
		return 1024 // Bound each legacy 64-bit block-cipher key to at most16MiB.
	}
	switch d.suite {
	case 0xccab:
		return 1 << 36
	case 0xc0a8, 0xc0a9:
		return 1 << 20
	default:
		return 1 << 24
	}
}

func (o OpenConnectOptions) dtlsCipherIDs() ([]uint16, error) {
	if o.dtlsResume() {
		return o.resumeCipherIDs()
	}
	if o.DTLSVersion != "1.3" {
		return ocDTLSCipherIDs(o.DTLSCipherSuites)
	}
	defaults := []uint16{0x1301, 0x1303, 0x1302}
	if o.DTLSCipherSuites == nil {
		return defaults, nil
	}
	names := []string{"TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_256_GCM_SHA384"}
	if len(o.DTLSCipherSuites) == 0 || len(o.DTLSCipherSuites) > 3 {
		return nil, errors.New("DTLS1.3 requires 1-3 cipher suites")
	}
	var ids []uint16
	for _, name := range o.DTLSCipherSuites {
		at := slices.Index(names, name)
		if at < 0 || slices.Contains(ids, defaults[at]) {
			return nil, errors.New("unknown or duplicate DTLS1.3 cipher suite")
		}
		ids = append(ids, defaults[at])
	}
	return ids, nil
}
func (o OpenConnectOptions) dtlsNegotiation() string {
	if o.dtlsResume() {
		ids, _ := o.dtlsCipherIDs()
		names := make([]string, 0, len(ids))
		for _, id := range ids {
			names = append(names, ocDTLSResumeName(id))
		}
		return strings.Join(names, ":")
	}
	if o.DTLSVersion == "1.3" {
		return "LANBOAT-DTLS13-PSK"
	}
	return "PSK-NEGOTIATE"
}

func (o OpenConnectOptions) dtlsCipherHeader() string {
	if o.dtlsResume() && o.DTLSVersion != "0.9" {
		return "X-DTLS12-CipherSuite"
	}
	return "X-DTLS-CipherSuite"
}

// The pre-Cisco1.2 names are carried in the original X-DTLS header.
func ocDTLSOldResumeName(id uint16) string {
	switch id {
	case 0x009c:
		return "OC-DTLS1_2-AES128-GCM"
	case 0x009d:
		return "OC-DTLS1_2-AES256-GCM"
	case 0xccab:
		return "OC2-DTLS1_2-CHACHA20-POLY1305"
	}
	return ""
}
func (o OpenConnectOptions) dtlsSelected(h http.Header) uint16 {
	ids, _ := o.dtlsCipherIDs()
	name := h.Get(o.dtlsCipherHeader())
	for _, id := range ids {
		if name != "" && ocDTLSResumeName(id) == name {
			return id
		}
		if name == "" && o.dtlsResume() && o.DTLSVersion != "0.9" && ocDTLSOldResumeName(id) != "" && h.Get("X-DTLS-CipherSuite") == ocDTLSOldResumeName(id) {
			return id
		}
	}
	return 0
}
func (o OpenConnectOptions) dtlsOffer(h http.Header) {
	h[o.dtlsCipherHeader()] = []string{o.dtlsNegotiation()}
	if o.dtlsResume() && o.DTLSVersion != "0.9" {
		ids, _ := o.dtlsCipherIDs()
		var names []string
		for _, id := range ids {
			if name := ocDTLSOldResumeName(id); name != "" {
				names = append(names, name)
			}
		}
		if len(names) != 0 {
			h["X-DTLS-CipherSuite"] = []string{strings.Join(names, ":")}
		}
	}
}
func (o OpenConnectOptions) dtlsAccepted(h http.Header) bool {
	if o.dtlsResume() {
		return o.dtlsSelected(h) != 0
	}
	return h.Get("X-DTLS-CipherSuite") == o.dtlsNegotiation()
}
