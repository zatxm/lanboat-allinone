package native

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestBrowserCertificateCodecs(t *testing.T) {
	for _, algorithm := range []string{"brotli", "zstd"} {
		t.Run(algorithm, func(t *testing.T) {
			message, err := os.ReadFile(filepath.Join("testdata", "browser", "certificate-"+algorithm+".bin"))
			if err != nil {
				t.Fatal(err)
			}
			want := bytes.Repeat([]byte("certificate-body"), 128)
			got, err := browserCertificate(message)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("decode reference", err)
			}
			header := bytes.Clone(message[4:9])
			compressed := bytes.Clone(message[12:])
			build := func(header, body []byte) []byte {
				return stMessage(25, append(bytes.Clone(header), stVector(body, 3)...))
			}
			for _, mode := range []string{"truncated", "trailing", "expanded", "short", "zero", "huge", "algorithm"} {
				t.Run(mode, func(t *testing.T) {
					h, b := bytes.Clone(header), bytes.Clone(compressed)
					switch mode {
					case "truncated":
						b = b[:len(b)-1]
					case "trailing":
						b = append(b, 0xff, 0)
					case "expanded":
						h[2], h[3], h[4] = 0, 0, 1
					case "short":
						h[4]++
					case "zero":
						clear(h[2:])
					case "huge":
						h[2], h[3], h[4] = 0x10, 0, 1
					case "algorithm":
						binary.BigEndian.PutUint16(h, 4)
					}
					if _, err = browserCertificate(build(h, b)); err == nil {
						t.Fatal("invalid certificate compression accepted")
					}
				})
			}
		})
	}
}
