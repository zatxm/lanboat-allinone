package native

import (
	"bytes"
	"testing"
)

func FuzzDNSQUICAndJuicity(f *testing.F) {
	q, _ := makeDNSQuery("example.test", 1)
	q[0], q[1] = 0, 0
	f.Add(append([]byte{0, byte(len(q))}, q...))
	var b bytes.Buffer
	h3WriteFrame(&b, 1, h3Encode([][2]string{{":method", "POST"}, {":scheme", "https"}, {":authority", "example.test"}, {":path", "/dns-query"}, {"content-type", "application/dns-message"}}))
	h3WriteFrame(&b, 0, q)
	f.Add(b.Bytes())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			return
		}
		readDoQMessage(bytes.NewReader(b))
		readDNSH3Message(bytes.NewReader(b))
		readDoQOrH3(bytes.NewReader(b), true)
		readJuicityPacket(bytes.NewReader(b))
		readJuicityAddress(bytes.NewReader(b))
	})
}
