package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestChromiumHTTPReferenceCapture(t *testing.T) {
	data, err := os.ReadFile("testdata/chromium-http/h2-154.json")
	if err != nil {
		t.Fatal(err)
	}
	var frames []struct {
		Type, Flags, Stream int
		Payload             string
	}
	if err = json.Unmarshal(data, &frames); err != nil {
		t.Fatal(err)
	}
	decoder := masqueHPACK{limit: 4096}
	for _, frame := range frames {
		if frame.Type != 1 {
			continue
		}
		wire, err := hex.DecodeString(frame.Payload)
		if err != nil {
			t.Fatal(err)
		}
		block, err := masqueHeaderFragment(masqueH2Frame(1, byte(frame.Flags), uint32(frame.Stream), wire))
		if err != nil {
			t.Fatal(err)
		}
		fields, err := decoder.decode(block)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("captured Chromium HTTP2 headers", frame.Stream, fields)
	}
}

func TestChromiumHTTP2PreambleProfile(t *testing.T) {
	r := newTestRuntime(t, Config{})
	var wire bytes.Buffer
	preamble := chromiumPreamble(Outbound{Server: "example.com", ServerPort: 443})
	m, err := newNaiveH2Session(r, &memoryNetConn{Reader: bytes.NewReader(nil), Writer: &wire}, preamble)
	if err != nil {
		t.Fatal(err)
	}
	defer m.fail(net.ErrClosed)
	encoded := wire.Bytes()
	if !bytes.HasPrefix(encoded, []byte(masqueH2Preface)) {
		t.Fatal("missing preface")
	}
	encoded = encoded[len(masqueH2Preface):]
	n := int(encoded[0])<<16 | int(encoded[1])<<8 | int(encoded[2])
	want, _ := hex.DecodeString("000100010000000200000000000404000000000600040000")
	if encoded[3] != 4 || !bytes.Equal(encoded[9:9+n], want) {
		t.Fatal("SETTINGS differ from Chromium capture", encoded[:9+n])
	}
	encoded = encoded[9+n:]
	if encoded[3] != 8 || binary.BigEndian.Uint32(encoded[9:13]) != 0x07ff0001 {
		t.Fatal("connection window differs from capture")
	}
	encoded = encoded[13:]
	if encoded[3] != 1 || encoded[4] != 0x25 || binary.BigEndian.Uint32(encoded[5:9]) != 1 || !bytes.Equal(encoded[9:14], []byte{0x80, 0, 0, 0, 255}) {
		t.Fatal("preamble stream/priority differs from capture")
	}
	fragment, err := masqueHeaderFragment(encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoder := masqueHPACK{limit: 4096}
	decoded, err := decoder.decode(fragment)
	if err != nil || !reflect.DeepEqual(decoded, preamble) {
		t.Fatal("preamble headers changed", decoded, err)
	}
	for _, field := range decoded {
		if field[0] == "authorization" || field[0] == "proxy-authorization" {
			t.Fatal("preamble contains credentials")
		}
	}
	if runtime.GOOS == "linux" {
		if decoded[6][1] != `"Linux"` || decoded[8][1] != "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36" {
			t.Fatal("Linux browser headers differ")
		}
	}
}

func TestChromiumHTTP2BufferBudget(t *testing.T) {
	var budget naiveBufferBudget
	session, stream := make(chan struct{}), make(chan struct{})
	if err := budget.reserve(naiveBufferedLimit, session, stream); err != nil {
		t.Fatal(err)
	}
	blocked := make(chan error, 1)
	go func() { blocked <- budget.reserve(1, session, stream) }()
	select {
	case <-blocked:
		t.Fatal("budget exceeded")
	case <-time.After(5 * time.Millisecond):
	}
	budget.release(1)
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reader was not resumed")
	}
	go func() { blocked <- budget.reserve(1, session, stream) }()
	close(stream)
	select {
	case err := <-blocked:
		if err == nil {
			t.Fatal("cancelled stream reserved memory")
		}
	case <-time.After(time.Second):
		t.Fatal("stream cancellation did not resume reader")
	}
	budget.release(naiveBufferedLimit)
	if budget.used != 0 {
		t.Fatal("receive memory leaked", budget.used)
	}
	m, _ := naiveH2Memory(t)
	s, _ := m.open(context.Background())
	s.ready = true
	m.bufferBudget = &budget
	if err := m.receiveFrame(0, 0, s.id, []byte("buffered")); err != nil {
		t.Fatal(err)
	}
	if budget.used != len("buffered") {
		t.Fatal("payload was not charged", budget.used)
	}
	s.close()
	if budget.used != 0 {
		t.Fatal("closed stream retained memory", budget.used)
	}
}

func TestChromiumHTTP3CapturedSettings(t *testing.T) {
	data, err := os.ReadFile("testdata/chromium-http/h3-154.json")
	if err != nil {
		t.Fatal(err)
	}
	var frames []struct {
		Stream, Kind uint64
		Payload      string
	}
	if err = json.Unmarshal(data, &frames); err != nil {
		t.Fatal(err)
	}
	parse := func(b []byte) [][2]uint64 {
		r := quicReader(b)
		var result [][2]uint64
		for len(r) > 0 {
			key, err := r.v()
			if err != nil {
				t.Fatal(err)
			}
			value, err := r.v()
			if err != nil {
				t.Fatal(err)
			}
			result = append(result, [2]uint64{key, value})
		}
		return result
	}
	var reference [][2]uint64
	for _, frame := range frames {
		wire, err := hex.DecodeString(frame.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Kind == 4 {
			reference = parse(wire)
			continue
		}
		if frame.Kind != 1 || frame.Stream != 0 {
			continue
		}
		required, base, fields, err := qpackBase(wire, 0, 65536)
		if err != nil || required != 0 {
			t.Fatal(required, base, err)
		}
		decoder := chromiumQPACKTable{}
		decoded, err := decoder.decode(fields, base, required)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded) < 2 || decoded[0] != [2]string{":method", "GET"} {
			t.Fatal("missing captured GET", decoded)
		}
		decoded[1][1] = "example.com"
		if runtime.GOOS == "linux" && !reflect.DeepEqual(decoded, chromiumPreamble(Outbound{Server: "example.com", ServerPort: 443})) {
			t.Fatal("preamble differs from real Chromium HTTP3", decoded)
		}
	}
	ours := parse(chromiumH3Settings())
	if len(reference) != 5 || len(ours) != 5 || !reflect.DeepEqual(reference[:4], ours[:4]) {
		t.Fatal("HTTP3 settings differ", reference, ours)
	}
	if ours[4][0] < 33 || (ours[4][0]-33)%31 != 0 {
		t.Fatal("invalid GREASE setting", ours[4])
	}
}

func TestChromiumHTTPCompression(t *testing.T) {
	fields := [][2]string{{":method", "CONNECT"}, {":authority", "proxy.example.com:443"}, {"padding", "XXXXXXXXXXXXXXXXXXXXXXXX"}, {"proxy-authorization", "Basic cHJpdmF0ZQ=="}, {"x-profile", "chromium154"}}
	encoder := chromiumHPACK{limit: 4096}
	decoder := masqueHPACK{limit: 4096}
	first := encoder.encode(fields, 4096)
	if _, err := decoder.decode(first); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		wire := encoder.encode(fields, 4096)
		if len(wire) >= len(first) {
			t.Fatal("compression context not reused")
		}
		decoded, err := decoder.decode(wire)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, fields) {
			t.Fatal("HPACK changed headers", decoded)
		}
		for _, entry := range encoder.table {
			if entry[0] == "proxy-authorization" {
				t.Fatal("credential entered dynamic table")
			}
		}
	}
	encoder.resize(0)
	encoder.resize(4096)
	wire := encoder.encode(fields, 4096)
	if len(wire) == 0 || wire[0] != 0x20 {
		t.Fatal("intermediate table eviction omitted", wire)
	}
	decoded, err := decoder.decode(wire)
	if err != nil || !reflect.DeepEqual(decoded, fields) {
		t.Fatal("table shrink and restore desynchronized decoder", decoded, err)
	}
	decoded, err = decoder.decode(encoder.encode(fields, 0))
	if err != nil || !reflect.DeepEqual(decoded, fields) || len(encoder.table) != 0 {
		t.Fatal("peer table shrink not respected", decoded, err)
	}
	qpack := chromiumQPACK(fields)
	headers, err := h3Decode(qpack)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range fields {
		if headers[field[0]] != field[1] {
			t.Fatal("QPACK changed headers", field, headers)
		}
	}
	frames := chromiumH2Headers(3, []byte{0x82})
	if frames[4] != 0x24 || !bytes.Equal(frames[9:14], []byte{0x80, 0, 0, 0, 146}) {
		t.Fatal("Chromium CONNECT priority differs from capture", frames)
	}
}
func TestChromiumHTTPHuffman(t *testing.T) {
	for _, value := range []string{"proxy.example.com", "https://example.com/a?q=abc", "", strings.Repeat("compression", 500), "中文UTF8"} {
		wire := httpHeaderText(nil, value, 7, 0)
		reader := quicReader(wire)
		decoded, err := h3ReadText(&reader, 7, 0x80)
		if err != nil || decoded != value || len(reader) != 0 {
			t.Fatal("HTTP Huffman round trip", value, decoded, err)
		}
	}
}
