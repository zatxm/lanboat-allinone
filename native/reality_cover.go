package native

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
)

var errRealityCoverShape = errors.New("Reality cover handshake cannot fit the authenticated flight")

type realityCover struct {
	hello, wire         []byte
	helloSizes, lengths []int
	suite               stCipherSuite
	group               tls.CurveID
}

func realityClientParameters(hello []byte) (*stClientHello, map[uint16][]byte, error) {
	if _, _, err := realityHelloData(hello); err != nil {
		return nil, nil, err
	}
	p := stCursor{data: hello[71:]}
	suites := p.vector(2)
	p.vector(1)
	raw := p.vector(2)
	if p.end() != nil || len(suites)%2 != 0 {
		return nil, nil, errors.New("invalid Reality cipher offer")
	}
	h := &stClientHello{session: hello[39:71]}
	for len(suites) > 0 {
		h.suites = append(h.suites, binary.BigEndian.Uint16(suites))
		suites = suites[2:]
	}
	ext, err := stExtensions(raw)
	return h, ext, err
}

// Learn from this connection's actual cover response, retaining every byte for
// transparent forwarding if the selected TLS shape cannot be reproduced.
func readRealityCover(remote io.Reader, hello []byte) (*realityCover, error) {
	c := &realityCover{}
	h, offered, err := realityClientParameters(hello)
	if err != nil {
		return c, err
	}
	var buffer [5 + shadowRecordLimit]byte
	read := func() ([]byte, error) {
		frame, err := shadowReadRecord(remote, buffer[:])
		if err != nil {
			return nil, err
		}
		if len(c.wire)+len(frame) > 65536 {
			return nil, errors.New("Reality cover flight exceeds64KiB")
		}
		c.wire = append(c.wire, frame...)
		return frame, nil
	}
	for len(c.helloSizes) < 8 {
		frame, err := read()
		if err != nil {
			return c, err
		}
		if frame[0] != 22 || frame[1] != 3 || frame[2] != 3 {
			return c, errors.New("Reality cover requires TLS1.3 ServerHello")
		}
		c.hello = append(c.hello, frame[5:]...)
		c.helloSizes = append(c.helloSizes, len(frame)-5)
		if len(c.hello) < 4 {
			continue
		}
		size := 4 + (int(c.hello[1])<<16 | int(c.hello[2])<<8 | int(c.hello[3]))
		if size > 8192 || size < len(c.hello) {
			return c, errors.New("invalid Reality cover ServerHello size")
		}
		if len(c.hello) != size {
			continue
		}
		suite, ext, retry, err := stServerParameters(c.hello, h)
		if err != nil {
			return c, err
		}
		if retry {
			return c, errors.New("Reality cover requested a key-share retry")
		}
		share := stCursor{data: ext[51]}
		c.group = tls.CurveID(share.number(2))
		key := share.vector(2)
		if share.end() != nil || c.group != tls.X25519 && c.group != tls.X25519MLKEM768 || c.group == tls.X25519 && len(key) != 32 || c.group == tls.X25519MLKEM768 && len(key) != 1120 {
			return c, errors.New("invalid Reality cover key share")
		}
		shares := stCursor{data: offered[51]}
		list := stCursor{data: shares.vector(2)}
		found := false
		for len(list.data) > 0 && list.err == nil {
			group := tls.CurveID(list.number(2))
			list.vector(2)
			found = found || group == c.group
		}
		if !found {
			return c, errors.New("Reality cover chose an unoffered key share")
		}
		c.suite = suite
		break
	}
	if c.suite.id == 0 {
		return c, errors.New("incomplete Reality cover ServerHello")
	}
	frame, err := read()
	if err != nil {
		return c, err
	}
	if !bytes.Equal(frame, []byte{20, 3, 3, 0, 1, 1}) {
		return c, errors.New("Reality cover requires compatibility CCS")
	}
	for len(c.lengths) < 4 {
		frame, err = read()
		if err != nil {
			return c, err
		}
		if frame[0] != 23 || frame[1] != 3 || frame[2] != 3 || len(frame) > 16406 || len(frame) < 22 {
			return c, errors.New("invalid Reality cover encrypted record")
		}
		c.lengths = append(c.lengths, len(frame))
		// TLS servers emit four handshake records, or coalesce them into one.
		if len(c.lengths) == 1 && len(frame) > 512 {
			break
		}
	}
	return c, nil
}

func realityPaddedRecord(cipher *stRecordCipher, kind byte, data []byte, size int) ([]byte, error) {
	innerSize := size - 5 - cipher.aead.Overhead()
	if innerSize < len(data)+1 || innerSize > 16385 {
		return nil, errRealityCoverShape
	}
	nonce, err := cipher.nonce()
	if err != nil {
		return nil, err
	}
	inner := make([]byte, innerSize)
	copy(inner, data)
	inner[len(data)] = kind
	header := []byte{23, 3, 3, byte((size - 5) >> 8), byte(size - 5)}
	return cipher.aead.Seal(header, nonce, inner, header), nil
}

func (c *realityCover) flight(cipher *stRecordCipher, messages [][]byte) ([]byte, error) {
	var out []byte
	if len(c.lengths) == 1 {
		all := bytes.Join(messages, nil)
		return realityPaddedRecord(cipher, 22, all, c.lengths[0])
	}
	if len(c.lengths) != len(messages) {
		return nil, errRealityCoverShape
	}
	for i, msg := range messages {
		record, err := realityPaddedRecord(cipher, 22, msg, c.lengths[i])
		if err != nil {
			return nil, err
		}
		out = append(out, record...)
	}
	return out, nil
}

func (c *realityCover) writeHello(w io.Writer, hello []byte) error {
	for _, size := range c.helloSizes {
		if err := writeAll(w, shadowFrame(22, hello[:size])); err != nil {
			return err
		}
		hello = hello[size:]
	}
	return writeAll(w, []byte{20, 3, 3, 0, 1, 1})
}
