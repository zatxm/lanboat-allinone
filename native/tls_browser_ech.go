package native

import (
	"bytes"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"encoding"
	"encoding/binary"
	"errors"
	"hash"
	"strings"
)

type browserECH struct {
	config                  echConfig
	sender                  *hpke.Sender
	enc, outerRandom, inner []byte
}

func (h *stClientHello) initECH() error {
	if !echDomain(strings.TrimSuffix(h.config.ServerName, ".")) {
		return errors.New("browser ECH requires an inner DNS server_name")
	}
	list := h.config.EncryptedClientHelloConfigList
	if err := validateECHList(list); err != nil {
		return err
	}
	r := echReader{b: list[2:]}
	for len(r.b) != 0 {
		before := r.b
		r.u16()
		r.vec()
		c, err := parseECHConfig(before[:len(before)-len(r.b)])
		if err != nil {
			return err
		}
		if !c.usable {
			continue
		}
		public, err := c.kem.NewPublicKey(c.public)
		if err != nil {
			return err
		}
		enc, sender, err := hpke.NewSender(public, c.kdf, c.aead, append([]byte("tls ech\x00"), c.raw...))
		if err != nil {
			return err
		}
		h.ech = &browserECH{config: c, sender: sender, enc: enc, outerRandom: make([]byte, 32)}
		rand.Read(h.ech.outerRandom)
		return nil
	}
	return errors.New("browser ECH has no supported configuration")
}

func browserHelloExtensions(message []byte, change func(uint16, []byte) []byte) ([]byte, error) {
	p := stCursor{data: message[4:]}
	p.take(34)
	p.vector(1)
	p.vector(2)
	p.vector(1)
	start := len(message) - len(p.data)
	ext := stCursor{data: p.vector(2)}
	if p.end() != nil {
		return nil, errors.New("invalid browser ClientHello")
	}
	var extensions []byte
	seen := false
	for len(ext.data) != 0 && ext.err == nil {
		id := uint16(ext.number(2))
		value := ext.vector(2)
		if id == 0xfe0d {
			seen = true
		}
		if value = change(id, value); value != nil {
			extensions = stExtension(extensions, id, value)
		}
	}
	if err := ext.end(); err != nil {
		return nil, err
	}
	if !seen {
		extensions = stExtension(extensions, 0xfe0d, change(0xfe0d, nil))
	}
	return stMessage(1, append(bytes.Clone(message[4:start]), stVector(extensions, 2)...)), nil
}

func (e *browserECH) seal(h *stClientHello, plain []byte) ([]byte, error) {
	inner, err := browserHelloExtensions(plain, func(id uint16, value []byte) []byte {
		switch id {
		case 0xfe0d:
			return []byte{1}
		case 43:
			return []byte{2, 3, 4}
		case 35, 21:
			return nil
		}
		return append([]byte{}, value...)
	})
	if err != nil {
		return nil, err
	}
	e.inner = inner
	// EncodedClientHelloInner omits the handshake header and session ID.
	sid := int(inner[38])
	encoded := append(bytes.Clone(inner[4:38]), 0)
	encoded = append(encoded, inner[39+sid:]...)
	p := stCursor{data: encoded}
	p.take(34)
	p.vector(1)
	p.vector(2)
	p.vector(1)
	start := len(encoded) - len(p.data)
	extensions := stCursor{data: p.vector(2)}
	var compressed []byte
	for len(extensions.data) != 0 && extensions.err == nil {
		id := uint16(extensions.number(2))
		value := extensions.vector(2)
		if id == 51 {
			id = 0xfd00
			value = []byte{2, 0, 51}
		}
		compressed = stExtension(compressed, id, value)
	}
	if p.end() != nil || extensions.end() != nil {
		return nil, errors.New("invalid ECH inner extensions")
	}
	encoded = append(bytes.Clone(encoded[:start]), stVector(compressed, 2)...)
	padding := max(0, int(e.config.nameLength)-len(strings.TrimSuffix(h.config.ServerName, ".")))
	encoded = append(encoded, make([]byte, padding)...)
	encoded = append(encoded, make([]byte, (32-len(encoded)%32)%32)...)
	var ech []byte
	ech = append(ech, 0)
	ech = binary.BigEndian.AppendUint16(ech, e.config.kdf.ID())
	ech = binary.BigEndian.AppendUint16(ech, e.config.aead.ID())
	ech = append(ech, e.config.id)
	ech = append(ech, stVector(e.enc, 2)...)
	ech = append(ech, stVector(make([]byte, len(encoded)+16), 2)...)
	outer, err := browserHelloExtensions(plain, func(id uint16, value []byte) []byte {
		switch id {
		case 0:
			return stVector(append([]byte{0}, stVector([]byte(e.config.name), 2)...), 2)
		case 0xfe0d:
			return ech
		case 16:
			return []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
		case 21:
			return nil
		}
		return append([]byte{}, value...)
	})
	if err != nil {
		return nil, err
	}
	copy(outer[6:38], e.outerRandom)
	ciphertext, err := e.sender.Seal(outer[4:], encoded)
	clear(encoded)
	if err != nil {
		return nil, err
	}
	copy(ech[len(ech)-len(ciphertext):], ciphertext)
	outer, err = browserHelloExtensions(outer, func(id uint16, value []byte) []byte {
		if id == 0xfe0d {
			return ech
		}
		return append([]byte{}, value...)
	})
	e.enc = nil
	return outer, err
}

func (e *browserECH) confirm(s stCipherSuite, transcript hash.Hash, sh []byte, retry bool) error {
	zeroed := bytes.Clone(sh)
	var confirmation []byte
	label := "ech accept confirmation"
	if retry {
		label = "hrr ech accept confirmation"
		p := stCursor{data: zeroed[4:]}
		p.take(34)
		p.vector(1)
		p.take(3)
		ext := stCursor{data: p.vector(2)}
		if p.end() != nil {
			return errors.New("invalid ECH retry")
		}
		for len(ext.data) != 0 && ext.err == nil {
			id := ext.number(2)
			value := ext.vector(2)
			if id == 0xfe0d {
				confirmation = bytes.Clone(value)
				clear(value)
			}
		}
		if ext.end() != nil {
			return errors.New("invalid ECH retry extensions")
		}
	} else if len(sh) >= 38 {
		confirmation = bytes.Clone(sh[30:38])
		clear(zeroed[30:38])
	}
	if len(confirmation) != 8 {
		return &tls.ECHRejectionError{}
	}
	state, err := transcript.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return err
	}
	t := s.newHash()
	if err = t.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		return err
	}
	if retry {
		first := t.Sum(nil)
		t.Reset()
		t.Write(stMessage(254, first))
	}
	t.Write(zeroed)
	secret := s.extract(make([]byte, s.hash.Size()), e.inner[6:38])
	defer clear(secret)
	want := s.expand(secret, label, t.Sum(nil), 8)
	if !bytes.Equal(confirmation, want) {
		return &tls.ECHRejectionError{}
	}
	return nil
}
