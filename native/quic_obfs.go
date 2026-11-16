package native

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
)

type Obfuscation string
type quicObfsOptions struct {
	Type          string `json:"type"`
	Password      string `json:"password,omitempty"`
	Host          string `json:"host,omitempty"`
	Path          string `json:"path,omitempty"`
	MinPacketSize int    `json:"min_packet_size,omitempty"`
	MaxPacketSize int    `json:"max_packet_size,omitempty"`
}

func (o *Obfuscation) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '{' {
		var v quicObfsOptions
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if e := d.Decode(&v); e != nil {
			return e
		}
		quic := v.Type == "salamander" || v.Type == "gecko"
		if !quic && v.Type != "http" && v.Type != "tls" || quic && (v.Password == "" || len(v.Password) > 4096 || v.Host != "" || v.Path != "") || !quic && v.Password != "" || v.Type != "gecko" && (v.MinPacketSize != 0 || v.MaxPacketSize != 0) {
			return errors.New("invalid obfuscation type or options")
		}
		if v.Type == "gecko" {
			if _, _, err := v.geckoSizes(); err != nil {
				return err
			}
		}
		data, _ := json.Marshal(v)
		*o = Obfuscation(data)
		return nil
	}
	var v string
	if e := json.Unmarshal(b, &v); e != nil {
		return e
	}
	*o = Obfuscation(v)
	return nil
}
func (o Obfuscation) MarshalJSON() ([]byte, error) {
	if len(o) > 0 && o[0] == '{' {
		return []byte(o), nil
	}
	return json.Marshal(string(o))
}
func (o Obfuscation) quicSettings() (quicObfsOptions, error) {
	if o == "" {
		return quicObfsOptions{}, nil
	}
	if o[0] != '{' {
		return quicObfsOptions{}, errors.New("QUIC obfs must contain type and password")
	}
	var cfg quicObfsOptions
	if e := json.Unmarshal([]byte(o), &cfg); e != nil {
		return cfg, e
	}
	if cfg.Type != "salamander" && cfg.Type != "gecko" || cfg.Password == "" {
		return cfg, errors.New("invalid QUIC obfuscation")
	}
	return cfg, nil
}
func salamanderSeal(b []byte, password string) []byte {
	salt := make([]byte, 8)
	rand.Read(salt)
	out := append(salt, b...)
	key := blake2b(append([]byte(password), salt...), 32)
	for i := 8; i < len(out); i++ {
		out[i] ^= key[(i-8)%32]
	}
	return out
}
func salamanderOpen(b []byte, password string) ([]byte, error) {
	if len(b) < 8 {
		return nil, errors.New("invalid Salamander datagram")
	}
	key := blake2b(append([]byte(password), b[:8]...), 32)
	out := b[8:]
	for i := range out {
		out[i] ^= key[i%32]
	}
	return out, nil
}

type salamanderConn struct {
	net.Conn
	password string
}

func (c *salamanderConn) Read(b []byte) (int, error) {
	raw := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(raw)
	n, e := c.Conn.Read(raw)
	if e != nil {
		return 0, e
	}
	plain, e := salamanderOpen(raw[:n], c.password)
	if e != nil {
		return 0, e
	}
	return copy(b, plain), nil
}
func (c *salamanderConn) Write(b []byte) (int, error) {
	_, e := c.Conn.Write(salamanderSeal(b, c.password))
	if e != nil {
		return 0, e
	}
	return len(b), nil
}

type salamanderPacket struct {
	net.PacketConn
	password string
}

func (c *salamanderPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	raw := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(raw)
	for {
		n, a, e := c.PacketConn.ReadFrom(raw)
		if e != nil {
			return 0, a, e
		}
		plain, e := salamanderOpen(raw[:n], c.password)
		if e == nil {
			return copy(b, plain), a, nil
		}
	}
}
func (c *salamanderPacket) WriteTo(b []byte, a net.Addr) (int, error) {
	_, e := c.PacketConn.WriteTo(salamanderSeal(b, c.password), a)
	if e != nil {
		return 0, e
	}
	return len(b), nil
}
