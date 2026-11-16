package native

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

type MKCPOptions struct {
	MTU              int     `json:"mtu,omitempty"`
	TTI              int     `json:"tti,omitempty"`
	UplinkCapacity   *int    `json:"uplink_capacity,omitempty"`
	DownlinkCapacity *int    `json:"downlink_capacity,omitempty"`
	Congestion       bool    `json:"congestion,omitempty"`
	ReadBuffer       int     `json:"read_buffer_size,omitempty"`
	WriteBuffer      int     `json:"write_buffer_size,omitempty"`
	Seed             *string `json:"seed,omitempty"`
	PacketEncoding   string  `json:"packet_encoding,omitempty"`
	Header           struct {
		Type   string `json:"type,omitempty"`
		Domain string `json:"domain,omitempty"`
	} `json:"header,omitempty"`
}

func (t Transport) mkcpOptions() MKCPOptions {
	var o MKCPOptions
	if t.KCP != nil {
		o = *t.KCP
	}
	if o.MTU == 0 {
		o.MTU = 1350
	}
	if o.TTI == 0 {
		o.TTI = 50
	}
	if o.ReadBuffer == 0 {
		o.ReadBuffer = 256 << 10
	}
	if o.WriteBuffer == 0 {
		o.WriteBuffer = 256 << 10
	}
	return o
}

func (o MKCPOptions) rate(up bool) int {
	v, fallback := o.UplinkCapacity, 5
	if !up {
		v, fallback = o.DownlinkCapacity, 20
	}
	if v == nil {
		return fallback * 1024 * 1024
	}
	return max(32*1024, *v*1024*1024)
}

func (t Transport) validateMKCP() error {
	if t.KCP != nil && t.Type != "mkcp" {
		return errors.New("kcp options require mkcp transport")
	}
	if t.Type != "mkcp" {
		return nil
	}
	o := t.mkcpOptions()
	if o.MTU < 576 || o.MTU > 1460 || o.TTI < 10 || o.TTI > 100 {
		return errors.New("mKCP mtu must be576-1460 and tti10-100ms")
	}
	if o.ReadBuffer < 4096 || o.ReadBuffer > 4<<20 || o.WriteBuffer < 4096 || o.WriteBuffer > 4<<20 {
		return errors.New("mKCP read/write buffers must be4096-4194304 bytes")
	}
	for _, v := range []*int{o.UplinkCapacity, o.DownlinkCapacity} {
		if v != nil && (*v < 0 || *v > 1024) {
			return errors.New("mKCP capacity must be0-1024 MiB/s")
		}
	}
	if o.PacketEncoding != "" && o.PacketEncoding != "legacy" && o.PacketEncoding != "raw" {
		return errors.New("mKCP packet_encoding must be legacy or raw")
	}
	if o.PacketEncoding == "raw" && o.Seed != nil {
		return errors.New("mKCP raw packets do not use the legacy seed envelope")
	}
	if o.Seed != nil && len(*o.Seed) > 4096 {
		return errors.New("mKCP seed exceeds4096 bytes")
	}
	switch o.Header.Type {
	case "", "none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns":
	default:
		return fmt.Errorf("unsupported mKCP header %q", o.Header.Type)
	}
	if o.Header.Domain != "" && o.Header.Type != "dns" {
		return errors.New("mKCP header domain requires dns")
	}
	if o.Header.Type == "dns" {
		domain := o.Header.Domain
		if domain == "" {
			domain = "www.example.com"
		}
		if len(domain) > 253 || strings.ContainsAny(domain, "\x00\r\n") {
			return errors.New("invalid mKCP DNS header domain")
		}
		for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
			if len(label) == 0 || len(label) > 63 {
				return errors.New("invalid mKCP DNS header label")
			}
		}
	}
	return nil
}

type mkcpCodec struct {
	kind   string
	raw    bool
	aead   cipher.AEAD
	header []byte
	seq    atomic.Uint32
}

func newMKCPCodec(o MKCPOptions) *mkcpCodec {
	c := &mkcpCodec{kind: o.Header.Type, raw: o.PacketEncoding == "raw"}
	if o.Seed != nil {
		key := sha256.Sum256([]byte(*o.Seed))
		block, _ := aes.NewCipher(key[:16])
		c.aead, _ = cipher.NewGCM(block)
	}
	switch c.kind {
	case "srtp", "utp", "wireguard":
		c.header = make([]byte, 4)
	case "wechat-video", "dtls":
		c.header = make([]byte, 13)
	case "dns":
		domain := o.Header.Domain
		if domain == "" {
			domain = "www.example.com"
		}
		c.header = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
			c.header = append(c.header, byte(len(label)))
			c.header = append(c.header, label...)
		}
		c.header = append(c.header, 0, 0, 1, 0, 1)
	}
	var seed [4]byte
	rand.Read(seed[:])
	c.seq.Store(binary.BigEndian.Uint32(seed[:]))
	return c
}

func (c *mkcpCodec) overhead() int {
	n := len(c.header)
	if c.raw {
		return n
	}
	if c.aead != nil {
		return n + 28
	}
	return n + 6
}

func mkcpChecksum(b []byte) uint32 {
	h := uint32(2166136261)
	for _, v := range b {
		h = (h ^ uint32(v)) * 16777619
	}
	return h
}

func (c *mkcpCodec) seal(b []byte) []byte {
	out := make([]byte, len(c.header), len(c.header)+len(b)+28)
	copy(out, c.header)
	seq := c.seq.Add(1)
	switch c.kind {
	case "srtp":
		copy(out, []byte{0xb5, 0xe8})
		binary.BigEndian.PutUint16(out[2:], uint16(seq))
	case "utp":
		binary.BigEndian.PutUint16(out, uint16(seq>>16))
		out[2] = 1
	case "wireguard":
		out[0] = 4
	case "wechat-video":
		copy(out, []byte{0xa1, 8, 0, 0, 0, 0, 0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30})
		binary.BigEndian.PutUint32(out[2:], seq)
	case "dtls":
		copy(out, []byte{23, 254, 253})
		binary.BigEndian.PutUint32(out[7:], seq)
		binary.BigEndian.PutUint16(out[11:], uint16(len(b)+c.overhead()-13))
	case "dns":
		binary.BigEndian.PutUint16(out, uint16(seq))
	}
	if c.raw {
		return append(out, b...)
	}
	if c.aead != nil {
		var nonce [12]byte
		rand.Read(nonce[:])
		out = append(out, nonce[:]...)
		return c.aead.Seal(out, nonce[:], b, nil)
	}
	start := len(out)
	out = append(out, 0, 0, 0, 0, byte(len(b)>>8), byte(len(b)))
	out = append(out, b...)
	p := out[start:]
	binary.BigEndian.PutUint32(p, mkcpChecksum(p[4:]))
	for i := 4; i < len(p); i++ {
		p[i] ^= p[i-4]
	}
	return out
}

func (c *mkcpCodec) open(packet []byte) ([]byte, error) {
	if len(packet) > 2048 || len(packet) < c.overhead()+4 {
		return nil, errors.New("invalid mKCP packet length")
	}
	if c.kind == "dns" && !bytes.Equal(packet[2:len(c.header)], c.header[2:]) {
		return nil, errors.New("mKCP DNS header mismatch")
	}
	b := packet[len(c.header):]
	if c.raw {
		return b, nil
	}
	if c.aead != nil {
		return c.aead.Open(nil, b[:12], b[12:], nil)
	}
	b = append([]byte(nil), b...)
	for i := len(b) - 1; i >= 4; i-- {
		b[i] ^= b[i-4]
	}
	if binary.BigEndian.Uint32(b) != mkcpChecksum(b[4:]) || int(binary.BigEndian.Uint16(b[4:])) != len(b)-6 {
		return nil, errors.New("mKCP checksum mismatch")
	}
	return b[6:], nil
}

type mkcpFrame struct {
	conv                        uint16
	cmd, flags                  byte
	stamp, number, next, window uint32
	acks                        []uint32
	body                        []byte
}

func parseMKCP(b []byte) ([]mkcpFrame, error) {
	var frames []mkcpFrame
	for len(b) > 0 {
		if len(b) < 4 || b[2] > 3 || b[3]&^byte(1) != 0 {
			return nil, errors.New("invalid mKCP segment")
		}
		f := mkcpFrame{conv: binary.BigEndian.Uint16(b), cmd: b[2], flags: b[3]}
		n := 16
		switch f.cmd {
		case 0:
			if len(b) < 17 || b[16] > 128 {
				return nil, errors.New("invalid mKCP ACK")
			}
			n = 17 + 4*int(b[16])
			if len(b) < n {
				return nil, errors.New("truncated mKCP ACK")
			}
			f.window, f.next, f.stamp = binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint32(b[8:]), binary.BigEndian.Uint32(b[12:])
			for p := 17; p < n; p += 4 {
				f.acks = append(f.acks, binary.BigEndian.Uint32(b[p:]))
			}
		case 1:
			if len(b) < 18 {
				return nil, errors.New("truncated mKCP data")
			}
			n = 18 + int(binary.BigEndian.Uint16(b[16:]))
			if len(b) < n || n > 2048 {
				return nil, errors.New("invalid mKCP data length")
			}
			f.stamp, f.number, f.next = binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint32(b[8:]), binary.BigEndian.Uint32(b[12:])
			f.body = b[18:n]
		default:
			if len(b) < n {
				return nil, errors.New("truncated mKCP control")
			}
			f.number, f.next, f.stamp = binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint32(b[8:]), binary.BigEndian.Uint32(b[12:])
		}
		if len(frames) > 0 && f.conv != frames[0].conv {
			return nil, errors.New("mixed mKCP conversations")
		}
		frames = append(frames, f)
		b = b[n:]
	}
	return frames, nil
}
