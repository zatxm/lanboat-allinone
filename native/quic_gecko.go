package native

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"
	"time"
)

const (
	geckoTTL         = 3 * time.Second
	geckoMaxMessages = 128
	geckoMaxPerPeer  = 8
	geckoMaxBytes    = 256 << 10
	geckoMaxPacket   = 8 * (2048 - 13)
)

func (o quicObfsOptions) geckoSizes() (int, int, error) {
	low, high := o.MinPacketSize, o.MaxPacketSize
	if low == 0 {
		low = 512
	}
	if high == 0 {
		high = 1200
	}
	if low < 14 || high < low || high < 163 || high > 2048 {
		return 0, 0, errors.New("Gecko sizes require 14 <= min_packet_size <= max_packet_size <= 2048 and max_packet_size >= 163 to carry a QUIC Initial")
	}
	return low, high, nil
}

type geckoKey struct {
	source string
	id     byte
}
type geckoMessage struct {
	created     time.Time
	chunks      [8][]byte
	total, mask byte
	size        int
}
type geckoCodec struct {
	password  string
	low, high int
	next      atomic.Uint32
	// PacketConn and Conn each have one receive loop. Sending uses only next
	// and immutable options; no receive lock or per-fragment timer is needed.
	messages map[geckoKey]*geckoMessage
	peers    map[string]int
	bytes    int
	cleaned  time.Time
}

func newGecko(o quicObfsOptions) *geckoCodec {
	low, high, _ := o.geckoSizes()
	c := &geckoCodec{password: o.Password, low: low, high: high}
	var seed [1]byte
	rand.Read(seed[:])
	c.next.Store(uint32(seed[0]))
	return c
}

func geckoRandom(low, high int) int {
	var b [4]byte
	rand.Read(b[:])
	return low + int(binary.BigEndian.Uint32(b[:])%uint32(high-low+1))
}

func (c *geckoCodec) write(packet []byte, send func([]byte) error) error {
	if len(packet) == 0 {
		return errors.New("empty Gecko packet")
	}
	if packet[0]&0x80 == 0 {
		return send(salamanderSeal(packet, c.password))
	}
	capacity := c.high - 13
	minimum := max(2, (len(packet)+capacity-1)/capacity)
	maximum := min(8, len(packet))
	if minimum > maximum {
		return errors.New("Gecko packet exceeds fragment capacity")
	}
	count, id := geckoRandom(minimum, maximum), byte(c.next.Add(1))
	for index := 0; index < count; index++ {
		remaining := count - index - 1
		n := geckoRandom(max(1, len(packet)-remaining*capacity), min(capacity, len(packet)-remaining))
		padding := geckoRandom(max(c.low, 13+n), c.high) - 13 - n
		frame := make([]byte, 5+padding+n)
		frame[0], frame[1], frame[2] = 0x80, id, byte(index<<4|count)
		binary.BigEndian.PutUint16(frame[3:5], uint16(padding))
		rand.Read(frame[5 : 5+padding])
		copy(frame[5+padding:], packet[:n])
		if err := send(salamanderSeal(frame, c.password)); err != nil {
			return err
		}
		packet = packet[n:]
	}
	return nil
}

func (c *geckoCodec) discard(key geckoKey, m *geckoMessage) {
	delete(c.messages, key)
	c.bytes -= m.size
	c.peers[key.source]--
	if c.peers[key.source] == 0 {
		delete(c.peers, key.source)
	}
}

func (c *geckoCodec) open(raw []byte, source string, now time.Time) []byte {
	plain, err := salamanderOpen(raw, c.password)
	if err != nil || len(plain) == 0 {
		return nil
	}
	if plain[0]&0x80 == 0 {
		return plain
	}
	if len(plain) < 6 || len(plain) > 2040 || plain[0] != 0x80 {
		return nil
	}
	index, total := plain[2]>>4, plain[2]&15
	padding := int(binary.BigEndian.Uint16(plain[3:5]))
	if total < 2 || total > 8 || index >= total || padding >= len(plain)-5 {
		return nil
	}
	chunk := plain[5+padding:]
	if now.Sub(c.cleaned) >= 250*time.Millisecond {
		for key, m := range c.messages {
			if now.Sub(m.created) >= geckoTTL {
				c.discard(key, m)
			}
		}
		c.cleaned = now
	}
	key := geckoKey{source, plain[1]}
	m := c.messages[key]
	if m != nil && (m.total != total || now.Sub(m.created) >= geckoTTL) {
		c.discard(key, m)
		return nil
	}
	if m == nil {
		if len(c.messages) >= geckoMaxMessages || c.peers[source] >= geckoMaxPerPeer {
			return nil
		}
		if c.messages == nil {
			c.messages = make(map[geckoKey]*geckoMessage)
			c.peers = make(map[string]int)
		}
		m = &geckoMessage{created: now, total: total}
		c.messages[key], c.peers[source] = m, c.peers[source]+1
	}
	if m.mask&(1<<index) != 0 {
		return nil
	}
	if m.size+len(chunk) > geckoMaxPacket || c.bytes+len(chunk) > geckoMaxBytes {
		c.discard(key, m)
		return nil
	}
	m.chunks[index] = append([]byte(nil), chunk...)
	m.mask |= 1 << index
	m.size += len(chunk)
	c.bytes += len(chunk)
	if m.mask != byte(1<<total-1) {
		return nil
	}
	packet := make([]byte, 0, m.size)
	for _, data := range m.chunks[:total] {
		packet = append(packet, data...)
	}
	c.discard(key, m)
	if packet[0]&0x80 == 0 {
		return nil
	}
	return packet
}

type geckoConn struct {
	net.Conn
	codec *geckoCodec
}

func (c *geckoConn) Read(b []byte) (int, error) {
	raw := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(raw)
	for {
		n, err := c.Conn.Read(raw)
		if err != nil {
			return 0, err
		}
		if packet := c.codec.open(raw[:n], "", time.Now()); packet != nil {
			return copy(b, packet), nil
		}
	}
}
func (c *geckoConn) Write(b []byte) (int, error) {
	err := c.codec.write(b, func(data []byte) error { _, err := c.Conn.Write(data); return err })
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

type geckoPacket struct {
	net.PacketConn
	codec *geckoCodec
}

func (c *geckoPacket) ReadFrom(b []byte) (int, net.Addr, error) {
	raw := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(raw)
	for {
		n, addr, err := c.PacketConn.ReadFrom(raw)
		if err != nil {
			return 0, addr, err
		}
		if packet := c.codec.open(raw[:n], addr.String(), time.Now()); packet != nil {
			return copy(b, packet), addr, nil
		}
	}
}
func (c *geckoPacket) WriteTo(b []byte, addr net.Addr) (int, error) {
	err := c.codec.write(b, func(data []byte) error { _, err := c.PacketConn.WriteTo(data, addr); return err })
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
