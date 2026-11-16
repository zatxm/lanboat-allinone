package native

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// FakeTCP carries one QUIC datagram per PSH/ACK segment. Reliability belongs to
// QUIC; passing these segments through a TCP byte stream loses packet boundaries.
type fakeTCPSegment struct {
	source, destination uint16
	sequence, ack       uint32
	flags               byte
	payload             []byte
}

func parseFakeTCP(b []byte) (fakeTCPSegment, bool) {
	if len(b) < 20 {
		return fakeTCPSegment{}, false
	}
	n := int(b[12]>>4) * 4
	if n < 20 || n > len(b) {
		return fakeTCPSegment{}, false
	}
	return fakeTCPSegment{binary.BigEndian.Uint16(b), binary.BigEndian.Uint16(b[2:]), binary.BigEndian.Uint32(b[4:]), binary.BigEndian.Uint32(b[8:]), b[13], b[n:]}, true
}

func encodeFakeTCP(b []byte, source, destination netip.AddrPort, sequence, ack uint32, window uint16, payload []byte) ([]byte, error) {
	if len(payload) > 65495 {
		return nil, errors.New("FakeTCP datagram exceeds IP packet limit")
	}
	b = append(b, make([]byte, 20)...)
	binary.BigEndian.PutUint16(b, source.Port())
	binary.BigEndian.PutUint16(b[2:], destination.Port())
	binary.BigEndian.PutUint32(b[4:], sequence)
	binary.BigEndian.PutUint32(b[8:], ack)
	b[12], b[13] = 5<<4, 0x18
	binary.BigEndian.PutUint16(b[14:], window)
	b = append(b, payload...)
	binary.BigEndian.PutUint16(b[16:], transportChecksum(tunPacket{source: source.Addr(), destination: destination.Addr(), protocol: 6}, b))
	return b, nil
}
