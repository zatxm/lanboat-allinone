package native

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"time"
)

type tunPacket struct {
	source, destination netip.Addr
	protocol            byte
	header              int
	nextHeader          int
	data                []byte
}

func parseTunPacket(data []byte) (tunPacket, error) {
	var p tunPacket
	if len(data) < 20 {
		return p, errors.New("short IP packet")
	}
	switch data[0] >> 4 {
	case 4:
		p.header = int(data[0]&15) * 4
		size := int(binary.BigEndian.Uint16(data[2:4]))
		if p.header < 20 || size < p.header || size > len(data) {
			return p, errors.New("invalid IPv4 length")
		}
		p.source = netip.AddrFrom4([4]byte(data[12:16]))
		p.destination = netip.AddrFrom4([4]byte(data[16:20]))
		p.protocol = data[9]
		p.data = data[:size]
	case 6:
		if len(data) < 40 {
			return p, errors.New("short IPv6 packet")
		}
		size := 40 + int(binary.BigEndian.Uint16(data[4:6]))
		if size > len(data) {
			return p, errors.New("invalid IPv6 length")
		}
		p.header = 40
		p.source = netip.AddrFrom16([16]byte(data[8:24]))
		p.destination = netip.AddrFrom16([16]byte(data[24:40]))
		p.protocol = data[6]
		p.nextHeader = 6
		p.data = data[:size]
		for p.protocol == 0 || p.protocol == 43 || p.protocol == 60 {
			if p.header+2 > size {
				return p, errors.New("short IPv6 extension")
			}
			n := (int(data[p.header+1]) + 1) * 8
			if p.header+n > size {
				return p, errors.New("invalid IPv6 extension length")
			}
			p.protocol = data[p.header]
			p.nextHeader = p.header
			p.header += n
		}
	default:
		return p, errors.New("unknown IP version")
	}
	return p, nil
}

// checksum is the Internet checksum. Summing 32-bit big-endian words and
// folding the carries yields the same ones' complement sum as 16-bit words.
func checksum(data []byte, initial uint32) uint16 {
	sum := uint64(initial)
	for len(data) >= 8 {
		v := binary.BigEndian.Uint64(data)
		sum += v>>32 + v&0xffffffff
		data = data[8:]
	}
	for len(data) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint64(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}

// addrBytes returns the AsSlice representation of a without allocating.
func addrBytes(a netip.Addr) ([16]byte, int) {
	if a.Is4() {
		var b [16]byte
		v := a.As4()
		copy(b[:], v[:])
		return b, 4
	}
	if a.IsValid() {
		return a.As16(), 16
	}
	return [16]byte{}, 0
}
func transportChecksum(p tunPacket, segment []byte) uint16 {
	source, n := addrBytes(p.source)
	dest, _ := addrBytes(p.destination)
	sum := uint32(p.protocol) + uint32(len(segment)&65535) + uint32(len(segment)>>16)
	for i := 0; i < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(source[i:])) + uint32(binary.BigEndian.Uint16(dest[i:]))
	}
	return checksum(segment, sum)
}
func updateTunPacket(p tunPacket, source, destination netip.Addr, sport, dport uint16) {
	segment := p.data[p.header:]
	binary.BigEndian.PutUint16(segment, sport)
	binary.BigEndian.PutUint16(segment[2:], dport)
	s, sn := addrBytes(source)
	d, dn := addrBytes(destination)
	if source.Is4() {
		copy(p.data[12:16], s[:sn])
		copy(p.data[16:20], d[:dn])
		clear(p.data[10:12])
		binary.BigEndian.PutUint16(p.data[10:12], checksum(p.data[:p.header], 0))
	} else {
		copy(p.data[8:24], s[:sn])
		copy(p.data[24:40], d[:dn])
	}
	p.source, p.destination = source, destination
	offset := 16
	if p.protocol == 17 {
		offset = 6
	}
	clear(segment[offset : offset+2])
	sum := transportChecksum(p, segment)
	if p.protocol == 17 && sum == 0 {
		sum = 65535
	}
	binary.BigEndian.PutUint16(segment[offset:], sum)
}
func makeUDPPacket(source, destination netip.Addr, sport, dport uint16, payload []byte) []byte {
	header := 20
	if source.Is6() {
		header = 40
	}
	packet := make([]byte, header+8+len(payload))
	segment := packet[header:]
	binary.BigEndian.PutUint16(segment[4:], uint16(len(segment)))
	copy(segment[8:], payload)
	if header == 20 {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		packet[8] = 64
		packet[9] = 17
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:], uint16(len(segment)))
		packet[6] = 17
		packet[7] = 64
	}
	p := tunPacket{source: source, destination: destination, protocol: 17, header: header, data: packet}
	updateTunPacket(p, source, destination, sport, dport)
	return packet
}

type fragmentKey struct {
	source, destination netip.Addr
	id                  uint32
	protocol            byte
}
type fragmentPart struct {
	offset int
	data   []byte
}
type fragmentAssembly struct {
	header          []byte
	parts           []fragmentPart
	total, received int
	until           time.Time
}
type tunFragments map[fragmentKey]*fragmentAssembly

func (f tunFragments) assemble(p tunPacket) ([]byte, error) {
	var id uint32
	var offset int
	var more bool
	var protocol byte
	start := p.header
	if p.source.Is4() {
		flags := binary.BigEndian.Uint16(p.data[6:8])
		if flags&0x3fff == 0 {
			return p.data, nil
		}
		id = uint32(binary.BigEndian.Uint16(p.data[4:6]))
		offset = int(flags&8191) * 8
		more = flags&0x2000 != 0
		protocol = p.protocol
	} else {
		if p.protocol != 44 {
			return p.data, nil
		}
		if start+8 > len(p.data) {
			return nil, errors.New("short IPv6 fragment")
		}
		protocol = p.data[start]
		flags := binary.BigEndian.Uint16(p.data[start+2:])
		offset = int(flags & 0xfff8)
		more = flags&1 != 0
		id = binary.BigEndian.Uint32(p.data[start+4:])
		start += 8
	}
	data := p.data[start:]
	if len(data) == 0 || offset+len(data) > 65515 || more && len(data)%8 != 0 {
		return nil, errors.New("invalid IP fragment")
	}
	key := fragmentKey{p.source, p.destination, id, protocol}
	entry := f[key]
	now := time.Now()
	if entry != nil && now.After(entry.until) {
		delete(f, key)
		entry = nil
	}
	if entry == nil {
		if len(f) >= 64 {
			for k, e := range f {
				if now.After(e.until) {
					delete(f, k)
				}
			}
		}
		if len(f) >= 64 {
			return nil, errors.New("IP fragment assembly capacity reached")
		}
		entry = &fragmentAssembly{total: -1, until: now.Add(30 * time.Second)}
		f[key] = entry
	}
	if len(entry.parts) >= 128 {
		delete(f, key)
		return nil, errors.New("too many IP fragments")
	}
	for _, part := range entry.parts {
		if offset < part.offset+len(part.data) && offset+len(data) > part.offset {
			delete(f, key)
			return nil, errors.New("overlapping IP fragments")
		}
	}
	if entry.total >= 0 && offset+len(data) > entry.total {
		delete(f, key)
		return nil, errors.New("IP fragment exceeds final size")
	}
	if !more {
		if entry.total >= 0 && entry.total != offset+len(data) {
			delete(f, key)
			return nil, errors.New("conflicting final IP fragments")
		}
		entry.total = offset + len(data)
		for _, part := range entry.parts {
			if part.offset+len(part.data) > entry.total {
				delete(f, key)
				return nil, errors.New("IP fragment exceeds final size")
			}
		}
	}
	if offset == 0 {
		entry.header = append([]byte(nil), p.data[:p.header]...)
	}
	entry.parts = append(entry.parts, fragmentPart{offset, append([]byte(nil), data...)})
	entry.received += len(data)
	if entry.total < 0 || entry.received != entry.total || entry.header == nil {
		return nil, nil
	}
	delete(f, key)
	packet := make([]byte, len(entry.header)+entry.total)
	copy(packet, entry.header)
	for _, part := range entry.parts {
		copy(packet[len(entry.header)+part.offset:], part.data)
	}
	if p.source.Is4() {
		clear(packet[6:8])
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		clear(packet[10:12])
		binary.BigEndian.PutUint16(packet[10:], checksum(packet[:len(entry.header)], 0))
	} else {
		packet[p.nextHeader] = protocol
		binary.BigEndian.PutUint16(packet[4:], uint16(len(packet)-40))
	}
	return packet, nil
}
