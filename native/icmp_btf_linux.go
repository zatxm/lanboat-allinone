package native

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// Only the running kernel's layouts are used; no distro-specific struct offsets.
type icmpBTF struct {
	types, strings []byte
	offsets        []int
	named          map[string]uint32
	order          binary.ByteOrder
}

func parseICMPBTF(data []byte) (*icmpBTF, error) {
	bad := errors.New("invalid ICMP tracing BTF")
	if len(data) < 24 || data[2] != 1 || data[3] != 0 {
		return nil, bad
	}
	var order binary.ByteOrder = binary.LittleEndian
	if order.Uint16(data) != 0xeb9f {
		order = binary.BigEndian
		if order.Uint16(data) != 0xeb9f {
			return nil, bad
		}
	}
	header := uint64(order.Uint32(data[4:]))
	section := func(offset, size uint32) []byte {
		start, end := header+uint64(offset), header+uint64(offset)+uint64(size)
		if header < 24 || end > uint64(len(data)) {
			return nil
		}
		return data[start:end]
	}
	b := &icmpBTF{types: section(order.Uint32(data[8:]), order.Uint32(data[12:])), strings: section(order.Uint32(data[16:]), order.Uint32(data[20:])), order: order, offsets: []int{-1}, named: map[string]uint32{}}
	if len(b.types) == 0 || len(b.strings) == 0 || b.strings[0] != 0 || b.strings[len(b.strings)-1] != 0 {
		return nil, bad
	}
	wanted := map[string]bool{"sk_buff": true, "net": true, "net_device": true, "ns_common": true, "task_struct": true, "mm_struct": true, "file": true, "inode": true, "super_block": true, "sock": true, "socket": true, "nf_hook_state": true, "__ip_local_out": true, "__ip6_local_out": true, "raw_sendmsg": true, "rawv6_sendmsg": true, "packet_sendmsg": true, "tpacket_fill_skb": true, "nf_hook_slow": true, "__dev_queue_xmit": true, "__dev_direct_xmit": true}
	for offset := 0; offset < len(b.types); {
		if len(b.types)-offset < 12 || len(b.offsets) > 1<<20 {
			return nil, bad
		}
		r := b.types[offset:]
		info := order.Uint32(r[4:])
		kind, count := info>>24&31, int(info&65535)
		size := 12
		switch kind {
		case 1, 14, 17:
			size += 4
		case 2, 7, 8, 9, 10, 11, 12, 16, 18:
		case 3:
			size += 12
		case 4, 5, 15, 19:
			size += 12 * count
		case 6, 13:
			size += 8 * count
		case 20:
			size += 4 + 4*count
		case 21:
			size += 4 * count
		case 22:
			size += 12 * count
		default:
			return nil, fmt.Errorf("unsupported ICMP tracing BTF kind %d", kind)
		}
		if size > len(r) {
			return nil, bad
		}
		name, ok := b.name(order.Uint32(r))
		if !ok {
			return nil, bad
		}
		if (kind == 4 || kind == 12) && wanted[string(name)] {
			b.named[string(name)] = uint32(len(b.offsets))
		}
		b.offsets = append(b.offsets, offset)
		offset += size
	}
	return b, nil
}

func (b *icmpBTF) name(offset uint32) ([]byte, bool) {
	if uint64(offset) >= uint64(len(b.strings)) {
		return nil, false
	}
	value := b.strings[offset:]
	n := bytes.IndexByte(value, 0)
	if n < 0 {
		return nil, false
	}
	return value[:n], true
}

func (b *icmpBTF) record(id uint32) ([]byte, uint32, bool) {
	if id == 0 || uint64(id) >= uint64(len(b.offsets)) {
		return nil, 0, false
	}
	r := b.types[b.offsets[id]:]
	return r, b.order.Uint32(r[4:]) >> 24 & 31, true
}

func (b *icmpBTF) unwrap(id uint32) uint32 {
	for range 16 {
		r, kind, ok := b.record(id)
		if !ok {
			return 0
		}
		if kind != 8 && kind != 9 && kind != 10 && kind != 11 && kind != 18 {
			return id
		}
		id = b.order.Uint32(r[8:])
	}
	return 0
}

func (b *icmpBTF) field(id uint32, name string, depth int) (int32, uint32, bool) {
	remaining := 4096
	return b.findField(id, name, depth, &remaining)
}

func (b *icmpBTF) findField(id uint32, name string, depth int, remaining *int) (int32, uint32, bool) {
	r, kind, ok := b.record(b.unwrap(id))
	if !ok || depth == 8 || kind != 4 && kind != 5 {
		return 0, 0, false
	}
	info := b.order.Uint32(r[4:])
	for i := 0; i < int(info&65535); i++ {
		if *remaining == 0 {
			return 0, 0, false
		}
		*remaining--
		member := r[12+i*12:]
		n, valid := b.name(b.order.Uint32(member))
		bits := b.order.Uint32(member[8:])
		if info>>31 != 0 && bits>>24 != 0 || bits&7 != 0 || bits > 1<<23 {
			continue
		}
		typeID := b.order.Uint32(member[4:])
		if valid && string(n) == name {
			return int32(bits / 8), typeID, true
		}
		if valid && len(n) == 0 {
			if offset, t, found := b.findField(typeID, name, depth+1, remaining); found {
				return int32(bits/8) + offset, t, true
			}
		}
	}
	return 0, 0, false
}

func (b *icmpBTF) offset(structure, member string, size uint32, pointer bool) (int32, error) {
	offset, id, ok := b.field(b.named[structure], member, 0)
	r, kind, valid := b.record(b.unwrap(id))
	if !ok || !valid || pointer && kind != 2 || !pointer && (kind != 1 && kind != 6 || b.order.Uint32(r[8:]) != size) {
		return 0, fmt.Errorf("ICMP tracing requires %s.%s", structure, member)
	}
	return offset, nil
}

func (b *icmpBTF) hook(name string, arguments ...string) (uint32, error) {
	id := b.named[name]
	r, kind, ok := b.record(id)
	if !ok || kind != 12 {
		return 0, fmt.Errorf("ICMP tracing hook %s unavailable", name)
	}
	p, kind, ok := b.record(b.order.Uint32(r[8:]))
	if !ok || kind != 13 || int(b.order.Uint32(p[4:])&65535) != len(arguments) {
		return 0, errors.New("unexpected ICMP tracing hook signature")
	}
	for i, structure := range arguments {
		if structure == "" {
			continue
		}
		ptr, kind, ok := b.record(b.unwrap(b.order.Uint32(p[16+i*8:])))
		if !ok || kind != 2 {
			return 0, errors.New("unexpected ICMP tracing hook argument")
		}
		t, kind, ok := b.record(b.unwrap(b.order.Uint32(ptr[8:])))
		if !ok || kind != 4 {
			return 0, errors.New("unexpected ICMP tracing hook argument type")
		}
		n, _ := b.name(b.order.Uint32(t))
		if string(n) != structure {
			return 0, errors.New("unexpected ICMP tracing hook argument name")
		}
	}
	return id, nil
}

func (b *icmpBTF) txRingHook() (id uint32, device, data int16, err error) {
	id, err = b.hook("tpacket_fill_skb", "packet_sock", "sk_buff", "", "net_device", "", "", "", "", "", "", "sockcm_cookie")
	if err == nil {
		return id, 24, 32, nil
	}
	// Newer kernels replace the frame argument with a cached hard-header length.
	id, err = b.hook("tpacket_fill_skb", "packet_sock", "sk_buff", "net_device", "", "", "", "", "", "", "", "sockcm_cookie")
	return id, 16, 24, err
}
