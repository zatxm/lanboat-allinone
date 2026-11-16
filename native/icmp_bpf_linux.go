package native

import (
	"encoding/binary"
	"fmt"
)

type icmpBPFInstruction struct {
	code, registers byte
	offset          int16
	value           int32
}

type icmpBPFProgram struct {
	code   []icmpBPFInstruction
	labels map[string]int
	jumps  map[int]string
}

func (p *icmpBPFProgram) emit(code, dst, src byte, offset int16, value int32) {
	p.code = append(p.code, icmpBPFInstruction{code, dst | src<<4, offset, value})
}

func (p *icmpBPFProgram) label(name string) { p.labels[name] = len(p.code) }
func (p *icmpBPFProgram) jump(code, dst, src byte, value int32, label string) {
	p.jumps[len(p.code)] = label
	p.emit(code, dst, src, 0, value)
}

func (p *icmpBPFProgram) constant(dst byte, value uint64, mapFD bool) {
	source := byte(0)
	if mapFD {
		source = 1 // BPF_PSEUDO_MAP_FD
	}
	p.emit(0x18, dst, source, 0, int32(value))
	p.emit(0, 0, 0, 0, int32(value>>32))
}

func (p *icmpBPFProgram) stack(dst byte, offset int32) {
	p.emit(0xbf, dst, 10, 0, 0)
	p.emit(0x07, dst, 0, 0, offset)
}

func (p *icmpBPFProgram) read(src byte, offset int32, stack int16, size int32) {
	p.stack(1, int32(stack))
	p.emit(0xb7, 2, 0, 0, size)
	p.emit(0xbf, 3, src, 0, 0)
	if offset != 0 {
		p.emit(0x07, 3, 0, 0, offset)
	}
	p.emit(0x85, 0, 0, 0, 113) // bpf_probe_read_kernel
	p.jump(0x55, 0, 0, 0, "out")
}

func (p *icmpBPFProgram) bytes() ([]byte, error) {
	b := make([]byte, 8*len(p.code))
	for i, in := range p.code {
		if name, ok := p.jumps[i]; ok {
			target, exists := p.labels[name]
			if !exists || target-i-1 < -32768 || target-i-1 > 32767 {
				return nil, fmt.Errorf("invalid ICMP BPF branch %q", name)
			}
			in.offset = int16(target - i - 1)
		}
		b[i*8], b[i*8+1] = in.code, in.registers
		binary.LittleEndian.PutUint16(b[i*8+2:], uint16(in.offset))
		binary.LittleEndian.PutUint32(b[i*8+4:], uint32(in.value))
	}
	return b, nil
}

func (b *icmpBTF) socketNetOffset() (int32, error) {
	common, id, ok := b.field(b.named["sock"], "__sk_common", 0)
	o, id, netOK := b.field(id, "skc_net", 0)
	n, ptr, found := b.field(id, "net", 0)
	_, kind, valid := b.record(b.unwrap(ptr))
	if !ok || !netOK || !found || !valid || kind != 2 {
		return 0, fmt.Errorf("ICMP tracing requires sock.skc_net.net")
	}
	return common + o + n, nil
}

func icmpSendProgram(b *icmpBTF, fd int, socket, exit bool) ([]byte, error) {
	p := &icmpBPFProgram{labels: map[string]int{}, jumps: map[int]string{}}
	if !exit {
		p.emit(0x79, 6, 1, 0, 0)
		if socket {
			offset, err := b.offset("socket", "sk", 8, true)
			if err != nil {
				return nil, err
			}
			p.read(6, offset, -16, 8)
		} else {
			p.emit(0x7b, 10, 6, -16, 0)
		}
	}
	p.emit(0x85, 0, 0, 0, 14) // Current kernel task, including namespace identity.
	p.emit(0x7b, 10, 0, -8, 0)
	p.constant(1, uint64(fd), true)
	p.stack(2, -8)
	if exit {
		p.emit(0x85, 0, 0, 0, 3)
	} else {
		p.stack(3, -16)
		p.emit(0xb7, 4, 0, 0, 0)
		p.emit(0x85, 0, 0, 0, 2)
	}
	p.label("out")
	p.emit(0xb7, 0, 0, 0, 0)
	p.emit(0x95, 0, 0, 0, 0)
	return p.bytes()
}

func icmpTraceProgram(b *icmpBTF, mapFD, sendFD int, hook string, netNS uint32, pidDev, pidNS uint64) ([]byte, error) {
	fields := []struct {
		structure, member string
		size              uint32
		pointer           bool
	}{
		{"net", "ns", 0, false}, {"ns_common", "inum", 4, false},
		{"sk_buff", "head", 8, true}, {"sk_buff", "data", 8, true}, {"sk_buff", "network_header", 2, false}, {"sk_buff", "len", 4, false}, {"sk_buff", "tail", 4, false},
		{"task_struct", "group_leader", 8, true}, {"task_struct", "start_boottime", 8, false}, {"task_struct", "mm", 8, true},
		{"mm_struct", "exe_file", 8, true}, {"file", "f_inode", 8, true}, {"inode", "i_ino", 8, false}, {"inode", "i_sb", 8, true}, {"super_block", "s_dev", 4, false},
		{"sock", "sk_socket", 8, true}, {"socket", "file", 8, true},
	}
	off := make([]int32, len(fields))
	for i, f := range fields {
		if i == 0 {
			var ok bool
			off[i], _, ok = b.field(b.named[f.structure], f.member, 0)
			if !ok {
				return nil, fmt.Errorf("ICMP tracing requires %s.%s", f.structure, f.member)
			}
			continue
		}
		var err error
		off[i], err = b.offset(f.structure, f.member, f.size, f.pointer)
		if err != nil {
			return nil, err
		}
	}
	p := &icmpBPFProgram{labels: map[string]int{}, jumps: map[int]string{}}
	// Key [-64,-8), identity [-112,-64), IP header [-176,-136), scratch below.
	p.emit(0xbf, 6, 1, 0, 0)
	if sendFD >= 0 {
		// Most traffic has no active raw/packet send; leave before reading skb or namespace fields.
		p.emit(0x85, 0, 0, 0, 14)
		p.emit(0x7b, 10, 0, -264, 0)
		p.constant(1, uint64(sendFD), true)
		p.stack(2, -264)
		p.emit(0x85, 0, 0, 0, 1)
		p.jump(0x15, 0, 0, 0, "out")
		p.emit(0x79, 0, 0, 0, 0)
		p.emit(0x7b, 10, 0, -280, 0)
	}
	switch hook {
	case "__ip_local_out", "__ip6_local_out":
		p.emit(0x79, 0, 6, 8, 0)
		p.emit(0x7b, 10, 0, -256, 0)
		p.emit(0x79, 3, 6, 0, 0)
		p.emit(0x79, 6, 6, 16, 0)
	case "nf_hook_slow":
		hookOffset, err := b.offset("nf_hook_state", "hook", 1, false)
		if err != nil {
			return nil, err
		}
		skOffset, err := b.offset("nf_hook_state", "sk", 8, true)
		if err != nil {
			return nil, err
		}
		netOffset, err := b.offset("nf_hook_state", "net", 8, true)
		if err != nil {
			return nil, err
		}
		p.emit(0x79, 7, 6, 8, 0)
		p.emit(0x79, 6, 6, 0, 0)
		p.read(7, hookOffset, -184, 1)
		p.emit(0x71, 0, 10, -184, 0)
		p.jump(0x55, 0, 0, 3, "out") // NF_INET_LOCAL_OUT, before any queue/reinjection.
		p.read(7, skOffset, -256, 8)
		p.read(7, netOffset, -248, 8)
		p.emit(0x79, 3, 10, -248, 0)
	case "__dev_queue_xmit", "__dev_direct_xmit":
		skOffset, err := b.offset("sk_buff", "sk", 8, true)
		if err != nil {
			return nil, err
		}
		netOffset, err := b.socketNetOffset()
		if err != nil {
			return nil, err
		}
		p.emit(0x79, 6, 6, 0, 0)
		p.read(6, skOffset, -256, 8)
		p.emit(0x79, 3, 10, -256, 0)
		p.jump(0x15, 3, 0, 0, "out")
		p.read(3, netOffset, -248, 8)
		p.emit(0x79, 3, 10, -248, 0)
	case "tpacket_fill_skb":
		// The assembled frame is contiguous here even when its skb uses page fragments.
		_, device, data, err := b.txRingHook()
		if err != nil {
			return nil, err
		}
		p.emit(0x79, 7, 6, 88, 0)
		p.emit(0x67, 7, 0, 0, 32)
		p.emit(0xc7, 7, 0, 0, 32)
		p.jump(0xd5, 7, 0, 0, "out")
		p.emit(0x79, 8, 6, data, 0)
		skOffset, err := b.offset("sk_buff", "sk", 8, true)
		if err != nil {
			return nil, err
		}
		typeOffset, err := b.offset("socket", "type", 2, false)
		if err != nil {
			return nil, err
		}
		headerOffset, err := b.offset("net_device", "hard_header_len", 2, false)
		if err != nil {
			return nil, err
		}
		netOffset, err := b.socketNetOffset()
		if err != nil {
			return nil, err
		}
		p.emit(0x79, 3, 6, 8, 0)
		p.read(3, skOffset, -256, 8)
		p.emit(0x79, 3, 10, -256, 0)
		p.jump(0x15, 3, 0, 0, "out")
		p.read(3, off[15], -248, 8)
		p.emit(0x79, 3, 10, -248, 0)
		p.read(3, typeOffset, -184, 2)
		p.emit(0x69, 0, 10, -184, 0)
		p.jump(0x55, 0, 0, 3, "ring-data") // SOCK_RAW frames include the device's L2 header.
		p.emit(0x79, 3, 6, device, 0)
		p.read(3, headerOffset, -184, 2)
		p.emit(0x69, 0, 10, -184, 0)
		p.jump(0x2d, 0, 7, 0, "out")
		p.emit(0x0f, 8, 0, 0, 0)
		p.emit(0x1f, 7, 0, 0, 0)
		p.label("ring-data")
		p.emit(0x7b, 10, 8, -288, 0)
		p.emit(0x7b, 10, 7, -296, 0)
		p.emit(0x79, 3, 10, -256, 0)
		p.read(3, netOffset, -248, 8)
		p.emit(0x79, 3, 10, -248, 0)
	default:
		return nil, fmt.Errorf("unknown ICMP tracing hook %s", hook)
	}
	p.read(3, off[0]+off[1], -184, 4)
	p.emit(0x61, 0, 10, -184, 0)
	p.jump(0x56, 0, 0, int32(netNS), "out") // Namespace inodes commonly have bit31 set; compare as u32.
	if sendFD >= 0 {
		// Queued or asynchronously transmitted packets must not inherit the core's identity.
		p.emit(0x79, 0, 10, -280, 0)
		p.emit(0x79, 1, 10, -256, 0)
		p.jump(0x5d, 0, 1, 0, "out")
	}
	for at := int16(-176); at < -8; at += 8 {
		p.emit(0x7a, 10, 0, at, 0)
	}
	if hook == "tpacket_fill_skb" {
		p.emit(0x79, 8, 10, -288, 0)
		p.emit(0x79, 7, 10, -296, 0)
		p.emit(0xbf, 6, 8, 0, 0)
		p.emit(0x0f, 6, 7, 0, 0)
	} else {
		p.read(6, off[2], -192, 8)
		p.read(6, off[3], -216, 8)
		p.read(6, off[4], -196, 2)
		p.read(6, off[5], -200, 4)
		p.read(6, off[6], -204, 4)
		p.emit(0x79, 8, 10, -192, 0)
		p.emit(0x69, 9, 10, -196, 0)
		p.emit(0x0f, 8, 9, 0, 0)
		p.emit(0x79, 0, 10, -216, 0)
		p.jump(0xad, 8, 0, 0, "out") // Network header must be at/after data, including L2 headers.
		p.emit(0xbf, 9, 8, 0, 0)
		p.emit(0x1f, 9, 0, 0, 0)
		p.emit(0x7b, 10, 9, -272, 0)
		p.emit(0x79, 6, 10, -192, 0)
		p.emit(0x61, 0, 10, -204, 0)
		p.emit(0x0f, 6, 0, 0, 0) // linear tail; never read non-linear fragments as header bytes.
		p.emit(0x61, 7, 10, -200, 0)
		p.emit(0x79, 0, 10, -272, 0)
		p.jump(0x2d, 0, 7, 0, "out")
		p.emit(0x1f, 7, 0, 0, 0)
	}
	p.jump(0xa5, 7, 0, 28, "out")
	p.emit(0xbf, 0, 8, 0, 0)
	p.emit(0x07, 0, 0, 0, 20)
	p.jump(0x2d, 0, 6, 0, "out")
	p.read(8, 0, -176, 20)
	p.emit(0x71, 0, 10, -176, 0)
	p.emit(0x77, 0, 0, 0, 4)
	p.jump(0x15, 0, 0, 6, "ipv6")
	p.jump(0x55, 0, 0, 4, "out")
	p.emit(0x62, 10, 0, -64, 4)
	p.emit(0x69, 0, 10, -174, 0)
	p.emit(0xdc, 0, 0, 0, 16)
	p.jump(0xa5, 0, 0, 28, "out")
	p.jump(0x2d, 0, 7, 0, "out")
	p.emit(0xbf, 7, 0, 0, 0) // Ethernet padding is not part of the IP packet.
	p.emit(0x71, 0, 10, -167, 0)
	p.jump(0x55, 0, 0, 1, "out")
	p.emit(0x69, 0, 10, -170, 0)
	p.emit(0xdc, 0, 0, 0, 16)
	p.emit(0x57, 0, 0, 0, 0x3fff)
	p.jump(0x55, 0, 0, 0, "out")
	p.emit(0x71, 9, 10, -176, 0)
	p.emit(0x57, 9, 0, 0, 15)
	p.emit(0x67, 9, 0, 0, 2)
	p.jump(0xa5, 9, 0, 20, "out")
	for i := range 2 {
		p.emit(0x61, 0, 10, int16(-164+i*4), 0)
		p.emit(0x63, 10, 0, int16(-56+i*16), 0)
	}
	p.jump(0x05, 0, 0, 0, "icmp")
	p.label("ipv6")
	p.jump(0xa5, 7, 0, 48, "out")
	p.emit(0xbf, 0, 8, 0, 0)
	p.emit(0x07, 0, 0, 0, 40)
	p.jump(0x2d, 0, 6, 0, "out")
	p.read(8, 0, -176, 40)
	p.emit(0x62, 10, 0, -64, 6)
	p.emit(0x69, 0, 10, -172, 0)
	p.emit(0xdc, 0, 0, 0, 16)
	p.jump(0xa5, 0, 0, 8, "out")
	p.emit(0x07, 0, 0, 0, 40)
	p.jump(0x2d, 0, 7, 0, "out")
	p.emit(0xbf, 7, 0, 0, 0)
	for i := range 4 {
		p.emit(0x79, 0, 10, int16(-168+i*8), 0)
		p.emit(0x7b, 10, 0, int16(-56+i*8), 0)
	}
	p.emit(0xb7, 9, 0, 0, 40)
	p.emit(0x71, 0, 10, -170, 0)
	for i := range 8 {
		next, fragment, ah, advance := fmt.Sprint("ext", i), fmt.Sprint("frag", i), fmt.Sprint("ah", i), fmt.Sprint("advance", i)
		p.jump(0x15, 0, 0, 58, "icmp")
		for _, kind := range []int32{0, 43, 60, 44, 51} {
			p.jump(0x15, 0, 0, kind, next)
		}
		p.jump(0x05, 0, 0, 0, "out")
		p.label(next)
		p.emit(0x63, 10, 0, -240, 0)
		p.emit(0xbf, 0, 9, 0, 0)
		p.emit(0x07, 0, 0, 0, 8)
		p.jump(0x2d, 0, 7, 0, "out")
		p.emit(0xbf, 3, 8, 0, 0)
		p.emit(0x0f, 3, 9, 0, 0)
		p.emit(0xbf, 0, 3, 0, 0)
		p.emit(0x07, 0, 0, 0, 8)
		p.jump(0x2d, 0, 6, 0, "out")
		p.read(3, 0, -232, 8)
		p.emit(0x61, 0, 10, -240, 0)
		p.jump(0x15, 0, 0, 44, fragment)
		p.jump(0x15, 0, 0, 51, ah)
		p.emit(0x71, 0, 10, -231, 0)
		p.emit(0x07, 0, 0, 0, 1)
		p.emit(0x67, 0, 0, 0, 3)
		p.jump(0x05, 0, 0, 0, advance)
		p.label(ah)
		p.emit(0x71, 0, 10, -231, 0)
		p.emit(0x07, 0, 0, 0, 2)
		p.emit(0x67, 0, 0, 0, 2)
		p.jump(0x05, 0, 0, 0, advance)
		p.label(fragment)
		p.emit(0x69, 0, 10, -230, 0)
		p.emit(0xdc, 0, 0, 0, 16)
		p.emit(0x57, 0, 0, 0, 0xfff9)
		p.jump(0x55, 0, 0, 0, "out")
		p.emit(0xb7, 0, 0, 0, 8)
		p.label(advance)
		p.emit(0x0f, 9, 0, 0, 0)
		p.emit(0x71, 0, 10, -232, 0)
	}
	p.jump(0x55, 0, 0, 58, "out")
	p.label("icmp")
	p.emit(0x1f, 7, 9, 0, 0)
	p.jump(0xa5, 7, 0, 8, "out")
	p.jump(0x25, 7, 0, 65535, "out")
	p.emit(0x63, 10, 7, -60, 0)
	p.emit(0x0f, 8, 9, 0, 0)
	p.emit(0xb7, 2, 0, 0, 16)
	p.jump(0x35, 7, 0, 16, "prefix")
	p.emit(0xbf, 2, 7, 0, 0)
	p.label("prefix")
	p.emit(0xbf, 0, 8, 0, 0)
	p.emit(0x0f, 0, 2, 0, 0)
	p.jump(0x2d, 0, 6, 0, "out")
	p.stack(1, -24)
	p.emit(0xbf, 3, 8, 0, 0)
	p.emit(0x85, 0, 0, 0, 113)
	p.jump(0x55, 0, 0, 0, "out")
	p.emit(0x6a, 10, 0, -22, 0) // Offloaded checksum bytes are not an identity field.
	// Kernel-generated ICMP errors/replies do not have a userspace socket file.
	p.emit(0x79, 3, 10, -256, 0)
	p.jump(0x15, 3, 0, 0, "out")
	p.read(3, off[15], -248, 8)
	p.emit(0x79, 3, 10, -248, 0)
	p.jump(0x15, 3, 0, 0, "out")
	p.read(3, off[16], -248, 8)
	p.emit(0x79, 3, 10, -248, 0)
	p.jump(0x15, 3, 0, 0, "out")
	p.constant(1, pidDev, false)
	p.constant(2, pidNS, false)
	p.stack(3, -232)
	p.emit(0xb7, 4, 0, 0, 8)
	p.emit(0x85, 0, 0, 0, 120) // namespace-relative PID, not the host/init namespace PID.
	p.jump(0x55, 0, 0, 0, "out")
	p.emit(0x61, 0, 10, -228, 0)
	p.jump(0x15, 0, 0, 0, "out")
	p.emit(0x63, 10, 0, -112, 0)
	p.emit(0x85, 0, 0, 0, 35)
	p.emit(0xbf, 6, 0, 0, 0)
	p.read(6, off[7], -248, 8)
	p.emit(0x79, 3, 10, -248, 0)
	p.read(3, off[8], -104, 8)
	for _, offset := range []int32{off[9], off[10], off[11]} {
		p.read(6, offset, -248, 8)
		p.emit(0x79, 6, 10, -248, 0)
		p.jump(0x15, 6, 0, 0, "out")
	}
	p.read(6, off[12], -96, 8)
	p.read(6, off[13], -248, 8)
	p.emit(0x79, 3, 10, -248, 0)
	p.read(3, off[14], -88, 4)
	p.emit(0x85, 0, 0, 0, 125)
	p.emit(0x7b, 10, 0, -72, 0)
	p.constant(1, uint64(mapFD), true)
	p.stack(2, -64)
	p.stack(3, -112)
	p.emit(0xb7, 4, 0, 0, 1) // First writer is immutable; conflicting writers set a sticky ambiguity bit.
	p.emit(0x85, 0, 0, 0, 2)
	p.constant(1, uint64(mapFD), true)
	p.stack(2, -64)
	p.emit(0x85, 0, 0, 0, 1)
	p.jump(0x15, 0, 0, 0, "out")
	p.emit(0xbf, 6, 0, 0, 0)
	for i := range 4 {
		p.emit(0x79, 0, 6, int16(i*8), 0)
		p.emit(0x79, 1, 10, int16(-112+i*8), 0)
		p.jump(0x5d, 0, 1, 0, "ambiguous")
	}
	p.emit(0x79, 0, 10, -72, 0)
	p.emit(0x7b, 6, 0, 40, 0)
	p.jump(0x05, 0, 0, 0, "out")
	p.label("ambiguous")
	p.emit(0xb7, 1, 0, 0, 1)
	p.emit(0xdb, 6, 1, 32, 0x40) // Atomic OR; concurrent sends cannot erase ambiguity.
	p.label("out")
	p.emit(0xb7, 0, 0, 0, 0)
	p.emit(0x95, 0, 0, 0, 0)
	return p.bytes()
}
