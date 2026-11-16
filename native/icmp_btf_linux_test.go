package native

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"unsafe"
)

func icmpBTFFixture(order binary.ByteOrder) []byte {
	str := []byte{0}
	name := func(s string) uint32 { at := len(str); str = append(str, append([]byte(s), 0)...); return uint32(at) }
	var types []byte
	put := func(v uint32) { var b [4]byte; order.PutUint32(b[:], v); types = append(types, b[:]...) }
	for _, s := range []string{"u32", "u16", "u64"} {
		put(name(s))
		put(1 << 24)
		size := map[string]uint32{"u32": 4, "u16": 2, "u64": 8}[s]
		put(size)
		put(size * 8)
	}
	put(name("inner"))
	put(4<<24 | 1)
	put(16)
	put(name("head"))
	put(3)
	put(64)
	put(name("outer"))
	put(4<<24 | 1)
	put(32)
	put(0)
	put(4)
	put(64)
	// Location records can coexist with the struct/function records used by tracing.
	put(0)
	put(20<<24 | 1)
	put(4)
	put(0)
	put(0)
	put(0)
	put(21<<24 | 1)
	put(0)
	put(6)
	put(0)
	put(22<<24 | 1)
	put(0)
	put(0)
	put(7)
	put(0)
	header := make([]byte, 24)
	order.PutUint16(header, 0xeb9f)
	header[2] = 1
	order.PutUint32(header[4:], 24)
	order.PutUint32(header[12:], uint32(len(types)))
	order.PutUint32(header[16:], uint32(len(types)))
	order.PutUint32(header[20:], uint32(len(str)))
	return append(append(header, types...), str...)
}

func TestICMPBTFParser(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		data := icmpBTFFixture(order)
		b, err := parseICMPBTF(data)
		if err != nil {
			t.Fatal(err)
		}
		if offset, id, ok := b.field(5, "head", 0); !ok || offset != 16 || id != 3 {
			t.Fatal("anonymous struct offset", offset, id, ok)
		}
		if _, _, ok := b.field(5, "missing", 0); ok {
			t.Fatal("invented missing field")
		}
		if _, err := b.hook("__ip_local_out"); err == nil {
			t.Fatal("accepted missing hook")
		}
		for i := range len(data) {
			if _, err := parseICMPBTF(data[:i]); err == nil {
				t.Fatal("accepted truncated BTF", i)
			}
		}
		for at, value := range map[int]uint32{4: 0xffffffff, 8: 0xffffffff, 12: 0xffffffff, 16: 0xffffffff, 20: 0xffffffff, 24: 0xffffffff, 28: 31 << 24} {
			bad := append([]byte(nil), data...)
			order.PutUint32(bad[at:], value)
			if _, err := parseICMPBTF(bad); err == nil {
				t.Fatal("accepted corrupt BTF", at)
			}
		}
	}
}

func TestICMPTraceKey(t *testing.T) {
	if unsafe.Sizeof(icmpTraceKey{}) != 56 || unsafe.Sizeof(icmpTraceOwner{}) != 48 {
		t.Fatal("BPF ABI sizes")
	}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		a := netip.MustParseAddr(ip)
		kind := byte(8)
		if a.Is6() {
			kind = 128
		}
		for _, size := range []int{8, 9, 15, 16, 32, 65535} {
			packet := make([]byte, size)
			packet[0], packet[6] = kind, 1
			key, ok := icmpProcessKey(a, a, packet)
			if !ok || key.length != uint32(size) || key.prefix[6] != 1 {
				t.Fatal("key shape")
			}
			packet[2], packet[3] = 12, 34
			other, _ := icmpProcessKey(a, a, packet)
			if key != other {
				t.Fatal("checksum changed identity")
			}
			packet[0], packet[1] = 3, 1
			if _, ok := icmpProcessKey(a, a, packet); !ok {
				t.Fatal("rejected application-owned non-Echo ICMP")
			}
		}
	}
	for _, packet := range [][]byte{nil, {8}, {8, 0, 0, 0, 0, 0, 0}, make([]byte, 65536)} {
		if _, ok := icmpProcessKey(netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), packet); ok {
			t.Fatal("accepted malformed Echo")
		}
	}
}

func TestICMPBTFSearchBudget(t *testing.T) {
	data := make([]byte, 24+12+256*12+1)
	binary.LittleEndian.PutUint16(data, 0xeb9f)
	data[2] = 1
	binary.LittleEndian.PutUint32(data[4:], 24)
	binary.LittleEndian.PutUint32(data[12:], 12+256*12)
	binary.LittleEndian.PutUint32(data[16:], 12+256*12)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint32(data[28:], 4<<24|256)
	binary.LittleEndian.PutUint32(data[32:], 8)
	for i := range 256 {
		binary.LittleEndian.PutUint32(data[40+i*12:], 1)
	}
	b, err := parseICMPBTF(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := b.field(1, "missing", 0); ok {
		t.Fatal("cyclic anonymous members invented a field")
	}
}

func TestICMPProcessStat(t *testing.T) {
	if start, err := processStartTick([]byte("17 (name with ) bracket) S " + strings.Repeat("0 ", 18) + "12345 0")); err != nil || start != 12345 {
		t.Fatal(start, err)
	}
	for _, data := range []string{"", "17 name S", "17 (name) S", "17 (name) S " + strings.Repeat("0 ", 18) + "bad"} {
		if _, err := processStartTick([]byte(data)); err == nil {
			t.Fatal("accepted bad stat", data)
		}
	}
}

func TestICMPTraceClosedFinder(t *testing.T) {
	f := &processFinder{}
	f.close()
	f.close()
	if f.start() == nil {
		t.Fatal("started a closed finder")
	}
	if _, _, observed := f.lookupICMP(context.Background(), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"), []byte{8, 0, 0, 0, 0, 0, 0, 1}); observed {
		t.Fatal("closed finder observed a packet")
	}
}

func FuzzICMPBTF(f *testing.F) {
	f.Add(icmpBTFFixture(binary.LittleEndian))
	f.Add(icmpBTFFixture(binary.BigEndian))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := parseICMPBTF(data[:min(len(data), 1<<16)])
		if err != nil {
			return
		}
		for i := range min(len(b.offsets), 128) {
			b.field(uint32(i), "head", 0)
			b.unwrap(uint32(i))
		}
	})
}
