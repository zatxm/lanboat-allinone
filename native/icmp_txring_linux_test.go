package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const icmpTXFrame = 8192
const icmpTXSlots = 4

func TestICMPTXRingHook(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, modern := range []bool{false, true} {
			t.Run(fmt.Sprint(order, "/modern=", modern), func(t *testing.T) {
				for _, invalid := range []bool{false, true} {
					var types []byte
					strings := []byte{0}
					next := uint32(0)
					add := func(name string, kind, count, value uint32, fields ...uint32) uint32 {
						next++
						offset := uint32(0)
						if name != "" {
							offset = uint32(len(strings))
							strings = append(strings, append([]byte(name), 0)...)
						}
						for _, n := range append([]uint32{offset, kind<<24 | count, value}, fields...) {
							var encoded [4]byte
							order.PutUint32(encoded[:], n)
							types = append(types, encoded[:]...)
						}
						return next
					}
					integer := add("int", 1, 0, 4, 32)
					var pointers []uint32
					for _, name := range []string{"packet_sock", "sk_buff", "net_device", "sockcm_cookie"} {
						id := add(name, 4, 0, 16)
						pointers = append(pointers, add("", 2, 0, id))
					}
					void := add("", 2, 0, 0)
					args := []uint32{pointers[0], pointers[1], void, pointers[2], void, integer, integer, void, integer, integer, pointers[3]}
					if modern {
						args = []uint32{pointers[0], pointers[1], pointers[2], void, integer, integer, void, integer, integer, integer, pointers[3]}
					}
					if invalid {
						args[1] = void
					}
					var fields []uint32
					for _, typ := range args {
						fields = append(fields, 0, typ)
					}
					proto := add("", 13, uint32(len(args)), integer, fields...)
					wantID := add("tpacket_fill_skb", 12, 0, proto)
					header := make([]byte, 24)
					order.PutUint16(header, 0xeb9f)
					header[2] = 1
					order.PutUint32(header[4:], 24)
					order.PutUint32(header[12:], uint32(len(types)))
					order.PutUint32(header[16:], uint32(len(types)))
					order.PutUint32(header[20:], uint32(len(strings)))
					b, err := parseICMPBTF(append(append(header, types...), strings...))
					if err != nil {
						t.Fatal(err)
					}
					id, dev, data, err := b.txRingHook()
					if invalid {
						if err == nil {
							t.Fatal("accepted incompatible hook")
						}
					} else if err != nil || id != wantID || dev != map[bool]int16{false: 24, true: 16}[modern] || data != dev+8 {
						t.Fatal(id, dev, data, err)
					}
				}
			})
		}
	}
}

type icmpTXRing struct {
	fd, version, next int
	memory            []byte
}

func newICMPTXRing(t *testing.T, version int, ipv6, raw, bypass bool, device string) *icmpTXRing {
	t.Helper()
	kind, ether := syscall.SOCK_DGRAM, uint16(0x0800)
	if raw {
		kind = syscall.SOCK_RAW
	}
	if ipv6 {
		ether = 0x86dd
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, kind|syscall.SOCK_CLOEXEC, int(ether>>8|ether<<8))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, 10, version); err != nil {
		t.Fatal(err)
	}
	if bypass {
		if err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, 20, 1); err != nil {
			t.Fatal(err)
		}
	}
	request := [7]uint32{icmpTXFrame, icmpTXSlots, icmpTXFrame, icmpTXSlots}
	size := uintptr(16)
	if version == 2 {
		size = 28
	}
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd), syscall.SOL_PACKET, 13, uintptr(unsafe.Pointer(&request)), size, 0); errno != 0 {
		t.Fatal(errno)
	}
	link, err := net.InterfaceByName(device)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Ifindex: link.Index, Protocol: ether>>8 | ether<<8}); err != nil {
		t.Fatal(err)
	}
	return mapICMPTXRing(t, fd, version)
}

func mapICMPTXRing(t *testing.T, fd, version int) *icmpTXRing {
	t.Helper()
	memory, err := syscall.Mmap(fd, 0, icmpTXFrame*icmpTXSlots, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Munmap(memory) })
	return &icmpTXRing{fd: fd, version: version, memory: memory}
}

func (r *icmpTXRing) layout() (status, length, data int) {
	switch r.version {
	case 0:
		word := int(unsafe.Sizeof(uintptr(0)))
		return 0, word, (word + 20 + 15) &^ 15
	case 1:
		return 0, 4, 32
	default:
		return 20, 16, 48
	}
}

func (r *icmpTXRing) status(frame []byte, set bool) uint32 {
	at, _, _ := r.layout()
	if r.version == 0 && unsafe.Sizeof(uintptr(0)) == 8 {
		p := (*uint64)(unsafe.Pointer(&frame[at]))
		if set {
			atomic.StoreUint64(p, 1)
		}
		return uint32(atomic.LoadUint64(p))
	}
	p := (*uint32)(unsafe.Pointer(&frame[at]))
	if set {
		atomic.StoreUint32(p, 1)
	}
	return atomic.LoadUint32(p)
}

func (r *icmpTXRing) send(t *testing.T, packets ...[]byte) {
	t.Helper()
	if len(packets) == 0 || len(packets) > icmpTXSlots {
		t.Fatal("invalid TX batch size", len(packets))
	}
	_, length, data := r.layout()
	frames := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		frame := r.memory[r.next*icmpTXFrame : (r.next+1)*icmpTXFrame]
		if r.status(frame, false)&7 != 0 || len(packet) > len(frame)-data {
			t.Fatal("TX frame unavailable or too small")
		}
		clear(frame[:data])
		binary.NativeEndian.PutUint32(frame[length:], uint32(len(packet)))
		copy(frame[data:], packet)
		r.status(frame, true)
		frames = append(frames, frame)
		r.next = (r.next + 1) % icmpTXSlots
	}
	if _, err := syscall.SendmsgN(r.fd, nil, nil, nil, syscall.MSG_DONTWAIT); err != nil {
		t.Fatal("TX_RING send", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for _, frame := range frames {
		for r.status(frame, false)&3 != 0 && time.Now().Before(deadline) {
			time.Sleep(100 * time.Microsecond)
		}
		if status := r.status(frame, false); status&7 != 0 {
			t.Fatal("TX_RING completion", status)
		}
	}
}

func testICMPTXRing(t *testing.T, f *processFinder) {
	for version := range 3 {
		for _, v6 := range []bool{false, true} {
			for _, raw := range []bool{false, true} {
				for _, bypass := range []bool{false, true} {
					t.Run(fmt.Sprintf("v%d/ipv6=%t/raw=%t/bypass=%t", version+1, v6, raw, bypass), func(t *testing.T) {
						r := newICMPTXRing(t, version, v6, raw, bypass, "lo")
						ip, header, ether := netip.MustParseAddr("127.0.0.1"), 20, uint16(0x0800)
						if v6 {
							ip, header, ether = netip.MustParseAddr("::1"), 40, 0x86dd
						}
						packet := func(id byte, padding int) ([]byte, icmpTraceKey) {
							b := icmpInjectionPacket(ip, ip, id)
							key, ok := icmpProcessKey(ip, ip, b[header:])
							if !ok {
								t.Fatal("invalid fixture key")
							}
							if raw {
								frame := make([]byte, 14+len(b))
								binary.BigEndian.PutUint16(frame[12:], ether)
								copy(frame[14:], b)
								b = frame
							}
							return append(b, make([]byte, padding)...), key
						}
						// Reuse every slot, batch submissions and force page-backed payloads.
						for batch := range 3 {
							var packets [][]byte
							var keys []icmpTraceKey
							for i := range icmpTXSlots {
								b, key := packet(byte(210+batch*icmpTXSlots+i), []int{0, 32, 1200, 4096}[i])
								packets, keys = append(packets, b), append(keys, key)
							}
							r.send(t, packets...)
							for _, key := range keys {
								owner, err := f.raw.lookup(key)
								if err != nil || owner.pid != uint32(os.Getpid()) || owner.flags != 0 {
									t.Fatal("TX_RING sender missing", owner, err)
								}
							}
						}
						duplicate, err := syscall.Dup(r.fd)
						if err != nil {
							t.Fatal(err)
						}
						file := os.NewFile(uintptr(duplicate), "txring-icmp")
						t.Cleanup(func() { file.Close() })
						writer := icmpTraceWorker(t, file, fmt.Sprint("txring", version), nil)
						id := byte(190 + version*4)
						if raw {
							id += 2
						}
						if bypass {
							id++
						}
						b, key := packet(id, 32)
						writer.send(t, b)
						owner, err := f.raw.lookup(key)
						if err != nil || owner.pid != uint32(writer.cmd.Process.Pid) || owner.flags != 0 {
							t.Fatal("TX_RING actual submitter missing", owner, err)
						}
						r.send(t, b, b, b, b)
						if _, path, seen := f.lookupICMP(context.Background(), ip, ip, icmpInjectionPacket(ip, ip, id)[header:]); !seen || path != "" {
							t.Fatal("TX_RING shared sender ambiguity lost", path, seen)
						}
					})
				}
			}
		}
	}
}
