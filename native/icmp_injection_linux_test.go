package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func icmpInjectionPacket(source, destination netip.Addr, id byte) []byte {
	packet := makeUDPPacket(source, destination, 0, 0, []byte{'i', 'n', 'j', 'e', 'c', 't', 'e', id})
	header, protocol, kind := 20, byte(1), byte(8)
	if source.Is6() {
		header, protocol, kind = 40, 58, 128
		packet[6] = protocol
	} else {
		packet[9] = protocol
	}
	segment := packet[header:]
	clear(segment[:8])
	segment[0], segment[7] = kind, id
	p := tunPacket{source: source, destination: destination, protocol: protocol, header: header, data: packet}
	if source.Is6() {
		binary.BigEndian.PutUint16(segment[2:], transportChecksum(p, segment))
	} else {
		binary.BigEndian.PutUint16(segment[2:], checksum(segment, 0))
		clear(packet[10:12])
		binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20], 0))
	}
	return packet
}

func icmpInjectionSocket(t *testing.T, v6 bool) *os.File {
	t.Helper()
	family, level, option := syscall.AF_INET, syscall.IPPROTO_IP, syscall.IP_HDRINCL
	if v6 {
		family, level, option = syscall.AF_INET6, syscall.IPPROTO_IPV6, 36
	}
	fd, err := syscall.Socket(family, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.IPPROTO_RAW)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "hdr-icmp")
	t.Cleanup(func() { file.Close() })
	if err = syscall.SetsockoptInt(fd, level, option, 1); err != nil {
		t.Fatal(err)
	}
	return file
}

func icmpInjectionSend(t *testing.T, fd int, packet []byte, mode string) {
	t.Helper()
	var target syscall.Sockaddr = &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if mode == "hdr6" {
		target = &syscall.SockaddrInet6{Addr: [16]byte{15: 1}}
	}
	if mode == "packet" {
		loop, err := net.InterfaceByName("lo")
		if err != nil {
			t.Fatal(err)
		}
		ether := uint16(0x0800)
		if packet[0]>>4 == 6 {
			ether = 0x86dd
		} else if packet[0]>>4 != 4 {
			ether = binary.BigEndian.Uint16(packet[12:14])
		}
		target = &syscall.SockaddrLinklayer{Ifindex: loop.Index, Protocol: ether>>8 | ether<<8, Halen: 6}
	}
	if err := syscall.Sendto(fd, packet, 0, target); err != nil {
		t.Fatal(err)
	}
}

func testICMPInjection(t *testing.T, f *processFinder) {
	if f.raw.injectionErr != nil || f.raw.ringErr != nil || len(f.raw.injectionLinks) != 10 {
		t.Fatal("injection tracking missing", f.raw.injectionErr, f.raw.ringErr, len(f.raw.injectionLinks))
	}
	id := byte(110)
	for _, v6 := range []bool{false, true} {
		t.Run(fmt.Sprint("hdr-ipv6=", v6), func(t *testing.T) {
			ip, mode, header := netip.MustParseAddr("127.0.0.1"), "hdr4", 20
			if v6 {
				ip, mode, header = netip.MustParseAddr("::1"), "hdr6", 40
			}
			file := icmpInjectionSocket(t, v6)
			packet := icmpInjectionPacket(ip, ip, 101)
			// Split the IP header across user iovecs; the kernel event must see the assembled packet.
			if err := syscall.Connect(int(file.Fd()), map[bool]syscall.Sockaddr{false: &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}, true: &syscall.SockaddrInet6{Addr: [16]byte{15: 1}}}[v6]); err != nil {
				t.Fatal(err)
			}
			parts := []syscall.Iovec{{Base: &packet[0]}, {Base: &packet[7]}}
			parts[0].SetLen(7)
			parts[1].SetLen(len(packet) - 7)
			msg := syscall.Msghdr{Iov: &parts[0], Iovlen: 2}
			if _, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, file.Fd(), uintptr(unsafe.Pointer(&msg)), 0); errno != 0 {
				t.Fatal(errno)
			}
			key, _ := icmpProcessKey(ip, ip, packet[header:])
			owner, err := f.raw.lookup(key)
			if err != nil || owner.pid != uint32(os.Getpid()) || owner.flags != 0 {
				t.Fatal("HDRINCL sender missing", owner, err)
			}
			a := icmpTraceWorker(t, file, mode, nil)
			b := icmpTraceWorker(t, file, mode, nil)
			packet = icmpInjectionPacket(ip, ip, 102)
			a.send(t, packet)
			key, _ = icmpProcessKey(ip, ip, packet[header:])
			owner, err = f.raw.lookup(key)
			if err != nil || owner.pid != uint32(a.cmd.Process.Pid) || owner.flags != 0 {
				t.Fatal("HDRINCL inherited writer missing", owner, err)
			}
			b.send(t, packet)
			if _, path, seen := f.lookupICMP(context.Background(), ip, ip, packet[header:]); !seen || path != "" {
				t.Fatal("HDRINCL ambiguity lost", path, seen)
			}
			if _, err := syscall.SendmsgN(int(file.Fd()), []byte{0}, nil, nil, 0); err == nil {
				t.Fatal("malformed injected header was accepted")
			}
			// No thread marker may survive the completed send (success or error).
			var next uint64
			attr := struct {
				fd, padding uint32
				key, value  unsafe.Pointer
			}{fd: uint32(f.raw.sendFD), value: unsafe.Pointer(&next)}
			if _, err := icmpBPFCall(4, unsafe.Pointer(&attr), unsafe.Sizeof(attr)); err != syscall.ENOENT {
				t.Fatal("send marker leaked", next, err)
			}
		})
		for _, raw := range []bool{false, true} {
			for _, bypass := range []bool{false, true} {
				t.Run(fmt.Sprintf("packet-ipv6=%t/raw=%t/bypass=%t", v6, raw, bypass), func(t *testing.T) {
					ip, header, ether := netip.MustParseAddr("127.0.0.1"), 20, uint16(0x0800)
					if v6 {
						ip, header, ether = netip.MustParseAddr("::1"), 40, 0x86dd
					}
					kind := syscall.SOCK_DGRAM
					if raw {
						kind = syscall.SOCK_RAW
					}
					fd, err := syscall.Socket(syscall.AF_PACKET, kind|syscall.SOCK_CLOEXEC, int(ether>>8|ether<<8))
					if err != nil {
						t.Fatal(err)
					}
					defer syscall.Close(fd)
					if bypass {
						if err = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, 20, 1); err != nil {
							t.Fatal(err)
						}
					}
					id++
					packet := icmpInjectionPacket(ip, ip, id)
					key, _ := icmpProcessKey(ip, ip, packet[header:])
					if raw {
						frame := make([]byte, 14+len(packet))
						binary.BigEndian.PutUint16(frame[12:], ether)
						copy(frame[14:], packet)
						packet = frame
					}
					packet = append(packet, make([]byte, 32)...)
					icmpInjectionSend(t, fd, packet, "packet")
					owner, err := f.raw.lookup(key)
					if err != nil || owner.pid != uint32(os.Getpid()) || owner.flags != 0 {
						t.Fatal("AF_PACKET sender missing", owner, err)
					}
					if !raw && !bypass {
						duplicate, err := syscall.Dup(fd)
						if err != nil {
							t.Fatal(err)
						}
						file := os.NewFile(uintptr(duplicate), "packet-icmp")
						defer file.Close()
						writer := icmpTraceWorker(t, file, "packet", nil)
						childPacket := icmpInjectionPacket(ip, ip, id+40)
						writer.send(t, childPacket)
						childKey, _ := icmpProcessKey(ip, ip, childPacket[header:])
						owner, err = f.raw.lookup(childKey)
						if err != nil || owner.pid != uint32(writer.cmd.Process.Pid) || owner.flags != 0 {
							t.Fatal("AF_PACKET actual writer missing", owner, err)
						}
						icmpInjectionSend(t, fd, childPacket, "packet")
						if _, path, seen := f.lookupICMP(context.Background(), ip, ip, childPacket[header:]); !seen || path != "" {
							t.Fatal("AF_PACKET ambiguity lost", path, seen)
						}
					}
				})
			}
		}
	}
}

func testICMPInjectionLifecycle(t *testing.T, f *processFinder) {
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseICMPBTF(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("signals-during-load", func(t *testing.T) {
		id, err := b.hook("__ip_local_out", "net", "sock", "sk_buff")
		if err != nil {
			t.Fatal(err)
		}
		p := &icmpBPFProgram{}
		for range 512 {
			p.emit(0xb7, 0, 0, 0, 0)
		}
		p.emit(0x95, 0, 0, 0, 0)
		code, err := p.bytes()
		if err != nil {
			t.Fatal(err)
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tid := syscall.Gettid()
		done := make(chan error, 1)
		go func() {
			for range 3 {
				time.Sleep(200 * time.Microsecond)
				if err := syscall.Tgkill(os.Getpid(), tid, syscall.SIGURG); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}()
		link, err := attachICMPTrace(id, code, false)
		if signalErr := <-done; signalErr != nil {
			t.Fatal(signalErr)
		}
		if err != nil {
			t.Fatal("signal-interrupted load failed", err)
		}
		syscall.Close(link)
	})
	t.Run("ring-hook-unavailable", func(t *testing.T) {
		netNS, err := os.Stat("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		pidNS, err := os.Stat("/proc/self/ns/pid")
		if err != nil {
			t.Fatal(err)
		}
		netStat, pidStat := netNS.Sys().(*syscall.Stat_t), pidNS.Sys().(*syscall.Stat_t)
		tracker := &icmpProcessTracker{mapFD: f.raw.mapFD, sendFD: -1}
		defer tracker.closeInjection()
		if err = tracker.startInjection(b, uint32(netStat.Ino), pidStat.Dev, pidStat.Ino); err != nil {
			t.Fatal(err)
		}
		id := b.named["tpacket_fill_skb"]
		delete(b.named, "tpacket_fill_skb")
		defer func() { b.named["tpacket_fill_skb"] = id }()
		before, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		if err = tracker.startTXRing(b, uint32(netStat.Ino), pidStat.Dev, pidStat.Ino); err == nil {
			t.Fatal("accepted missing ring hook")
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(before) != len(after) || len(tracker.injectionLinks) != 9 || tracker.sendFD < 0 {
			t.Fatal("ring failure damaged base injection or leaked descriptors", len(before), len(after), err)
		}
	})
	t.Run("partial-load-cleanup", func(t *testing.T) {
		netNS, err := os.Stat("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		pidNS, err := os.Stat("/proc/self/ns/pid")
		if err != nil {
			t.Fatal(err)
		}
		netStat, pidStat := netNS.Sys().(*syscall.Stat_t), pidNS.Sys().(*syscall.Stat_t)
		delete(b.named, "packet_sendmsg")
		before, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		tracker := &icmpProcessTracker{mapFD: f.raw.mapFD, sendFD: -1}
		if err = tracker.startInjection(b, uint32(netStat.Ino), pidStat.Dev, pidStat.Ino); err == nil {
			t.Fatal("accepted missing injection hook")
		}
		if tracker.sendFD != -1 || len(tracker.injectionLinks) != 0 {
			t.Fatal("failed optional load retained resources")
		}
		tracker.closeInjection()
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(before) != len(after) {
			t.Fatal("failed load leaked descriptors", len(before), len(after), err)
		}
		ip := netip.MustParseAddr("127.0.0.1")
		packet := []byte{8, 0, 0, 0, 0, 0, 0, 129, 'b', 'a', 's', 'e'}
		file := icmpTraceRawSocket(t, false)
		icmpTraceSend(t, int(file.Fd()), packet, ip)
		if _, path, seen := f.lookupICMP(context.Background(), ip, ip, packet); !seen || path == "" {
			t.Fatal("optional failure broke base tracking")
		}
	})
}
