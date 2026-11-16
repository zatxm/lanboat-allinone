package native

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

func processICMPInode(ctx context.Context, source, destination netip.AddrPort, deadline time.Time, uidOut ...*uint32) (uint32, error) {
	suffix := ""
	if source.Addr().Is6() {
		suffix = "6"
	}
	var inode uint32
	for _, name := range []string{"icmp", "raw"} {
		file, err := os.Open("/proc/net/" + name + suffix)
		if err != nil {
			return 0, err
		}
		candidate, err := processICMPTable(ctx, file, source, destination, deadline, name == "raw", uidOut...)
		file.Close()
		if err != nil {
			return 0, err
		}
		if name == "icmp" {
			inode = candidate
			if inode == 0 {
				return 0, nil
			}
		}
	}
	return inode, nil
}

func processICMPTable(ctx context.Context, reader io.Reader, source, destination netip.AddrPort, deadline time.Time, raw bool, uidOut ...*uint32) (uint32, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 4096)
	if !scanner.Scan() || !strings.Contains(scanner.Text(), "local_address") {
		return 0, errors.New("invalid ICMP socket table")
	}
	src, dst := source.Addr().WithZone(""), destination.Addr().WithZone("")
	id := source.Port()
	if raw {
		id = 1
		if src.Is6() {
			id = 58
		}
	}
	var inode uint32
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if time.Now().After(deadline) {
			return 0, context.DeadlineExceeded
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return 0, errors.New("short ICMP socket record")
		}
		local, ok := processICMPAddress(fields[1])
		remote, remoteOK := processICMPAddress(fields[2])
		if !ok || !remoteOK {
			return 0, errors.New("invalid ICMP socket address")
		}
		if local.Port() != id || remote.Port() != 0 || local.Addr().BitLen() != src.BitLen() || remote.Addr().BitLen() != dst.BitLen() || local.Addr() != src && !local.Addr().IsUnspecified() || remote.Addr() != dst && !remote.Addr().IsUnspecified() {
			continue
		}
		// Raw sockets choose their own Echo ID; a matching listener makes attribution uncertain.
		if raw {
			return 0, errors.New("ambiguous raw ICMP owner")
		}
		candidate, err := strconv.ParseUint(fields[9], 10, 32)
		if err != nil || candidate == 0 {
			return 0, errors.New("invalid ICMP socket inode")
		}
		if inode != 0 && inode != uint32(candidate) {
			return 0, errors.New("ambiguous ICMP socket owner")
		}
		if len(uidOut) != 0 {
			uid, err := strconv.ParseUint(fields[7], 10, 32)
			if err != nil {
				return 0, err
			}
			*uidOut[0] = uint32(uid)
		}
		inode = uint32(candidate)
	}
	return inode, scanner.Err()
}

func processICMPAddress(value string) (netip.AddrPort, bool) {
	ip, port, ok := strings.Cut(value, ":")
	if !ok || len(ip) != 8 && len(ip) != 32 || len(port) != 4 {
		return netip.AddrPort{}, false
	}
	var data [16]byte
	for i := 0; i < len(ip)/8; i++ {
		n, err := strconv.ParseUint(ip[i*8:i*8+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, false
		}
		binary.NativeEndian.PutUint32(data[i*4:], uint32(n))
	}
	n, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	address := netip.AddrFrom16(data)
	if len(ip) == 8 {
		address = netip.AddrFrom4([4]byte(data[:4]))
	}
	return netip.AddrPortFrom(address, uint16(n)), true
}
