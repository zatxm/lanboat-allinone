package native

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type processOwner struct{ pid, fd string }

type processFinder struct {
	mu      sync.Mutex
	owners  map[uint32]processOwner
	lastPID string
	users   map[uint32]processUser
	rawOnce sync.Once
	raw     *icmpProcessTracker
	rawErr  error
	closed  bool
}

type processUser struct {
	name  string
	until time.Time
}

func (f *processFinder) lookup(ctx context.Context, origin socketOrigin) (string, string) {
	m := f.lookupIdentity(ctx, origin, true)
	return m.ProcessName, m.ProcessPath
}

func processSocketOwner(ctx context.Context, origin socketOrigin, deadline time.Time) (uint32, uint32) {
	if ctx.Err() != nil || origin.network != "tcp" && origin.network != "udp" && origin.network != "icmp" {
		return 0, 0
	}
	source, e := netip.ParseAddrPort(origin.source)
	if e != nil || source.Port() == 0 {
		return 0, 0
	}
	destination, e := netip.ParseAddrPort(origin.destination)
	if e != nil || destination.Port() == 0 && origin.network != "icmp" || !processLocalAddress(source.Addr()) {
		return 0, 0
	}
	if origin.network == "icmp" && destination.Port() != 0 {
		return 0, 0
	}
	if !destination.Addr().IsUnspecified() && source.Addr().Unmap().Is4() != destination.Addr().Unmap().Is4() {
		return 0, 0
	}
	var inode, uid uint32
	if origin.network == "icmp" {
		inode, e = processICMPInode(ctx, source, destination, deadline, &uid)
	} else {
		inode, e = processSocketInode(ctx, origin.network, source, destination, deadline, &uid)
	}
	if e != nil || inode == 0 {
		return 0, 0
	}
	return inode, uid
}

func (f *processFinder) lookupIdentity(ctx context.Context, origin socketOrigin, wantPath bool) Metadata {
	deadline := time.Now().Add(250 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	inode, uid := processSocketOwner(ctx, origin, deadline)
	return f.identityForInode(ctx, inode, uid, wantPath, deadline)
}

func (f *processFinder) identityForInode(ctx context.Context, inode, uid uint32, wantPath bool, deadline time.Time) Metadata {
	if inode == 0 {
		return Metadata{}
	}

	identity := Metadata{UserID: &uid}
	withPath := func(path string) Metadata {
		identity.ProcessName, identity.ProcessPath = filepath.Base(path), path
		return identity
	}
	if !wantPath {
		return identity
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil || time.Now().After(deadline) {
		return Metadata{}
	}
	target := "socket:[" + strconv.FormatUint(uint64(inode), 10) + "]"
	if owner, ok := f.owners[inode]; ok {
		if path := owner.path(target); path != "" {
			return withPath(path)
		}
		delete(f.owners, inode)
	}
	find := func(pid string) string {
		fds, err := os.ReadDir("/proc/" + pid + "/fd")
		if err != nil {
			return ""
		}
		for _, fd := range fds {
			if ctx.Err() != nil || time.Now().After(deadline) {
				break
			}
			owner := processOwner{pid: pid, fd: fd.Name()}
			if path := owner.path(target); path != "" {
				if len(f.owners) >= 256 {
					clear(f.owners)
				}
				if f.owners == nil {
					f.owners = make(map[uint32]processOwner)
				}
				f.owners[inode], f.lastPID = owner, pid
				return path
			}
		}
		return ""
	}
	if f.lastPID != "" {
		if path := find(f.lastPID); path != "" {
			return withPath(path)
		}
	}
	proc, e := os.Open("/proc")
	if e != nil {
		return identity
	}
	defer proc.Close()
	for ctx.Err() == nil && time.Now().Before(deadline) {
		entries, err := proc.ReadDir(64)
		for _, entry := range entries {
			pid := entry.Name()
			if _, err := strconv.ParseUint(pid, 10, 32); err != nil || pid == f.lastPID {
				continue
			}
			if path := find(pid); path != "" {
				return withPath(path)
			}
		}
		if err != nil {
			break
		}
	}
	return identity
}

func (o processOwner) path(target string) string {
	base := "/proc/" + o.pid + "/"
	if link, e := os.Readlink(base + "fd/" + o.fd); e != nil || link != target {
		return ""
	}
	path, _ := os.Readlink(base + "exe")
	// Revalidate after reading exe: close/exec must not reuse a cached identity.
	if link, e := os.Readlink(base + "fd/" + o.fd); e != nil || link != target {
		return ""
	}
	return strings.TrimSuffix(path, " (deleted)")
}

func processLocalAddress(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	if ip.IsLoopback() {
		return true
	}
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		p, e := netip.ParsePrefix(address.String())
		if e == nil && p.Addr().Unmap() == ip {
			return true
		}
	}
	return false
}

// Query the kernel's socket table, never infer a process from a peer's port alone.
func processSocketInode(ctx context.Context, network string, source, destination netip.AddrPort, deadline time.Time, uidOut ...*uint32) (uint32, error) {
	fd, e := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 4) // NETLINK_SOCK_DIAG
	if e != nil {
		return 0, e
	}
	defer syscall.Close(fd)
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	var inode, uid uint32
	best, ambiguous := 0, false
	exact := network == "tcp" && !destination.Addr().IsUnspecified()
	families := []byte{syscall.AF_INET6}
	if source.Addr().Unmap().Is4() {
		families = []byte{syscall.AF_INET, syscall.AF_INET6}
	}
	for _, family := range families {
		var b [72]byte // nlmsghdr + inet_diag_req_v2
		binary.NativeEndian.PutUint32(b[:], uint32(len(b)))
		binary.NativeEndian.PutUint16(b[4:], 20) // SOCK_DIAG_BY_FAMILY
		binary.NativeEndian.PutUint16(b[6:], syscall.NLM_F_REQUEST|syscall.NLM_F_DUMP)
		if exact {
			binary.NativeEndian.PutUint16(b[6:], syscall.NLM_F_REQUEST)
			if family == syscall.AF_INET {
				src, dst := source.Addr().As4(), destination.Addr().As4()
				copy(b[28:], src[:])
				copy(b[44:], dst[:])
			} else {
				src, dst := source.Addr().As16(), destination.Addr().As16()
				copy(b[28:], src[:])
				copy(b[44:], dst[:])
			}
			binary.NativeEndian.PutUint64(b[64:], ^uint64(0)) // INET_DIAG_NOCOOKIE
			if zone := source.Addr().Zone(); zone != "" {
				if link, e := net.InterfaceByName(zone); e == nil {
					binary.NativeEndian.PutUint32(b[60:], uint32(link.Index))
				}
			}
		}
		binary.NativeEndian.PutUint32(b[8:], uint32(family))
		b[16], b[17] = family, syscall.IPPROTO_TCP
		if network == "udp" {
			b[17] = syscall.IPPROTO_UDP
		}
		binary.NativeEndian.PutUint32(b[20:], ^uint32(0))
		binary.BigEndian.PutUint16(b[24:], source.Port())
		if network == "tcp" {
			binary.BigEndian.PutUint16(b[26:], destination.Port())
		}
		if e := syscall.Sendto(fd, b[:], 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); e != nil {
			return 0, e
		}
		done := false
		for !done {
			if ctx.Err() != nil {
				return 0, ctx.Err()
			}
			left := time.Until(deadline)
			if left <= 0 {
				return 0, context.DeadlineExceeded
			}
			wait := syscall.NsecToTimeval(left.Nanoseconds())
			if e := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &wait); e != nil {
				return 0, e
			}
			n, from, e := syscall.Recvfrom(fd, buffer, 0)
			if e == syscall.EINTR {
				continue
			}
			if e != nil {
				return 0, e
			}
			peer, ok := from.(*syscall.SockaddrNetlink)
			if !ok || peer.Pid != 0 {
				return 0, errors.New("invalid socket diagnostic sender")
			}
			messages, e := syscall.ParseNetlinkMessage(buffer[:n])
			if e != nil {
				return 0, e
			}
			for _, m := range messages {
				if m.Header.Seq != uint32(family) || m.Header.Flags&0x10 != 0 { // NLM_F_DUMP_INTR
					return 0, errors.New("incomplete socket diagnostic snapshot")
				}
				switch m.Header.Type {
				case syscall.NLMSG_DONE:
					if len(m.Data) >= 4 {
						if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
							return 0, syscall.Errno(-code)
						}
					}
					done = true
				case syscall.NLMSG_ERROR:
					if len(m.Data) < 4 {
						return 0, syscall.EINVAL
					}
					if code := int32(binary.NativeEndian.Uint32(m.Data)); code != 0 {
						if exact && syscall.Errno(-code) == syscall.ENOENT {
							done = true
							continue
						}
						return 0, syscall.Errno(-code)
					}
				case 20:
					candidate, score := matchProcessSocket(m.Data, network, source, destination)
					if exact {
						if candidate != 0 && len(uidOut) != 0 {
							*uidOut[0] = binary.NativeEndian.Uint32(m.Data[64:68])
						}
						return candidate, nil
					}
					if score > best {
						inode, best, ambiguous = candidate, score, false
						uid = binary.NativeEndian.Uint32(m.Data[64:68])
					} else if score == best && score > 0 && inode != candidate {
						ambiguous = true
					}
				}
			}
		}
	}
	if ambiguous {
		return 0, errors.New("ambiguous socket owner")
	}
	if inode != 0 && len(uidOut) != 0 {
		*uidOut[0] = uid
	}
	return inode, nil
}

func matchProcessSocket(b []byte, network string, source, destination netip.AddrPort) (uint32, int) {
	if len(b) < 72 || binary.BigEndian.Uint16(b[4:]) != source.Port() {
		return 0, 0
	}
	var local, remote netip.Addr
	switch b[0] {
	case syscall.AF_INET:
		local, remote = netip.AddrFrom4([4]byte(b[8:12])), netip.AddrFrom4([4]byte(b[24:28]))
	case syscall.AF_INET6:
		local, remote = netip.AddrFrom16([16]byte(b[8:24])).Unmap(), netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	default:
		return 0, 0
	}
	src, dst := source.Addr().WithZone("").Unmap(), destination.Addr().WithZone("").Unmap()
	score := 1
	if local == src {
		score += 2
	} else if network != "udp" || !local.IsUnspecified() {
		return 0, 0
	} else if b[0] == syscall.AF_INET6 && src.Is4() {
		// A v6-only wildcard cannot own a v4 datagram.
		dual := false
		for attrs := b[72:]; len(attrs) >= 4; {
			n := int(binary.NativeEndian.Uint16(attrs))
			if n < 4 || n > len(attrs) {
				return 0, 0
			}
			if binary.NativeEndian.Uint16(attrs[2:]) == 11 && n == 5 {
				dual = attrs[4] == 0 // INET_DIAG_SKV6ONLY
			}
			step := (n + 3) &^ 3
			if step > len(attrs) {
				break
			}
			attrs = attrs[step:]
		}
		if !dual {
			return 0, 0
		}
	}
	port := binary.BigEndian.Uint16(b[6:])
	if port == destination.Port() && (remote == dst || dst.IsUnspecified()) {
		score += 4
	} else if network != "udp" || port != 0 || !remote.IsUnspecified() {
		return 0, 0
	}
	if inode := binary.NativeEndian.Uint32(b[68:]); inode != 0 {
		return inode, score
	}
	return 0, 0
}

func (f *processFinder) userName(uid uint32) string {
	now := time.Now()
	f.mu.Lock()
	cached, ok := f.users[uid]
	f.mu.Unlock()
	if ok && now.Before(cached.until) {
		return cached.name
	}
	name := ""
	if account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		name = account.Username
	}
	f.mu.Lock()
	if len(f.users) >= 256 {
		clear(f.users)
	}
	if f.users == nil {
		f.users = map[uint32]processUser{}
	}
	f.users[uid] = processUser{name: name, until: now.Add(time.Minute)}
	f.mu.Unlock()
	return name
}
