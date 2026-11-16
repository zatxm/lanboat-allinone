package native

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

type mdnsPathsKey struct{}
type mdnsPath struct {
	name     string
	index    int
	local    netip.Addr
	prefixes []netip.Prefix
}

func mdnsPaths(names []string) ([]mdnsPath, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, "", err
	}
	slices.SortFunc(interfaces, func(a, b net.Interface) int { return strings.Compare(a.Name, b.Name) })
	var paths []mdnsPath
	var namespace strings.Builder
	found := map[string]bool{}
	for _, iface := range interfaces {
		if len(names) != 0 && !slices.Contains(names, iface.Name) {
			continue
		}
		found[iface.Name] = true
		if iface.Flags&net.FlagUp == 0 || len(names) == 0 && (iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagMulticast == 0) {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, "", err
		}
		var prefixes []netip.Prefix
		var v4, v6 netip.Addr
		for _, address := range addresses {
			p, e := netip.ParsePrefix(address.String())
			if e != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
				continue
			}
			prefixes = append(prefixes, p)
			if p.Addr().Is4() && !v4.IsValid() {
				v4 = p.Addr()
			}
			if p.Addr().Is6() && (!v6.IsValid() || p.Addr().IsLinkLocalUnicast()) {
				v6 = p.Addr()
			}
		}
		slices.SortFunc(prefixes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		fmt.Fprintf(&namespace, "%s/%d/%s/%v;", iface.Name, iface.Index, iface.HardwareAddr, prefixes)
		for _, ip := range []netip.Addr{v4, v6} {
			if ip.IsValid() {
				paths = append(paths, mdnsPath{iface.Name, iface.Index, ip, prefixes})
			}
		}
	}
	for _, name := range names {
		if !found[name] {
			return nil, "", fmt.Errorf("mDNS interface %q not found", name)
		}
	}
	if len(paths) == 0 || len(paths) > 128 {
		return nil, "", errors.New("mDNS requires1-64 active interfaces with usable addresses")
	}
	return paths, namespace.String(), nil
}

func (p mdnsPath) onLink(ip netip.Addr) bool {
	ip = ip.WithZone("").Unmap()
	if ip.IsUnspecified() || ip.IsMulticast() || ip.Is4() != p.local.Is4() {
		return false
	}
	if ip.Is6() && ip.IsLinkLocalUnicast() {
		return true
	}
	return slices.ContainsFunc(p.prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(ip) })
}

func (r *resolver) exchangeMDNS(ctx context.Context, server DNSServer, query []byte) ([]byte, error) {
	host, end, _, err := dnsQuestion(query)
	if err != nil {
		return nil, err
	}
	paths, _ := ctx.Value(mdnsPathsKey{}).([]mdnsPath)
	if len(paths) == 0 {
		paths, _, err = mdnsPaths(server.Interfaces)
		if err != nil {
			return nil, err
		}
	}
	// RFC6762 one-shot queries use an ephemeral source port and conventional
	// unicast replies. They coexist with system responders already on port5353.
	wire, err := dnsAppendName(make([]byte, 12), host)
	if err != nil {
		return nil, err
	}
	wire = append(wire, query[end-4:end]...)
	wire[5] = 1
	if _, err = rand.Read(wire[:2]); err != nil {
		return nil, err
	}
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	type result struct {
		data []byte
		err  error
	}
	results := make(chan result, len(paths))
	var jobs sync.WaitGroup
	defer jobs.Wait()
	defer cancel()
	for _, path := range paths {
		jobs.Add(1)
		go func() {
			defer jobs.Done()
			data, err := r.mdnsQuery(ctx, path, wire)
			results <- result{data, err}
		}()
	}
	var failures []error
	for range paths {
		answer := <-results
		if answer.err == nil {
			copy(answer.data[:2], query[:2])
			answer.data[2] = answer.data[2]&^1 | query[2]&1
			answer.data[3] &^= 0x20 // Local multicast data is not DNSSEC-authenticated.
			return answer.data, nil
		}
		failures = append(failures, answer.err)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, errors.Join(failures...)
}

func (r *resolver) mdnsQuery(ctx context.Context, path mdnsPath, query []byte) ([]byte, error) {
	network, group := "udp4", netip.MustParseAddr("224.0.0.251")
	local := path.local
	if local.Is6() {
		network, group = "udp6", netip.MustParseAddr("ff02::fb").WithZone(path.name)
		if local.IsLinkLocalUnicast() {
			local = local.WithZone(path.name)
		}
	}
	var mark uint32
	if r.runtime != nil {
		mark = r.runtime.protectMark.Load()
		if mark == 0 {
			mark = uint32(r.runtime.config.Route.DefaultMark)
		}
	}
	listener := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		if e := raw.Control(func(fd uintptr) { err = mdnsSocketOptions(fd, path, mark) }); e != nil {
			return e
		}
		return err
	}}
	packets, err := listener.ListenPacket(ctx, network, netip.AddrPortFrom(local, 0).String())
	if err != nil {
		return nil, err
	}
	defer packets.Close()
	stop := context.AfterFunc(ctx, func() { packets.Close() })
	defer stop()
	conn := packets.(*net.UDPConn)
	buf := make([]byte, 65535)
	var sent time.Time
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Since(sent) >= time.Second {
			if _, err := conn.WriteToUDPAddrPort(query, netip.AddrPortFrom(group, 5353)); err != nil {
				return nil, err
			}
			sent = time.Now()
		}
		_ = conn.SetReadDeadline(sent.Add(time.Second))
		n, peer, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return nil, err
		}
		if peer.Port() != 5353 || !path.onLink(peer.Addr()) || mdnsReply(query, buf[:n]) != nil {
			continue
		}
		return buf[:n], nil
	}
}

func mdnsReply(query, reply []byte) error {
	host, _, typ, err := validateDNSQuestionResponse(query, reply)
	if err != nil {
		return err
	}
	if reply[2]&0xfa != 0x80 || reply[3]&15 != 0 {
		return errors.New("invalid or truncated mDNS response")
	}
	sections, err := dnsRecords(reply)
	if err != nil {
		return err
	}
	useful := false
	for index, section := range sections {
		for _, rr := range section {
			if rr.typ == 41 {
				continue
			}
			if rr.class != 1 {
				return errors.New("invalid legacy mDNS record class")
			}
			if index == 0 && rr.name == host && (typ == 255 || rr.typ == typ || rr.typ == 5 || rr.typ == 47) {
				useful = true
			}
			// A one-shot resolver does not subscribe to cache-flush announcements.
			binary.BigEndian.PutUint32(reply[rr.ttlOffset:], min(rr.ttl, 10))
		}
	}
	if !useful {
		return errors.New("mDNS response has no relevant answer")
	}
	return nil
}
