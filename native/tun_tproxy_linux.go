//go:build linux

package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

func (t *tunTunnel) configureTProxy() error {
	if !t.local6.IsValid() {
		return nil
	}
	_, output, _, mark := t.in.redirectMarks()
	listener, e := (&net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var err error
		e := raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, 75, 1)
			if err == nil {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, 36, int(output))
			}
		})
		if e != nil {
			return e
		}
		return err
	}}).Listen(context.Background(), "tcp6", "[::]:0")
	if e != nil {
		return fmt.Errorf("IPv6 transparent listener: %w", e)
	}
	lo, e := net.InterfaceByName("lo")
	if e != nil {
		listener.Close()
		return e
	}
	table := t.in.IPRoute2TableIndex
	if table == 0 {
		table = 2022
	}
	table++
	priority := t.in.IPRoute2RuleIndex
	if priority == 0 {
		priority = 9000
	}
	priority--
	route := tunRoute(lo.Index, table, syscall.AF_INET6)
	route[6], route[7] = 254, 2
	rule := tunRule(table, priority, mark, syscall.AF_INET6)
	binary.NativeEndian.PutUint32(rule[8:], 0)
	if e = netlinkChange(24, route, true); e != nil {
		listener.Close()
		return e
	}
	if e = netlinkChange(32, rule, true); e != nil {
		netlinkChange(25, route, false)
		listener.Close()
		return e
	}
	t.tpListener = listener
	previous := t.cleanup
	t.cleanup = func() {
		listener.Close()
		_ = netlinkChange(33, rule, false)
		_ = netlinkChange(25, route, false)
		previous()
	}
	return nil
}
