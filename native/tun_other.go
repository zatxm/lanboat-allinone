//go:build !linux && !windows && !darwin

package native

import (
	"errors"
	"syscall"
)

func (r *Runtime) socketControlFor(o DialOptions, network, address string, raw syscall.RawConn) error {
	if o.BindInterface != "" {
		return errors.New("interface binding requires Linux, Windows or macOS")
	}
	return nil
}
func (r *Runtime) prepareEndpointTUN() error {
	return errors.New("TUN requires Linux, Windows or macOS")
}
func openTUN(r *Runtime, in Inbound) (*tunTunnel, error) {
	return nil, errors.New("TUN requires Linux, Windows or macOS")
}
func validateTUNPlatform(in Inbound) error { return errors.New("TUN requires Linux, Windows or macOS") }
func (t *tunTunnel) configureDNS() error   { return nil }
func systemDNSBeforeTUN() []string         { return nil }

func (t *tunTunnel) configureMonitor() error { return nil }
