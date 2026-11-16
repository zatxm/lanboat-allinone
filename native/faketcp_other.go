//go:build !linux

package native

import (
	"context"
	"errors"
	"net"
)

func fakeTCPPlatform() error { return errors.New("HY1 FakeTCP requires Linux raw TCP sockets") }
func listenFakeTCP(context.Context, string, ...ListenOptions) (net.PacketConn, error) {
	return nil, fakeTCPPlatform()
}
func (r *Runtime) dialFakeTCP(context.Context, Outbound) (net.Conn, error) {
	return nil, fakeTCPPlatform()
}
