package native

import (
	"errors"
	"net"
	"syscall"
)

func kcpSetDSCP(conn net.Conn, dscp int) error {
	for {
		if c, ok := conn.(*ownedConn); ok {
			conn = c.Conn
		} else {
			break
		}
	}
	if dscp == 0 {
		return nil
	}
	return kcpSocketDSCP(conn, dscp)
}
func kcpSetPacketDSCP(conn net.PacketConn, dscp int) error {
	if dscp == 0 {
		return nil
	}
	return kcpSocketDSCP(conn, dscp)
}
func kcpSocketDSCP(conn any, dscp int) error {
	socket, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return errors.New("kcptun DSCP requires a native UDP socket")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) { optionErr = kcpSocketTraffic(fd, dscp<<2) })
	if err != nil {
		return err
	}
	return optionErr
}
