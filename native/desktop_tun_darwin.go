package native

import (
	"io"
	"net"
	"os"
)

func (t *tunTunnel) prepareDesktopEgress() error {
	t.device = &framedTUN{ReadWriteCloser: t.device}
	iface, err := net.InterfaceByName(t.name)
	if err != nil {
		return err
	}
	if err = t.runtime.refreshDarwinEgress(iface.Index); err != nil {
		return err
	}
	t.runtime.tunRouting.Store(true)
	return nil
}

func DesktopTUNFile(device io.ReadWriteCloser) *os.File {
	return device.(*desktopTUNLease).t.device.(*framedTUN).ReadWriteCloser.(*os.File)
}
