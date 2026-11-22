//go:build !linux && !darwin && !windows

package native

import "errors"

func (t *tunTunnel) prepareDesktopEgress() error {
	return errors.New("desktop TUN is unavailable on this platform")
}
