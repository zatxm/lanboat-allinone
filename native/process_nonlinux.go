//go:build !linux

package native

import (
	"context"
	"net/netip"
)

type processFinder struct{}

func (*processFinder) lookupICMP(context.Context, netip.Addr, netip.Addr, []byte) (string, string, bool) {
	return "", "", false
}
func (*processFinder) close()              {}
func (*Runtime) startProcessTracking(bool) {}

func (f *processFinder) lookupIdentity(ctx context.Context, origin socketOrigin, wantPath bool) Metadata {
	if !wantPath {
		return Metadata{}
	}
	name, path := f.lookup(ctx, origin)
	return Metadata{ProcessName: name, ProcessPath: path}
}
func (*processFinder) lookupICMPIdentity(context.Context, netip.Addr, netip.Addr, []byte) (Metadata, bool) {
	return Metadata{}, false
}
func (*processFinder) userName(uint32) string { return "" }
