//go:build !linux && !darwin

package native

import (
	"context"
	"net/netip"
)

func systemNeighbors(context.Context) map[netip.Addr]neighborEntry { return nil }
