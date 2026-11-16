//go:build windows

package native

import (
	"context"
	"fmt"
	"net/netip"
	"syscall"
	"time"
	"unsafe"
)

type winIPInterfaceRow struct {
	Family                                                                          uint16
	LUID                                                                            uint64
	Index, MaxReassembly                                                            uint32
	Identifier                                                                      uint64
	MinRouterAdvertisement, MaxRouterAdvertisement                                  uint32
	Advertising, Forwarding, WeakSend, WeakReceive, AutomaticMetric, NeighborDetect uint8
	ManagedAddress, StatefulAddress, AdvertiseDefault                               uint8
	RouterDiscovery, DadTransmits, BaseReachable, Retransmit, PMTUTimeout           uint32
	LinkLocalBehavior, LinkLocalTimeout                                             uint32
	Zones                                                                           [16]uint32
	SitePrefixLength, Metric, MTU                                                   uint32
	Connected, WakePatterns, NeighborDiscovery, RouterDiscoverySupported            uint8
	Reachable                                                                       uint32
	TransmitOffload, ReceiveOffload, DisableDefaultRoutes                           uint8
}

type winUnicastAddressRow struct {
	Address                           [28]byte
	LUID                              uint64
	Index, PrefixOrigin, SuffixOrigin uint32
	ValidLifetime, PreferredLifetime  uint32
	PrefixLength, SkipAsSource        uint8
	DadState, Scope                   uint32
	Created                           int64
}

func winIPInterface(luid uint64, family uint16) (winIPInterfaceRow, error) {
	row := winIPInterfaceRow{Family: family, LUID: luid}
	code, _, _ := tunIPHelper.NewProc("GetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return row, fmt.Errorf("get TUN IP interface family %d: %w", family, syscall.Errno(code))
	}
	return row, nil
}

func winConfigureIPInterface(luid uint64, family uint16, mtu uint32) error {
	row, err := winIPInterface(luid, family)
	if err != nil {
		return err
	}
	// A userspace tunnel has no router advertisements or duplicate-address responder.
	row.RouterDiscovery, row.DadTransmits = 0, 0
	row.ManagedAddress, row.StatefulAddress = 0, 0
	row.AutomaticMetric, row.Metric, row.SitePrefixLength = 0, 0, 0
	row.MTU = mtu
	code, _, _ := tunIPHelper.NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(&row)))
	if code != 0 {
		return fmt.Errorf("configure TUN IP interface family %d: %w", family, syscall.Errno(code))
	}
	return nil
}

func winAddressEntry(luid uint64, prefix netip.Prefix) *winUnicastAddressRow {
	row := &winUnicastAddressRow{}
	tunIPHelper.NewProc("InitializeUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(row)))
	row.LUID, row.Address = luid, winRouteAddress(prefix.Addr())
	row.PrefixOrigin, row.SuffixOrigin = 1, 1
	row.PrefixLength, row.SkipAsSource, row.DadState = uint8(prefix.Bits()), 0, 4
	return row
}

func winAddAddress(ctx context.Context, luid uint64, prefix netip.Prefix) error {
	row := winAddressEntry(luid, prefix)
	code, _, _ := tunIPHelper.NewProc("CreateUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(row)))
	if code != 0 {
		return fmt.Errorf("assign TUN address %s: %w", prefix, syscall.Errno(code))
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		code, _, _ = tunIPHelper.NewProc("GetUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(row)))
		if code != 0 {
			return fmt.Errorf("read TUN address %s: %w", prefix, syscall.Errno(code))
		}
		if row.DadState == 4 && row.SkipAsSource == 0 {
			return nil
		}
		if row.DadState != 1 {
			return fmt.Errorf("TUN address %s is not usable: DAD=%d skip_source=%d", prefix, row.DadState, row.SkipAsSource)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("TUN address %s did not become usable: %w", prefix, ctx.Err())
		case <-ticker.C:
		}
	}
}
