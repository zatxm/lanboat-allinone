package native

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"

	"go.uber.org/zap"
)

const DesktopTUNTable = 20245
const DesktopTUNPriority = 9045

func DesktopTUNInbound() Inbound {
	in := Inbound{
		Type: "tun", Tag: "tun-in", MTU: 1500, AutoRoute: true, StrictRoute: true,
		Address: []string{"172.29.45.1/30", "fdfe:29:45::1/126"},
		DNSMode: "native", exclusiveTUN: true,
	}
	switch runtime.GOOS {
	case "linux":
		in.InterfaceName, in.DNSMode = "lanboat-tun0", "routed"
		in.IPRoute2TableIndex, in.IPRoute2RuleIndex = DesktopTUNTable, DesktopTUNPriority
	case "windows":
		in.InterfaceName = "Lanboat"
	}
	return in
}

// DesktopTUNInfo describes the privileged device attached to an unprivileged runtime.
type DesktopTUNInfo struct {
	Name string
	Mark uint32
}

type desktopTUNAttachment struct {
	info    DesktopTUNInfo
	device  io.ReadWriteCloser
	protect func(uintptr) error
}

type desktopTUNKey struct{}

// WithDesktopTUN attaches a preconfigured system device to the tun-in inbound.
// The caller owns the device until Start succeeds, and must keep the broker alive.
func WithDesktopTUN(ctx context.Context, info DesktopTUNInfo, device io.ReadWriteCloser, protect func(uintptr) error) context.Context {
	return context.WithValue(ctx, desktopTUNKey{}, &desktopTUNAttachment{info, device, protect})
}

// OpenDesktopTUN opens the project's fixed desktop tunnel and installs its routes.
// It creates no forwarding stack or user-configured outbounds.
func OpenDesktopTUN(ctx context.Context, dnsOwner string) (DesktopTUNInfo, io.ReadWriteCloser, error) {
	in := DesktopTUNInbound()
	if err := validateTUNPlatform(in); err != nil {
		return DesktopTUNInfo{}, nil, err
	}
	if in.InterfaceName != "" {
		if _, err := net.InterfaceByName(in.InterfaceName); err == nil {
			return DesktopTUNInfo{}, nil, errors.New("Lanboat TUN interface already exists")
		}
	}
	r := &Runtime{ctx: ctx, logger: zap.NewNop(), config: Config{Inbounds: []Inbound{in}}}
	t, err := openTUN(r, in)
	if err != nil {
		return DesktopTUNInfo{}, nil, err
	}
	t.dnsOwner = dnsOwner
	if err := t.configureDNS(); err != nil {
		t.cleanup()
		t.device.Close()
		return DesktopTUNInfo{}, nil, err
	}
	return DesktopTUNInfo{t.name, t.mark}, &desktopTUNLease{t: t}, nil
}

type desktopTUNLease struct {
	t    *tunTunnel
	once sync.Once
}

func (d *desktopTUNLease) Read(b []byte) (int, error)  { return d.t.device.Read(b) }
func (d *desktopTUNLease) Write(b []byte) (int, error) { return d.t.device.Write(b) }
func (d *desktopTUNLease) Close() error {
	d.once.Do(func() {
		d.t.cleanup()
		d.t.device.Close()
	})
	return nil
}

func (r *Runtime) attachDesktopTUN(in Inbound, a *desktopTUNAttachment) (*tunTunnel, error) {
	if a.device == nil || a.info.Name == "" || in.Tag != "tun-in" {
		return nil, errors.New("invalid desktop TUN attachment")
	}
	t := &tunTunnel{runtime: r, in: in, name: a.info.Name, mark: a.info.Mark, device: a.device}
	for _, value := range tunAddresses(in) {
		prefix, _ := netip.ParsePrefix(value)
		t.addLocal(prefix.Addr())
	}
	if err := t.prepareDesktopEgress(); err != nil {
		return nil, err
	}
	r.retainTUNProtection(a.info.Mark)
	r.network.exclude(t.name, true)
	t.cleanup = r.releaseTUNProtection
	return t, nil
}

// ShareDesktopEgress lets an on-demand diagnostic use the same protected egress.
// Call this on a freshly constructed runtime, before starting it.
func (r *Runtime) ShareDesktopEgress(child *Runtime) {
	attachment, _ := r.ctx.Value(desktopTUNKey{}).(*desktopTUNAttachment)
	if attachment == nil {
		return
	}
	child.ctx = context.WithValue(child.ctx, desktopTUNKey{}, attachment)
	child.protectMark.Store(r.protectMark.Load())
	child.tunEgress4.Store(r.tunEgress4.Load())
	child.tunEgress6.Store(r.tunEgress6.Load())
	child.tunRouting.Store(r.tunRouting.Load())
}
