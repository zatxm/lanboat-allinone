package native

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

// Listen options deliberately exclude outbound source addresses and dial timeouts.
type ListenOptions struct {
	NetNS                string `json:"netns,omitempty"`
	namespace            *networkNamespace
	BindInterface        string       `json:"bind_interface,omitempty"`
	RoutingMark          FirewallMark `json:"routing_mark,omitempty"`
	ReuseAddr            bool         `json:"reuse_addr,omitempty"`
	TCPFastOpen          bool         `json:"tcp_fast_open,omitempty"`
	TCPMultiPath         bool         `json:"tcp_multi_path,omitempty"`
	DisableTCPKeepAlive  bool         `json:"disable_tcp_keep_alive,omitempty"`
	TCPKeepAlive         string       `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveInterval string       `json:"tcp_keep_alive_interval,omitempty"`
	UDPFragment          *bool        `json:"udp_fragment,omitempty"`
}

func (o ListenOptions) dialOptions() DialOptions {
	return DialOptions{NetNS: o.NetNS, namespace: o.namespace, BindInterface: o.BindInterface, RoutingMark: o.RoutingMark, ReuseAddr: o.ReuseAddr, TCPFastOpen: o.TCPFastOpen, TCPMultiPath: o.TCPMultiPath, DisableTCPKeepAlive: o.DisableTCPKeepAlive, TCPKeepAlive: o.TCPKeepAlive, TCPKeepAliveInterval: o.TCPKeepAliveInterval, UDPFragment: o.UDPFragment}
}
func (o DialOptions) listenOptions() ListenOptions {
	return ListenOptions{NetNS: o.NetNS, namespace: o.namespace, BindInterface: o.BindInterface, RoutingMark: o.RoutingMark, ReuseAddr: o.ReuseAddr, TCPFastOpen: o.TCPFastOpen, TCPMultiPath: o.TCPMultiPath, DisableTCPKeepAlive: o.DisableTCPKeepAlive, TCPKeepAlive: o.TCPKeepAlive, TCPKeepAliveInterval: o.TCPKeepAliveInterval, UDPFragment: o.UDPFragment}
}
func (o ListenOptions) validate(kind string) error {
	if err := o.dialOptions().validate(); err != nil {
		return err
	}
	o.NetNS, o.namespace = "", nil
	if kind == "tun" && o != (ListenOptions{}) {
		return errors.New("socket listen options do not apply to tun interfaces")
	}
	return nil
}
func (o ListenOptions) listenConfig() net.ListenConfig {
	idle, _ := optionDuration(o.TCPKeepAlive, 5*time.Minute)
	interval, _ := optionDuration(o.TCPKeepAliveInterval, 75*time.Second)
	lc := net.ListenConfig{KeepAliveConfig: net.KeepAliveConfig{Enable: !o.DisableTCPKeepAlive, Idle: idle, Interval: interval}}
	if o.DisableTCPKeepAlive {
		lc.KeepAlive = -1
	}
	lc.SetMultipathTCP(o.TCPMultiPath)
	lc.Control = func(network, address string, raw syscall.RawConn) error {
		opts := o.dialOptions()
		// Listening sockets must not inherit the runtime's outbound TUN protection.
		if err := (&Runtime{}).socketControlFor(opts, network, address, raw); err != nil {
			return err
		}
		return listenSocketOptions(opts, network, raw)
	}
	return lc
}
func (o ListenOptions) listen(ctx context.Context, network, address string) (net.Listener, error) {
	if o.NetNS != "" && o.namespace == nil {
		return nil, errors.New("network namespace was not initialized")
	}
	if o.namespace != nil {
		return o.namespace.listen(ctx, o, network, address)
	}
	lc := o.listenConfig()
	return lc.Listen(ctx, network, address)
}
func (o ListenOptions) listenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	if o.NetNS != "" && o.namespace == nil {
		return nil, errors.New("network namespace was not initialized")
	}
	if o.namespace != nil {
		return o.namespace.packet(ctx, DialOptions{}, o, network, address, "", true)
	}
	lc := o.listenConfig()
	return lc.ListenPacket(ctx, network, address)
}
