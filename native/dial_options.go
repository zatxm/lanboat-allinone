package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type DialOptions struct {
	NetworkOptions
	NetNS                string `json:"netns,omitempty"`
	namespace            *networkNamespace
	BindInterface        string       `json:"bind_interface,omitempty"`
	Inet4BindAddress     string       `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress     string       `json:"inet6_bind_address,omitempty"`
	BindAddressNoPort    bool         `json:"bind_address_no_port,omitempty"`
	RoutingMark          FirewallMark `json:"routing_mark,omitempty"`
	ReuseAddr            bool         `json:"reuse_addr,omitempty"`
	ConnectTimeout       string       `json:"connect_timeout,omitempty"`
	TCPFastOpen          bool         `json:"tcp_fast_open,omitempty"`
	TCPMultiPath         bool         `json:"tcp_multi_path,omitempty"`
	DisableTCPKeepAlive  bool         `json:"disable_tcp_keep_alive,omitempty"`
	TCPKeepAlive         string       `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveInterval string       `json:"tcp_keep_alive_interval,omitempty"`
	UDPFragment          *bool        `json:"udp_fragment,omitempty"`
}

func (o DialOptions) validate() error {
	if err := o.NetworkOptions.validate(); err != nil {
		return err
	}
	if o.NetworkOptions.active() && (o.BindInterface != "" || o.Inet4BindAddress != "" || o.Inet6BindAddress != "") {
		return errors.New("network strategy conflicts with explicit interface or source address")
	}

	if o.NetNS != "" {
		if runtime.GOOS != "linux" {
			return errors.New("netns requires Linux")
		}
		if _, err := namespacePath(o.NetNS); err != nil {
			return err
		}
	}
	if strings.ContainsAny(o.BindInterface, "\x00\r\n") {
		return errors.New("invalid bind_interface")
	}
	for i, address := range []string{o.Inet4BindAddress, o.Inet6BindAddress} {
		if address == "" {
			continue
		}
		ip, err := netip.ParseAddr(address)
		if err != nil || ip.Is4In6() || ip.Is4() != (i == 0) || ip.Zone() != "" && i == 0 {
			return errors.New("bind address must match its IP family")
		}
	}
	for _, value := range []string{o.ConnectTimeout, o.TCPKeepAlive, o.TCPKeepAliveInterval} {
		if _, err := optionDuration(value, time.Second); err != nil {
			return err
		}
	}
	if o.DisableTCPKeepAlive && (o.TCPKeepAlive != "" || o.TCPKeepAliveInterval != "") {
		return errors.New("TCP keep alive periods conflict with disable_tcp_keep_alive")
	}
	if runtime.GOOS != "linux" && (o.RoutingMark != 0 || o.BindAddressNoPort) {
		return errors.New("routing_mark and bind_address_no_port require Linux")
	}
	return nil
}

func (r *Runtime) socketControl(network, address string, raw syscall.RawConn) error {
	return r.socketControlFor(DialOptions{}, network, address, raw)
}

func (r *Runtime) newDialer(o DialOptions, network, address string) (*net.Dialer, error) {
	if r == nil {
		r = &Runtime{}
	}
	timeout, _ := optionDuration(o.ConnectTimeout, 0)
	idle, _ := optionDuration(o.TCPKeepAlive, 5*time.Minute)
	interval, _ := optionDuration(o.TCPKeepAliveInterval, 75*time.Second)
	d := &net.Dialer{Timeout: timeout, KeepAliveConfig: net.KeepAliveConfig{Enable: !o.DisableTCPKeepAlive, Idle: idle, Interval: interval}}
	if o.DisableTCPKeepAlive {
		d.KeepAlive = -1
	}
	d.SetMultipathTCP(o.TCPMultiPath)
	d.Control = func(network, address string, raw syscall.RawConn) error {
		if err := r.socketControlFor(o, network, address, raw); err != nil {
			return err
		}
		return dialSocketOptions(o, network, raw)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, errors.New("dial address must be resolved before binding")
	}
	bind := o.Inet4BindAddress
	if ip.Is6() && !ip.Is4In6() {
		bind = o.Inet6BindAddress
	}
	if bind != "" {
		local, _ := netip.ParseAddr(bind)
		if strings.HasPrefix(network, "tcp") {
			d.LocalAddr = &net.TCPAddr{IP: local.AsSlice(), Zone: local.Zone()}
		} else {
			d.LocalAddr = &net.UDPAddr{IP: local.AsSlice(), Zone: local.Zone()}
		}
	}
	return d, nil
}

func (r *Runtime) dialSocket(ctx context.Context, o DialOptions, network, address string) (net.Conn, error) {
	if o.NetNS != "" && o.namespace == nil {
		return nil, errors.New("network namespace was not initialized")
	}
	if o.namespace != nil {
		return o.namespace.dial(ctx, o, network, address)
	}
	if o.NetworkOptions.active() {
		return r.selectDial(ctx, o, network, address)
	}
	d, err := r.newDialer(o, network, address)
	if err != nil {
		return nil, err
	}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", address, err)
	}
	return conn, nil
}

func (r *Runtime) listenPacketWithOptions(ctx context.Context, o DialOptions, network, local, target string) (net.PacketConn, error) {
	if o.NetNS != "" && o.namespace == nil {
		return nil, errors.New("network namespace was not initialized")
	}
	if o.namespace != nil {
		return o.namespace.packet(ctx, o, ListenOptions{}, network, local, target, false)
	}
	if o.NetworkOptions.active() {
		return r.selectPacket(ctx, o, network, local, target)
	}
	d, err := r.newDialer(o, network, target)
	if err != nil {
		return nil, err
	}
	if bind, ok := d.LocalAddr.(*net.UDPAddr); ok {
		host := bind.IP.String()
		if bind.Zone != "" {
			host += "%" + bind.Zone
		}
		if strings.HasPrefix(network, "ip") {
			local = host
		} else {
			_, port, _ := net.SplitHostPort(local)
			local = net.JoinHostPort(host, port)
		}
	}
	lc := net.ListenConfig{Control: func(network, _ string, raw syscall.RawConn) error {
		return d.Control(network, target, raw)
	}}
	return lc.ListenPacket(ctx, network, local)
}
