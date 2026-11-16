package native

import (
	"errors"
	"net"
	"reflect"
	"strconv"
	"time"
)

func (in Inbound) validateDirect() error {
	if in.Type != "direct" {
		if in.OverrideAddress != "" || in.OverridePort != 0 {
			return errors.New("override_address/override_port require direct inbound")
		}
		return nil
	}
	if !reflect.DeepEqual(in, Inbound{ListenOptions: in.ListenOptions, Type: in.Type, Tag: in.Tag, Listen: in.Listen, ListenPort: in.ListenPort, Network: in.Network, OverrideAddress: in.OverrideAddress, OverridePort: in.OverridePort, UDPTimeout: in.UDPTimeout}) {
		return errors.New("direct inbound uses raw TCP/UDP;protocol authentication,TLS and transport options are not applicable")
	}
	if in.Network != "" && in.Network != "tcp" && in.Network != "udp" {
		return errors.New("direct network must be tcp or udp")
	}
	if in.OverrideAddress != "" {
		if _, err := encodeAddress(portAddress(in.OverrideAddress, 1)); err != nil {
			return err
		}
	}

	return nil
}

func (in Inbound) directTarget(local net.Addr) string {
	host, port, _ := net.SplitHostPort(local.String())
	if in.OverrideAddress != "" {
		host = in.OverrideAddress
	}
	if in.OverridePort != 0 {
		port = strconv.Itoa(int(in.OverridePort))
	}
	return net.JoinHostPort(host, port)
}

// Called while Start holds r.mu; all sockets enter the usual rollback/Close path.
func (r *Runtime) listenDirect(in Inbound, host string) error {
	var packets net.PacketConn
	if in.Network != "udp" {
		listener, err := in.ListenOptions.listen(r.ctx, "tcp", portAddress(host, in.ListenPort))
		if err != nil {
			return err
		}
		if in.Network == "" {
			listener, packets, err = bindPairedUDPWithOptions(r.ctx, listener, in.ListenPort == 0, in.ListenOptions)
			if err != nil {
				return err
			}
		}
		r.listeners[in.Tag] = listener
	} else {
		var err error
		packets, err = in.ListenOptions.listenPacket(r.ctx, "udp", portAddress(host, in.ListenPort))
		if err != nil {
			return err
		}
	}
	if packets != nil {
		if r.directPackets == nil {
			r.directPackets = map[string]net.PacketConn{}
		}
		r.directPackets[in.Tag] = packets
	}
	return nil
}

func (r *Runtime) serveDirectPackets(in Inbound, packets net.PacketConn) {
	flows := newUDPFlows(r)
	defer flows.Close()
	flows.timeout, _ = optionDuration(in.UDPTimeout, udpTimeout)
	buffer := make([]byte, 65535)
	address := in.directTarget(packets.LocalAddr())
	for {
		n, peer, err := packets.ReadFrom(buffer)
		if err != nil {
			return
		}
		q := request{origin: r.socketOrigin(peer, packets.LocalAddr()), network: "udp", address: address, inbound: in.Tag, source: peer.String()}
		_ = flows.send(peer.String(), q, buffer[:n], func(b []byte, _ string) error {
			_ = packets.SetWriteDeadline(time.Now().Add(handshakeTimeout))
			_, err := packets.WriteTo(b, peer)
			return err
		})
	}
}
