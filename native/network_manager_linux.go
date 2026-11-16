package native

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

const networkManagerName = "org.freedesktop.NetworkManager"
const networkManagerPath = "/org/freedesktop/NetworkManager"

type networkManagerBus struct {
	conn   net.Conn
	reader *bufio.Reader
	serial uint32
	owner  string
}

func connectNetworkManager(ctx context.Context) (*networkManagerBus, error) {
	conn, reader, err := connectSystemBus(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	b := &networkManagerBus{conn: conn, reader: reader}
	_, err = b.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "", nil)
	if err == nil {
		var reply busMessage
		reply, err = b.call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", "s", []any{networkManagerName})
		if err == nil {
			if reply.signature != "s" || len(reply.values) != 1 || !strings.HasPrefix(reply.values[0].(string), ":") {
				err = errors.New("invalid NetworkManager owner")
			} else {
				b.owner = reply.values[0].(string)
			}
		}
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return b, nil
}

func (b *networkManagerBus) call(destination, path, iface, member, signature string, values []any) (busMessage, error) {
	b.serial++
	// Do not auto-start services just to collect optional routing metadata.
	m := busMessage{kind: 1, flags: 2, serial: b.serial, destination: destination, path: path, iface: iface, member: member, signature: signature, values: values}
	if err := writeAll(b.conn, m.encode()); err != nil {
		return busMessage{}, err
	}
	for {
		reply, err := busRead(b.reader)
		if err != nil {
			return busMessage{}, err
		}
		if reply.reply != b.serial || reply.kind != 2 && reply.kind != 3 {
			continue
		}
		if reply.sender != destination && !(reply.kind == 3 && reply.sender == "org.freedesktop.DBus") {
			return busMessage{}, errors.New("unexpected NetworkManager reply sender")
		}
		if reply.kind == 3 {
			return busMessage{}, fmt.Errorf("NetworkManager: %s", reply.failure)
		}
		return reply, nil
	}
}

func (b *networkManagerBus) properties(path, iface string) (map[string]any, error) {
	reply, err := b.call(b.owner, path, "org.freedesktop.DBus.Properties", "GetAll", "s", []any{iface})
	if err != nil {
		return nil, err
	}
	if reply.signature != "a{sv}" || len(reply.values) != 1 {
		return nil, errors.New("invalid NetworkManager properties")
	}
	props := map[string]any{}
	for _, entry := range reply.values[0].([]any) {
		pair := entry.([]any)
		name := pair[0].(string)
		if _, exists := props[name]; exists {
			return nil, errors.New("duplicate NetworkManager property")
		}
		props[name] = pair[1].(busVariant).value
	}
	return props, nil
}

func (b *networkManagerBus) device(name string, active bool) Metadata {
	reply, err := b.call(b.owner, networkManagerPath, networkManagerName, "GetDeviceByIpIface", "s", []any{name})
	if err != nil || reply.signature != "o" || len(reply.values) != 1 {
		return Metadata{}
	}
	path := reply.values[0].(string)
	props, err := b.properties(path, networkManagerName+".Device")
	if err != nil {
		return Metadata{}
	}
	kind, _ := props["DeviceType"].(uint32)
	m := Metadata{}
	switch kind {
	case 1:
		m.NetworkType = "ethernet"
	case 2:
		m.NetworkType = "wifi"
	case 8:
		m.NetworkType = "cellular"
	case 0:
		return m
	default:
		m.NetworkType = "other"
	}
	state, _ := props["State"].(uint32)
	if !active || state != 100 {
		return m
	}
	metered, _ := props["Metered"].(uint32)
	m.NetworkIsExpensive = metered == 1 || metered == 3
	if kind != 2 {
		return m
	}
	wireless, err := b.properties(path, networkManagerName+".Device.Wireless")
	if err != nil {
		return m
	}
	ap, _ := wireless["ActiveAccessPoint"].(string)
	if ap == "" || ap == "/" {
		return m
	}
	props, err = b.properties(ap, networkManagerName+".AccessPoint")
	if err != nil {
		return m
	}
	ssid, _ := props["Ssid"].([]byte)
	if len(ssid) <= 32 {
		m.WiFiSSID = string(ssid)
	}
	mac, _ := props["HwAddress"].(string)
	if value, err := net.ParseMAC(mac); err == nil && len(value) == 6 {
		m.WiFiBSSID = value.String()
	}
	return m
}
