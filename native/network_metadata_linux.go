package native

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

func linuxDefaultInterface(reader io.Reader, ipv6 bool) string {
	scanner := bufio.NewScanner(reader)
	name, best := "", ^uint64(0)
	for scanner.Scan() {
		v := strings.Fields(scanner.Text())
		var metric, flags uint64
		var err error
		candidate := ""
		if ipv6 {
			if len(v) != 10 || v[0] != strings.Repeat("0", 32) || v[1] != "00" || v[3] != "00" {
				continue
			}
			metric, err = strconv.ParseUint(v[5], 16, 32)
			flags, _ = strconv.ParseUint(v[8], 16, 32)
			candidate = v[9]
		} else {
			if len(v) < 8 || v[1] != "00000000" || v[7] != "00000000" {
				continue
			}
			metric, err = strconv.ParseUint(v[6], 10, 32)
			flags, _ = strconv.ParseUint(v[3], 16, 32)
			candidate = v[0]
		}
		if err == nil && flags&1 != 0 && flags&0x200 == 0 && candidate != "lo" && metric < best {
			name, best = candidate, metric
		}
	}
	return name
}

func (r *Runtime) networkDefaultInterfaces() ([]string, [2]string, bool) {
	if name := r.config.Route.DefaultInterface; name != "" && !r.config.Route.AutoDetectInterface {
		return []string{name}, [2]string{name, name}, true
	}
	var names []string
	var families [2]string
	known := true
	for i, path := range []string{"/proc/net/route", "/proc/net/ipv6_route"} {
		if f, err := os.Open(path); err == nil {
			name := linuxDefaultInterface(f, i == 1)
			families[i] = name
			f.Close()
			if name != "" && (len(names) == 0 || name != names[0]) {
				names = append(names, name)
			}
		} else if !os.IsNotExist(err) {
			known = false
		}
	}
	return names, families, known
}

func sameSystemNetwork() bool {
	self, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	if self == "" {
		return false
	}
	if initial != "" {
		return self == initial
	}
	// Unprivileged desktop users may not read PID1's namespace symlink.
	for _, name := range []string{"route", "ipv6_route"} {
		a, err := os.ReadFile("/proc/self/net/" + name)
		b, other := os.ReadFile("/proc/1/net/" + name)
		if err != nil || other != nil || !bytes.Equal(a, b) {
			return false
		}
	}
	return true
}

func systemNetworkMetadata(ctx context.Context, r *Runtime) Metadata {
	interfaces, err := net.Interfaces()
	if err != nil {
		return Metadata{}
	}
	defaults, families, knownDefault := r.networkDefaultInterfaces()
	// Read system services only when the process shares the system network view.
	var bus *networkManagerBus
	selecting, _ := ctx.Value(networkSelectionKey{}).(bool)
	if sameSystemNetwork() && (selecting || r.needsMetadata(networkFields&^(1<<12))) {
		bus, _ = connectNetworkManager(ctx)
		if bus != nil {
			defer bus.conn.Close()
			stop := context.AfterFunc(ctx, func() { bus.conn.Close() })
			defer stop()
		}
	}
	result := Metadata{NetworkInterfaceAddress: map[string][]netip.Addr{}, DefaultInterfaceAddress: []netip.Addr{}}
	completeAddresses := true
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		values, err := iface.Addrs()
		if err != nil {
			completeAddresses = false
			continue
		}
		var addresses []netip.Addr
		isDefault := slices.Contains(defaults, iface.Name)
		for _, value := range values {
			p, err := netip.ParsePrefix(value.String())
			if err != nil || p.Addr().IsUnspecified() {
				continue
			}
			ip := p.Addr().Unmap()
			addresses = append(addresses, ip)
		}
		kind := linuxInterfaceType(iface.Name)
		var info Metadata
		if bus != nil && ctx.Err() == nil {
			info = bus.device(iface.Name, isDefault)
			if info.NetworkType != "" {
				kind = info.NetworkType
			}
		}
		choice := networkChoice{Name: iface.Name, Kind: kind, Addresses: addresses}
		for _, ip := range addresses {
			if ip.Is4() && families[0] == iface.Name || ip.Is6() && families[1] == iface.Name {
				if ip.Is4() {
					choice.Default4 = true
				} else {
					choice.Default6 = true
				}
			}
		}
		result.networkChoices = append(result.networkChoices, choice)
		result.NetworkInterfaceAddress[kind] = append(result.NetworkInterfaceAddress[kind], addresses...)
		if isDefault {
			result.DefaultInterfaceAddress = append(result.DefaultInterfaceAddress, addresses...)
			if defaults[0] == iface.Name || result.NetworkType == "" {
				result.NetworkType = kind
				result.NetworkIsExpensive = info.NetworkIsExpensive
				result.WiFiSSID, result.WiFiBSSID = info.WiFiSSID, info.WiFiBSSID
			}
		}
	}
	if !completeAddresses {
		result.NetworkInterfaceAddress = nil
	}
	if !completeAddresses || !knownDefault {
		result.DefaultInterfaceAddress = nil
	}
	return result
}

func linuxInterfaceType(name string) string {
	base := "/sys/class/net/" + name + "/"
	if strings.HasPrefix(name, "wwan") || strings.HasPrefix(name, "rmnet") || strings.HasPrefix(name, "pdp") {
		return "cellular"
	}
	if data, err := os.ReadFile(base + "uevent"); err == nil && strings.Contains(string(data), "DEVTYPE=wwan") {
		return "cellular"
	}
	if _, err := os.Stat(base + "wireless"); err == nil {
		return "wifi"
	}
	if _, err := os.Stat(base + "phy80211"); err == nil {
		return "wifi"
	}
	// Ethernet framing alone also describes bridges/veth/TUNs; require hardware.
	if _, err := os.Stat(base + "device"); err == nil {
		if data, err := os.ReadFile(base + "type"); err == nil && strings.TrimSpace(string(data)) == "1" {
			return "ethernet"
		}
	}
	return "other"
}
