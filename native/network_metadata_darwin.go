//go:build darwin

package native

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

type metadataBuffer struct{ bytes.Buffer }

func (b *metadataBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 256<<10 {
		return 0, io.ErrShortWrite
	}
	return b.Buffer.Write(p)
}
func metadataCommand(ctx context.Context, path string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, path, args...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	var output metadataBuffer
	command.Stdout = &output
	err := command.Run()
	return output.String(), err
}
func systemNetworkMetadata(ctx context.Context, r *Runtime) Metadata {
	result := Metadata{NetworkInterfaceAddress: map[string][]netip.Addr{}}
	interfaces, err := net.Interfaces()
	if err != nil {
		return Metadata{}
	}
	kinds := map[string]string{}
	if text, err := metadataCommand(ctx, "/usr/sbin/networksetup", "-listallhardwareports"); err == nil {
		kind := "other"
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "Hardware Port:") {
				kind = "other"
				if strings.Contains(line, "Wi-Fi") || strings.Contains(line, "AirPort") {
					kind = "wifi"
				} else if strings.Contains(line, "Ethernet") {
					kind = "ethernet"
				}
			} else if strings.HasPrefix(line, "Device:") {
				kinds[strings.TrimSpace(strings.TrimPrefix(line, "Device:"))] = kind
			}
		}
	}
	var defaults []string
	var families [2]string
	if name := r.config.Route.DefaultInterface; name != "" && !r.config.Route.AutoDetectInterface {
		defaults = append(defaults, name)
		families = [2]string{name, name}
	} else {
		for familyIndex, family := range []string{"-inet", "-inet6"} {
			text, err := metadataCommand(ctx, "/sbin/route", "-n", "get", family, "default")
			if err != nil {
				continue
			}
			for _, line := range strings.Split(text, "\n") {
				if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "interface:" {
					defaults = append(defaults, fields[1])
					families[familyIndex] = fields[1]
					break
				}
			}
		}
	}
	if len(defaults) > 0 {
		result.DefaultInterfaceAddress = []netip.Addr{}
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		kind := kinds[iface.Name]
		if kind == "" {
			kind = "other"
		}
		addresses, err := iface.Addrs()
		if err != nil {
			result.NetworkInterfaceAddress = nil
			continue
		}
		selected := false
		for _, name := range defaults {
			selected = selected || name == iface.Name
		}
		choice := networkChoice{Name: iface.Name, Kind: kind}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil || prefix.Addr().IsUnspecified() {
				continue
			}
			choice.Addresses = append(choice.Addresses, prefix.Addr().Unmap())
			if prefix.Addr().Is4() && families[0] == iface.Name || prefix.Addr().Is6() && families[1] == iface.Name {
				if prefix.Addr().Is4() {
					choice.Default4 = true
				} else {
					choice.Default6 = true
				}
			}
			if result.NetworkInterfaceAddress != nil {
				result.NetworkInterfaceAddress[kind] = append(result.NetworkInterfaceAddress[kind], prefix.Addr().Unmap())
			}
			if selected {
				result.DefaultInterfaceAddress = append(result.DefaultInterfaceAddress, prefix.Addr().Unmap())
			}
		}
		result.networkChoices = append(result.networkChoices, choice)
		if selected && result.NetworkType == "" {
			result.NetworkType = kind
			if kind == "wifi" {
				if text, err := metadataCommand(ctx, "/usr/sbin/networksetup", "-getairportnetwork", iface.Name); err == nil {
					if _, ssid, ok := strings.Cut(strings.TrimSpace(text), ": "); ok {
						result.WiFiSSID = ssid
					}
				}
			}
		}
	}
	appleNetworkMetadata(ctx, &result)
	return result
}
