//go:build !windows && !darwin

package native

import "os"

func systemDNSNetwork() dnsNetworkState {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return dnsNetworkState{}
	}
	defer f.Close()
	return parseDNSNetwork(f, false)
}
