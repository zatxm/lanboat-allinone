//go:build darwin

package native

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

func systemDNSNetwork() dnsNetworkState {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	text, err := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns").Output()
	if err != nil {
		return dnsNetworkState{}
	}
	return parseDNSNetwork(strings.NewReader(string(text)), true)
}
