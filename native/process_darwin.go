//go:build darwin

package native

import (
	"bufio"
	"context"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
)

func (*processFinder) lookup(ctx context.Context, origin socketOrigin) (string, string) {
	source, err := netip.ParseAddrPort(origin.source)
	if err != nil || origin.network != "tcp" && origin.network != "udp" {
		return "", ""
	}
	destination, err := netip.ParseAddrPort(origin.destination)
	if err != nil {
		return "", ""
	}
	family := "4"
	if source.Addr().Is6() && !source.Addr().Is4In6() {
		family = "6"
	}
	data, err := metadataCommand(ctx, "/usr/sbin/lsof", "-nP", "-a", "-i"+family+strings.ToUpper(origin.network)+":"+strconv.Itoa(int(source.Port())), "-Fpn")
	if err != nil {
		return "", ""
	}
	pid, owner, best, ambiguous := "", "", 0, false
	scan := bufio.NewScanner(strings.NewReader(data))
	for scan.Scan() {
		line := scan.Text()
		if len(line) < 2 {
			continue
		}
		if line[0] == 'p' {
			if _, err := strconv.ParseUint(line[1:], 10, 32); err != nil {
				pid = ""
			} else {
				pid = line[1:]
			}
			continue
		}
		if line[0] != 'n' || pid == "" {
			continue
		}
		fields := strings.Fields(line[1:])
		if len(fields) == 0 {
			continue
		}
		ends := strings.SplitN(fields[0], "->", 2)
		wildcard := "*:" + strconv.Itoa(int(source.Port()))
		local, err := netip.ParseAddrPort(ends[0])
		score := 1
		if err == nil && local.Addr().Unmap().WithZone("") == source.Addr().Unmap().WithZone("") && local.Port() == source.Port() {
			score = 2
		} else if ends[0] != wildcard {
			continue
		}
		if origin.network == "tcp" {
			if len(ends) != 2 {
				continue
			}
			remote, err := netip.ParseAddrPort(ends[1])
			if err != nil || remote.Addr().Unmap().WithZone("") != destination.Addr().Unmap().WithZone("") || remote.Port() != destination.Port() {
				continue
			}
		}
		if score > best {
			owner, best, ambiguous = pid, score, false
		} else if score == best && owner != pid {
			ambiguous = true
		}
	}
	if owner == "" || ambiguous {
		return "", ""
	}
	path, err := metadataCommand(ctx, "/bin/ps", "-p", owner, "-o", "comm=")
	if err != nil {
		return "", ""
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", ""
	}
	return filepath.Base(path), path
}
