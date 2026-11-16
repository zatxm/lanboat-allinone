package native

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strings"
)

func (s *DNSServer) UnmarshalJSON(b []byte) error {
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(b, &fields); e != nil {
		return e
	}
	var kind string
	json.Unmarshal(fields["type"], &kind)
	var paths []string
	if kind == "hosts" {
		if raw := fields["path"]; raw != nil {
			if e := json.Unmarshal(raw, &paths); e != nil {
				var path string
				if e = json.Unmarshal(raw, &path); e != nil {
					return e
				}
				paths = []string{path}
			}
			delete(fields, "path")
		}
	}
	b, e := json.Marshal(fields)
	if e != nil {
		return e
	}
	type plain DNSServer
	if e = decodeOptions(b, (*plain)(s)); e != nil {
		return e
	}
	s.HostsPaths = paths
	return nil
}
func (s DNSServer) MarshalJSON() ([]byte, error) {
	type plain DNSServer
	b, e := json.Marshal(plain(s))
	if e != nil {
		return nil, e
	}
	if s.Type != "hosts" || len(s.HostsPaths) == 0 {
		return b, nil
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(b, &fields)
	fields["path"], _ = json.Marshal(s.HostsPaths)
	return json.Marshal(fields)
}
func loadDNSHosts(s DNSServer) (map[string][]string, error) {
	paths := s.HostsPaths
	explicit := len(paths) > 0
	if !explicit {
		path := "/etc/hosts"
		if runtime.GOOS == "windows" {
			path = os.Getenv("SystemRoot") + `\System32\Drivers\etc\hosts`
		}
		paths = []string{path}
	}
	hosts := map[string][]string{}
	for _, path := range paths {
		file, e := os.Open(os.ExpandEnv(path))
		if e != nil {
			if !explicit && os.IsNotExist(e) {
				continue
			}
			return nil, e
		}
		scanner := bufio.NewScanner(io.LimitReader(file, (4<<20)+1))
		size := 0
		for scanner.Scan() {
			line, _, _ := strings.Cut(scanner.Text(), "#")
			size += len(line)
			if size > 4<<20 {
				file.Close()
				return nil, errors.New("hosts file exceeds4MiB")
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			ip, e := netip.ParseAddr(fields[0])
			if e != nil {
				continue
			}
			for _, host := range fields[1:] {
				host = canonicalDomain(host)
				hosts[host] = append(hosts[host], ip.String())
			}
		}
		e = scanner.Err()
		file.Close()
		if e != nil {
			return nil, e
		}
	}
	for host, ips := range s.Predefined {
		hosts[canonicalDomain(host)] = ips
	}
	return hosts, nil
}
