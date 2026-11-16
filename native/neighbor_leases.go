package native

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const neighborLeaseBytes = 8 << 20

func readNeighborLeases(path string) map[netip.Addr]neighborEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > neighborLeaseBytes {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(f, neighborLeaseBytes+1))
	if err != nil || len(data) > neighborLeaseBytes {
		return nil
	}
	return parseNeighborLeases(data, time.Now())
}

func duidMAC(s string) string {
	b, err := hex.DecodeString(strings.NewReplacer(":", "", "-", "").Replace(s))
	if err != nil {
		return ""
	}
	var mac []byte
	if len(b) == 14 && b[0] == 0 && b[1] == 1 && b[2] == 0 && b[3] == 1 {
		mac = b[8:]
	} else if len(b) == 10 && b[0] == 0 && b[1] == 3 && b[2] == 0 && b[3] == 1 {
		mac = b[4:]
	}
	if len(mac) != 6 {
		return ""
	}
	return normalizedMAC(net.HardwareAddr(mac).String())
}

func putNeighborLease(out map[netip.Addr]neighborEntry, ip string, e neighborEntry, now time.Time) {
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Is4In6() || address.Zone() != "" || !address.IsGlobalUnicast() && !address.IsLinkLocalUnicast() {
		return
	}
	if !e.valid(now) {
		delete(out, address)
		return
	}
	if len(out) < neighborLimit || out[address] != (neighborEntry{}) {
		out[address] = e
	}
}

func leaseExpiration(s string) (time.Time, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, false
	}
	if n == 0 {
		return time.Time{}, true
	}
	return time.Unix(n, 0), true
}

func parseNeighborLeases(data []byte, now time.Time) map[netip.Addr]neighborEntry {
	out := map[netip.Addr]neighborEntry{}
	if len(data) > neighborLeaseBytes {
		return out
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("address,")) {
		parseKeaLeases(trimmed, out, now)
		return out
	}
	if iscNeighborBlock.Match(data) {
		parseISCLeases(data, out, now, neighborEntry{}, 0)
		return out
	}
	if bytes.HasPrefix(trimmed, []byte("{")) {
		parseAppleLeases(data, out, now)
		return out
	}
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(make([]byte, 4096), 65536)
	for s.Scan() {
		v := strings.Fields(s.Text())
		if len(v) == 0 || strings.HasPrefix(v[0], "#") {
			continue
		}
		// dnsmasq DHCP4/6: expiry, Ethernet MAC or DUID, address, hostname, client-id.
		if len(v) >= 4 {
			until, ok := leaseExpiration(v[0])
			if ok {
				mac := normalizedMAC(v[1])
				if mac == "" {
					mac = duidMAC(v[1])
				}
				putNeighborLease(out, v[2], neighborEntry{mac: mac, hostname: neighborHostname(v[3]), until: until}, now)
				continue
			}
		}
		// odhcpd's generated hosts file contains only currently active addresses.
		if len(v) >= 2 {
			for _, name := range v[1:] {
				if strings.HasPrefix(name, "#") {
					break
				}
				if host := neighborHostname(name); host != "" {
					putNeighborLease(out, v[0], neighborEntry{hostname: host}, now)
					break
				}
			}
		}
	}
	if s.Err() != nil {
		clear(out)
	}
	return out
}

func parseKeaLeases(data []byte, out map[netip.Addr]neighborEntry, now time.Time) {
	// Reject oversized CSV lines before the record reader allocates its field vectors.
	lines := bufio.NewScanner(bytes.NewReader(data))
	lines.Buffer(make([]byte, 4096), 65536)
	for lines.Scan() {
	}
	if lines.Err() != nil {
		return
	}
	r := csv.NewReader(bytes.NewReader(data))
	header, err := r.Read()
	if err != nil || len(header) > 64 {
		return
	}
	columns := map[string]int{}
	for i, h := range header {
		columns[h] = i
	}
	for {
		row, err := r.Read()
		if err == io.EOF {
			return
		}
		if err != nil {
			clear(out)
			return
		}
		field := func(name string) string {
			if i, ok := columns[name]; ok && i < len(row) {
				return row[i]
			}
			return ""
		}
		ip := field("address")
		until, ok := leaseExpiration(field("expire"))
		if !ok {
			continue
		}
		if state := field("state"); state != "" && state != "0" || field("valid_lifetime") == "0" || field("lease_type") == "2" {
			until = now.Add(-time.Second)
		}
		mac := normalizedMAC(field("hwaddr"))
		if mac == "" {
			mac = duidMAC(field("duid"))
		}
		putNeighborLease(out, ip, neighborEntry{mac: mac, hostname: neighborHostname(field("hostname")), until: until}, now)
	}
}

var iscNeighborBlock = regexp.MustCompile(`(?m)\b(lease|ia-na|iaaddr)\s+("[^"\r\n]+"|[0-9a-fA-F:.]+)\s*\{`)
var iscNeighborMAC = regexp.MustCompile(`(?m)\bhardware\s+ethernet\s+([0-9a-fA-F:]+)\s*;`)
var iscNeighborHost = regexp.MustCompile(`(?m)\b(?:client-hostname|set\s+ddns-fwd-name\s*=)\s*"([^"\r\n]+)"\s*;`)
var iscNeighborEnds = regexp.MustCompile(`(?m)\bends\s+([^;\r\n]+);`)
var iscNeighborState = regexp.MustCompile(`(?m)\bbinding\s+state\s+([^;\r\n]+);`)

func parseISCLeases(data []byte, out map[netip.Addr]neighborEntry, now time.Time, parent neighborEntry, depth int) {
	if depth > 2 {
		return
	}
	for len(data) > 0 {
		m := iscNeighborBlock.FindSubmatchIndex(data)
		if m == nil {
			return
		}
		kind, address := string(data[m[2]:m[3]]), string(data[m[4]:m[5]])
		start, level, quote, escaped := m[1], 1, false, false
		end := start
		for ; end < len(data) && level > 0; end++ {
			c := data[end]
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' && quote {
				escaped = true
			} else if c == '"' {
				quote = !quote
			} else if !quote {
				if c == '{' {
					level++
				} else if c == '}' {
					level--
				}
			}
		}
		if level != 0 {
			clear(out)
			return
		}
		body, e := data[start:end-1], parent
		if v := iscNeighborMAC.FindSubmatch(body); v != nil {
			e.mac = normalizedMAC(string(v[1]))
		}
		if v := iscNeighborHost.FindSubmatch(body); v != nil {
			e.hostname = neighborHostname(string(v[1]))
		}
		if kind == "ia-na" {
			// ISC stores DUID bytes using octal escapes in a quoted lease identifier.
			if decoded, err := strconv.Unquote(address); err == nil {
				e.mac = duidMAC(hex.EncodeToString([]byte(decoded)))
			}
			parseISCLeases(body, out, now, e, depth+1)
		} else {
			hasEnd := false
			if v := iscNeighborEnds.FindSubmatch(body); v != nil {
				value := strings.TrimSpace(string(v[1]))
				hasEnd = value == "never"
				if !hasEnd {
					fields := strings.Fields(value)
					if len(fields) == 3 {
						var err error
						e.until, err = time.Parse("2006/01/02 15:04:05", fields[1]+" "+fields[2])
						hasEnd = err == nil
					} else if len(fields) == 2 && fields[0] == "epoch" {
						e.until, hasEnd = leaseExpiration(fields[1])
					}
				}
			}
			if v := iscNeighborState.FindSubmatch(body); v != nil && string(v[1]) != "active" {
				e.until = now.Add(-time.Second)
			}
			if hasEnd {
				putNeighborLease(out, address, e, now)
			}
		}
		data = data[end:]
	}
}

var appleNeighborBlock = regexp.MustCompile(`(?s)\{([^{}]*)\}`)
var appleNeighborField = regexp.MustCompile(`(?m)^\s*(name|ip_address|hw_address|lease)\s*=\s*([^\r\n]+)`)

func parseAppleLeases(data []byte, out map[netip.Addr]neighborEntry, now time.Time) {
	blocks := appleNeighborBlock.FindAllSubmatch(data, neighborLimit+1)
	if len(blocks) > neighborLimit {
		return
	}
	for _, block := range blocks {
		fields := map[string]string{}
		matches := appleNeighborField.FindAllSubmatch(block[1], 33)
		if len(matches) > 32 {
			clear(out)
			return
		}
		for _, field := range matches {
			fields[string(field[1])] = strings.TrimSpace(string(field[2]))
		}
		n, err := strconv.ParseUint(fields["lease"], 0, 63)
		if err != nil {
			continue
		}
		mac := strings.TrimPrefix(fields["hw_address"], "1,")
		putNeighborLease(out, fields["ip_address"], neighborEntry{mac: normalizedMAC(mac), hostname: neighborHostname(fields["name"]), until: time.Unix(int64(n), 0)}, now)
	}
}
