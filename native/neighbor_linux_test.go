package native

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestNeighborLinuxNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_NEIGHBOR_NAMESPACE") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestNeighborLinuxNamespace$", "-test.v", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "LANBOAT_NEIGHBOR_NAMESPACE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("neighbor namespace: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	ip := func(args ...string) {
		t.Helper()
		out, err := exec.Command("ip", args...).CombinedOutput()
		if err != nil {
			t.Fatal(args, err, string(out))
		}
	}
	ip("link", "set", "lo", "up")
	ip("link", "add", "lan-test", "type", "dummy")
	ip("link", "set", "lan-test", "up")
	ip("addr", "add", "192.0.2.1/24", "dev", "lan-test")
	ip("addr", "add", "192.0.2.2/24", "dev", "lan-test")
	ip("-6", "addr", "add", "fd00::1/64", "dev", "lan-test", "nodad")
	ip("neigh", "replace", "192.0.2.2", "lladdr", neighborTestMAC, "nud", "permanent", "dev", "lan-test")
	ip("-6", "neigh", "replace", "fd00::2", "lladdr", neighborTestMAC, "nud", "permanent", "dev", "lan-test")
	ip("-6", "neigh", "replace", "fd00::3", "lladdr", neighborTestMAC, "nud", "permanent", "dev", "lan-test")
	snapshot := systemNeighbors(context.Background())
	for _, address := range []string{"192.0.2.2", "fd00::2"} {
		if snapshot[netip.MustParseAddr(address)].mac != neighborTestMAC {
			t.Fatal("kernel neighbor not read", snapshot)
		}
	}
	path := filepath.Join(t.TempDir(), "dnsmasq.leases")
	write := func(mac string, expire int64) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf("%d %s 192.0.2.2 nas *\n", expire, mac)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(neighborTestMAC, time.Now().Add(time.Hour).Unix())
	r, logs := loggingRuntime(t, Config{Log: LogOptions{Level: "debug"}, Inbounds: []Inbound{{Type: "mixed", Tag: "proxy", Listen: "192.0.2.1"}, {Type: "dns", Tag: "dns", Listen: "192.0.2.1"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{DHCPLeaseFiles: []string{path}, FindNeighbor: true, Final: "deny", Rules: []Rule{{SourceMACAddress: []string{neighborTestMAC}, SourceHostname: []string{"nas"}, Outbound: "direct"}}}, DNS: DNSConfig{Final: "deny-dns", Servers: []DNSServer{{Type: "hosts", Tag: "allow-dns", Predefined: map[string][]string{"device.test": {"192.0.2.9"}}}, {Type: "hosts", Tag: "deny-dns", Predefined: map[string][]string{"device.test": {"192.0.2.8"}}}}, Rules: []DNSRule{{Rule: Rule{SourceMACAddress: []string{neighborTestMAC}, SourceHostname: []string{"nas"}}, Server: "allow-dns"}}}})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "neighbor-routed") }))
	defer origin.Close()
	proxy, _ := url.Parse("http://" + r.Address("proxy"))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("192.0.2.2")}}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	get := func(want int) {
		t.Helper()
		response, err := client.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != want || want == 200 && string(body) != "neighbor-routed" {
			t.Fatal(response.StatusCode, string(body), err)
		}
	}
	get(200)
	privacy := request{source: "[fd00::3]:1234"}
	r.enrichNeighbor(context.Background(), &privacy)
	if privacy.metadata.SourceHostname != "nas" || privacy.metadata.SourceMACAddress != neighborTestMAC {
		t.Fatal("IPv6 privacy address lost MAC-associated hostname", privacy.metadata)
	}
	if logs.FilterMessageSnippet("router: found source MAC address: "+neighborTestMAC).Len() == 0 || logs.FilterMessageSnippet("router: found source hostname: nas").Len() == 0 {
		t.Fatal("missing neighbor logs", logs.All())
	}
	query := func(network, want string) {
		t.Helper()
		dialer := &net.Dialer{Timeout: time.Second}
		if network == "tcp" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP("192.0.2.2")}
		} else {
			dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP("192.0.2.2")}
		}
		c, err := dialer.DialContext(context.Background(), network, r.Address("dns"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		q, _ := makeDNSQuery("device.test", 1)
		if network == "tcp" {
			writeAll(c, binary.BigEndian.AppendUint16(nil, uint16(len(q))))
		}
		writeAll(c, q)
		b := make([]byte, 4096)
		n := 0
		if network == "tcp" {
			var size [2]byte
			_, err = io.ReadFull(c, size[:])
			if err == nil {
				n = int(binary.BigEndian.Uint16(size[:]))
				_, err = io.ReadFull(c, b[:n])
			}
		} else {
			n, err = c.Read(b)
		}
		if err != nil {
			t.Fatal(err)
		}
		ips, _, err := parseDNSReply(q, b[:n])
		if err != nil || len(ips) != 1 || ips[0].String() != want {
			t.Fatal(network, ips, err)
		}
	}
	for _, network := range []string{"tcp", "udp"} {
		query(network, "192.0.2.9")
	}
	write("02:11:22:33:44:66", time.Now().Add(time.Hour).Unix())
	r.neighbors.invalidate()
	get(502)
	for _, network := range []string{"tcp", "udp"} {
		query(network, "192.0.2.8")
	}
	q := request{source: "192.0.2.2:1234"}
	r.enrichNeighbor(context.Background(), &q)
	if q.metadata.SourceMACAddress != neighborTestMAC || q.metadata.SourceHostname != "" {
		t.Fatal("stale lease overrode live kernel identity", q.metadata)
	}
	write(neighborTestMAC, 1)
	r.neighbors.invalidate()
	q.metadata = Metadata{}
	r.enrichNeighbor(context.Background(), &q)
	if q.metadata.SourceHostname != "" {
		t.Fatal("expired lease still matched", q.metadata)
	}
	ip("neigh", "replace", "192.0.2.2", "nud", "failed", "dev", "lan-test")
	if state := systemNeighbors(context.Background()); state[netip.MustParseAddr("192.0.2.2")].mac != "" {
		t.Fatal("FAILED neighbor attributed", state)
	}
}

func TestNeighborLinuxMessages(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.2")
	body := make([]byte, 12)
	body[0] = syscall.AF_INET
	binary.NativeEndian.PutUint32(body[4:], 2)
	binary.NativeEndian.PutUint16(body[8:], 0x80)
	body = append(body, nlAttribute(1, ip.AsSlice())...)
	body = append(body, nlAttribute(2, []byte{2, 17, 34, 51, 68, 85})...)
	got, mac, index := linuxNeighborEntry(body)
	if got != ip || mac != neighborTestMAC || index != 2 {
		t.Fatal(got, mac, index)
	}
	for _, state := range []uint16{0, 1, 0x20, 0x21} {
		bad := append([]byte(nil), body...)
		binary.NativeEndian.PutUint16(bad[8:], state)
		if got, _, _ := linuxNeighborEntry(bad); got.IsValid() {
			t.Fatal("invalid state accepted", state)
		}
	}
	for i := range len(body) {
		if i == len(body)-2 { // Netlink attributes may omit trailing alignment padding.
			continue
		}
		truncated := body[:i]
		got, mac, _ := linuxNeighborEntry(truncated)
		if got.IsValid() && mac != "" {
			t.Fatal("truncated neighbor accepted", i)
		}
	}
	bad := append([]byte(nil), body...)
	bad[10] = 8
	if got, _, _ := linuxNeighborEntry(bad); got.IsValid() {
		t.Fatal("proxy neighbor accepted")
	}
}

func FuzzNeighborLinuxMessage(f *testing.F) {
	f.Add([]byte{2, 0, 0, 0, 1, 0, 0, 0, 128, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		linuxNeighborEntry(b)
	})
}
