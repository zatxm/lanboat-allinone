package native

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func mdnsNamespace(t *testing.T, mount bool) bool {
	t.Helper()
	if os.Getenv("LANBOAT_MDNS_CHILD") != "1" {
		args := []string{"-Urn"}
		if mount {
			args = []string{"--user", "--map-auto", "--map-root-user", "--setgroups", "allow", "--net", "--mount"}
		}
		cmd := exec.Command("unshare", append(args, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.timeout=60s")...)
		cmd.Env = append(os.Environ(), "LANBOAT_MDNS_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated mDNS: %v\n%s", err, out)
		}
		t.Log(string(out))
		return false
	}
	mdnsCommand(t, "ip", "link", "set", "lo", "up")
	for index, v4 := range []string{"192.0.2.1/24", "198.51.100.1/24"} {
		name := fmt.Sprintf("mdns%d", index)
		mdnsCommand(t, "ip", "link", "add", name, "type", "dummy")
		mdnsCommand(t, "ip", "addr", "add", v4, "dev", name)
		mdnsCommand(t, "ip", "-6", "addr", "add", fmt.Sprintf("2001:db8:%d::1/64", index+44), "dev", name, "nodad")
		mdnsCommand(t, "ip", "-6", "addr", "add", "fe80::1/64", "dev", name, "nodad")
		mdnsCommand(t, "ip", "link", "set", name, "up", "multicast", "on")
	}
	return true
}

func mdnsCommand(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func mdnsResponder(t *testing.T, ifaceName string, ipv6 bool, answer func([]byte) []byte) *atomic.Int64 {
	t.Helper()
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		t.Fatal(err)
	}
	network, group := "udp4", "224.0.0.251:5353"
	if ipv6 {
		network, group = "udp6", "[ff02::fb%"+ifaceName+"]:5353"
	}
	address, _ := net.ResolveUDPAddr(network, group)
	conn, err := net.ListenMulticastUDP(network, iface, address)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := conn.SyscallConn()
	var optionErr error
	_ = raw.Control(func(fd uintptr) {
		if ipv6 {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVHOPLIMIT, 1)
		} else {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, 49, 0) // IP_MULTICAST_ALL
			if optionErr == nil {
				optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTTL, 1)
			}
		}
	})
	if optionErr != nil {
		conn.Close()
		t.Fatal(optionErr)
	}
	var count atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		b, oob := make([]byte, 65535), make([]byte, 128)
		for {
			n, control, _, peer, err := conn.ReadMsgUDP(b, oob)
			if err != nil {
				return
			}
			messages, _ := syscall.ParseSocketControlMessage(oob[:control])
			hops := 0
			for _, message := range messages {
				if len(message.Data) >= 4 && (message.Header.Level == syscall.IPPROTO_IP && message.Header.Type == syscall.IP_TTL || message.Header.Level == syscall.IPPROTO_IPV6 && message.Header.Type == syscall.IPV6_HOPLIMIT) {
					hops = int(binary.NativeEndian.Uint32(message.Data))
				}
			}
			if hops != 255 || peer.Port == 5353 || n < 12 || b[2] != 0 || b[3] != 0 {
				t.Error("invalid one-shot multicast query", hops, peer, b[:n])
				continue
			}
			if _, end, _, e := dnsQuestion(b[:n]); e != nil || end != n {
				t.Error("mDNS leaked upstream EDNS or malformed question", e)
				continue
			}
			count.Add(1)
			if reply := answer(bytes.Clone(b[:n])); reply != nil {
				_, _ = conn.WriteToUDP(reply, peer)
			}
		}
	}()
	t.Cleanup(func() { conn.Close(); <-done })
	return &count
}

func TestMDNSNamespace(t *testing.T) {
	if !mdnsNamespace(t, false) {
		return
	}
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprint(ipv6), func(t *testing.T) {
			count := mdnsResponder(t, "mdns0", ipv6, func(query []byte) []byte {
				reply := dnsAnswer(query)
				reply[3] |= 0x20
				return reply
			})
			paths, _, err := mdnsPaths([]string{"mdns0"})
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range paths {
				if path.local.Is6() != ipv6 {
					continue
				}
				r, _ := newResolver(DNSConfig{Servers: []DNSServer{{Type: "mdns", Tag: "lan", Interfaces: []string{"mdns0"}}}})
				defer r.Close()
				ctx := context.WithValue(context.Background(), mdnsPathsKey{}, []mdnsPath{path})
				for _, typ := range []uint16{1, 28} {
					query, _ := makeDNSQuery("device.local", typ)
					out, err := r.exchangeMDNS(ctx, r.server, query)
					ips, ttl, parseErr := parseDNSReply(query, out)
					if err != nil || parseErr != nil || len(ips) != 1 || ttl != 10 || out[3]&0x20 != 0 || out[2]&1 != query[2]&1 {
						t.Fatal(err, parseErr, ips, ttl)
					}
				}
				if count.Load() != 2 {
					t.Fatal("unexpected query count", count.Load())
				}
				return
			}
			t.Fatal("no interface address for requested family")
		})
	}
	t.Run("cache-and-policy", func(t *testing.T) {
		answer := func(query []byte) []byte { time.Sleep(10 * time.Millisecond); return dnsAnswer(query) }
		v4 := mdnsResponder(t, "mdns0", false, answer)
		v6 := mdnsResponder(t, "mdns0", true, answer)
		r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "block", Tag: "deny"}}, DNS: DNSConfig{ClientSubnet: "192.0.2.0/24", Servers: []DNSServer{{Type: "mdns", Tag: "lan", Interfaces: []string{"mdns0"}}, {Type: "hosts", Tag: "hosts", Predefined: map[string][]string{"internet.test": {"192.0.2.99"}}}}, Final: "hosts", Rules: []DNSRule{{Rule: Rule{DomainSuffix: []string{"local"}}, Server: "lan"}}}})
		var jobs sync.WaitGroup
		for range 16 {
			jobs.Add(1)
			go func() {
				defer jobs.Done()
				query, _ := makeDNSQuery("device.local", 1)
				reply, err := r.ExchangeDNS(context.Background(), query, "test")
				if _, _, parseErr := parseDNSReply(query, reply); err != nil || parseErr != nil {
					t.Error(err, parseErr)
				}
			}()
		}
		jobs.Wait()
		if count := v4.Load() + v6.Load(); count < 1 || count > 2 {
			t.Fatal("cache/coalescing missed", count)
		}
		query, _ := makeDNSQuery("internet.test", 1)
		reply, err := r.ExchangeDNS(context.Background(), query, "test")
		ips, _, parseErr := parseDNSReply(query, reply)
		if err != nil || parseErr != nil || len(ips) != 1 || ips[0].String() != "192.0.2.99" {
			t.Fatal(err, parseErr, ips)
		}
	})
	t.Run("lost-first-query", func(t *testing.T) {
		var seen atomic.Int64
		mdnsResponder(t, "mdns0", false, func(query []byte) []byte {
			if seen.Add(1) == 1 {
				return nil
			}
			return dnsAnswer(query)
		})
		paths, _, _ := mdnsPaths([]string{"mdns0"})
		r, _ := newResolver(DNSConfig{})
		defer r.Close()
		for _, path := range paths {
			if !path.local.Is4() {
				continue
			}
			query, _ := makeDNSQuery("retry.local", 1)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx = context.WithValue(ctx, mdnsPathsKey{}, []mdnsPath{path})
			if _, err := r.exchangeMDNS(ctx, DNSServer{}, query); err != nil || seen.Load() != 2 {
				t.Fatal(err, seen.Load())
			}
			return
		}
		t.Fatal("no IPv4 path")
	})
	t.Run("interface-isolation", func(t *testing.T) {
		count := mdnsResponder(t, "mdns1", false, func(query []byte) []byte { return dnsAnswer(query) })
		r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "mdns", Tag: "lan", Interfaces: []string{"mdns0"}}}}})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		query, _ := makeDNSQuery("isolated.local", 1)
		if _, err := r.ExchangeDNS(ctx, query, "test"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("query escaped interface or missed deadline", err)
		}
		if count.Load() != 0 {
			t.Fatal("query leaked to unselected interface")
		}
	})
	t.Run("network-snapshot", func(t *testing.T) {
		paths, before, err := mdnsPaths(nil)
		if err != nil || len(paths) != 4 {
			t.Fatal(err, paths)
		}
		for _, path := range paths {
			if path.name == "lo" {
				t.Fatal("default selected loopback")
			}
		}
		mdnsCommand(t, "ip", "addr", "add", "192.0.2.2/24", "dev", "mdns0")
		_, after, err := mdnsPaths(nil)
		if err != nil || before == after {
			t.Fatal("address change retained DNS cache namespace", err)
		}
		if _, _, err := mdnsPaths([]string{"missing"}); err == nil {
			t.Fatal("missing interface silently replaced")
		}
	})
	t.Run("close-cancels-query", func(t *testing.T) {
		seen := make(chan struct{}, 1)
		mdnsResponder(t, "mdns0", false, func([]byte) []byte {
			select {
			case seen <- struct{}{}:
			default:
			}
			return nil
		})
		r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "mdns", Tag: "lan", Interfaces: []string{"mdns0"}}}}})
		done := make(chan error, 1)
		go func() {
			query, _ := makeDNSQuery("missing.local", 1)
			_, err := r.ExchangeDNS(context.Background(), query, "test")
			done <- err
		}()
		select {
		case <-seen:
		case <-time.After(time.Second):
			t.Fatal("query not sent")
		}
		r.Close()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("close retained mDNS socket")
		}
	})
}

func TestMDNSAvahi(t *testing.T) {
	if !mdnsNamespace(t, true) {
		return
	}
	mdnsCommand(t, "mount", "--make-rprivate", "/")
	mdnsCommand(t, "mount", "-t", "tmpfs", "tmpfs", "/run")
	mdnsCommand(t, "mount", "-t", "tmpfs", "tmpfs", "/etc/avahi")
	if err := os.MkdirAll("/etc/avahi/services", 0755); err != nil {
		t.Fatal(err)
	}
	service := `<service-group><name>LanboatRef</name><service><type>_lanboat._tcp</type><port>443</port><txt-record>role=reference</txt-record></service></service-group>`
	if err := os.WriteFile("/etc/avahi/services/lanboat.service", []byte(service), 0644); err != nil {
		t.Fatal(err)
	}
	config := "[server]\nhost-name=lanboat-mdns-ref\ndomain-name=local\nuse-ipv4=yes\nuse-ipv6=yes\nallow-interfaces=avahi0\nenable-dbus=no\n[wide-area]\nenable-wide-area=no\n[publish]\npublish-addresses=yes\npublish-workstation=no\n[reflector]\nenable-reflector=no\n"
	dir := t.TempDir()
	file := filepath.Join(dir, "avahi.conf")
	if err := os.WriteFile(file, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "avahi.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	// A separate network peer also covers queriers that disable multicast loopback.
	cmd := exec.Command("unshare", "-n", "sh", "-c", `kill -STOP $$; exec "$@"`, "sh", "avahi-daemon", "--no-drop-root", "--no-chroot", "--no-rlimits", "--no-proc-title", "--debug", "-f", file)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	stopped := false
	for until := time.Now().Add(time.Second); time.Now().Before(until); {
		status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		if bytes.Contains(status, []byte("State:\tT")) {
			stopped = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !stopped {
		t.Fatal("Avahi namespace not ready")
	}
	pid := fmt.Sprint(cmd.Process.Pid)
	mdnsCommand(t, "ip", "link", "add", "mdns2", "type", "veth", "peer", "name", "avahi0")
	mdnsCommand(t, "ip", "link", "set", "avahi0", "netns", pid)
	for _, address := range []string{"203.0.113.1/24", "2001:db8:66::1/64", "fe80::1/64"} {
		mdnsCommand(t, "ip", "addr", "add", address, "dev", "mdns2", "nodad")
	}
	mdnsCommand(t, "ip", "link", "set", "mdns2", "up")
	mdnsCommand(t, "ip", "route", "add", "default", "via", "203.0.113.2", "dev", "mdns2")
	mdnsCommand(t, "ip", "-6", "route", "add", "default", "via", "fe80::2", "dev", "mdns2")
	for _, address := range []string{"203.0.113.2/24", "2001:db8:66::2/64", "fe80::2/64"} {
		mdnsCommand(t, "nsenter", "-t", pid, "-n", "ip", "addr", "add", address, "dev", "avahi0", "nodad")
	}
	mdnsCommand(t, "nsenter", "-t", pid, "-n", "ip", "link", "set", "lo", "up")
	mdnsCommand(t, "nsenter", "-t", pid, "-n", "ip", "link", "set", "avahi0", "up")
	if err := cmd.Process.Signal(syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	ready := false
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
		data, _ := os.ReadFile(log.Name())
		if strings.Contains(string(data), "Server startup complete") && strings.Contains(string(data), "successfully established") {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		data, _ := os.ReadFile(log.Name())
		t.Fatalf("Avahi not ready: %s", data)
	}
	r := newTestRuntime(t, Config{DNS: DNSConfig{DisableCache: true, Servers: []DNSServer{{Type: "mdns", Tag: "lan", Interfaces: []string{"mdns2"}}}}})
	for _, typ := range []uint16{1, 28} {
		query, _ := makeDNSQuery("lanboat-mdns-ref.local", typ)
		reply, err := r.ExchangeDNS(context.Background(), query, "test")
		ips, ttl, e := parseDNSReply(query, reply)
		want := netip.MustParseAddr("203.0.113.2")
		if typ == 28 {
			want = netip.MustParseAddr("2001:db8:66::2")
		}
		if err != nil || e != nil || !slices.Contains(ips, want) || ttl > 10 {
			t.Fatal(err, e, ips, ttl)
		}
	}
	for _, record := range []struct {
		host string
		typ  uint16
	}{{"2.113.0.203.in-addr.arpa", 12}, {"_lanboat._tcp.local", 12}, {"LanboatRef._lanboat._tcp.local", 33}, {"LanboatRef._lanboat._tcp.local", 16}} {
		query, _ := makeDNSQuery(record.host, record.typ)
		reply, err := r.ExchangeDNS(context.Background(), query, "test")
		sections, parseErr := dnsRecords(reply)
		if err != nil || parseErr != nil || len(sections[0]) == 0 {
			t.Fatal(record, err, parseErr)
		}
	}
	ref := os.Getenv("LANBOAT_TEST_SINGBOX15")
	if ref == "" {
		ref, _ = filepath.Abs("../.cache/sing-box-1.15.0-alpha.13/sing-box")
	}
	port := unusedPort(t)
	reference := map[string]any{"log": map[string]any{"level": "debug"}, "inbounds": []any{map[string]any{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": port}}, "dns": map[string]any{"timeout": "1s", "servers": []any{map[string]any{"type": "mdns", "tag": "lan", "interface": []string{"mdns2"}}}}, "route": map[string]any{"rules": []any{map[string]any{"inbound": "dns-in", "action": "hijack-dns"}}}}
	data, _ := json.Marshal(reference)
	file = filepath.Join(dir, "reference.json")
	os.WriteFile(file, data, 0600)
	refLog, _ := os.Create(filepath.Join(dir, "reference.log"))
	defer refLog.Close()
	peer := exec.Command(ref, "run", "-c", file)
	peer.Stdout, peer.Stderr = refLog, refLog
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { peer.Process.Kill(); peer.Wait() }()
	for until := time.Now().Add(3 * time.Second); ; {
		conn, err := net.DialTimeout("tcp", portAddress("127.0.0.1", port), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if time.Now().After(until) {
			data, _ := os.ReadFile(refLog.Name())
			t.Fatalf("reference not ready: %s", data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, typ := range []uint16{1, 28} {
		query, _ := makeDNSQuery("lanboat-mdns-ref.local", typ)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		reply, err := r.resolver.exchangeOn(ctx, DNSServer{Type: "udp", Server: "127.0.0.1", ServerPort: port}, query)
		cancel()
		ips, _, e := parseDNSReply(query, reply)
		want := netip.MustParseAddr("203.0.113.2")
		if typ == 28 {
			want = netip.MustParseAddr("2001:db8:66::2")
		}
		if err != nil || e != nil || !slices.Contains(ips, want) {
			logData, _ := os.ReadFile(refLog.Name())
			avahiData, _ := os.ReadFile(log.Name())
			t.Fatal("official mDNS resolver", err, e, ips, string(logData), string(avahiData))
		}
	}
	t.Log("Native and official1.15 mDNS resolvers queried unmodified Avahi via real multicast")
}
