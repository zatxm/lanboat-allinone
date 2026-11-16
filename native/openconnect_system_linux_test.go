//go:build linux

package native

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestOpenConnectSystemReferenceNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_OC_SYSTEM_PEER") == "1" {
		ocSystemReferencePeer(t)
		return
	}
	if os.Getenv("LANBOAT_OC_SYSTEM_REF_CHILD") != "1" {
		cmd := exec.Command("unshare", "--user", "--map-auto", "--map-root-user", "--setgroups", "allow", "--net", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=120s")
		cmd.Env = append(os.Environ(), "LANBOAT_OC_SYSTEM_REF_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated ocserv system interface: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	masqueSystemCommand(t, "link", "set", "lo", "up")
	masqueSystemCommand(t, "link", "add", "ocleft", "type", "veth", "peer", "name", "ocright")
	defer masqueSystemCommand(t, "link", "del", "ocleft")
	cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.timeout=110s")
	cmd.Env = append(os.Environ(), "LANBOAT_OC_SYSTEM_PEER=1")
	input, _ := cmd.StdinPipe()
	output, _ := cmd.StdoutPipe()
	log, err := os.Create(filepath.Join(t.TempDir(), "peer.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd.Stderr = log
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		input.Close()
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-done
		}
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Log(string(b))
		}
	}()
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "peer-namespace-ready\n" {
		t.Fatalf("ocserv peer namespace not ready: %q %v", line, err)
	}
	masqueSystemCommand(t, "link", "set", "ocright", "netns", strconv.Itoa(cmd.Process.Pid))
	masqueSystemCommand(t, "addr", "add", "198.18.0.1/24", "dev", "ocleft")
	masqueSystemCommand(t, "link", "set", "ocleft", "up")
	io.WriteString(input, "start\n")
	var startup strings.Builder
	var ports struct{ VPN, TCP, UDP uint16 }
	for {
		line, err := reader.ReadString('\n')
		startup.WriteString(line)
		if err != nil {
			t.Fatal("ocserv peer did not start", err, startup.String())
		}
		if rest, ok := strings.CutPrefix(line, "peer-ready:"); ok {
			if err = json.Unmarshal([]byte(rest), &ports); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	for _, dtls := range []bool{false, true} {
		t.Run(fmt.Sprint("dtls", dtls), func(t *testing.T) {
			o := Outbound{Type: "openconnect", Tag: "vpn", Server: "198.18.0.2", ServerPort: ports.VPN, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: OpenConnectOptions{System: true, Name: "lbocref", DisableDTLS: !dtls}}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{o}})
			p := ocSystemWait(t, client.ocClients["vpn"], nil)
			if dtls {
				ocWaitDTLS(t, p)
			}
			for _, ip := range []string{"198.18.0.2", "2001:db8:77::2"} {
				masqueSystemRoundtrip(t, "tcp", portAddress(ip, ports.TCP))
				masqueSystemRoundtrip(t, "udp", portAddress(ip, ports.UDP))
				if b, err := exec.Command("ping", "-c", "1", "-W", "3", ip).CombinedOutput(); err != nil {
					t.Fatalf("ocserv kernel ICMP: %v %s", err, b)
				}
			}
			client.resetNetworkTransports()
			ocSystemWait(t, client.ocClients["vpn"], p)
			masqueSystemRoundtrip(t, "tcp", portAddress("198.18.0.2", ports.TCP))
			client.Close()
			if _, err := net.InterfaceByName("lbocref"); err == nil {
				t.Fatal("reference session retained interface")
			}
		})
	}
}

func ocSystemReferencePeer(t *testing.T) {
	t.Helper()
	fmt.Fprintln(os.Stdout, "peer-namespace-ready")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"addr", "add", "198.18.0.2/24", "dev", "ocright"}, {"addr", "add", "2001:db8:77::2/128", "dev", "lo"}, {"link", "set", "ocright", "up"}} {
		masqueSystemCommand(t, args...)
	}
	root, err := filepath.Abs("../.cache/openconnect-reference/root")
	if err != nil {
		t.Fatal(err)
	}
	if path := os.Getenv("LANBOAT_TEST_OPENCONNECT"); path != "" {
		root = path
	}
	dir := t.TempDir()
	write := func(name, text string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cert := certificate(t)
	certPath := write("cert.pem", strings.Join(cert.Certificate, "\n"))
	keyPath := write("key.pem", strings.Join(cert.Key, "\n"))
	lib := "LD_LIBRARY_PATH=" + filepath.Join(root, "usr/lib/x86_64-linux-gnu")
	passwd := filepath.Join(dir, "passwd")
	cmd := exec.Command(filepath.Join(root, "usr/bin/ocpasswd"), "-c", passwd, "client")
	cmd.Env, cmd.Stdin = append(os.Environ(), lib), strings.NewReader("private\nprivate\n")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ocpasswd: %v %s", err, b)
	}
	port := unusedPort(t)
	config := fmt.Sprintf("auth = \"plain[passwd=%s]\"\nlisten-host = 198.18.0.2\ntcp-port = %d\nudp-port = %d\nrun-as-user = root\nrun-as-group = root\nsocket-file = %s\npid-file = %s\nserver-cert = %s\nserver-key = %s\nisolate-workers = false\ndevice = ocvpn\nipv4-network = 10.67.0.0/24\nipv6-network = fd67::/64\nipv6-subnet-prefix = 128\nmtu = 1500\nmax-clients = 8\nmax-same-clients = 4\ntry-mtu-discovery = false\nkeepalive = 20\ndpd = 30\ndtls-legacy = false\nroute = 198.18.0.0/24\nroute = 2001:db8:77::/64\nno-route = 198.18.0.99/32\n", passwd, port, port, filepath.Join(dir, "oc.sock"), filepath.Join(dir, "pid"), certPath, keyPath)
	path := write("ocserv.conf", config)
	cmd = exec.Command(filepath.Join(root, "usr/sbin/ocserv"), "-f", "--log-stderr", "-d", "2", "-c", path)
	cmd.Env = append(os.Environ(), lib)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ocWaitListening(t, portAddress("198.18.0.2", port))
	tcp, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go func() {
		for {
			c, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udp, err := net.ListenPacket("udp4", "198.18.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	_, tp, _ := net.SplitHostPort(tcp.Addr().String())
	_, up, _ := net.SplitHostPort(udp.LocalAddr().String())
	udp6, err := net.ListenPacket("udp6", net.JoinHostPort("2001:db8:77::2", up))
	if err != nil {
		t.Fatal(err)
	}
	defer udp6.Close()
	for _, peer := range []net.PacketConn{udp, udp6} {
		go func() {
			b := make([]byte, 65535)
			for {
				n, a, err := peer.ReadFrom(b)
				if err != nil {
					return
				}
				peer.WriteTo(b[:n], a)
			}
		}()
	}
	fmt.Fprintf(os.Stdout, "peer-ready:{\"VPN\":%d,\"TCP\":%s,\"UDP\":%s}\n", port, tp, up)
	io.Copy(io.Discard, os.Stdin)
}

func TestOpenConnectSystemNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_OC_SYSTEM_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v", "-test.timeout=120s")
		cmd.Env = append(os.Environ(), "LANBOAT_OC_SYSTEM_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated OpenConnect system interface: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	masqueSystemCommand(t, "link", "set", "lo", "up")
	t.Run("late-server", ocSystemDelayedServer)
	t.Run("authentication-stops", ocSystemAuthenticationStops)
	for _, dtls := range []bool{false, true} {
		for _, split := range []bool{false, true} {
			t.Run(fmt.Sprintf("dtls%v/split%v", dtls, split), func(t *testing.T) {
				ocSystemTraffic(t, dtls, split)
			})
		}
	}
	t.Run("collision", func(t *testing.T) {
		masqueSystemCommand(t, "link", "add", "lbocbusy", "type", "dummy")
		defer masqueSystemCommand(t, "link", "del", "lbocbusy")
		s, _ := ocPair(t)
		o := testOutbound(t, Inbound{Type: "openconnect", Users: []User{{Username: "client", Password: "p<&\"密码"}}}, s.Address("server"))
		o.TLS = TLSOptions{Enabled: true, Insecure: true}
		o.System, o.Name, o.Group = true, "lbocbusy", "staff"
		o.Password = "p<&\"密码"
		raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
		c, err := New(context.Background(), raw, zap.NewNop())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err = c.ocClients[o.Tag].session(context.Background()); err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatal("interface collision was not rejected", err)
		}
		if _, err = net.InterfaceByName("lbocbusy"); err != nil || c.protectMark.Load() != 0 {
			t.Fatal("collision modified interface/protection", err)
		}
	})
}

func ocSystemDelayedServer(t *testing.T) {
	port := unusedPort(t)
	out := Outbound{Type: "openconnect", Tag: "proxy", Server: "127.0.0.1", ServerPort: port, Username: "client", Password: "private", TLS: TLSOptions{Enabled: true, Insecure: true}, OpenConnectOptions: OpenConnectOptions{System: true, Name: "lboclate", DisableDTLS: true}}
	raw, _ := json.Marshal(Config{Outbounds: []Outbound{out}})
	core, logs := observer.New(zap.WarnLevel)
	client, err := New(context.Background(), raw, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait for the background connector's real refusal, not a separate probe.
	for until := time.Now().Add(3 * time.Second); logs.Len() == 0; {
		if time.Now().After(until) {
			t.Fatal("initial connection refusal was not reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", ListenPort: port, Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DisableDTLS: true, SplitInclude: []string{"192.0.2.0/24"}}}}, Route: Route{Rules: []Rule{{IPCIDR: []string{"192.0.2.0/24"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}}})
	defer server.Close()
	ocSystemWait(t, client.ocClients["proxy"], nil)
	_, targetPort, _ := net.SplitHostPort(relayEchoTCP(t))
	masqueSystemRoundtrip(t, "tcp", net.JoinHostPort("192.0.2.42", targetPort))
	client.Close()
}

func ocSystemAuthenticationStops(t *testing.T) {
	server, _ := ocPair(t)
	o := testOutbound(t, Inbound{Type: "openconnect"}, server.Address("server"))
	o.TLS = TLSOptions{Enabled: true, Insecure: true}
	o.Group, o.Password, o.System, o.Name = "staff", "wrong-password", true, "lbocbad"
	raw, _ := json.Marshal(Config{Outbounds: []Outbound{o}})
	core, logs := observer.New(zap.WarnLevel)
	client, err := New(context.Background(), raw, zap.New(core))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = client.Start(); err != nil {
		t.Fatal(err)
	}
	for until := time.Now().Add(3 * time.Second); logs.Len() == 0; {
		if time.Now().After(until) {
			t.Fatal("authentication failure was not reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(2200 * time.Millisecond)
	if logs.Len() != 1 || client.protectMark.Load() != 0 || client.ocClients[o.Tag].tunnel.Load() != nil {
		t.Fatal("authentication was retried or resources survived failure", logs.All())
	}
}

func ocSystemWait(t *testing.T, c *ocClient, previous *ocTunnel) *ocTunnel {
	t.Helper()
	for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
		p := c.tunnel.Load()
		if p != nil && p != previous && p.system != nil {
			select {
			case <-p.done:
			default:
				return p
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("OpenConnect system session did not start")
	return nil
}

func ocSystemTraffic(t *testing.T, dtls, split bool) {
	in := Inbound{Type: "openconnect", Tag: "server", Listen: "127.0.0.1", Users: []User{{Username: "client", Password: "private"}}, TLS: certificate(t), OpenConnectOptions: OpenConnectOptions{DisableDTLS: !dtls, SplitExclude: []string{"192.0.2.99/32", "2001:db8:44::99/128"}}}
	if split {
		in.SplitInclude = []string{"192.0.2.0/255.255.255.0", "2001:db8:44::/64"}
	}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}, Route: Route{Rules: []Rule{{IPCIDR: []string{"2001:db8:44::/64"}, Protocol: []string{"icmp"}, OverrideAddress: "::1", Outbound: "direct"}, {IPCIDR: []string{"192.0.2.0/24", "2001:db8:44::/64"}, OverrideAddress: "127.0.0.1", Outbound: "direct"}}}})
	out := testOutbound(t, in, server.Address("server"))
	out.OpenConnectOptions = OpenConnectOptions{System: true, Name: "lboc0", DisableDTLS: !dtls}
	out.Username, out.Password = "client", "private"
	var client *Runtime
	if os.Getenv("LANBOAT_OC_ENDPOINT") == "1" {
		client = ocEndpointRuntime(t, ocEndpointOptions{Tag: out.Tag, Server: "https://" + server.Address("server"), Username: out.Username, Password: out.Password, NoUDP: !dtls, OpenConnectOptions: out.OpenConnectOptions, TLS: ocEndpointTLS{TLSOptions: out.TLS}}, Config{})
	} else {
		client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	}
	p := ocSystemWait(t, client.ocClients[out.Tag], nil)
	if dtls {
		ocWaitDTLS(t, p)
	}
	iface, err := net.InterfaceByName("lboc0")
	if err != nil || iface.MTU != 1280 {
		t.Fatal(iface, err)
	}
	routes := masqueSystemCommand(t, "-4", "route", "show", "table", "all")
	if !strings.Contains(routes, "dev lboc0") || client.protectMark.Load() == 0 {
		t.Fatal("missing split routing/protection", routes)
	}
	for _, ip := range []string{"192.0.2.99", "2001:db8:44::99"} {
		if b, _ := exec.Command("ip", "route", "get", ip).CombinedOutput(); strings.Contains(string(b), "dev lboc0") {
			t.Fatal("excluded route captured", ip, string(b))
		}
	}
	tcp, udp := relayEchoTCP(t), echoUDP(t)
	_, tcpPort, _ := net.SplitHostPort(tcp)
	_, udpPort, _ := net.SplitHostPort(udp)
	for _, ip := range []string{"192.0.2.42", "2001:db8:44::42"} {
		masqueSystemRoundtrip(t, "tcp", net.JoinHostPort(ip, tcpPort))
		masqueSystemRoundtrip(t, "udp", net.JoinHostPort(ip, udpPort))
		if b, err := exec.Command("ping", "-c", "1", "-W", "3", ip).CombinedOutput(); err != nil {
			t.Fatalf("kernel ICMP %s: %v\n%s", ip, err, b)
		}
	}
	// API and kernel connections share the same assignment without tuple collisions.
	for _, network := range []string{"tcp", "udp"} {
		port := tcpPort
		if network == "udp" {
			port = udpPort
		}
		conn, err := client.Dial(context.Background(), network, net.JoinHostPort("192.0.2.42", port))
		if err != nil {
			t.Fatal(err)
		}
		if network == "tcp" {
			l, err := net.Listen(network, conn.LocalAddr().String())
			if err == nil {
				l.Close()
				t.Fatal("API TCP port not reserved")
			}
		} else {
			l, err := net.ListenPacket(network, conn.LocalAddr().String())
			if err == nil {
				l.Close()
				t.Fatal("API UDP port not reserved")
			}
		}
		masqueSystemEcho(t, conn, 4096)
		conn.Close()
	}
	if dtls {
		p.dtlsMu.Lock()
		sent := p.dtls.sent.Load()
		p.dtlsMu.Unlock()
		if sent == 0 {
			t.Fatal("system traffic never used DTLS")
		}
	}
	p.close()
	<-p.finished
	q := ocSystemWait(t, client.ocClients[out.Tag], p)
	if q.system == p.system {
		t.Fatal("reconnect retained old interface")
	}
	masqueSystemRoundtrip(t, "tcp", net.JoinHostPort("192.0.2.42", tcpPort))
	client.Close()
	if _, err = net.InterfaceByName("lboc0"); err == nil || client.protectMark.Load() != 0 {
		t.Fatal("close retained interface/protection", err)
	}
	if b := masqueSystemCommand(t, "rule", "show"); strings.Contains(b, "20000") || strings.Contains(b, "lboc0") {
		t.Fatal("policy rules survived close", b)
	}
}
