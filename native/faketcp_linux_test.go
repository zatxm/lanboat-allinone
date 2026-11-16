package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestFakeTCPNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_FAKETCP_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestFakeTCPNamespace$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_FAKETCP_CHILD=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated FakeTCP: %v\n%s", err, output)
		}
		t.Log(string(output))
		return
	}
	if output, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("loopback: %v %s", err, output)
	}
	if output, err := exec.Command("ip", "-6", "addr", "add", "fe80::1/64", "dev", "lo", "nodad").CombinedOutput(); err != nil {
		t.Fatalf("link-local IPv6: %v %s", err, output)
	}
	t.Run("datagrams", testFakeTCPDatagrams)
	t.Run("concurrent", testFakeTCPConcurrent)
	t.Run("authentication", testFakeTCPAuthentication)
	for _, host := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "fe80::1%lo"} {
		for _, mask := range []string{"", "xplus"} {
			t.Run("native/"+host+"/"+mask, func(t *testing.T) {
				in := Inbound{Type: "hysteria", Tag: "server", Listen: host, Protocol: "faketcp", TLS: certificate(t), Users: []User{{Password: "private"}}}
				in.ListenOptions = ListenOptions{BindInterface: "lo", ReuseAddr: true, TCPFastOpen: true}
				if mask != "" {
					in.Obfs = "mask-fixture"
				}
				server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
				address := server.Address("server")
				if host == "0.0.0.0" {
					_, port, _ := net.SplitHostPort(address)
					address = "127.0.0.1:" + port
				}
				if host == "::" {
					_, port, _ := net.SplitHostPort(address)
					address = "[::1]:" + port
				}
				out := testOutbound(t, in, address)
				out.Username, out.UUID, out.Protocol, out.Obfs = "", "", "faketcp", in.Obfs
				client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
				assertTCP(t, client)
				assertUDPSizes(t, client, []int{1, 511, 4096, 14000})
			})
		}
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, mask := range []string{"", "xplus"} {
			for _, direction := range []string{"client", "server"} {
				t.Run("official/"+host+"/"+mask+"/"+direction, func(t *testing.T) { testFakeTCPReference(t, host, mask, direction) })
			}
		}
	}
}

func testFakeTCPDatagrams(t *testing.T) {
	pc, err := listenFakeTCP(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	var o Outbound
	json.Unmarshal([]byte(`{"server":"127.0.0.1","server_port":`+port+`}`), &o)
	r := newTestRuntime(t, Config{})
	c, err := r.dialFakeTCP(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	server := pc.(*fakeTCPPacket)
	for end := time.Now().Add(time.Second); ; {
		server.mu.Lock()
		_, ready := server.peers[c.LocalAddr().(*net.UDPAddr).AddrPort()]
		server.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(end) {
			t.Fatal("server did not register handshake")
		}
		time.Sleep(time.Millisecond)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	pc.SetDeadline(time.Now().Add(2 * time.Second))
	flow := c.(*fakeTCPConn)
	flow.mu.Lock()
	kernel := flow.flows[flow.peers[flow.remote.AddrPort()]].conn
	flow.mu.Unlock()
	for _, payload := range [][]byte{[]byte("one"), bytes.Repeat([]byte{7}, 1200)} {
		if _, err = c.Write(payload); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 65535)
		n, peer, err := pc.ReadFrom(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatal("server", n, err)
		}
		if _, err = pc.WriteTo(buffer[:n], peer); err != nil {
			t.Fatal(err)
		}
		n, err = c.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatal("client", n, err)
		}
	}
	kernel.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, err := kernel.Read(make([]byte, 32)); !os.IsTimeout(err) {
		t.Fatal("QUIC payload reached TCP byte stream", err)
	}
}

func testFakeTCPConcurrent(t *testing.T) {
	in := Inbound{Type: "hysteria", Tag: "server", Listen: "127.0.0.1", Protocol: "faketcp", TLS: certificate(t), Users: []User{{Password: "private"}}}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			out := testOutbound(t, in, server.Address("server"))
			out.Protocol = "faketcp"
			out.Username, out.UUID = "", ""
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			assertTCP(t, client)
			fakeTCPDebug(t, client)
			assertUDPSizes(t, client, []int{1, 4096})
		})
	}
	workers.Wait()
}

func testFakeTCPAuthentication(t *testing.T) {
	in := Inbound{Type: "hysteria", Tag: "server", Listen: "127.0.0.1", Protocol: "faketcp", TLS: certificate(t), Users: []User{{Password: "private"}}}
	server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
	target := tcpEcho(t)
	for _, mode := range []string{"password", "certificate", "mask"} {
		t.Run(mode, func(t *testing.T) {
			out := testOutbound(t, in, server.Address("server"))
			out.Protocol = "faketcp"
			out.Username, out.UUID = "", ""
			out.TLS.Insecure, out.TLS.Certificate = false, in.TLS.Certificate
			switch mode {
			case "password":
				out.Password = "wrong"
			case "certificate":
				out.TLS.ServerName = "wrong.example"
			case "mask":
				out.Obfs = "wrong-mask"
			}
			client := newTestRuntime(t, Config{Outbounds: []Outbound{out}})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := client.Dial(ctx, "tcp", target)
			if conn != nil {
				conn.Close()
			}
			if err == nil {
				t.Fatal("invalid credentials accepted")
			}
		})
	}
}

func TestFakeTCPDeadlines(t *testing.T) {
	p := newFakeTCP()
	defer p.Close()
	done := make(chan error, 1)
	go func() { _, _, err := p.ReadFrom(make([]byte, 32)); done <- err }()
	p.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if err := <-done; !os.IsTimeout(err) {
		t.Fatal("deadline did not interrupt read", err)
	}
	p.SetReadDeadline(time.Time{})
	p.queue <- fakeTCPDatagram{data: []byte("packet"), addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}}
	p.bytes = 6
	b := make([]byte, 32)
	n, _, err := p.ReadFrom(b)
	if err != nil || string(b[:n]) != "packet" {
		t.Fatal(n, err)
	}
	go func() { _, _, err := p.ReadFrom(b); done <- err }()
	p.Close()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatal("close did not interrupt read", err)
	}
	if _, err = p.WriteTo([]byte("x"), &net.UDPAddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("write after close", err)
	}
}

func TestFakeTCPPktinfo(t *testing.T) {
	for _, oob := range [][]byte{nil, {1}, make([]byte, 32)} {
		if _, _, ok := fakeTCPDestination(oob); ok {
			t.Fatal("accepted invalid metadata")
		}
	}
	for _, text := range []string{"192.0.2.1", "2001:db8::1"} {
		ip := netip.MustParseAddr(text)
		oob := fakeTCPPktinfo(ip)
		if ip.Is4() {
			data := oob[syscall.CmsgLen(0):]
			copy(data[8:12], data[4:8])
		}
		if got, _, ok := fakeTCPDestination(oob); !ok || got != ip {
			t.Fatal("packet metadata", got, ok)
		}
	}
}

func TestFakeTCPAddressScopes(t *testing.T) {
	for _, text := range []string{"169.254.1.1", "192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"} {
		ip := netip.MustParseAddr(text)
		got, err := fakeTCPAddr(net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, 443)), "")
		if err != nil || got.Addr() != ip.Unmap() || got.Port() != 443 {
			t.Fatal("unscoped address", got, err)
		}
	}
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{"lo", strconv.Itoa(iface.Index)} {
		got, err := fakeTCPAddr(&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 443}, zone)
		if err != nil || got.Addr().Zone() != strconv.Itoa(iface.Index) {
			t.Fatal("interface scope", got, err)
		}
	}
	if _, err := fakeTCPAddr(&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 443}, "missing-lanboat-interface"); err == nil {
		t.Fatal("accepted unknown scope")
	}
}

func testFakeTCPReference(t *testing.T, host, mask, direction string) {
	in := Inbound{Type: "hysteria", Tag: "server", Listen: host, Protocol: "faketcp", TLS: certificate(t), Users: []User{{Password: "private"}}}
	if mask != "" {
		in.Obfs = "mask-fixture"
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(cert, []byte(strings.Join(in.TLS.Certificate, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(strings.Join(in.TLS.Key, "\n")), 0600); err != nil {
		t.Fatal(err)
	}
	var client *Runtime
	if direction == "client" {
		in.ListenPort = unusedPort(t)
		ready := portAddress(host, in.ListenPort)
		startHysteria1Reference(t, map[string]any{"listen": portAddress(host, in.ListenPort), "protocol": "faketcp", "cert": cert, "key": key, "up_mbps": 100, "down_mbps": 100, "obfs": string(in.Obfs), "auth": map[string]any{"mode": "passwords", "config": []string{"private"}}}, "server", ready)
		out := testOutbound(t, in, portAddress(host, in.ListenPort))
		out.Username, out.UUID, out.Protocol, out.Obfs = "", "", "faketcp", in.Obfs
		out.TLS.Insecure, out.TLS.Certificate = false, in.TLS.Certificate
		client = newTestRuntime(t, Config{Outbounds: []Outbound{out}})
	} else {
		server := newTestRuntime(t, Config{Inbounds: []Inbound{in}})
		local := portAddress("127.0.0.1", unusedPort(t))
		startHysteria1Reference(t, map[string]any{"server": server.Address("server"), "protocol": "faketcp", "up_mbps": 100, "down_mbps": 100, "obfs": string(in.Obfs), "auth_str": "private", "server_name": "example.com", "ca": cert, "socks5": map[string]any{"listen": local}}, "client", local)
		front := testOutbound(t, Inbound{Type: "socks"}, local)
		front.Username, front.Password, front.UUID = "", "", ""
		client = newTestRuntime(t, Config{Outbounds: []Outbound{front}})
	}
	assertTCP(t, client)
	fakeTCPDebug(t, client)
	assertUDPSizes(t, client, []int{1, 511, 4000})
}

func fakeTCPDebug(t *testing.T, r *Runtime) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, name := range []string{"raw", "raw6"} {
			b, _ := os.ReadFile("/proc/net/" + name)
			t.Log(name, string(b))
		}
		for _, p := range r.quicClients {
			p.mu.Lock()
			if p.current != nil {
				t.Log("connection", p.current.conn.err())
				p.current.mu.Lock()
				t.Log("pending fragments", p.current.fragments)
				p.current.mu.Unlock()
			}
			p.mu.Unlock()
		}
	})
}
