package native

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTailscaleSystemInterfaceReference(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live system-interface test uses a Linux user/network namespace")
	}
	if os.Getenv("LANBOAT_TS_SYSTEM_NS") != "1" {
		testbin, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command("unshare", "-Urn", testbin, "-test.run=^TestTailscaleSystemInterfaceReference$", "-test.v", "-test.timeout=45s")
		cmd.Env = append(os.Environ(), "LANBOAT_TS_SYSTEM_NS=1")
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("isolated namespace: %v\n%s", e, b)
		}
		t.Log(string(b))
		return
	}
	if b, e := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); e != nil {
		t.Fatalf("loopback: %v %s", e, b)
	}
	for _, args := range [][]string{{"link", "add", "testnet0", "type", "dummy"}, {"addr", "add", "192.0.2.254/24", "dev", "testnet0"}, {"link", "set", "testnet0", "up"}, {"route", "add", "default", "dev", "testnet0"}} {
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("test network: %v %s", e, b)
		}
	}
	url, decoder, input := startTSReference(t, false)
	r := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, Hostname: "system-iface", StateDirectory: t.TempDir(), SystemInterface: true, SystemInterfaceName: "lbts0", ForceDERP: true, AcceptRoutes: true, ExitNode: "reference"}}}, Route: Route{Final: "ts"}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status, e := r.TailscaleStatus(ctx, "ts")
	if e != nil {
		t.Fatal(e)
	}
	c := r.tailscaleClient("ts")
	c.mu.Lock()
	var peers []netip.Addr
	for _, n := range c.nodes {
		for _, a := range n.Addresses {
			peers = append(peers, a.Addr())
		}
	}
	c.mu.Unlock()
	for _, ip := range peers {
		for _, network := range []string{"tcp", "udp"} {
			port := "8080"
			if network == "udp" {
				port = "8081"
			}
			conn, e := net.DialTimeout(network, net.JoinHostPort(ip.String(), port), 5*time.Second)
			if e != nil {
				t.Fatal(ip, network, e)
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			_, e = conn.Write([]byte("kernel-packet"))
			if e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 13)
			_, e = io.ReadFull(conn, b)
			conn.Close()
			if e != nil || string(b) != "kernel-packet" {
				t.Fatal(ip, network, string(b), e)
			}
		}
	}
	for _, address := range []string{"192.0.2.123:8080", "203.0.113.7:8080", "[2001:db8::7]:8080"} {
		conn, e := net.DialTimeout("tcp", address, 3*time.Second)
		if e != nil {
			t.Fatal("kernel routed connection", address, e)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		conn.Write([]byte("routed"))
		b := make([]byte, 6)
		_, e = io.ReadFull(conn, b)
		conn.Close()
		if e != nil || string(b) != "routed" {
			t.Fatal(address, e, string(b))
		}
	}
	for _, ip := range peers {
		if b, e := exec.Command("ping", "-c", "1", "-W", "2", ip.String()).CombinedOutput(); e != nil {
			t.Fatalf("kernel ICMP %s: %v %s", ip, e, b)
		}
	}
	// A runtime socket must continue to use the user-mode stack on an interface-enabled endpoint.
	conn, e := r.Dial(ctx, "tcp", net.JoinHostPort(peers[0].String(), "8080"))
	if e != nil {
		t.Fatal(e)
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	conn.Write([]byte("mixed"))
	b := make([]byte, 5)
	_, e = io.ReadFull(conn, b)
	conn.Close()
	if e != nil || string(b) != "mixed" {
		t.Fatal(e, string(b))
	}
	for _, a := range status.Addresses {
		l, e := net.Listen("tcp", net.JoinHostPort(a.Addr().String(), "8091"))
		if e != nil {
			t.Fatal(e)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			conn, e := l.Accept()
			if e == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				io.Copy(conn, conn)
			}
		}()
		e = json.NewEncoder(input).Encode(map[string]string{"op": "echo", "network": "tcp", "address": l.Addr().String(), "data": "kernel-service"})
		if e != nil {
			t.Fatal(e)
		}
		var reply struct{ Data, Error string }
		if e = decoder.Decode(&reply); e != nil || reply.Error != "" || reply.Data != "kernel-service" {
			t.Fatal(reply, e)
		}
		l.Close()
		<-done
	}
	if _, e := io.WriteString(input, "no-routes\n"); e != nil {
		t.Fatal(e)
	}
	var ack struct{ OK bool }
	if e := decoder.Decode(&ack); e != nil || !ack.OK {
		t.Fatal(e, ack)
	}
	for deadline := time.Now().Add(2 * time.Second); ; {
		_, e := c.choose(netip.MustParseAddr("203.0.113.7"))
		if e != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("withdrawn route still selected")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, plan := c.systemPlan()
	if !strings.Contains(strings.Join(plan, ","), "0.0.0.0/0") {
		t.Fatal("lost exit would leak to physical default", plan)
	}
	iface, e := net.InterfaceByName("lbts0")
	if e != nil || iface.MTU != 1280 {
		t.Fatal(iface, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = net.InterfaceByName("lbts0"); e == nil {
		t.Fatal("system interface leaked")
	}
	if r.protectMark.Load() != 0 {
		t.Fatal("socket protection leaked")
	}
}

func TestTailscaleSystemInterfaceConfig(t *testing.T) {
	for _, field := range []string{`"system_interface_mtu":1279`, `"system_interface_name":"bad/name"`, `"system_interface_mtu":65505`} {
		if _, e := Parse([]byte(`{"endpoints":[{"type":"tailscale","tag":"ts","system_interface":true,` + field + `}]}`)); e == nil {
			t.Fatal("accepted", field)
		}
	}
	for _, field := range []string{`"system_interface_mtu":1280`, `"system_interface_name":"x"`} {
		if _, e := Parse([]byte(`{"endpoints":[{"type":"tailscale","tag":"ts",` + field + `}]}`)); e == nil {
			t.Fatal("options without interface accepted", field)
		}
	}
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	if a, b := r.retainTUNProtection(1234), r.retainTUNProtection(5678); a != 1234 || b != 1234 {
		t.Fatal(a, b)
	}
	r.releaseTUNProtection()
	if r.protectMark.Load() != 1234 {
		t.Fatal("closing one interface unprotected others")
	}
	r.releaseTUNProtection()
	if r.protectMark.Load() != 0 {
		t.Fatal("protection not released")
	}
	c := newTailscaleClient(r, Outbound{})
	if e := c.applyMap([]byte(`{"Node":{"Addresses":["100.64.0.1/32","fd7a:115c:a1e0::1/128"]},"Peers":[{"ID":1,"AllowedIPs":["192.0.2.0/24","0.0.0.0/0"]}]}`)); e != nil {
		t.Fatal(e)
	}
	_, routes := c.systemPlan()
	if strings.Contains(strings.Join(routes, ","), "192.0.2.") {
		t.Fatal("unaccepted subnet installed", routes)
	}
	c.o.AcceptRoutes = true
	_, routes = c.systemPlan()
	if !strings.Contains(strings.Join(routes, ","), "192.0.2.") {
		t.Fatal("accepted subnet missing", routes)
	}
	c.cancel()
}

func TestTailscaleSystemInterfaceACL(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	c := newTailscaleClient(r, Outbound{})
	defer c.cancel()
	local, remote := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("100.64.0.2")
	memory := &packetMemory{}
	s := &tsSystemInterface{c: c, tun: &tunTunnel{in: Inbound{MTU: 1280}, device: memory}, addresses: []netip.Prefix{netip.PrefixFrom(local, 32)}, flows: map[tsSystemFlow]tsSystemState{}}
	outgoing, _ := parseTunPacket(makeUDPPacket(local, remote, 23456, 9999, []byte("request")))
	incoming, _ := parseTunPacket(makeUDPPacket(remote, local, 9999, 23456, []byte("reply")))
	s.receive(incoming)
	if memory.Len() != 0 {
		t.Fatal("unsolicited packet bypassed ACL")
	}
	s.trackOutbound(outgoing)
	s.receive(incoming)
	if memory.Len() == 0 {
		t.Fatal("reply to host flow blocked")
	}
	memory.Reset()
	s.flows = map[tsSystemFlow]tsSystemState{}
	if e := c.applyMap([]byte(`{"PacketFilter":[{"SrcIPs":["100.64.0.2"],"DstPorts":[{"IP":"100.64.0.1","Ports":{"First":23456,"Last":23456}}]}]}`)); e != nil {
		t.Fatal(e)
	}
	s.receive(incoming)
	if memory.Len() == 0 {
		t.Fatal("ACL-authorized inbound blocked")
	}
	memory.Reset()
	s.trackOutbound(outgoing)
	if e := c.applyMap([]byte(`{"PacketFilter":[]}`)); e != nil {
		t.Fatal(e)
	}
	s.receive(incoming)
	if memory.Len() != 0 {
		t.Fatal("server reply promoted inbound flow past ACL revocation")
	}
}
