package native

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTailscalePublishedRoutesAndFilters(t *testing.T) {
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}})
	c := newTailscaleClient(r, Outbound{Tag: "ts", TailscaleOptions: TailscaleOptions{AdvertiseRoutes: []string{"192.0.2.5/24"}, AdvertiseExitNode: true, AdvertiseTags: []string{"tag:router"}}})
	defer c.cancel()
	info := c.hostinfo()
	if !slices.Equal(info["RoutableIPs"].([]string), []string{"0.0.0.0/0", "192.0.2.0/24", "::/0"}) {
		t.Fatal(info)
	}
	for _, raw := range []string{`"advertise_routes":["bad"]`, `"advertise_routes":["127.0.0.1/8"]`, `"advertise_tags":["router"]`, `"advertise_tags":["tag:x/y"]`, `"udp_timeout":"0s"`} {
		if _, e := Parse([]byte(`{"endpoints":[{"type":"tailscale",` + raw + `}]}`)); e == nil {
			t.Fatal("invalid option", raw)
		}
	}
	c.o.ExitNode = "exit"
	if e := c.applyMap([]byte(`{"Node":{"Addresses":["100.64.0.1/32"],"AllowedIPs":["100.64.0.1/32","192.0.2.0/24"]},"PacketFilter":[{"SrcIPs":["100.64.0.2"],"DstPorts":[{"IP":"192.0.2.0/24","Ports":{"First":80,"Last":81}}]}],"Peers":[{"ID":2,"Name":"exit","Addresses":["100.64.0.2/32"],"AllowedIPs":["0.0.0.0/0"]},{"ID":3,"Addresses":["100.64.0.3/32"],"AllowedIPs":["100.64.0.3/32"]}]}`)); e != nil {
		t.Fatal(e)
	}
	packet := func(source, dest string, port uint16) tunPacket {
		p, e := parseTunPacket(makeUDPPacket(netip.MustParseAddr(source), netip.MustParseAddr(dest), 12345, port, []byte("acl")))
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	if !c.acceptsPacket(packet("100.64.0.2", "192.0.2.1", 80)) {
		t.Fatal("approved route rejected")
	}
	for _, p := range []tunPacket{packet("100.64.0.3", "192.0.2.1", 80), packet("100.64.0.2", "192.0.2.1", 82), packet("100.64.0.2", "203.0.113.1", 80), packet("100.64.0.2", "100.64.0.1", 80), packet("100.64.0.2", "127.0.0.1", 80)} {
		if c.acceptsPacket(p) {
			t.Fatal("unauthorized packet accepted", p.source, p.destination)
		}
	}
	if c.ownsSource(2, netip.MustParseAddr("100.64.0.3")) || !c.ownsSource(3, netip.MustParseAddr("100.64.0.3")) || !c.ownsSource(2, netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("source ownership")
	}
	if e := c.applyMap([]byte(`{"PacketFilters":{"base":null,"extra":[{"SrcIPs":["100.64.0.2-100.64.0.4"],"DstPorts":[{"IP":"*","Ports":{"First":81,"Last":81}}],"IPProto":[17]}]}}`)); e != nil {
		t.Fatal(e)
	}
	if c.acceptsPacket(packet("100.64.0.2", "192.0.2.1", 80)) || !c.acceptsPacket(packet("100.64.0.3", "192.0.2.1", 81)) {
		t.Fatal("incremental filters")
	}
	if e := c.applyMap([]byte(`{"PacketFilters":{"extra":null}}`)); e != nil {
		t.Fatal(e)
	}
	if c.acceptsPacket(packet("100.64.0.3", "192.0.2.1", 81)) {
		t.Fatal("deleted grant remains active")
	}
	if e := c.applyMap([]byte(`{"TKAInfo":{"Disabled":true}}`)); e != nil {
		t.Fatal("disabled Tailnet Lock", e)
	}
}

func startTSReference(t *testing.T, interactive bool) (string, *json.Decoder, io.Writer) {
	t.Helper()
	binary := os.Getenv("LANBOAT_TEST_TAILSCALE")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_TAILSCALE must name the official reference")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(os.Environ(), "TS_DISABLE_LOGTAIL=true", "HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "NO_PROXY=*")
	if interactive {
		cmd.Env = append(cmd.Env, "LANBOAT_TS_INTERACTIVE=1")
	}
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	logname := filepath.Join(t.TempDir(), "reference.log")
	log, e := os.Create(logname)
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
		log.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logname)
			t.Log(string(b))
		}
	})
	decoder := json.NewDecoder(bufio.NewReader(stdout))
	var fixture struct {
		ControlURL string `json:"control_url"`
	}
	if e := decoder.Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	return fixture.ControlURL, decoder, stdin
}

func TestTailscaleInteractiveAndOnDemand(t *testing.T) {
	url, decoder, input := startTSReference(t, true)
	dir := filepath.Join(t.TempDir(), "state")
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{ControlURL: url, StateDirectory: dir, OnDemand: true}}}})
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("on_demand started without request", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	login, e := r.TailscaleAuthURL(ctx, "ts")
	if e != nil || login == "" {
		t.Fatal("login URL", login, e)
	}
	pending, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	_, e = r.TailscaleStatus(pending, "ts")
	stop()
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("unapproved login became ready", e)
	}
	io.WriteString(input, login+"\n")
	var approved struct{ OK bool }
	if e := decoder.Decode(&approved); e != nil || !approved.OK {
		t.Fatal("complete login", e, approved)
	}
	if _, e = r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	if login, e = r.TailscaleAuthURL(ctx, "ts"); e != nil || login != "" {
		t.Fatal("login URL not cleared", login, e)
	}
	identity := slices.Clone(r.tailscaleClient("ts").nodeKey.Bytes())
	if e = r.DisconnectTailscale("ts"); e != nil {
		t.Fatal(e)
	}
	if _, e = r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	if !slices.Equal(identity, r.tailscaleClient("ts").nodeKey.Bytes()) {
		t.Fatal("on-demand reconnect lost identity")
	}
	var jobs sync.WaitGroup
	for range 8 {
		jobs.Go(func() {
			if err := r.DisconnectTailscale("ts"); err != nil {
				t.Error(err)
			}
		})
	}
	jobs.Wait()
	if _, e = r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal("rapid on-demand reconnect", e)
	}
}

func TestTailscalePublishedRouteReference(t *testing.T) {
	url, decoder, input := startTSReference(t, false)
	tcp, udp := tcpEcho(t), echoUDP(t)
	_, tcpPort, _ := net.SplitHostPort(tcp)
	_, udpPort, _ := net.SplitHostPort(udp)
	tcpPN, _ := strconv.Atoi(tcpPort)
	udpPN, _ := strconv.Atoi(udpPort)
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), Hostname: "router", AdvertiseRoutes: []string{"198.51.100.0/24"}, AdvertiseExitNode: true, AdvertiseTags: []string{"tag:router"}, ForceDERP: true}}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct", Rules: []Rule{{Network: []string{"tcp"}, Action: "route-options", OverrideAddress: "127.0.0.1", OverridePort: uint16(tcpPN)}, {Network: []string{"udp"}, Action: "route-options", OverrideAddress: "127.0.0.1", OverridePort: uint16(udpPN)}}}})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, e := r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	enc := json.NewEncoder(input)
	if e := enc.Encode(map[string]string{"op": "approve", "hostname": "router"}); e != nil {
		t.Fatal(e)
	}
	var approved struct{ Routes []string }
	if e := decoder.Decode(&approved); e != nil {
		t.Fatal(e)
	}
	if len(approved.Routes) != 3 {
		t.Fatal("routes not advertised", approved)
	}
	c := r.tailscaleClients["ts"]
	for deadline := time.Now().Add(5 * time.Second); ; {
		c.mu.Lock()
		approved := slices.Contains(c.self.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
		c.mu.Unlock()
		if approved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("approval missing")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, network := range []string{"tcp", "udp"} {
		for _, address := range []string{"198.51.100.1:8080", "203.0.113.1:8080", "[2001:db8::5]:8080"} {
			if e := enc.Encode(map[string]string{"op": "echo", "network": network, "address": address, "data": "published route"}); e != nil {
				t.Fatal(e)
			}
			var result struct{ Data, Error string }
			if e := decoder.Decode(&result); e != nil {
				t.Fatal(e)
			}
			if result.Data != "published route" || result.Error != "" {
				t.Fatal(network, address, result)
			}
		}
	}
}

func TestTailscaleControlResolverAndUDPTimeout(t *testing.T) {
	address := tcpEcho(t)
	_, port, _ := net.SplitHostPort(address)
	r := newTestRuntime(t, Config{DNS: DNSConfig{Servers: []DNSServer{{Type: "hosts", Tag: "bootstrap", Predefined: map[string][]string{"controller.example": {"127.0.0.1"}}}}}})
	c := newTailscaleClient(r, Outbound{DomainResolver: "bootstrap"})
	defer c.cancel()
	conn, e := c.controlDirect(context.Background(), "tcp", net.JoinHostPort("controller.example", port))
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	stack := newIPStack(&ipEndpoint{runtime: r, done: r.ctx.Done(), local: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, udpIdleTimeout: time.Second})
	defer stack.close()
	u, e := stack.dial(context.Background(), "udp", "192.0.2.2:53")
	if e != nil {
		t.Fatal(e)
	}
	stack.expire(time.Now().Add(2 * time.Second))
	if _, e = u.Read(make([]byte, 10)); !errors.Is(e, net.ErrClosed) {
		t.Fatal("UDP idle timeout", e)
	}
}

func TestTailscaleExitLAN(t *testing.T) {
	r := newTestRuntime(t, Config{})
	c := newTailscaleClient(r, Outbound{TailscaleOptions: TailscaleOptions{ExitNode: "exit", ExitNodeAllowLANAccess: true}})
	defer c.cancel()
	c.once.Do(func() {})
	c.self.Addresses = []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}
	close(c.ready)
	c.localRoutes = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("100.0.0.0/8")}
	conn, e := c.dial(context.Background(), "tcp", tcpEcho(t))
	if e != nil {
		t.Fatal(e)
	}
	conn.Close()
	c.nodes[2] = tsNode{ID: 2, Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
	if c.localExitDestination(netip.MustParseAddr("100.64.0.2")) {
		t.Fatal("LAN exception bypassed exact tailnet route")
	}
}

func TestTailscaleTaildropReference(t *testing.T) {
	url, decoder, input := startTSReference(t, false)
	dir := t.TempDir()
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), Hostname: "receiver", ForceDERP: true, TaildropDirectory: dir}}}})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, e := r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if e := json.NewEncoder(input).Encode(map[string]string{"op": "push", "hostname": "receiver", "address": "hello.txt", "data": "taildrop content"}); e != nil {
			t.Fatal(e)
		}
		var result struct {
			OK    bool
			Error string
		}
		if e := decoder.Decode(&result); e != nil {
			t.Fatal(e)
		}
		if !result.OK {
			c := r.tailscaleClient("ts")
			c.mu.Lock()
			t.Logf("self user=%d tags=%v addresses=%v filters=%d api=%d peers=%d", c.self.User, c.self.Tags, c.self.Addresses, len(c.filter), c.peerAPI.port, len(c.peers))
			for _, n := range c.nodes {
				t.Logf("peer id=%d user=%d addresses=%v", n.ID, n.User, n.Addresses)
			}
			for _, p := range c.peers {
				p.wg.stack.mu.Lock()
				t.Logf("peer TCP=%d UDP=%d inbound=%s", len(p.wg.stack.tcp), len(p.wg.stack.udp), p.wg.stack.peer.inbound)
				p.wg.stack.mu.Unlock()
			}
			c.mu.Unlock()
			t.Fatal(result.Error)
		}
	}
	for _, name := range []string{"hello.txt", "hello.txt (1)"} {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil || string(b) != "taildrop content" {
			t.Fatal(name, string(b), e)
		}
	}
	for _, name := range []string{"../escape", "foo/bar", "foo\\bar", "..", ".hidden", "CON", "x.partial", "x.deleted", "bad\x00name"} {
		if tsDropName(name) {
			t.Fatal("unsafe filename accepted", name)
		}
	}
}

func TestTailscaleTaildropFilesystemBoundary(t *testing.T) {
	r := newTestRuntime(t, Config{})
	dir := t.TempDir()
	c := newTailscaleClient(r, Outbound{TailscaleOptions: TailscaleOptions{TaildropDirectory: dir}})
	defer c.cancel()
	if e := c.startPeerAPI(); e != nil {
		t.Fatal(e)
	}
	defer c.peerAPI.close()
	if e := c.applyMap([]byte(`{"Node":{"User":1,"Addresses":["100.64.0.1/32"]},"Peers":[{"ID":2,"User":1,"Addresses":["100.64.0.2/32"]},{"ID":3,"User":2,"Addresses":["100.64.0.3/32"]}]}`)); e != nil {
		t.Fatal(e)
	}
	put := func(path, source, origin string, body io.Reader) int {
		req := httptest.NewRequest("PUT", path, body)
		req.RemoteAddr = source
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		c.peerAPI.ServeHTTP(w, req)
		return w.Code
	}
	if code := put("/v0/put/file.txt", "100.64.0.3:1234", "", strings.NewReader("other user")); code != http.StatusForbidden {
		t.Fatal(code)
	}
	if code := put("/v0/put/file.txt", "100.64.0.2:1234", "https://example.org", strings.NewReader("browser")); code != http.StatusForbidden {
		t.Fatal(code)
	}
	if code := put("/v0/put/%2e%2e%2foutside", "100.64.0.2:1234", "", strings.NewReader("escape")); code != http.StatusBadRequest {
		t.Fatal(code)
	}
	outside := filepath.Join(t.TempDir(), "untouched")
	if e := os.WriteFile(outside, []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(outside, filepath.Join(dir, "file.txt")); e != nil {
		t.Fatal(e)
	}
	if code := put("/v0/put/file.txt", "100.64.0.2:1234", "", strings.NewReader("new file")); code != http.StatusOK {
		t.Fatal(code)
	}
	if b, e := os.ReadFile(outside); e != nil || string(b) != "original" {
		t.Fatal("symlink escaped root", string(b), e)
	}
	if b, e := os.ReadFile(filepath.Join(dir, "file.txt (1)")); e != nil || string(b) != "new file" {
		t.Fatal(string(b), e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 2 {
		t.Fatal("temporary files leaked", entries, e)
	}
}

func TestTailscaleDirectWithoutDERP(t *testing.T) {
	url, decoder, input := startTSReference(t, false)
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir()}}}, Route: Route{Final: "ts"}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, e := r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	c := r.tailscaleClient("ts")
	var address string
	for deadline := time.Now().Add(3 * time.Second); ; {
		c.mu.Lock()
		for id, n := range c.nodes {
			if len(n.Endpoints) > 0 && len(n.Addresses) > 0 {
				n.HomeDERP = 0
				n.DERP = ""
				c.nodes[id] = n
				address = net.JoinHostPort(n.Addresses[0].Addr().String(), "8080")
			}
		}
		c.mu.Unlock()
		if address != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing direct endpoints")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, e := r.Dial(ctx, "tcp", address)
	if e != nil {
		t.Fatal("first direct-only connection", e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = conn.Write([]byte("first")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 5)
	if _, e = io.ReadFull(conn, b); e != nil || string(b) != "first" {
		t.Fatal(string(b), e)
	}
	c.mu.Lock()
	var node tsNode
	for _, n := range c.nodes {
		node = n
		break
	}
	self := c.self
	c.mu.Unlock()
	peer, e := c.peer(node)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range node.Addresses {
		kind, reply := byte(8), byte(0)
		if a.Addr().Is6() {
			kind, reply = 128, 129
		}
		response, e := peer.wg.stack.exchangeICMP(ctx, a.Addr(), []byte{kind, 0, 0, 0, 0, 3, 0, 1}, 64)
		if e != nil || len(response.data) < 8 || response.data[0] != reply {
			t.Fatal("outbound ICMP", a, response, e)
		}
	}
	for _, a := range self.Addresses {
		if e := json.NewEncoder(input).Encode(map[string]string{"op": "ping", "address": a.Addr().String()}); e != nil {
			t.Fatal(e)
		}
		var result struct {
			OK    bool
			Error string
		}
		if e := decoder.Decode(&result); e != nil || !result.OK {
			t.Fatal("inbound ICMP", a, result, e)
		}
	}
}

func TestTailscaleExpiryClosesSessions(t *testing.T) {
	r := newTestRuntime(t, Config{})
	private, public := wgTestKey(t)
	c := newTailscaleClient(r, Outbound{})
	defer c.cancel()
	p, e := newWGPeer(r, []string{private}, public, "", []string{"100.64.0.1/32"}, nil, "", 1280, 0)
	if e != nil {
		t.Fatal(e)
	}
	peer := &tsPeer{id: 2, key: "peer", wg: p, indices: [3]uint32{7, 0, 0}}
	c.peers["peer"] = peer
	c.indices[7] = peer
	c.nodes[2] = tsNode{ID: 2, KeyExpiry: time.Now().Add(-time.Second)}
	c.expirePeers(time.Now())
	if len(c.peers) != 0 || len(c.indices) != 0 {
		t.Fatal("expired peer remains indexed")
	}
	select {
	case <-p.done:
	default:
		t.Fatal("expired session still running")
	}
}

func TestTailscaleSelectedExitSourceOwnership(t *testing.T) {
	r := newTestRuntime(t, Config{})
	c := newTailscaleClient(r, Outbound{TailscaleOptions: TailscaleOptions{ExitNode: "exit-b"}})
	defer c.cancel()
	if e := c.applyMap([]byte(`{"Peers":[{"ID":1,"Name":"exit-a.test.","Addresses":["100.64.0.2/32"],"AllowedIPs":["0.0.0.0/0","::/0","10.0.0.0/8"]},{"ID":2,"Name":"exit-b.test.","Addresses":["100.64.0.3/32","fd7a:115c:a1e0::3/128"],"AllowedIPs":["0.0.0.0/0","::/0"]}]}`)); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{"8.8.8.8", "10.1.2.3", "2001:db8::5"} {
		ip := netip.MustParseAddr(raw)
		node, e := c.choose(ip)
		if e != nil || node.ID != 2 || !c.ownsSource(2, ip) || c.ownsSource(1, ip) {
			t.Fatal("selected exit rejected or another exit accepted", raw, node.ID, e)
		}
	}
	c.o.AcceptRoutes = true
	if e := c.applyMap([]byte(`{}`)); e != nil {
		t.Fatal(e)
	}
	if !c.ownsSource(1, netip.MustParseAddr("10.1.2.3")) || c.ownsSource(2, netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("accepted subnet did not override default")
	}
	c.mu.Lock()
	expired := c.nodes[1]
	expired.KeyExpiry = time.Now().Add(-time.Second)
	c.nodes[1] = expired
	c.mu.Unlock()
	if !c.ownsSource(2, netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expired subnet route blocked selected exit")
	}
	c.o.ExitNode = "fd7a:115c:a1e0:0:0:0:0:3"
	if node, e := c.choose(netip.MustParseAddr("8.8.8.8")); e != nil || node.ID != 2 {
		t.Fatal("expanded IPv6 exit address", node, e)
	}
}

func TestTailscaleClearedAddresses(t *testing.T) {
	r := newTestRuntime(t, Config{})
	c := newTailscaleClient(r, Outbound{})
	c.once.Do(func() { close(c.done) })
	c.readyOnce.Do(func() { close(c.ready) })
	r.tailscaleClients["revoked"] = c
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, e := r.TailscaleStatus(ctx, "revoked"); !errors.Is(e, errTSNoAddresses) {
		t.Fatal("revoked endpoint reports ready", e)
	}
	if _, e := r.TailscaleAuthURL(ctx, "revoked"); !errors.Is(e, errTSNoAddresses) {
		t.Fatal("login API spins after address revocation", e)
	}
}

func TestTailscaleRevokedStackRejectsNewFlow(t *testing.T) {
	r := newTestRuntime(t, Config{})
	done := make(chan struct{})
	stack := newIPStack(&ipEndpoint{runtime: r, inbound: "ts", done: done})
	stack.peer.acceptPacket = func(tunPacket) bool { close(done); stack.close(); return true }
	segment := make([]byte, 20)
	binary.BigEndian.PutUint16(segment, 12345)
	binary.BigEndian.PutUint16(segment[2:], 23456)
	segment[12], segment[13] = 0x50, 2
	packet := makeWGIP(netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1"), 6, segment)
	p, e := parseTunPacket(packet)
	if e != nil {
		t.Fatal(e)
	}
	binary.BigEndian.PutUint16(packet[p.header+16:], transportChecksum(p, segment))
	stack.input(p)
	stack.mu.Lock()
	n := len(stack.tcp)
	stack.mu.Unlock()
	if n != 0 {
		t.Fatal("flow created after revocation")
	}
}

func TestTailscaleRekeyKeepsActiveIndices(t *testing.T) {
	r := newTestRuntime(t, Config{})
	c := newTailscaleClient(r, Outbound{Tag: "ts", TailscaleOptions: TailscaleOptions{StateDirectory: t.TempDir()}})
	defer c.cancel()
	if e := c.loadState(); e != nil {
		t.Fatal(e)
	}
	defer c.lock.Close()
	server, e := ecdh.X25519().GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	node := tsNode{ID: 2, Key: tsKeyName(server, "nodekey"), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
	nodes := []tsNode{node}
	b, _ := json.Marshal(tsMap{Node: &tsNode{Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}, Peers: &nodes})
	if e = c.applyMap(b); e != nil {
		t.Fatal(e)
	}
	p, e := c.peer(node)
	if e != nil {
		t.Fatal(e)
	}
	defer p.wg.close()
	var old uint32
	rekey, dropped := false, 0
	p.wg.sender = func(b []byte, _ net.Addr) error {
		if binary.LittleEndian.Uint32(b) != 1 {
			return nil
		}
		index := binary.LittleEndian.Uint32(b[4:])
		c.mu.Lock()
		mapped := c.indices[index] == p
		kept := old == 0 || c.indices[old] == p
		count := len(c.indices)
		c.mu.Unlock()
		if !mapped || !kept || count > 3 {
			return errors.New("WireGuard rekey lost active index or leaked pending indices")
		}
		if rekey && dropped < 3 {
			dropped++
			return nil
		}
		pub, _, ck, h, e := wgReadInitiation(server, b)
		if e != nil {
			return e
		}
		reply, _, e := wgRespond(server, pub, make([]byte, 32), ck, h, b)
		if e != nil {
			return e
		}
		p.wg.handle(reply, p.addr)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if e = p.wg.ensure(ctx); e != nil {
		t.Fatal(e)
	}
	p.wg.mu.Lock()
	old = p.wg.current.local
	p.wg.current.at = time.Now().Add(-121 * time.Second)
	p.wg.mu.Unlock()
	rekey = true
	if e = p.wg.ensure(ctx); e != nil {
		t.Fatal(e)
	}
	c.mu.Lock()
	count := len(c.indices)
	kept := c.indices[old] == p
	c.mu.Unlock()
	if dropped != 3 || count != 2 || !kept {
		t.Fatal("rekey index lifecycle", dropped, count, kept)
	}
	other := &tsPeer{}
	c.mu.Lock()
	c.indices[7] = other
	c.mu.Unlock()
	if e = p.syncIndices(7, 0, 0); e == nil {
		t.Fatal("index collision accepted")
	}
	c.mu.Lock()
	delete(c.indices, 7)
	expired := c.nodes[2]
	expired.Expired = true
	c.nodes[2] = expired
	c.mu.Unlock()
	c.expirePeers(time.Now())
	if len(c.indices) != 0 {
		t.Fatal("revoked peer retained indices")
	}
}
