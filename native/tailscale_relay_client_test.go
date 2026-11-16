package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTailscalePeerRelayReference(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("isolated UDP firewall test needs Linux")
	}
	if os.Getenv("LANBOAT_TS_RELAY_NS") != "1" {
		bin, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command("unshare", "-Urn", bin, "-test.run=^TestTailscalePeerRelayReference$", "-test.v", "-test.timeout=50s")
		cmd.Env = append(os.Environ(), "LANBOAT_TS_RELAY_NS=1")
		b, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("isolated relay: %v\n%s", e, b)
		}
		t.Log(string(b))
		return
	}
	own, _ := os.Readlink("/proc/self/ns/net")
	initial, _ := os.Readlink("/proc/1/ns/net")
	if own == initial {
		t.Fatal("refusing firewall changes in initial network namespace")
	}
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "add", "relaytest0", "type", "dummy"}, {"addr", "add", "192.0.2.254/24", "dev", "relaytest0"}, {"link", "set", "relaytest0", "up"}, {"route", "add", "default", "dev", "relaytest0"}} {
		if b, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatal(e, string(b))
		}
	}
	t.Setenv("LANBOAT_TS_RELAY", "1")
	t.Setenv("LANBOAT_TS_OFFICIAL_RELAY", "1")
	url, decoder, input := startTSReference(t, false)
	nft := func(script string) {
		t.Helper()
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(e, string(b))
		}
	}
	nft("add table inet relaytest\nadd chain inet relaytest output { type filter hook output priority 0; policy accept; }\nadd rule inet relaytest output meta l4proto udp udp dport != 40017 udp sport != 40017 drop\n")
	r := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, Hostname: "native-relay-client", StateDirectory: t.TempDir()}}}, Route: Route{Final: "ts"}})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, e := r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	c := r.tailscaleClient("ts")
	var target tsNode
	for deadline := time.Now().Add(4 * time.Second); ; {
		c.mu.Lock()
		ready := false
		for _, node := range c.nodes {
			if node.Name == "reference.test.ts.net." {
				target = node
			}
			ready = ready || node.Hostinfo != nil && node.Hostinfo.PeerRelay
		}
		c.mu.Unlock()
		if ready && target.ID != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reference relay not advertised")
		}
		time.Sleep(10 * time.Millisecond)
	}
	peer, e := c.peer(target)
	if e != nil {
		t.Fatal(e)
	}
	echo := func(network string) {
		t.Helper()
		port := "8080"
		if network == "udp" {
			port = "8081"
		}
		conn, e := r.Dial(ctx, network, net.JoinHostPort(target.Addresses[0].Addr().String(), port))
		if e != nil {
			t.Fatal(network, e)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(4 * time.Second))
		payload := bytes.Repeat([]byte("peer-relay"), 100)
		if _, e = conn.Write(payload); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, len(payload))
		if _, e = io.ReadFull(conn, b); e != nil || !bytes.Equal(b, payload) {
			t.Fatal("relay echo", network, e)
		}
	}
	echo("tcp")
	for deadline := time.Now().Add(15 * time.Second); ; {
		peer.probe(target)
		path := peer.relay.Load()
		ready := false
		if path != nil {
			path.mu.Lock()
			ready = path.selected.IsValid()
			path.mu.Unlock()
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			c.mu.Lock()
			t.Logf("nodes=%+v pending=%+v paths=%d", c.nodes, c.relayRequests, len(c.relayPaths))
			c.mu.Unlock()
			if path != nil {
				path.mu.Lock()
				t.Logf("path=%+v candidates=%+v", path.description, path.candidates)
				path.mu.Unlock()
			}
			t.Fatal("relay path not confirmed")
		}
		time.Sleep(100 * time.Millisecond)
	}
	peer.mu.Lock()
	direct := peer.direct
	peer.mu.Unlock()
	if direct.IsValid() {
		t.Fatal("firewall test accidentally used direct path", direct)
	}
	io.WriteString(input, "relay-status\n")
	var status struct {
		DERPPort int `json:"derp_port"`
		Relay    struct {
			Sessions []struct {
				VNI              uint32
				Client1, Client2 struct{ PacketsTx uint64 }
			}
		}
	}
	if e = decoder.Decode(&status); e != nil {
		t.Fatal(e)
	}
	if status.DERPPort == 0 || len(status.Relay.Sessions) == 0 {
		t.Fatal("official relay has no allocation", status)
	}
	// Existing DERP sockets are blocked too: both request and response must now traverse the relay.
	nft("add rule inet relaytest output meta l4proto tcp tcp dport " + strconv.Itoa(status.DERPPort) + " drop\nadd rule inet relaytest output meta l4proto tcp tcp sport " + strconv.Itoa(status.DERPPort) + " drop\n")
	echo("tcp")
	echo("udp")
	io.WriteString(input, "relay-status\n")
	if e = decoder.Decode(&status); e != nil {
		t.Fatal(e)
	}
	active := false
	for _, session := range status.Relay.Sessions {
		active = active || session.Client1.PacketsTx > 0 && session.Client2.PacketsTx > 0
	}
	if !active {
		t.Fatal("official relay did not forward both directions", status)
	}
}

func TestTailscaleRelayDescriptionBounds(t *testing.T) {
	valid := tsRelayDescription{server: [32]byte{1}, clients: [2][32]byte{{2}, {3}}, lamport: 1, vni: 1, bind: time.Minute, idle: time.Minute, endpoints: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1234")}}.marshal()
	if _, e := tsParseRelayDescription(valid); e != nil {
		t.Fatal(e)
	}
	for _, n := range []int{0, 1, 123, 124, 141, len(valid) - 1} {
		if _, e := tsParseRelayDescription(valid[:n]); e == nil {
			t.Fatal("short description accepted", n)
		}
	}
	for _, offset := range []int{0, 32, 64, 96, 104, 108, 116, 140} {
		b := bytes.Clone(valid)
		size := 4
		if offset < 96 {
			size = 32
		} else if offset == 96 || offset == 108 || offset == 116 {
			size = 8
		} else if offset == 140 {
			size = 2
		}
		clear(b[offset : offset+size])
		if _, e := tsParseRelayDescription(b); e == nil {
			t.Fatal("invalid zero field accepted", offset)
		}
	}
	b := bytes.Clone(valid)
	binary.BigEndian.PutUint32(b[104:], 0x1000000)
	if _, e := tsParseRelayDescription(b); e == nil {
		t.Fatal("oversize VNI accepted")
	}
	b = bytes.Clone(valid)
	binary.BigEndian.PutUint64(b[116:], 1<<63)
	if _, e := tsParseRelayDescription(b); e == nil {
		t.Fatal("overflowed lifetime accepted")
	}
}
func TestTailscaleRelayClientBindingAndRevocation(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	c := newTailscaleClient(r, Outbound{Tag: "ts"})
	defer func() { c.cancel(); c.jobs.Wait() }()
	c.nodeKey, _ = ecdh.X25519().GenerateKey(rand.Reader)
	c.discoKey, _ = ecdh.X25519().GenerateKey(rand.Reader)
	relayKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	relayDisco, _ := ecdh.X25519().GenerateKey(rand.Reader)
	sessionDisco, _ := ecdh.X25519().GenerateKey(rand.Reader)
	peerKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	peerDisco, _ := ecdh.X25519().GenerateKey(rand.Reader)
	var e error
	c.udp, e = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer c.udp.Close()
	server, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer server.Close()
	ep := server.LocalAddr().(*net.UDPAddr).AddrPort()
	peer := tsNode{ID: 2, Key: tsKeyName(peerKey, "nodekey"), DiscoKey: tsKeyName(peerDisco, "discokey"), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
	relay := tsNode{ID: 3, Key: tsKeyName(relayKey, "nodekey"), DiscoKey: tsKeyName(relayDisco, "discokey"), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.3/32")}, Hostinfo: &tsHostinfo{PeerRelay: true}}
	filter := json.RawMessage("[{\"SrcIPs\":[\"100.64.0.1\"],\"CapGrant\":[{\"Dsts\":[\"100.64.0.3/32\"],\"Caps\":[\"tailscale.com/cap/relay-target\"]}]}]")
	m, _ := json.Marshal(map[string]any{"Node": tsNode{ID: 1, Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}}, "Peers": []tsNode{peer, relay}, "PacketFilter": filter})
	if e = c.applyMap(m); e != nil {
		t.Fatal(e)
	}
	p, e := c.peer(peer)
	if e != nil {
		t.Fatal(e)
	}
	defer p.wg.close()
	description := tsRelayDescription{server: [32]byte(sessionDisco.PublicKey().Bytes()), clients: [2][32]byte{[32]byte(c.discoKey.PublicKey().Bytes()), [32]byte(peerDisco.PublicKey().Bytes())}, lamport: 1, vni: 42, bind: time.Minute, idle: time.Minute, endpoints: []netip.AddrPort{ep}}
	c.relayRequests = map[uint32]tsRelayRequest{7: {peer: p, serverID: 3, serverKey: relay.Key, serverDisco: relay.DiscoKey, sent: time.Now()}}
	response := append(binary.BigEndian.AppendUint32([]byte{9, 0}, 7), description.marshal()...)
	c.receiveRelayDescription(relay, append(binary.BigEndian.AppendUint32([]byte{9, 0}, 8), description.marshal()...))
	if p.relay.Load() != nil {
		t.Fatal("unsolicited relay response accepted")
	}
	c.receiveRelayDescription(relay, response)
	current := p.relay.Load()
	if current == nil {
		t.Fatal("authorized relay response rejected")
	}
	box, e := tsBoxKey(sessionDisco, c.discoKey.PublicKey().Bytes())
	if e != nil {
		t.Fatal(e)
	}
	receive := func(control bool) []byte {
		t.Helper()
		b := make([]byte, 2048)
		server.SetReadDeadline(time.Now().Add(time.Second))
		n, _, e := server.ReadFromUDPAddrPort(b)
		if e != nil {
			t.Fatal(e)
		}
		b = b[:n]
		if len(b) < 86 || binary.BigEndian.Uint16(b[2:]) != 0x7a11 || (b[1] == 0x80) != control {
			t.Fatal("invalid disco Geneve framing")
		}
		if !control {
			return b
		}
		m, e := tsBoxOpen(box, b[46:])
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	bind := receive(true)
	if len(bind) != 74 || bind[0] != 4 {
		t.Fatal("expected bind", bind)
	}
	challenge := bytes.Clone(bind)
	challenge[0] = 5
	copy(challenge[42:], bytes.Repeat([]byte{3}, 32))
	wire := append([]byte("TS💬"), sessionDisco.PublicKey().Bytes()...)
	wire = append(wire, tsBoxSeal(box, challenge)...)
	c.receiveRelay(tsGeneve(description.vni, true, wire), ep)
	if answer := receive(true); answer[0] != 6 || !bytes.Equal(answer[42:], challenge[42:]) {
		t.Fatal("wrong relay answer")
	}
	receive(false)
	// Drop that answer; an unverified path must still retry binding.
	current.mu.Lock()
	current.probeAt = time.Now().Add(-4 * time.Second)
	current.mu.Unlock()
	current.probe()
	if retry := receive(true); retry[0] != 4 {
		t.Fatal("lost binding answer did not retry")
	}
	for range 32 {
		c.receiveRelay(tsGeneve(description.vni, true, wire), ep)
	}
	current.mu.Lock()
	probes := len(current.probes)
	current.mu.Unlock()
	if probes > 1 {
		t.Fatal("duplicate challenges bypassed probe rate limit", probes)
	}
	if e = c.applyMap([]byte("{\"PacketFilter\":[]}")); e != nil {
		t.Fatal(e)
	}
	if p.relay.Load() != nil || len(c.relayPaths) != 0 || len(c.relayRequests) != 0 {
		t.Fatal("revoked relay survived")
	}
	c.o.ForceDERP = true
	c.receiveRelayDescription(peer, append([]byte{7, 0}, description.marshal()...))
	if p.relay.Load() != nil {
		t.Fatal("force_derp accepted relay invitation")
	}
}
