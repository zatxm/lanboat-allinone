package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestTailscaleRelayReference(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_TAILSCALE")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_TAILSCALE required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(os.Environ(), "LANBOAT_TS_RELAY_ORACLE=1")
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	stdin, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Log(stderr.String())
		}
	}()
	dec := json.NewDecoder(stdout)
	var hello struct{ Keys []string }
	if e = dec.Decode(&hello); e != nil {
		t.Fatal(e)
	}
	var keys [2][32]byte
	for i, k := range hello.Keys {
		b, e := hex.DecodeString(strings.TrimPrefix(k, "discokey:"))
		if e != nil || len(b) != 32 {
			t.Fatal(k, e)
		}
		copy(keys[i][:], b)
	}
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	c := newTailscaleClient(r, Outbound{Tag: "relay", TailscaleOptions: TailscaleOptions{RelayServerStaticEndpoints: []string{"127.0.0.1:1"}}})
	defer c.cancel()
	c.discoKey, _ = ecdh.X25519().GenerateKey(rand.Reader)
	if e = c.applyMap([]byte(`{"Node":{"Addresses":["100.64.0.1/32"]},"Peers":[{"ID":1,"DiscoKey":"` + hello.Keys[0] + `","Addresses":["100.64.0.2/32"]}],"PacketFilter":[{"SrcIPs":["100.64.0.2"],"CapGrant":[{"Dsts":["100.64.0.1/32"],"Caps":["tailscale.com/cap/relay"]}]}]}`)); e != nil {
		t.Fatal(e)
	}
	if e = c.startRelay(); e != nil {
		t.Fatal(e)
	}
	defer c.relay.close()
	allocation, e := c.relay.allocate(keys, 1)
	if e != nil {
		t.Fatal(e)
	}
	endpoint := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(c.relay.udp.LocalAddr().(*net.UDPAddr).Port))
	if e = json.NewEncoder(stdin).Encode(map[string]any{"server": tsKeyName(c.relay.disco, "discokey"), "vni": allocation.vni, "address": endpoint, "description": c.relay.description(allocation)}); e != nil {
		t.Fatal(e)
	}
	var reply struct{ OK bool }
	if e = dec.Decode(&reply); e != nil || !reply.OK {
		t.Fatal(reply, e)
	}
	c.relay.mu.Lock()
	state := *c.relay.allocations[allocation.vni]
	c.relay.mu.Unlock()
	if !state.endpoints[0].IsValid() || !state.endpoints[1].IsValid() {
		t.Fatal("relay not bound", state)
	}
	if e = c.applyMap([]byte(`{"PacketFilter":[]}`)); e != nil {
		t.Fatal(e)
	}
	packet := tsGeneve(allocation.vni, false, make([]byte, 32))
	packet[8] = 4
	c.relay.receive(packet, state.endpoints[0])
	c.relay.mu.Lock()
	_, ok := c.relay.allocations[allocation.vni]
	c.relay.mu.Unlock()
	if ok {
		t.Fatal("revoked relay remained usable")
	}
}

func TestTailscaleRelayAuthorization(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}})
	c := newTailscaleClient(r, Outbound{})
	defer c.cancel()
	c.discoKey, _ = ecdh.X25519().GenerateKey(rand.Reader)
	c.relay = &tsRelayServer{c: c, allocations: map[uint32]*tsRelayAllocation{}}
	var keys [2][32]byte
	rand.Read(keys[0][:])
	rand.Read(keys[1][:])
	for _, k := range [][2][32]byte{{}, {keys[0], keys[0]}, {keys[0], {}}} {
		if _, e := c.relay.allocate(k, 1); e == nil {
			t.Fatal("bad keys accepted")
		}
	}
	n := tsNode{ID: 1, Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}}
	c.nodes[1] = n
	if c.relay.authorized(n) {
		t.Fatal("allocation without grant allowed")
	}
	for i := range 64 {
		keys[1][0] = byte(i)
		if _, e := c.relay.allocate(keys, 1); e != nil {
			t.Fatal(i, e)
		}
	}
	keys[1][0] = 65
	if _, e := c.relay.allocate(keys, 1); e == nil {
		t.Fatal("per-owner limit not enforced")
	}
}

func TestTailscaleRelayIdle(t *testing.T) {
	now := time.Now()
	a := tsRelayAllocation{endpoints: [2]netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1"), netip.MustParseAddrPort("127.0.0.1:2")}, last: [2]time.Time{now, now.Add(-time.Minute)}}
	a.touch(0)
	if time.Until(a.expires) > time.Second {
		t.Fatal("one-way traffic extended both sides of relay", a.expires)
	}
	a.touch(1)
	if time.Until(a.expires) < 59*time.Second {
		t.Fatal("bidirectional activity did not refresh allocation")
	}
}
