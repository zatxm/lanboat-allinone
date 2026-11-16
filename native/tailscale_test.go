package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTailscaleBoxOracle(t *testing.T) {
	type row struct{ Private, Public, Box, Plain string }
	var rows []row
	for _, size := range []int{0, 1, 31, 32, 33, 64, 1280, 65535} {
		a, _ := ecdh.X25519().GenerateKey(rand.Reader)
		b, _ := ecdh.X25519().GenerateKey(rand.Reader)
		key, e := tsBoxKey(a, b.PublicKey().Bytes())
		if e != nil {
			t.Fatal(e)
		}
		plain := make([]byte, size)
		rand.Read(plain)
		box := tsBoxSeal(key, plain)
		got, e := tsBoxOpen(key, box)
		if e != nil || !bytes.Equal(got, plain) {
			t.Fatal("box roundtrip", e)
		}
		box[len(box)-1] ^= 1
		if _, e = tsBoxOpen(key, box); e == nil {
			t.Fatal("box forgery accepted")
		}
		box[len(box)-1] ^= 1
		rows = append(rows, row{hex.EncodeToString(a.Bytes()), hex.EncodeToString(b.PublicKey().Bytes()), hex.EncodeToString(box), hex.EncodeToString(plain)})
	}
	program := `import ctypes,ctypes.util,json,sys
l=ctypes.CDLL(ctypes.util.find_library('sodium'));l.sodium_init()
l.crypto_box_beforenm.argtypes=[ctypes.c_void_p]*3
l.crypto_secretbox_open_easy.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ulonglong,ctypes.c_void_p,ctypes.c_void_p]
for r in json.load(sys.stdin):
 k=ctypes.create_string_buffer(32);assert l.crypto_box_beforenm(k,bytes.fromhex(r['Public']),bytes.fromhex(r['Private']))==0
 b=bytes.fromhex(r['Box']);out=ctypes.create_string_buffer(max(1,len(b)-40))
 assert l.crypto_secretbox_open_easy(out,b[24:],len(b)-24,b[:24],k)==0
 assert out.raw[:len(b)-40].hex()==r['Plain']
print('libsodium NaCl box vectors passed')`
	b, _ := json.Marshal(rows)
	cmd := exec.Command("python3", "-c", program)
	cmd.Stdin = bytes.NewReader(b)
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("NaCl external oracle: %v %s", e, out)
	}
}

func TestTailscaleConfig(t *testing.T) {
	for _, field := range []string{`"control_url":"http://example.com"`, `"control_url":"https://u:p@example.com"`, `"control_url":"https://example.com?q=1"`, `"server":"host"`, `"detour":"direct"`, `"mtu":1280`} {
		_, e := Parse([]byte(`{"endpoints":[{"type":"tailscale","tag":"ts",` + field + `}],"route":{"final":"ts"}}`))
		if e == nil {
			t.Fatal("accepted", field)
		}
	}
	_, e := Parse([]byte(`{"endpoints":[{"type":"tailscale","tag":"ts","auth_key":"test","control_url":"http://127.0.0.1:1234","exit_node":"exit","force_derp":true,"accept_routes":true}],"route":{"final":"ts"}}`))
	if e != nil {
		t.Fatal(e)
	}
}

func TestTailscaleRouting(t *testing.T) {
	c := &tailscaleClient{nodes: map[int64]tsNode{
		1: {ID: 1, Name: "one.test.", Key: "first", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		2: {ID: 2, Name: "exit.test.", StableID: "exit-stable", Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}},
	}}
	ip := netip.MustParseAddr("192.0.2.5")
	if _, e := c.choose(ip); e == nil {
		t.Fatal("subnet accepted while disabled")
	}
	c.o.AcceptRoutes = true
	if n, e := c.choose(ip); e != nil || n.ID != 1 {
		t.Fatal("subnet route", n, e)
	}
	if n, e := c.choose(netip.MustParseAddr("100.64.0.1")); e != nil || n.ID != 1 {
		t.Fatal("peer route", e)
	}
	if _, e := c.choose(netip.MustParseAddr("8.8.8.8")); e == nil {
		t.Fatal("implicit exit node")
	}
	for _, exit := range []string{"exit-stable", "exit", "exit.test.", "100.64.0.2"} {
		c.o.ExitNode = exit
		if n, e := c.choose(netip.MustParseAddr("8.8.8.8")); e != nil || n.ID != 2 {
			t.Fatal(exit, n, e)
		}
	}
	n := c.nodes[2]
	n.AllowedIPs = nil
	c.nodes[2] = n
	if _, e := c.choose(netip.MustParseAddr("8.8.8.8")); e == nil {
		t.Fatal("unapproved exit route")
	}
}

func TestTailscaleState(t *testing.T) {
	dir := t.TempDir()
	o := Outbound{Tag: "ts", TailscaleOptions: TailscaleOptions{StateDirectory: dir}}
	c := &tailscaleClient{o: o}
	if e := c.loadState(); e != nil {
		t.Fatal(e)
	}
	d := &tailscaleClient{o: o}
	if e := d.loadState(); e == nil {
		d.lock.Close()
		t.Fatal("concurrent identity accepted")
	}
	want := slices.Clone(c.nodeKey.Bytes())
	c.lock.Close()
	if e := d.loadState(); e != nil {
		t.Fatal(e)
	}
	defer d.lock.Close()
	if !slices.Equal(want, d.nodeKey.Bytes()) {
		t.Fatal("identity changed across restart")
	}
	if mode, e := os.Stat(filepath.Join(dir, "state.json")); e != nil || mode.Mode().Perm()&0077 != 0 {
		t.Fatal("state permissions", mode, e)
	}
	d.lock.Close()
	d.o.ControlURL = "https://other.example"
	if e := d.loadState(); e == nil {
		t.Fatal("state crossed controller trust boundary")
	}
	if d.lock != nil {
		d.lock.Close()
	}
}

func TestTailscaleFailedStartStable(t *testing.T) {
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}})
	c := newTailscaleClient(r, Outbound{})
	c.fail(errTSAuth)
	c.cancel()
	r.tailscaleClients["failed"] = c
	defer c.close()
	for range 100 {
		if e := c.wait(context.Background()); !errors.Is(e, errTSAuth) {
			t.Fatal("lost terminal authentication error", e)
		}
		if _, e := r.TailscaleAuthURL(context.Background(), "failed"); !errors.Is(e, errTSAuth) {
			t.Fatal("login API lost terminal error", e)
		}
	}
}

func TestTailscaleNoiseRecords(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	a, _ := newChaChaAEAD(key, false)
	var wire bytes.Buffer
	w := &tsNoiseConn{Conn: memoryNetConn{bytes.NewReader(nil), &wire}, tx: a}
	want := bytes.Repeat([]byte("record-"), 2000)
	if n, e := w.Write(want); e != nil || n != len(want) {
		t.Fatal(n, e)
	}
	for _, data := range [][]byte{wire.Bytes(), append(slices.Clone(wire.Bytes()), 0)} {
		r := &tsNoiseConn{reader: bufio.NewReader(bytes.NewReader(data)), rx: a}
		got := make([]byte, len(want))
		if _, e := io.ReadFull(r, got); e != nil || !bytes.Equal(got, want) {
			t.Fatal("record stream", e)
		}
	}
	for _, data := range [][]byte{{4, 255, 255}, {1, 0, 16}, wire.Bytes()[:10], append([]byte{4, 0, 16}, make([]byte, 16)...)} {
		r := &tsNoiseConn{reader: bufio.NewReader(bytes.NewReader(data)), rx: a}
		buf := make([]byte, 1)
		if _, e := r.Read(buf); e == nil {
			t.Fatal("invalid record accepted")
		}
		if _, e := r.Read(buf); e == nil {
			t.Fatal("error was not sticky")
		}
	}
	var nonce [12]byte
	wire.Reset()
	payload := a.Seal(nil, nonce[:], []byte("first"), nil)
	frame := binary.BigEndian.AppendUint16([]byte{4}, uint16(len(payload)))
	frame = append(frame, payload...)
	r := &tsNoiseConn{reader: bufio.NewReader(bytes.NewReader(append(slices.Clone(frame), frame...))), rx: a}
	b := make([]byte, 5)
	if _, e := io.ReadFull(r, b); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Read(b); e == nil {
		t.Fatal("record replay accepted")
	}
}

func TestTailscaleMapChanges(t *testing.T) {
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}})
	c := newTailscaleClient(r, Outbound{})
	if e := c.applyMap([]byte(`{"Node":{"Addresses":["100.64.1.1/32"]},"Peers":[{"ID":1,"Name":"one","AllowedIPs":["192.0.2.0/24"]}]}`)); e != nil {
		t.Fatal(e)
	}
	if len(c.nodes) != 1 {
		t.Fatal("initial peer")
	}
	if e := c.applyMap([]byte(`{"PeersChangedPatch":[{"NodeID":1,"Endpoints":["192.0.2.2:1234"],"DERPRegion":9}],"PeersChanged":[{"ID":2,"Name":"two"}]}`)); e != nil {
		t.Fatal(e)
	}
	if len(c.nodes) != 2 || c.nodes[1].HomeDERP != 9 || len(c.nodes[1].Endpoints) != 1 {
		t.Fatal("incremental update")
	}
	if e := c.applyMap([]byte(`{"PeersRemoved":[1,2]}`)); e != nil {
		t.Fatal(e)
	}
	if len(c.nodes) != 0 {
		t.Fatal("revocation")
	}
	if e := c.applyMap([]byte(`{"PeersChanged":[{"ID":3}]}`)); e != nil {
		t.Fatal(e)
	}
	c.resetMap = true
	if e := c.applyMap([]byte(`{}`)); e != nil {
		t.Fatal(e)
	}
	if len(c.nodes) != 0 {
		t.Fatal("reconnected empty map retained revoked peers")
	}
	if e := c.applyMap([]byte(`{"TKAInfo":{"Head":"locked"}}`)); !errors.Is(e, errTSTailnetLock) {
		t.Fatal("unsigned locked tailnet accepted", e)
	}
	c.cancel()
}

func TestTailscaleIPv6DatagramLimit(t *testing.T) {
	key := bytes.Repeat([]byte{3}, 32)
	for _, size := range []int{2200, 60000, 65456, 65457} {
		p := &wgPeer{mtu: 1280, remote: streamAddr("test"), current: &wgTransport{send: key, remote: 7, confirmed: true, at: time.Now()}}
		var wire []byte
		p.sender = func(b []byte, _ net.Addr) error { wire = slices.Clone(b); return nil }
		packet := makeUDPPacket(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2"), 1, 2, bytes.Repeat([]byte{9}, size))
		err := tsSendIP(p, packet)
		if size > 65456 {
			if err == nil || wire != nil {
				t.Fatal("oversize sent")
			}
			continue
		}
		if err != nil || len(wire) > 65536 {
			t.Fatal(size, len(wire), err)
		}
		rx := &wgTransport{receive: key, local: 7, at: time.Now()}
		got, err := rx.open(wire)
		if err != nil || !bytes.Equal(got, packet) {
			t.Fatal("complete datagram", size, err)
		}
	}
}

func TestTailscaleSTUN(t *testing.T) {
	id := [12]byte{1, 2, 3}
	c := &tailscaleClient{stun: map[[12]byte]time.Time{id: time.Now()}, stunChanged: make(chan struct{}, 1)}
	b := []byte{1, 1, 0, 12, 0x21, 0x12, 0xa4, 0x42}
	b = append(b, id[:]...)
	b = append(b, 0, 0x20, 0, 8, 0, 1)
	b = binary.BigEndian.AppendUint16(b, 54321^0x2112)
	ip := [4]byte{203, 0, 113, 1}
	for i, v := range ip {
		b = append(b, v^[]byte{0x21, 0x12, 0xa4, 0x42}[i])
	}
	forged := slices.Clone(b)
	forged[8] ^= 1
	c.handleSTUN(forged, netip.AddrPort{})
	if len(c.endpoints) != 0 {
		t.Fatal("unrequested STUN accepted")
	}
	c.handleSTUN(b, netip.AddrPort{})
	want := netip.MustParseAddrPort("203.0.113.1:54321")
	if len(c.endpoints) != 1 || c.endpoints[0] != want {
		t.Fatal("XOR-MAPPED-ADDRESS", c.endpoints)
	}
	c.handleSTUN(b, netip.AddrPort{})
	if len(c.endpoints) != 1 {
		t.Fatal("STUN replay changed state")
	}
}

func FuzzTailscaleBox(f *testing.F) {
	key := [32]byte{9}
	for _, b := range [][]byte{nil, make([]byte, 39), make([]byte, 40), tsBoxSeal(key, []byte("disco"))} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		plain, e := tsBoxOpen(key, b)
		if e == nil {
			if len(plain) != len(b)-40 {
				t.Fatal("invalid plaintext size")
			}
		}
	})
}

func TestTailscaleOfficial(t *testing.T) {
	binary := os.Getenv("LANBOAT_TEST_TAILSCALE")
	if binary == "" {
		t.Fatal("LANBOAT_TEST_TAILSCALE must name the separately built official Tailscale test reference")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = append(os.Environ(), "TS_DISABLE_LOGTAIL=true")
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
	defer log.Close()
	cmd.Stderr = log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(logname)
			t.Log(string(b))
		}
	})
	var fixture struct {
		ControlURL string   `json:"control_url"`
		IP         string   `json:"ip"`
		IPs        []string `json:"ips"`
	}
	if e = json.NewDecoder(bufio.NewReader(stdout)).Decode(&fixture); e != nil {
		t.Fatal(e)
	}
	for _, force := range []bool{true, false} {
		t.Run(map[bool]string{true: "DERP", false: "Direct"}[force], func(t *testing.T) {
			cfg := Config{Log: LogOptions{Disabled: true}, Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: fixture.ControlURL, StateDirectory: t.TempDir(), TaildropDirectory: t.TempDir(), Hostname: "lanboat", ForceDERP: force}}}, Route: Route{Final: "ts"}}
			b, _ := json.Marshal(cfg)
			r, e := New(ctx, b, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			if e = r.Start(); e != nil {
				t.Fatal(e)
			}
			callCtx, stop := context.WithTimeout(ctx, 15*time.Second)
			defer stop()
			status, e := r.TailscaleStatus(callCtx, "ts")
			if e != nil {
				t.Fatal(e)
			}
			if len(status.Addresses) == 0 {
				t.Fatal("missing address")
			}
			c := r.tailscaleClients["ts"]
			for deadline := time.Now().Add(10 * time.Second); ; {
				c.mu.Lock()
				count := len(c.nodes)
				c.mu.Unlock()
				if count > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("no reference peer")
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, network := range []string{"tcp", "udp"} {
				port := "8080"
				if network == "udp" {
					port = "8081"
				}
				for _, host := range append(slices.Clone(fixture.IPs), "reference") {
					conn, e := r.Dial(callCtx, network, net.JoinHostPort(host, port))
					if e != nil {
						t.Fatal(network, host, e)
					}
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					sizes := []int{2200}
					if network == "udp" {
						sizes = []int{1, 1200, 2200, 60000}
						if force {
							sizes = []int{1, 1200, 2200, 14000}
						}
					}
					for _, size := range sizes {
						payload := bytes.Repeat([]byte{byte(size)}, size)
						if network == "tcp" {
							go writeAll(conn, payload)
						} else {
							// UDP may drop a fragmented datagram during a relay burst.
							matched := false
							for attempt := 0; attempt < 3; attempt++ {
								conn.SetDeadline(time.Now().Add(2 * time.Second))
								if _, e = conn.Write(payload); e != nil {
									t.Fatal(e)
								}
								got := make([]byte, 65535)
								n := 0
								n, e = conn.Read(got)
								if e == nil && bytes.Equal(got[:n], payload) {
									matched = true
									break
								}
							}
							if !matched {
								c.mu.Lock()
								for _, p := range c.peers {
									p.wg.stack.mu.Lock()
									for k, f := range p.wg.stack.fragments {
										t.Logf("fragments %v total=%d received=%d count=%d", k, f.total, f.received, len(f.parts))
									}
									p.wg.stack.mu.Unlock()
								}
								c.mu.Unlock()
								t.Fatal(network, host, size, "UDP echo after three attempts", e)
							}
							continue
						}
						got := make([]byte, len(payload))
						_, e = io.ReadFull(conn, got)
						if e != nil || !bytes.Equal(got, payload) {
							t.Fatal(network, host, size, "echo", e)
						}
					}
					conn.Close()
				}
			}
			if !force {
				deadline := time.Now().Add(5 * time.Second)
				for {
					found := false
					c.mu.Lock()
					for _, p := range c.peers {
						p.mu.Lock()
						found = found || p.direct.IsValid()
						p.mu.Unlock()
					}
					c.mu.Unlock()
					if found {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("no authenticated direct path")
					}
					time.Sleep(20 * time.Millisecond)
				}
			} else {
				c.mu.Lock()
				if len(c.endpoints) != 0 {
					t.Fatal("forced DERP advertised UDP endpoints")
				}
				for _, p := range c.peers {
					p.mu.Lock()
					bad := p.direct.IsValid() || len(p.probes) > 0
					p.mu.Unlock()
					if bad {
						t.Fatal("forced DERP used direct discovery")
					}
				}
				c.mu.Unlock()
			}
			// A subnet cannot leak into a normal peer route when accept_routes is false.
			if _, e = r.Dial(callCtx, "tcp", "192.0.2.5:8080"); e == nil {
				t.Fatal("disabled subnet accepted")
			}
			identity := slices.Clone(c.nodeKey.Bytes())
			r.Close()
			cfg.Endpoints[0].AcceptRoutes = true
			cfg.Endpoints[0].ExitNode = "reference"
			b, _ = json.Marshal(cfg)
			r, e = New(ctx, b, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			if e = r.Start(); e != nil {
				t.Fatal(e)
			}
			status, e = r.TailscaleStatus(callCtx, "ts")
			if e != nil {
				t.Fatal(e)
			}
			c = r.tailscaleClients["ts"]
			if !slices.Equal(identity, c.nodeKey.Bytes()) {
				t.Fatal("identity changed after restart")
			}
			for deadline := time.Now().Add(5 * time.Second); ; {
				c.mu.Lock()
				n := len(c.nodes)
				c.mu.Unlock()
				if n > 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("restart missing peers")
				}
				time.Sleep(10 * time.Millisecond)
			}
			echo := func(address string) {
				conn, e := r.Dial(callCtx, "tcp", address)
				if e != nil {
					t.Fatal(address, e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				go writeAll(conn, []byte("routed"))
				b := make([]byte, 6)
				_, e = io.ReadFull(conn, b)
				if e != nil || string(b) != "routed" {
					t.Fatal(address, "routed echo", e)
				}
			}
			echo("192.0.2.5:8080")
			echo("203.0.113.7:8080")
		})
	}
	t.Run("Authentication", func(t *testing.T) {
		cfg := Config{Log: LogOptions{Disabled: true}, Outbounds: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "wrong-secret", ControlURL: fixture.ControlURL, StateDirectory: t.TempDir(), TaildropDirectory: t.TempDir()}}}, Route: Route{Final: "ts"}}
		b, _ := json.Marshal(cfg)
		r, e := New(ctx, b, nil)
		if e != nil {
			t.Fatal(e)
		}
		defer r.Close()
		_, e = r.TailscaleStatus(ctx, "ts")
		if !errors.Is(e, errTSAuth) || strings.Contains(e.Error(), "wrong-secret") {
			t.Fatal("auth failure", e)
		}
	})
}
