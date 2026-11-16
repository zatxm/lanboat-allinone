package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/derp/derpserver"
	_ "tailscale.com/feature/relayserver"
	_ "tailscale.com/feature/taildrop"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsnet"
	"tailscale.com/tstest/integration/testcontrol"
	"tailscale.com/types/key"
)

func main() {
	if os.Getenv("LANBOAT_TS_CERTIFICATE") == "1" {
		certificateOracle()
		return
	}
	if os.Getenv("LANBOAT_TS_LOCK_NOISE") == "1" {
		lockNoiseOracle()
		return
	}
	if os.Getenv("LANBOAT_TS_LOCK_ORACLE") == "1" {
		lockOracle()
		return
	}
	if os.Getenv("LANBOAT_TS_RELAY_ORACLE") == "1" {
		relayOracle()
		return
	}
	log.SetOutput(os.Stderr)
	quiet := func(format string, args ...any) {
		if os.Getenv("LANBOAT_TS_DEBUG") == "1" {
			log.Printf(format, args...)
		}
	}
	d := derpserver.New(key.NewNode(), quiet)
	defer d.Close()
	ds := httptest.NewTLSServer(derpserver.Handler(d))
	defer ds.Close()
	_, port, _ := net.SplitHostPort(ds.Listener.Addr().String())
	dp, _ := strconv.Atoi(port)
	pin := sha256.Sum256(ds.Certificate().Raw)
	control := &testcontrol.Server{RequireAuthKey: "test-only-auth", AllNodesSameUser: true, MagicDNSDomain: "test.ts.net", Logf: quiet, DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1, RegionCode: "local", Nodes: []*tailcfg.DERPNode{{Name: "local", RegionID: 1, HostName: "127.0.0.1", DERPPort: dp, STUNPort: -1, CertName: "sha256-raw:" + hex.EncodeToString(pin[:])}}}}}}

	control.PeerRelayGrants = os.Getenv("LANBOAT_TS_RELAY") == "1"
	if os.Getenv("LANBOAT_TS_SSH") == "1" {
		u, e := user.Current()
		must(e)
		control.SSHPolicy = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{Principals: []*tailcfg.SSHPrincipal{{Any: true}}, SSHUsers: map[string]string{u.Username: u.Username}, Action: &tailcfg.SSHAction{Accept: true, AllowLocalPortForwarding: true, AllowRemotePortForwarding: true, AllowAgentForwarding: true}, AcceptEnv: []string{"LANG", "LC_*"}}}}
	}
	cs := httptest.NewServer(control)
	control.HTTPTestServer = cs
	defer cs.Close()
	if os.Getenv("LANBOAT_TS_INTERACTIVE") == "1" {
		control.RequireAuthKey = ""
		control.RequireAuth = true
		json.NewEncoder(os.Stdout).Encode(map[string]string{"control_url": cs.URL})
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": control.CompleteAuth(scanner.Text())})
		}
		return
	}
	dir, e := os.MkdirTemp("", "lanboat-ts-reference-")
	must(e)
	defer os.RemoveAll(dir)
	s := &tsnet.Server{Dir: dir, Hostname: "reference", AuthKey: "test-only-auth", ControlURL: cs.URL, Logf: quiet, UserLogf: quiet, Ephemeral: true}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	status, e := s.Up(ctx)
	must(e)
	if os.Getenv("LANBOAT_TS_DNS") == "1" {
		must(startDNSReference(s, status.TailscaleIPs))
	}
	routes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	lc, e := s.LocalClient()
	must(e)
	_, e = lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AdvertiseRoutes: routes, RouteAll: true}, AdvertiseRoutesSet: true, RouteAllSet: true})
	must(e)
	var recording *sshRecordHarness
	if os.Getenv("LANBOAT_TS_RECORDING") == "1" {
		recording = &sshRecordHarness{}
		must(recording.start(s))
		defer recording.close()
	}
	var relay *tsnet.Server
	if os.Getenv("LANBOAT_TS_OFFICIAL_RELAY") == "1" {
		relayDir, e := os.MkdirTemp("", "lanboat-relay-reference-")
		must(e)
		defer os.RemoveAll(relayDir)
		relay = &tsnet.Server{Dir: relayDir, Hostname: "relay-reference", AuthKey: "test-only-auth", ControlURL: cs.URL, Logf: quiet, UserLogf: quiet, Ephemeral: true}
		defer relay.Close()
		_, e = relay.Up(ctx)
		must(e)
		rlc, e := relay.LocalClient()
		must(e)
		port := uint16(40017)
		_, e = rlc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{RelayServerPort: &port, RelayServerStaticEndpoints: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:40017")}}, RelayServerPortSet: true, RelayServerStaticEndpointsSet: true})
		must(e)
	}
	tcp, e := s.Listen("tcp", ":8080")
	must(e)
	defer tcp.Close()
	go echoTCP(tcp)
	var ips []string
	for _, ip := range status.TailscaleIPs {
		ips = append(ips, ip.String())
		udp, e := s.ListenPacket("udp", net.JoinHostPort(ip.String(), "8081"))
		must(e)
		defer udp.Close()
		go echoUDP(udp)
	}
	s.RegisterFallbackTCPHandler(func(_, dst netip.AddrPort) (func(net.Conn), bool) {
		if dst.Port() != 8080 {
			return nil, false
		}
		return func(c net.Conn) { defer c.Close(); io.Copy(c, c) }, true
	})
	for _, n := range control.AllNodes() {
		control.SetSubnetRoutes(n.Key, routes)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"control_url": cs.URL, "ip": status.TailscaleIPs[0].String(), "ips": ips, "tcp_port": 8080, "udp_port": 8081, "hostname": "reference"})
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "{") {
			var command struct {
				Op, Hostname, Network, Address, Data string
				Policy                               *tailcfg.SSHPolicy
				DNS                                  *tailcfg.DNSConfig
			}
			must(json.Unmarshal(scanner.Bytes(), &command))
			switch command.Op {
			case "dns-exit":
				// Deterministic DNS responder over real tsnet; no host DNS or WAN queries.
				var peer *tailcfg.Node
				for _, node := range control.AllNodes() {
					if node.Hostinfo.Hostname() == "reference" {
						peer = node.Clone()
						peer.AllowedIPs = append(peer.AllowedIPs, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
						info := peer.Hostinfo.AsStruct()
						info.Services = []tailcfg.Service{{Proto: "peerapi4", Port: 5354}, {Proto: "peerapi6", Port: 5354}}
						peer.Hostinfo = info.View()
					}
				}
				ok := false
				if peer != nil {
					for _, node := range control.AllNodes() {
						if node.Hostinfo.Hostname() == command.Hostname {
							ok = control.AddRawMapResponse(node.Key, &tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{peer}, DNSConfig: command.DNS}) || ok
						}
					}
				}
				json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": ok})
			case "dns":
				ok := false
				for _, node := range control.AllNodes() {
					if command.Hostname == "" || node.Hostinfo.Hostname() == command.Hostname {
						ok = control.AddRawMapResponse(node.Key, &tailcfg.MapResponse{DNSConfig: command.DNS}) || ok
					}
				}
				json.NewEncoder(os.Stdout).Encode(map[string]bool{"ok": ok})
			case "dns-query":
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				b, _, err := lc.QueryDNS(ctx, command.Address, command.Data)
				cancel()
				if err != nil {
					json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
				} else {
					json.NewEncoder(os.Stdout).Encode(map[string]any{"wire": b})
				}
			case "ssh-policy":
				control.SetSSHPolicy(command.Policy)
				fmt.Fprintln(os.Stdout, "{\"ok\":true}")
			case "recording-mode":
				if recording == nil {
					fmt.Fprintln(os.Stdout, "{\"error\":\"recording disabled\"}")
					break
				}
				recording.setMode(command.Data)
				fmt.Fprintln(os.Stdout, "{\"ok\":true}")
			case "recording-status":
				if recording == nil {
					fmt.Fprintln(os.Stdout, "{\"error\":\"recording disabled\"}")
					break
				}
				json.NewEncoder(os.Stdout).Encode(recording.snapshot())
			case "ssh-bridge":
				bridge, e := net.Listen("tcp", "127.0.0.1:0")
				must(e)
				defer bridge.Close()
				go func() {
					for {
						in, e := bridge.Accept()
						if e != nil {
							return
						}
						go func() {
							defer in.Close()
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
							out, e := s.Dial(ctx, "tcp", command.Address)
							cancel()
							if e != nil {
								return
							}
							defer out.Close()
							done := make(chan struct{})
							go func() {
								io.Copy(out, in)
								if close, ok := out.(interface{ CloseWrite() error }); ok {
									close.CloseWrite()
								}
								close(done)
							}()
							io.Copy(in, out)
							in.Close()
							out.Close()
							<-done
						}()
					}
				}()
				json.NewEncoder(os.Stdout).Encode(map[string]any{"address": bridge.Addr().String()})
			case "ssh-revoke":
				control.SetSSHPolicy(&tailcfg.SSHPolicy{})
				fmt.Fprintln(os.Stdout, `{"ok":true}`)
			case "approve":
				var approved []netip.Prefix
				for _, node := range control.AllNodes() {
					if node.Hostinfo.Hostname() == command.Hostname {
						approved = node.Hostinfo.RoutableIPs().AsSlice()
						control.SetSubnetRoutes(node.Key, approved)
						if slices.Contains(approved, netip.MustParsePrefix("0.0.0.0/0")) {
							ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
							_, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{ExitNodeID: node.StableID}, ExitNodeIDSet: true, AdvertiseRoutesSet: true})
							cancel()
							must(err)
						}
					}
				}
				json.NewEncoder(os.Stdout).Encode(map[string]any{"routes": approved})
			case "ping":
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				result, err := lc.Ping(ctx, netip.MustParseAddr(command.Address), tailcfg.PingICMP)
				cancel()
				if err != nil {
					json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
				} else {
					json.NewEncoder(os.Stdout).Encode(map[string]any{"error": result.Err, "ok": result.Err == ""})
				}
			case "push":
				var target tailcfg.StableNodeID
				for _, node := range control.AllNodes() {
					control.SetNodeCapMap(node.Key, tailcfg.NodeCapMap{nodecap.FileSharing: nil})
					if node.Hostinfo.Hostname() == command.Hostname {
						target = node.StableID
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
					targets, _ := lc.FileTargets(ctx)
					if slices.ContainsFunc(targets, func(t apitype.FileTarget) bool {
						return t.Node.StableID == target && t.Node.HomeDERP != 0
					}) {
						break
					}
					time.Sleep(20 * time.Millisecond)
				}
				err := lc.PushFile(ctx, target, int64(len(command.Data)), command.Address, strings.NewReader(command.Data))
				if err != nil {
					targets, te := lc.FileTargets(context.Background())
					b, _ := json.Marshal(targets)
					fmt.Fprintf(os.Stderr, "file targets: %s err=%v\n", b, te)
					for _, n := range control.AllNodes() {
						fmt.Fprintf(os.Stderr, "node %s services=%v\n", n.Name, n.Hostinfo.Services().AsSlice())
					}
				}
				cancel()
				if err != nil {
					json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
				} else {
					fmt.Fprintln(os.Stdout, `{"ok":true}`)
				}
			case "echo":
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				dialer := s.Sys().Dialer.Get()
				var target netip.AddrPort
				var err error
				for {
					var routed bool
					target, routed, err = dialer.UserDialPlan(ctx, command.Network, command.Address)
					if err != nil || routed {
						break
					}
					select {
					case <-ctx.Done():
						err = ctx.Err()
					case <-time.After(10 * time.Millisecond):
					}
					if err != nil {
						break
					}
				}
				var conn net.Conn
				if err == nil {
					// Use the public netstack entry points to forbid host fallback.
					if strings.HasPrefix(command.Network, "udp") {
						conn, err = dialer.NetstackDialUDP(ctx, target)
					} else {
						conn, err = dialer.NetstackDialTCP(ctx, target)
					}
				}
				if err == nil {
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					_, err = conn.Write([]byte(command.Data))
					if err == nil {
						got := make([]byte, len(command.Data))
						_, err = io.ReadFull(conn, got)
						if err == nil {
							json.NewEncoder(os.Stdout).Encode(map[string]string{"data": string(got)})
						}
					}
					conn.Close()
				}
				cancel()
				if err != nil {
					json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
				}
			default:
				fmt.Fprintln(os.Stdout, `{"error":"unknown command"}`)
			}
			continue
		}
		switch scanner.Text() {
		case "relay-status":
			if relay == nil {
				fmt.Fprintln(os.Stdout, `{"error":"relay disabled"}`)
				continue
			}
			rlc, e := relay.LocalClient()
			must(e)
			state, e := rlc.DebugPeerRelaySessions(context.Background())
			must(e)
			json.NewEncoder(os.Stdout).Encode(map[string]any{"derp_port": dp, "relay": state})
		case "nodes":
			json.NewEncoder(os.Stdout).Encode(control.AllNodes())
		case "no-routes":
			for _, n := range control.AllNodes() {
				if n.Name == "reference.test.ts.net." {
					control.SetSubnetRoutes(n.Key, nil)
				}
			}
			fmt.Fprintln(os.Stdout, `{"ok":true}`)
		case "expire":
			control.SetExpireAllNodes(true)
			fmt.Fprintln(os.Stdout, `{"ok":true}`)
		default:
			fmt.Fprintln(os.Stdout, `{"ok":false}`)
		}
	}
}

func must(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
func echoTCP(l net.Listener) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() { defer c.Close(); io.Copy(c, c) }()
	}
}
func echoUDP(p net.PacketConn) {
	b := make([]byte, 65535)
	for {
		n, a, e := p.ReadFrom(b)
		if e != nil {
			return
		}
		if wrote, err := p.WriteTo(b[:n], a); err != nil {
			fmt.Fprintf(os.Stderr, "UDP write %d/%d: %v\n", wrote, n, err)
		}
	}
}
