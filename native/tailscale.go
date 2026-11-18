package native

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type TailscaleOptions struct {
	SSHServer                  TailscaleSSHOptions `json:"ssh_server,omitempty"`
	RelayServerPort            uint16              `json:"relay_server_port,omitempty"`
	RelayServerStaticEndpoints []string            `json:"relay_server_static_endpoints,omitempty"`
	SystemInterface            bool                `json:"system_interface,omitempty"`
	SystemInterfaceName        string              `json:"system_interface_name,omitempty"`
	SystemInterfaceMTU         int                 `json:"system_interface_mtu,omitempty"`
	AuthKey                    string              `json:"auth_key,omitempty"`
	ControlURL                 string              `json:"control_url,omitempty"`
	ExitNode                   string              `json:"exit_node,omitempty"`
	ForceDERP                  bool                `json:"force_derp,omitempty"`
	AcceptRoutes               bool                `json:"accept_routes,omitempty"`
	StateDirectory             string              `json:"state_directory,omitempty"`
	Hostname                   string              `json:"hostname,omitempty"`
	Ephemeral                  bool                `json:"ephemeral,omitempty"`
	ListenPort                 uint16              `json:"listen_port,omitempty"`
	ExitNodeAllowLANAccess     bool                `json:"exit_node_allow_lan_access,omitempty"`
	AdvertiseRoutes            []string            `json:"advertise_routes,omitempty"`
	AdvertiseExitNode          bool                `json:"advertise_exit_node,omitempty"`
	AdvertiseTags              []string            `json:"advertise_tags,omitempty"`
	UDPTimeout                 string              `json:"udp_timeout,omitempty"`
	OnDemand                   bool                `json:"on_demand,omitempty"`
	TaildropDirectory          string              `json:"taildrop_directory,omitempty"`
}

func (o TailscaleOptions) empty() bool {
	if o.SSHServer != (TailscaleSSHOptions{}) {
		return false
	}
	return o.AuthKey == "" && o.ControlURL == "" && o.ExitNode == "" && !o.ForceDERP && !o.AcceptRoutes && o.StateDirectory == "" && o.Hostname == "" && !o.Ephemeral && o.ListenPort == 0 && !o.ExitNodeAllowLANAccess && len(o.AdvertiseRoutes) == 0 && !o.AdvertiseExitNode && len(o.AdvertiseTags) == 0 && o.UDPTimeout == "" && !o.OnDemand && o.TaildropDirectory == "" && o.RelayServerPort == 0 && len(o.RelayServerStaticEndpoints) == 0 && !o.SystemInterface && o.SystemInterfaceName == "" && o.SystemInterfaceMTU == 0
}

func (o TailscaleOptions) validate(out Outbound) error {
	if out.Inet4BindAddress != "" && out.Inet6BindAddress != "" {
		return errors.New("Tailscale's shared UDP socket accepts one local bind address")
	}
	if o.SSHServer.Enabled && !tsSSHPlatform() {
		return errors.New("Tailscale SSH server requires Linux or macOS")
	}
	if !o.SSHServer.Enabled && (o.SSHServer.DisablePTY || o.SSHServer.DisableSFTP || o.SSHServer.DisableForwarding) {
		return errors.New("Tailscale SSH options require ssh_server.enabled")
	}
	u, err := url.Parse(o.controlURL())
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && u.Scheme != "http" {
		return errors.New("Tailscale control_url must be an HTTP(S) URL without credentials, query or fragment")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return errors.New("Tailscale control_url requires HTTPS outside loopback")
	}
	if out.Server != "" || out.ServerPort != 0 || out.Transport.Type != "" || out.MTU != 0 {
		return errors.New("Tailscale uses control_url and its own WireGuard/DERP transport, not server/transport/mtu")
	}
	if len(o.RelayServerStaticEndpoints) > 64 {
		return errors.New("too many relay_server_static_endpoints")
	}
	if len(o.AuthKey) > 4096 || strings.ContainsAny(o.AuthKey, "\r\n") || len(o.Hostname) > 253 || strings.ContainsAny(o.Hostname, "\r\n\x00") {
		return errors.New("invalid Tailscale auth_key or hostname")
	}
	if _, err = optionDuration(o.UDPTimeout, 5*time.Minute); err != nil {
		return err
	}
	for _, raw := range o.RelayServerStaticEndpoints {
		addr, e := netip.ParseAddrPort(raw)
		if e != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() {
			return errors.New("invalid Tailscale relay_server_static_endpoints")
		}
	}
	if o.RelayServerPort == 0 && len(o.RelayServerStaticEndpoints) > 0 {
		return errors.New("relay_server_static_endpoints requires relay_server_port")
	}
	if o.SystemInterfaceMTU != 0 && (o.SystemInterfaceMTU < 1280 || o.SystemInterfaceMTU > 65504) {
		return errors.New("Tailscale system_interface_mtu must be 1280-65504")
	}
	if !o.SystemInterface && (o.SystemInterfaceName != "" || o.SystemInterfaceMTU != 0) {
		return errors.New("Tailscale interface options require system_interface")
	}
	if o.SystemInterface {
		if err = validateTUNPlatform(Inbound{InterfaceName: o.SystemInterfaceName}); err != nil {
			return err
		}
	}
	for _, raw := range o.AdvertiseRoutes {
		p, e := netip.ParsePrefix(raw)
		if e != nil || p.Addr().Is4In6() || p.Addr().IsMulticast() || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
			return errors.New("invalid Tailscale advertise_routes prefix")
		}
	}
	for _, tag := range o.AdvertiseTags {
		if !strings.HasPrefix(tag, "tag:") || len(tag) < 5 || tag[4] < 'a' || tag[4] > 'z' {
			return errors.New("invalid Tailscale advertise_tags tag")
		}
		for _, ch := range tag[4:] {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return errors.New("invalid Tailscale advertise_tags tag")
			}
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

func (o TailscaleOptions) controlURL() string {
	if o.ControlURL == "" {
		return "https://controlplane.tailscale.com"
	}
	return strings.TrimRight(o.ControlURL, "/")
}

type tsState struct {
	ControlURL           string
	Machine, Node, Disco []byte
	TKA                  *tsTKAStored
}

type tsService struct {
	Proto string
	Port  uint16
}
type tsHostinfo struct {
	PeerRelay bool
	Services  []tsService
}
type tsNode struct {
	ID                            int64
	StableID, Name, Key, DiscoKey string
	Addresses, AllowedIPs         []netip.Prefix
	Endpoints                     []netip.AddrPort
	DERP                          string
	HomeDERP                      int
	KeyExpiry                     time.Time
	Expired                       bool
	Online                        *bool
	User                          int64
	Tags                          []string
	UnsignedPeerAPIOnly           bool
	KeySignature                  []byte
	lockInvalid                   bool
	CapMap                        map[string][]json.RawMessage
	Hostinfo                      *tsHostinfo
}

func (n tsNode) restricted() bool { return n.UnsignedPeerAPIOnly || n.lockInvalid }

func (n tsNode) derp() int {
	if n.HomeDERP != 0 {
		return n.HomeDERP
	}
	_, port, _ := net.SplitHostPort(n.DERP)
	id, _ := strconv.Atoi(port)
	return id
}

func tsPublic(raw string, prefix string) ([]byte, error) {
	if !strings.HasPrefix(raw, prefix+":") {
		return nil, errors.New("invalid Tailscale " + prefix + " key")
	}
	b, e := hex.DecodeString(strings.TrimPrefix(raw, prefix+":"))
	if e != nil || len(b) != 32 || slices.Equal(b, make([]byte, 32)) {
		return nil, errors.New("invalid Tailscale " + prefix + " key")
	}
	return b, nil
}

func tsKeyName(key *ecdh.PrivateKey, prefix string) string {
	return prefix + ":" + hex.EncodeToString(key.PublicKey().Bytes())
}

type tailscaleClient struct {
	dnsConfig                  tsDNSConfig
	dns                        atomic.Pointer[tsDNSSnapshot]
	r                          *Runtime
	o                          Outbound
	ctx                        context.Context
	cancel                     context.CancelFunc
	once                       sync.Once
	done, ready                chan struct{}
	readyOnce                  sync.Once
	mu                         sync.Mutex
	err                        error
	resetMap                   bool
	self                       tsNode
	nodes                      map[int64]tsNode
	peers                      map[string]*tsPeer
	indices                    map[uint32]*tsPeer
	nodeKeys, discoKeys        map[[32]byte]int64
	derps                      map[int]*tsDERP
	regions                    map[int]tsDERPRegion
	home                       int
	udp                        *net.UDPConn
	state                      tsState
	stateDir                   string
	tka                        *tsTKA
	lockHead                   string
	machine, nodeKey, discoKey *ecdh.PrivateKey
	control                    *http.Transport
	keyHTTP                    *http.Transport
	lock                       *os.File
	endpoints                  []netip.AddrPort
	stun                       map[[12]byte]time.Time
	stunChanged                chan struct{}
	jobs                       sync.WaitGroup
	filters                    map[string][]tsFilterRule
	filter                     []tsFilter
	localRoutes                []netip.Prefix
	authURL                    string
	authChanged                chan struct{}
	peerAPI                    *tsPeerAPI
	ssh                        *tsSSHServer
	sshPolicy                  *tsSSHPolicy
	userLogins                 map[int64]string
	relay                      *tsRelayServer
	relayPaths                 map[tsRelayPathKey]*tsRelayPath
	relayRequests              map[uint32]tsRelayRequest
	systemMu                   sync.Mutex
	system                     atomic.Pointer[tsSystemInterface]
	prior                      <-chan struct{}
	addressOwners              map[netip.Addr]int64
	prefixOwners               map[netip.Prefix][]int64
	sourceBits4, sourceBits6   []int
}

func (c *tailscaleClient) spawn(fn func()) {
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	c.jobs.Add(1)
	c.mu.Unlock()
	go func() { defer c.jobs.Done(); fn() }()
}

func newTailscaleClient(r *Runtime, o Outbound) *tailscaleClient {
	if o.TaildropDirectory == "" {
		o.TaildropDirectory = "Taildrop"
	}
	ctx, cancel := context.WithCancel(r.ctx)
	c := &tailscaleClient{r: r, o: o, ctx: ctx, cancel: cancel, done: make(chan struct{}), ready: make(chan struct{}), nodes: map[int64]tsNode{}, peers: map[string]*tsPeer{}, indices: map[uint32]*tsPeer{}, nodeKeys: map[[32]byte]int64{}, discoKeys: map[[32]byte]int64{}, derps: map[int]*tsDERP{}, regions: map[int]tsDERPRegion{}, stun: map[[12]byte]time.Time{}, stunChanged: make(chan struct{}, 1), filters: map[string][]tsFilterRule{}, authChanged: make(chan struct{}, 1)}
	if o.ExitNodeAllowLANAccess {
		addresses, _ := net.InterfaceAddrs()
		for _, a := range addresses {
			if p, e := netip.ParsePrefix(a.String()); e == nil && p.Addr().IsGlobalUnicast() && !p.Addr().IsLoopback() {
				if !netip.MustParsePrefix("100.64.0.0/10").Contains(p.Addr()) && !netip.MustParsePrefix("fd7a:115c:a1e0::/48").Contains(p.Addr()) {
					c.localRoutes = append(c.localRoutes, p.Masked())
				}
			}
		}
	}
	return c
}

func (c *tailscaleClient) start() { c.once.Do(func() { go c.run() }) }
func (c *tailscaleClient) close() {
	c.cancel()
	c.start()
	<-c.done
	if s := c.dns.Load(); s != nil {
		s.close()
	}
}

func (c *tailscaleClient) loadState() error {
	dir := c.o.StateDirectory
	if dir == "" {
		base, e := os.UserConfigDir()
		if e != nil {
			return e
		}
		dir = filepath.Join(base, "lanboat-allinone", "tailscale", hex.EncodeToString(blake2s([]byte(c.o.Tag), nil, 8)))
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	var e error
	c.lock, e = lockStateFile(filepath.Join(dir, "lock"))
	if e != nil {
		return e
	}
	c.stateDir = dir
	name := filepath.Join(dir, "state.json")
	b, e := os.ReadFile(name)
	if e == nil {
		if e = json.Unmarshal(b, &c.state); e != nil {
			return errors.New("invalid Tailscale state file")
		}
		if c.state.ControlURL != c.o.controlURL() {
			return errors.New("Tailscale state belongs to another control_url; use a different state_directory")
		}
	} else if errors.Is(e, os.ErrNotExist) {
		c.state.ControlURL = c.o.controlURL()
		for _, dst := range []*[]byte{&c.state.Machine, &c.state.Node, &c.state.Disco} {
			k, e := ecdh.X25519().GenerateKey(rand.Reader)
			if e != nil {
				return e
			}
			*dst = k.Bytes()
		}
		b, _ = json.Marshal(c.state)
		f, e := os.CreateTemp(dir, ".state-")
		if e != nil {
			return e
		}
		defer os.Remove(f.Name())
		if e = f.Chmod(0600); e == nil {
			e = writeAll(f, b)
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e == nil {
			e = os.Rename(f.Name(), name)
		}
		if e != nil {
			return e
		}
	} else {
		return e
	}
	for _, pair := range []struct {
		raw  []byte
		dest **ecdh.PrivateKey
	}{{c.state.Machine, &c.machine}, {c.state.Node, &c.nodeKey}, {c.state.Disco, &c.discoKey}} {
		*pair.dest, e = ecdh.X25519().NewPrivateKey(pair.raw)
		if e != nil {
			return errors.New("invalid Tailscale state key")
		}
	}
	c.tka, e = tsTKARestore(c.state.TKA)
	return e
}

func (c *tailscaleClient) run() {
	defer close(c.done)
	defer func() {
		c.cancel()
		if s := c.dns.Load(); s != nil {
			s.close()
		}
		if c.ssh != nil {
			c.ssh.close()
		}
		c.systemMu.Lock()
		if s := c.system.Swap(nil); s != nil {
			s.close()
		}
		c.systemMu.Unlock()
		if c.relay != nil {
			c.relay.close()
		}
		if c.peerAPI != nil {
			c.peerAPI.close()
		}
		if c.control != nil {
			c.control.CloseIdleConnections()
		}
		if c.keyHTTP != nil {
			c.keyHTTP.CloseIdleConnections()
		}
		if c.udp != nil {
			c.udp.Close()
		}
		c.mu.Lock()
		peers := slices.Collect(maps.Values(c.peers))
		derps := slices.Collect(maps.Values(c.derps))
		c.mu.Unlock()
		for _, d := range derps {
			d.close()
		}
		for _, p := range peers {
			p.wg.close()
		}
		c.jobs.Wait()
		if c.lock != nil {
			c.lock.Close()
		}
	}()
	if c.prior != nil {
		<-c.prior
	}
	if c.ctx.Err() != nil {
		return
	}
	if c.ctx.Err() != nil {
		return
	}
	if e := c.loadState(); e != nil {
		c.fail(e)
		return
	}
	if e := c.startSSH(); e != nil {
		c.fail(e)
		return
	}
	if c.o.TaildropDirectory != "" {
		if e := c.startPeerAPI(); e != nil {
			c.fail(e)
			return
		}
	}
	udp, e := c.listenPacket(c.o.ListenPort)
	if e != nil {
		c.fail(e)
		return
	}
	c.udp = udp.(*net.UDPConn)
	if !c.o.ForceDERP {
		c.endpoints = tsLocalEndpoints(uint16(c.udp.LocalAddr().(*net.UDPAddr).Port))
	}
	if c.o.RelayServerPort != 0 {
		if e := c.startRelay(); e != nil {
			c.fail(e)
			return
		}
	}
	c.control, c.keyHTTP = c.transports()
	c.spawn(c.maintain)
	readerDone := make(chan struct{})
	go func() { defer close(readerDone); c.readUDP() }()
	defer func() { c.udp.Close(); <-readerDone }()
	delay := time.Second
	for c.ctx.Err() == nil {
		err := c.controlSession()
		if c.ctx.Err() != nil {
			return
		}
		// Authentication errors are returned to the caller without exposing keys or response bodies.
		if errors.Is(err, errTSAuth) || errors.Is(err, errTSTailnetLock) || errors.Is(err, errTSSystemInterface) {
			c.fail(err)
			return
		}
		logWarn(c.r.logger, err, c.r.outboundLabel(c.o.Tag), ": control reconnect")
		timer := time.NewTimer(delay)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, 30*time.Second)
	}
}

func (c *tailscaleClient) listenPacket(port uint16) (net.PacketConn, error) {
	network, local, target := "udp", "", "0.0.0.0"
	if c.o.Inet4BindAddress != "" {
		network, local, target = "udp4", c.o.Inet4BindAddress, c.o.Inet4BindAddress
	} else if c.o.Inet6BindAddress != "" {
		network, local, target = "udp6", c.o.Inet6BindAddress, c.o.Inet6BindAddress
	}
	return c.r.listenPacketWithOptions(c.ctx, c.o.DialOptions, network, net.JoinHostPort(local, strconv.Itoa(int(port))), net.JoinHostPort(target, "0"))
}

func (c *tailscaleClient) fail(err error) {
	c.mu.Lock()
	c.err = err
	c.mu.Unlock()
	if s := c.dns.Load(); s != nil {
		s.close()
	}
	c.readyOnce.Do(func() { close(c.ready) })
}

func tsLocalEndpoints(port uint16) []netip.AddrPort {
	var result []netip.AddrPort
	interfaces, _ := net.Interfaces()
	for _, in := range interfaces {
		if in.Flags&net.FlagUp == 0 || in.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := in.Addrs()
		for _, raw := range addresses {
			p, e := netip.ParsePrefix(raw.String())
			if e != nil {
				continue
			}
			ip := p.Addr().Unmap()
			if ip.IsGlobalUnicast() {
				result = append(result, netip.AddrPortFrom(ip, port))
			}
		}
	}
	return result
}

func (c *tailscaleClient) wait(ctx context.Context) error {
	c.start()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
	case <-c.ready:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(c.self.Addresses) == 0 {
		return errTSNoAddresses
	}
	if c.self.Expired || !c.self.KeyExpiry.IsZero() && time.Now().After(c.self.KeyExpiry) {
		return errors.New("Tailscale node key expired")
	}
	return nil
}

func (c *tailscaleClient) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	c.mu.Lock()
	for _, n := range c.nodes {
		full := strings.TrimSuffix(strings.ToLower(n.Name), ".")
		if name == full || name == strings.Split(full, ".")[0] {
			ips := make([]netip.Addr, 0, len(n.Addresses))
			for _, p := range n.Addresses {
				ips = append(ips, p.Addr())
			}
			c.mu.Unlock()
			return ips, nil
		}
	}
	c.mu.Unlock()
	return c.r.resolver.lookupReal(ctx, host)
}

func (c *tailscaleClient) choose(ip netip.Addr) (tsNode, error) {
	return c.chooseRoute(ip, true)
}

func (c *tailscaleClient) chooseRoute(ip netip.Addr, allowExit bool) (tsNode, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best tsNode
	bits := -1
	for _, n := range c.nodes {
		if n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) {
			continue
		}
		for _, p := range n.Addresses {
			if p.Addr() == ip {
				return n, nil
			}
		}
	}
	for _, n := range c.nodes {
		if n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) {
			continue
		}
		if c.o.AcceptRoutes {
			for _, p := range n.AllowedIPs {
				if p.Bits() > 0 && p.Contains(ip) && (p.Bits() > bits || p.Bits() == bits && n.ID < best.ID) {
					best = n
					bits = p.Bits()
				}
			}
		}
	}
	if bits >= 0 {
		return best, nil
	}
	if allowExit && c.o.ExitNode != "" {
		for _, n := range c.nodes {
			if n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) {
				continue
			}
			if tsExitNodeMatches(n, c.o.ExitNode) {
				for _, p := range n.AllowedIPs {
					if p.Bits() == 0 && p.Addr().Is4() == ip.Is4() {
						return n, nil
					}
				}
				return tsNode{}, errors.New("selected Tailscale exit node has no approved default route")
			}
		}
		return tsNode{}, errors.New("Tailscale exit node was not found in the network map")
	}
	return tsNode{}, fmt.Errorf("no Tailscale route to %s (check accept_routes and exit_node)", ip)
}

func tsExitNodeMatches(n tsNode, target string) bool {
	if target == "" {
		return false
	}
	if target == n.StableID || strings.EqualFold(strings.TrimSuffix(n.Name, "."), strings.TrimSuffix(target, ".")) || strings.EqualFold(strings.Split(n.Name, ".")[0], target) {
		return true
	}
	ip, e := netip.ParseAddr(target)
	return e == nil && slices.ContainsFunc(n.Addresses, func(a netip.Prefix) bool { return a.Addr().Unmap() == ip.Unmap() })
}

func (c *tailscaleClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if e := c.wait(ctx); e != nil {
		return nil, e
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	ips, e := c.resolve(ctx, host)
	if e != nil {
		return nil, e
	}
	var last error
	for _, ip := range ips {
		if c.localExitDestination(ip) {
			return c.r.directWithOptions(ctx, c.o.DialOptions, network, net.JoinHostPort(ip.String(), port))
		}
		n, e := c.choose(ip)
		if e != nil {
			last = e
			continue
		}
		p, e := c.peer(n)
		if e != nil {
			return nil, e
		}
		if e = p.ensure(ctx); e != nil {
			last = e
			continue
		}
		conn, e := p.wg.stack.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c.r.own(conn)
		}
		last = e
	}
	if last == nil {
		last = errors.New("Tailscale target has no usable address")
	}
	return nil, last
}

func (c *tailscaleClient) localExitDestination(ip netip.Addr) bool {
	if !c.o.ExitNodeAllowLANAccess || c.o.ExitNode == "" || !slices.ContainsFunc(c.localRoutes, func(p netip.Prefix) bool { return p.Contains(ip) }) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range c.self.Addresses {
		if a.Addr() == ip {
			return false
		}
	}
	for _, n := range c.nodes {
		for _, a := range n.Addresses {
			if a.Addr() == ip {
				return false
			}
		}
		if c.o.AcceptRoutes {
			for _, p := range n.AllowedIPs {
				if p.Bits() > 0 && p.Contains(ip) {
					return false
				}
			}
		}
	}
	return true
}

// TailscaleStatus contains no authentication or private key material.
type TailscaleStatus struct {
	Addresses            []netip.Prefix `json:"addresses"`
	Peers                int            `json:"peers"`
	ForceDERP            bool           `json:"force_derp"`
	AcceptRoutes         bool           `json:"accept_routes"`
	ExitNode             string         `json:"exit_node,omitempty"`
	NodeKey              string         `json:"node_key"`
	TailnetLockPublicKey string         `json:"tailnet_lock_public_key"`
	TailnetLockHead      string         `json:"tailnet_lock_head,omitempty"`
	TailnetLock          bool           `json:"tailnet_lock"`
	NodeKeySigned        bool           `json:"node_key_signed"`
}

// TailscaleAuthURL waits for a login URL or successful registration without waiting for device approval.
func (r *Runtime) TailscaleAuthURL(ctx context.Context, tag string) (string, error) {
	c := r.tailscaleClient(tag)
	if c == nil {
		return "", errors.New("unknown Tailscale endpoint")
	}
	c.start()
	for {
		c.mu.Lock()
		url, err, registered := c.authURL, c.err, len(c.self.Addresses) > 0
		c.mu.Unlock()
		if err != nil {
			return "", err
		}
		if c.ctx.Err() != nil {
			return "", c.wait(ctx)
		}
		if url != "" || registered {
			return url, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-c.ctx.Done():
			return "", c.wait(ctx)
		case <-c.ready:
			return "", c.wait(ctx)
		case <-c.authChanged:
		}
	}
}

func (r *Runtime) TailscaleStatus(ctx context.Context, tag string) (TailscaleStatus, error) {
	c := r.tailscaleClient(tag)
	if c == nil {
		return TailscaleStatus{}, errors.New("unknown Tailscale endpoint")
	}
	if e := c.wait(ctx); e != nil {
		return TailscaleStatus{}, e
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return TailscaleStatus{Addresses: slices.Clone(c.self.Addresses), Peers: len(c.nodes), ForceDERP: c.o.ForceDERP, AcceptRoutes: c.o.AcceptRoutes, ExitNode: c.o.ExitNode, NodeKey: tsKeyName(c.nodeKey, "nodekey"), TailnetLockPublicKey: c.lockPublic(), TailnetLockHead: c.lockHead, TailnetLock: c.lockHead != "", NodeKeySigned: c.lockHead != "" && !c.self.lockInvalid}, nil
}

func (r *Runtime) tailscaleClient(tag string) *tailscaleClient {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tailscaleClients[tag]
}

// DisconnectTailscale releases an on-demand endpoint; its next use reconnects with the persisted identity.
func (r *Runtime) DisconnectTailscale(tag string) error {
	r.mu.Lock()
	c := r.tailscaleClients[tag]
	if r.closed || c == nil || !c.o.OnDemand {
		r.mu.Unlock()
		return errors.New("disconnect requires an active runtime and an on_demand Tailscale endpoint")
	}
	next := newTailscaleClient(r, c.o)
	next.prior = c.done
	r.tailscaleClients[tag] = next
	r.mu.Unlock()
	c.close()
	return nil
}

func tsPrivateBase64(key *ecdh.PrivateKey) keyLines {
	return keyLines{base64.StdEncoding.EncodeToString(key.Bytes())}
}
