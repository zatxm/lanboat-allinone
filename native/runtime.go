package native

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Stats struct {
	Connections int64 `json:"connections"`
	Uplink      int64 `json:"uplink_bytes"`
	Downlink    int64 `json:"downlink_bytes"`
}

type Runtime struct {
	genericMuxClients        map[string]*genericMuxClient
	namespaces               map[string]*networkNamespace
	namespaceKernelOnly      bool
	wgEndpoints              map[string]*wgEndpoint
	neighbors                neighborCache
	udpTimeouts              map[string]time.Duration
	processes                processFinder
	network                  networkMetadataCache
	metadataFields           uint32
	metadataSets             []*ruleCollection
	logSequence              atomic.Uint64
	controller               *controller
	certificateProviders     map[string]*managedCertificate
	acme                     *acmeChallenges
	realityMu                sync.Mutex
	realityPosts             map[realityPostKey]*realityPost
	realityProbes            atomic.Int32
	cloakClients             map[string]*cloakClient
	cloakServers             map[string]*cloakServer
	cloakBudget              atomic.Int64
	cloakHandshakes          atomic.Int32
	kcpMu                    sync.Mutex
	kcpConns                 map[*kcpConn]struct{}
	kcpBudget                atomic.Int64
	kcpFECBudget             atomic.Int64
	kcpClients               map[string]*kcptunClient
	mkcpMu                   sync.Mutex
	mkcpConns                map[*mkcpConn]struct{}
	mkcpBudget               atomic.Int64
	mieruClients             map[string]*mieruClient
	mieruListeners           map[string]*mieruListener
	mieruUsers               map[string][]*mieruUser
	mieruBudget              atomic.Int64
	xhttpClients             map[string]*xHTTPClient
	xhttpServers             map[string]*xHTTPServer
	tailscaleClients         map[string]*tailscaleClient
	proxyMuxClients          map[string]*proxyMuxClient
	quicTransports           map[string]*quicTransportClient
	masqueClients            map[string]*masqueClient
	masqueServers            map[string]*masqueServer
	ocClients                map[string]*ocClient
	ocAuthHandler            atomic.Pointer[OpenConnectAuthHandler]
	ocNegotiateHandler       atomic.Pointer[OpenConnectNegotiateHandler]
	ocServers                map[string]*ocServer
	masqueConfigVersion      atomic.Uint64
	masqueNetworkServers     map[string]*masqueNetworkServer
	snellClients             map[string]*snellPool
	trojanMuxClients         map[string]*trojanMuxClient
	sudokuMuxClients         map[string]*sudokuMuxClient
	sudokuHTTPSessions       map[string]*sudokuHTTPSession
	sudokuHTTPUploads        chan struct{}
	sudokuReverseServers     map[string]*sudokuReverseServer
	sudokuReverseClients     map[string]*sudokuReverseClient
	sudokuUsers              []*sudokuUsers
	tunnels                  []*tunTunnel
	trustStreams             atomic.Int32
	naiveBuffers             naiveBufferBudget
	relayBinds               atomic.Int32
	protectMark              atomic.Uint32
	tunProtectMu             sync.Mutex
	tunProtectUsers          int
	tunEgress4               atomic.Int32
	tunEgress6               atomic.Int32
	tunGateway4, tunGateway6 atomic.Uint64
	tunRouting               atomic.Bool
	config                   Config
	ctx                      context.Context
	cancel                   context.CancelFunc
	logger                   *zap.Logger
	closeLogger              func()
	mu                       sync.Mutex
	started, closed          bool
	closeDone                chan struct{}
	listeners                map[string]net.Listener
	packetListeners          []net.PacketConn
	directPackets            map[string]net.PacketConn
	connections              map[net.Conn]struct{}
	workers                  sync.WaitGroup
	outbounds                map[string]Outbound
	clientTLS                map[string]*tls.Config
	serverTLS                map[string]*tls.Config
	keys                     map[string]*ssKey
	vmessUsers               map[string][]vmessUser
	vmessLegacy              map[string]*vmessLegacyIndex
	sshClients               map[string]*sshClient
	groups                   map[string]*outboundGroup
	sshKeys                  map[string]crypto.Signer
	wgClients                map[string]*wgClient
	wgListeners              map[string]*wgListener
	trustClients             map[string]*trustClient
	quicClients              map[string]*quicProxyClient
	quicListeners            map[string]*quicEndpoint
	anyClients               map[string]*anyClient
	httpClients              map[string]*http.Transport
	httpServers              []*http.Server
	rules                    []routeRule
	ruleSets                 map[string]*ruleCollection
	resolver                 *resolver
	resolved                 map[string]*resolvedService
	replay                   replayWindow
	up, down                 atomic.Int64
	stopParent               func() bool
}

// New creates no listening sockets. A supplied zap logger remains owned by its caller.
func New(ctx context.Context, raw []byte, logger *zap.Logger) (*Runtime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	closeLogger := func() {}
	if logger != nil {
		if cfg.Log.Disabled {
			logger = zap.NewNop()
		} else if cfg.Log.Level != "" {
			var level zapcore.Level
			if err := level.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
				return nil, err
			}
			if logger.Core().Enabled(level) {
				logger = logger.WithOptions(zap.IncreaseLevel(level))
			}
		}
	}
	if logger == nil {
		if cfg.Log.Disabled {
			logger = zap.NewNop()
		} else {
			level := zap.NewAtomicLevelAt(zap.InfoLevel)
			if cfg.Log.Level != "" {
				if err := level.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
					return nil, err
				}
			}
			output := cfg.Log.Output
			if output == "" {
				output = "stderr"
			}
			writer, release, openErr := zap.Open(output)
			err = openErr
			if err != nil {
				return nil, err
			}
			logger = zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), writer, level))
			closeLogger = func() { _ = logger.Sync(); release() }
		}
	}
	// Parent cancellation enters Close's bounded cleanup before cancelling
	// network exits needed to remove an outstanding DNS01 proof.
	child, cancel := context.WithCancel(context.WithoutCancel(ctx))
	for _, s := range cfg.Services {
		cfg.Inbounds = append(cfg.Inbounds, Inbound{Type: "dns", Tag: s.Tag, Listen: s.Listen, ListenPort: s.ListenPort})
	}
	r := &Runtime{config: cfg, ctx: child, cancel: cancel, logger: logger, closeLogger: closeLogger, listeners: map[string]net.Listener{}, connections: map[net.Conn]struct{}{}, outbounds: map[string]Outbound{}, clientTLS: map[string]*tls.Config{}, serverTLS: map[string]*tls.Config{}, keys: map[string]*ssKey{}}
	for _, in := range cfg.Inbounds {
		if in.UDPTimeout != "" {
			if r.udpTimeouts == nil {
				r.udpTimeouts = map[string]time.Duration{}
			}
			r.udpTimeouts[in.Tag], _ = optionDuration(in.UDPTimeout, udpTimeout)
		}
	}

	r.resolved = map[string]*resolvedService{}
	for _, s := range cfg.Services {
		r.resolved[s.Tag] = newResolvedService(r, s)
	}
	r.mkcpConns = make(map[*mkcpConn]struct{})
	r.kcpConns = make(map[*kcpConn]struct{})
	r.kcpClients = make(map[string]*kcptunClient)
	r.cloakClients = map[string]*cloakClient{}
	r.cloakServers = map[string]*cloakServer{}
	r.vmessUsers = make(map[string][]vmessUser)
	r.vmessLegacy = make(map[string]*vmessLegacyIndex)
	r.sshClients = map[string]*sshClient{}
	r.groups = map[string]*outboundGroup{}
	r.sshKeys = map[string]crypto.Signer{}
	r.wgClients = map[string]*wgClient{}
	r.tailscaleClients = map[string]*tailscaleClient{}
	r.wgListeners = map[string]*wgListener{}
	r.trustClients = make(map[string]*trustClient)
	r.quicClients = make(map[string]*quicProxyClient)
	r.quicTransports = make(map[string]*quicTransportClient)
	r.quicListeners = make(map[string]*quicEndpoint)
	r.snellClients = make(map[string]*snellPool)
	r.trojanMuxClients = map[string]*trojanMuxClient{}
	r.sudokuMuxClients = map[string]*sudokuMuxClient{}
	r.sudokuHTTPSessions = map[string]*sudokuHTTPSession{}
	r.sudokuHTTPUploads = make(chan struct{}, 8)
	r.sudokuReverseServers = map[string]*sudokuReverseServer{}
	r.sudokuReverseClients = map[string]*sudokuReverseClient{}
	r.proxyMuxClients = map[string]*proxyMuxClient{}
	r.genericMuxClients = map[string]*genericMuxClient{}
	r.masqueClients = map[string]*masqueClient{}
	r.masqueServers = map[string]*masqueServer{}
	r.mieruClients = map[string]*mieruClient{}
	r.mieruListeners = map[string]*mieruListener{}
	r.mieruUsers = map[string][]*mieruUser{}
	r.xhttpClients = map[string]*xHTTPClient{}
	r.xhttpServers = map[string]*xHTTPServer{}
	r.ocClients = map[string]*ocClient{}
	r.ocServers = map[string]*ocServer{}
	r.masqueNetworkServers = map[string]*masqueNetworkServer{}
	r.anyClients = make(map[string]*anyClient)
	r.httpClients = make(map[string]*http.Transport)
	r.ruleSets = make(map[string]*ruleCollection)
	for _, s := range cfg.Route.RuleSet {
		r.ruleSets[s.Tag] = &ruleCollection{}
	}
	ready := false
	defer func() {
		if !ready {
			_ = r.Close()
		}
	}()
	if err := r.bindNamespaces(); err != nil {
		return nil, err
	}
	cfg = r.config
	usagePaths := map[string]bool{}
	for _, in := range cfg.Inbounds {
		if in.Type != "sudoku" || len(in.Sudoku.Users) == 0 {
			continue
		}
		if in.Sudoku.UsagePath != "" {
			path, err := filepath.Abs(in.Sudoku.UsagePath)
			if err != nil {
				return nil, err
			}
			if usagePaths[path] {
				return nil, errors.New("Sudoku inbounds must use distinct usage_path files")
			}
			usagePaths[path] = true
		}
		users, err := newSudokuUsers(r, in)
		if err != nil {
			return nil, err
		}
		in.Sudoku.users = users
		r.sudokuUsers = append(r.sudokuUsers, users)
	}
	r.certificateProviders = make(map[string]*managedCertificate)
	for _, options := range cfg.CertificateProviders {
		if err := options.normalize(); err != nil {
			return nil, err
		}
		if p := r.existingTailscaleCertificate(options); p != nil {
			r.certificateProviders[options.Tag] = p
			continue
		}
		r.certificateProviders[options.Tag] = &managedCertificate{r: r, options: options, now: time.Now}
		if options.Type == "acme" || options.Type == "tailscale" {
			r.initACME()
		}
	}
	for _, o := range cfg.Outbounds {
		if o.Type == "lua" && o.Plugin != "" {
			if o.TLS.Enabled {
				security := o.TLS
				o.nodeTLS = &security
				var err error
				o.nodeConfig, err = security.config(false, o.Server)
				if err != nil {
					return nil, err
				}
			}
			o.TLS = TLSOptions{}
		}
		o = o.pluginTransport()
		r.outbounds[o.Tag] = o
		if o.reverse {
			continue
		}
		if o.plugin != nil && o.plugin.cloak != nil {
			r.cloakClients[o.Tag] = &cloakClient{r: r, o: o}
		}
		if o.plugin != nil && o.plugin.kcp != nil {
			r.kcpClients[o.Tag] = &kcptunClient{r: r, o: o}
		}
		if o.Multiplex.generic(o.Type) {
			r.genericMuxClients[o.Tag] = &genericMuxClient{runtime: r, outbound: o}
		}
		if (o.Type == "vmess" || o.Type == "vless") && (o.Multiplex.Enabled && !o.Multiplex.generic(o.Type) || o.Flow != "") || o.plugin != nil && o.plugin.mux {
			r.proxyMuxClients[o.Tag] = &proxyMuxClient{runtime: r, outbound: o}
		}
		if o.Type == "selector" || o.Type == "urltest" {
			r.groups[o.Tag] = newOutboundGroup(r, o)
		}
		c, err := o.TLS.config(false, o.Server)
		if p := o.plugin; p != nil && p.shadow != nil {
			host := o.Server
			if p.server != "" {
				host = p.server
			}
			c, err = p.tls.config(false, host)
		}
		if err != nil {
			return nil, err
		}
		r.clientTLS[o.Tag] = c
		if o.Transport.Type == "xhttp" {
			c, e := newXHTTPClient(r, o)
			if e != nil {
				return nil, e
			}
			r.xhttpClients[o.Tag] = c
		}
		if o.Transport.usesHTTP2(o.TLS.Enabled) {
			r.httpClients[o.Tag] = r.newHTTPTransport(o)
		}
		if o.Type == "shadowsocks" || o.Type == "shadowsocksr" {
			r.keys["out:"+o.Tag], _ = newSSKey(o.Method, o.Password)
		}
		if o.Shadowsocks != nil && o.Shadowsocks.Enabled {
			r.keys["out:"+o.Tag], _ = o.Shadowsocks.key()
		}
		if o.Type == "vmess" {
			u, _ := newVMessUser(o.UUID)
			r.vmessUsers["out:"+o.Tag] = []vmessUser{u}
		}
		if o.Type == "trojan" && o.Multiplex.Enabled && !o.Multiplex.generic(o.Type) {
			r.trojanMuxClients[o.Tag] = &trojanMuxClient{runtime: r, outbound: o}
		}
		if o.Type == "sudoku" && o.Multiplex.Enabled {
			r.sudokuMuxClients[o.Tag] = &sudokuMuxClient{runtime: r, outbound: o}
		}
		if o.Type == "sudoku" && o.Sudoku.Reverse != nil {
			r.sudokuReverseClients[o.Tag] = &sudokuReverseClient{r: r, out: o, wake: make(chan struct{}, 1)}
		}
		if o.Type == "snell" && o.Multiplex.Enabled {
			timeout := 5 * time.Second
			if o.IdleSessionTimeout != "" {
				timeout, _ = time.ParseDuration(o.IdleSessionTimeout)
			}
			r.snellClients[o.Tag] = &snellPool{runtime: r, outbound: o, timeout: timeout, all: map[*snellConn]bool{}}
		}
		if o.Type == "ssh" {
			if len(o.PrivateKey) > 0 || o.PrivateKeyPath != "" {
				key, e := sshPrivate(o.PrivateKey, o.PrivateKeyPath, o.PrivateKeyPassphrase)
				if e != nil {
					return nil, e
				}
				r.sshKeys["out:"+o.Tag] = key
			}
			r.sshClients[o.Tag] = &sshClient{runtime: r, outbound: o}
		}
		if o.Type == "wireguard" {
			if o.wgEndpoint != nil {
				if r.wgEndpoints == nil {
					r.wgEndpoints = map[string]*wgEndpoint{}
				}
				r.wgEndpoints[o.Tag] = &wgEndpoint{r: r, o: *o.wgEndpoint}
			} else {
				r.wgClients[o.Tag] = &wgClient{runtime: r, outbound: o}
			}
		}
		if o.Type == "tailscale" {
			r.tailscaleClients[o.Tag] = newTailscaleClient(r, o)
		}
		if o.Type == "openconnect" {
			client := &ocClient{r: r, o: o, gate: make(chan struct{}, 1), wake: make(chan struct{}, 1)}
			if e := o.ocEndpoint; e != nil {
				client.cookie = e.Cookie
				settings, _ := e.masqueNATOptions.settings()
				client.nat = newMasqueNAT(r, settings)
			}
			r.ocClients[o.Tag] = client
		}
		if o.Type == "mieru" {
			r.mieruClients[o.Tag] = &mieruClient{r: r, o: o, user: newMieruUser(o.Username, o.Password)}
		}
		if o.Type == "masque" {
			r.masqueClients[o.Tag] = &masqueClient{nat: newMasqueNAT(r, o.nat), runtime: r, outbound: o, wake: make(chan struct{}, 1)}
		}
		if o.Type == "trusttunnel" || o.Type == "naive" {
			r.trustClients[o.Tag] = newTrustClient(r, o)
		}
		if isQUICProxy(o.Type) {
			r.quicClients[o.Tag] = &quicProxyClient{runtime: r, outbound: o}
		}
		if o.Transport.Type == "quic" {
			r.quicTransports[o.Tag] = &quicTransportClient{runtime: r, outbound: o}
		}
		if o.Type == "anytls" {
			padding, _ := parseAnyPadding(defaultAnyPadding)
			r.anyClients[o.Tag] = &anyClient{runtime: r, outbound: o, padding: padding}
		}
	}
	for index := range r.config.Inbounds {
		in := &r.config.Inbounds[index]
		if in.Tag == "" {
			in.Tag = fmt.Sprintf("inbound-%d", index)
		}
		if _, ok := r.serverTLS[in.Tag]; ok {
			cancel()
			return nil, errors.New("duplicate inbound tag")
		}
		if in.plugin != nil && in.plugin.cloak != nil {
			r.cloakServers[in.Tag] = &cloakServer{r: r, sessions: map[uint32]*cloakServerSession{}}
		}
		options := in.pluginTransport().TLS
		if options.CertificateProvider != "" {
			options.provider, err = r.certificateProvider(options.CertificateProvider)
			if err != nil {
				return nil, err
			}
		}
		c, err := options.config(true, "")
		if err != nil {
			return nil, err
		}
		if in.Type == "openconnect" {
			c = cloneTLSConfig(c)
			c.NextProtos = []string{"http/1.1"}
			c.DynamicRecordSizingDisabled = true
			if c.MinVersion < tls.VersionTLS12 {
				c.MinVersion = tls.VersionTLS12
			}
			r.ocServers[in.Tag] = newOCServer()
		}
		if in.Type == "masque" {
			r.masqueNetworkServers[in.Tag] = newMasqueNetworkServer(in.MasqueOptions)
			if in.endpoint {
				r.masqueServers[in.Tag] = newMasqueServer(*in)
				r.masqueServers[in.Tag].nat = newMasqueNAT(r, in.nat)
			}
		}
		r.serverTLS[in.Tag] = c
		if in.NaiveFrontend != "" {
			in.naiveFrontend = r.newNaiveFrontend(in.NaiveFrontend)
		}
		if in.Transport.Type == "xhttp" {
			r.xhttpServers[in.Tag] = newXHTTPServer(r, *in)
		}
		if in.Type == "mieru" {
			for _, u := range in.Users {
				name := u.Username
				if name == "" {
					name = u.Name
				}
				r.mieruUsers[in.Tag] = append(r.mieruUsers[in.Tag], newMieruUser(name, u.Password))
			}
		}
		if in.Type == "ssh" {
			key, e := sshPrivate(in.PrivateKey, in.PrivateKeyPath, in.PrivateKeyPassphrase)
			if e != nil {
				return nil, e
			}
			r.sshKeys["in:"+in.Tag] = key
		}
		if in.Type == "shadowsocks" || in.Type == "shadowsocksr" {
			r.keys["in:"+in.Tag], _ = newSSInboundKey(*in)
		}
		if in.Shadowsocks != nil && in.Shadowsocks.Enabled {
			r.keys["in:"+in.Tag], _ = in.Shadowsocks.key()
		}
		if in.Type == "vmess" {
			for _, user := range in.Users {
				u, _ := newVMessUser(user.UUID)
				u.legacy = user.AlterID > 0
				r.vmessUsers["in:"+in.Tag] = append(r.vmessUsers["in:"+in.Tag], u)
			}
			r.vmessLegacy[in.Tag] = newVMessLegacyIndex(r.vmessUsers["in:"+in.Tag])
		}
	}
	r.rules, _ = compileRoute(cfg.Route, r.outbounds, r.ruleSets)
	r.resolver, err = newResolver(cfg.DNS, r)
	if err != nil {
		return nil, err
	}
	r.initMetadataRules()

	for _, s := range cfg.Route.RuleSet {
		if s.DownloadDetour != "" {
			if _, ok := r.outbounds[s.DownloadDetour]; !ok {
				return nil, fmt.Errorf("unknown rule_set download_detour %q", s.DownloadDetour)
			}
		}
		if err := r.loadRuleSet(child, s, false); err != nil {
			return nil, err
		}
	}
	options, _ := cfg.controllerOptions()
	if options != nil {
		r.controller = newController(r, *options)
		r.logger = r.logger.WithOptions(zap.WrapCore(func(core zapcore.Core) zapcore.Core { return zapcore.NewTee(core, &controllerLogCore{c: r.controller}) }))
	}
	r.mu.Lock()
	r.stopParent = context.AfterFunc(ctx, func() { _ = r.Close() })
	r.mu.Unlock()
	ready = true
	return r, nil
}

func (r *Runtime) Start() error {
	r.mu.Lock()
	if r.closeDone != nil || r.started {
		r.mu.Unlock()
		return errors.New("runtime already started or closed")
	}
	var startErr error
	for _, ep := range r.wgEndpoints {
		if !ep.o.OnDemand {
			if _, err := ep.session(r.ctx); err != nil {
				r.mu.Unlock()
				_ = r.Close()
				return err
			}
		}
	}
	r.startProcessTracking(r.needsProcess())
	for _, users := range r.sudokuUsers {
		if err := users.save(); err != nil {
			r.mu.Unlock()
			_ = r.Close()
			return fmt.Errorf("initialize Sudoku usage: %w", err)
		}
	}
	for _, in := range r.config.Inbounds {
		if in.Type == "sudoku" && in.Sudoku.Reverse != nil {
			listener, err := in.ListenOptions.listen(r.ctx, "tcp", in.Sudoku.Reverse.Listen)
			if err != nil {
				r.mu.Unlock()
				_ = r.Close()
				return err
			}
			r.sudokuReverseServers[in.Tag] = &sudokuReverseServer{r: r, listener: listener, bodySlots: make(chan struct{}, 4)}
		}
	}
	for _, in := range r.config.Inbounds {
		in = in.pluginTransport()
		if in.Type == "masque" && in.system {
			s := r.masqueServers[in.Tag]
			var err error
			s.system, err = newMasqueSystem(r, in.Tag, in.interfaceName, in.MTU, in.serverAddress)
			if err != nil {
				startErr = err
				break
			}
			s.system.server = s
			s.system.start()
		}
		if in.Type == "tun" {
			tunnel, err := r.startTUN(in)
			if err != nil {
				startErr = err
				break
			}
			r.tunnels = append(r.tunnels, tunnel)
			continue
		}
		host := in.Listen
		if host == "" {
			host = "127.0.0.1"
		}
		if in.Type == "direct" {
			if startErr = r.listenDirect(in, host); startErr != nil {
				break
			}
			continue
		}
		if in.plugin != nil && in.plugin.kcp != nil {
			l, e := r.listenKCP(in, host)
			if e != nil {
				startErr = e
				break
			}
			r.listeners[in.Tag] = l
			continue
		}
		var pairedPacket net.PacketConn
		if in.Transport.Type == "mkcp" {
			l, e := r.listenMKCP(in, host)
			if e != nil {
				startErr = e
				break
			}
			r.listeners[in.Tag] = l
			continue
		}
		if in.Type == "mieru" && in.Network == "udp" {
			pc, e := in.ListenOptions.listenPacket(r.ctx, "udp", portAddress(host, in.ListenPort))
			if e != nil {
				startErr = e
				break
			}
			r.mieruListeners[in.Tag] = &mieruListener{r: r, in: in, packet: pc, peers: map[string]*mieruCarrier{}}
			continue
		}
		if in.Type == "wireguard" {
			l, e := r.listenWG(in)
			if e != nil {
				startErr = e
				break
			}
			r.wgListeners[in.Tag] = l
			continue
		}
		if in.Type == "naive" && in.Network != "udp" || in.Type == "masque" && in.masqueTCP() {
			listener, err := in.ListenOptions.listen(r.ctx, "tcp", portAddress(host, in.ListenPort))
			if err == nil && (in.Type == "naive" && in.Network != "tcp" || in.Type == "masque" && in.masqueServes(3)) {
				listener, pairedPacket, err = bindPairedUDPWithOptions(r.ctx, listener, in.ListenPort == 0, in.ListenOptions)
			}
			if err != nil {
				startErr = err
				break
			}
			r.listeners[in.Tag] = listener
			if in.Type == "naive" && in.Network == "tcp" || in.Type == "masque" && !in.masqueServes(3) {
				continue
			}
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			_, _ = fmt.Sscan(port, &in.ListenPort)
		}
		if isQUICInbound(in) {
			packets := pairedPacket
			var err error
			if packets == nil {
				if in.Type == "hysteria" && in.Protocol == "faketcp" {
					packets, err = listenFakeTCP(r.ctx, portAddress(host, in.ListenPort), in.ListenOptions)
				} else {
					packets, err = in.ListenOptions.listenPacket(r.ctx, "udp", portAddress(host, in.ListenPort))
				}
			}
			if err != nil {
				startErr = err
				break
			}
			cfg := cloneTLSConfig(r.serverTLS[in.Tag])
			if len(cfg.NextProtos) == 0 {
				cfg.NextProtos = quicALPN(in.Type)
			}
			if in.Type == "hysteria" && in.Protocol == "wechat-video" {
				packets = newWechatPacket(packets)
			}
			obfs, _ := in.Obfs.quicSettings()
			if obfs.Type == "gecko" {
				packets = &geckoPacket{PacketConn: packets, codec: newGecko(obfs)}
			} else if obfs.Password != "" {
				packets = &salamanderPacket{PacketConn: packets, password: obfs.Password}
			}
			if in.Type == "hysteria" && in.Obfs != "" {
				packets = &xplusPacket{PacketConn: packets, password: string(in.Obfs)}
			}
			minimum := 1200
			if in.Type == "brook" {
				minimum = 1300
			}
			if in.Type == "masque" {
				minimum = 1400
				cfg.NextProtos = []string{"h3"}
			}
			options := proxyQUICOptions(in.Type, in.CongestionControl)
			if in.Type == "naive" {
				options = naiveQUICOptions(in.QUICCongestionControl, true)
			}
			if in.BBRProfile != "" {
				options.bbrProfile = in.BBRProfile
			}
			if in.plugin != nil && in.plugin.hy2 {
				options = proxyQUICOptions("hysteria2", "")
			}
			options.disableLossCompensation = in.DisableLossCompensation
			if in.Type == "hysteria" && in.Protocol == "faketcp" {
				options.receiveMTU = 1200
			}
			options.initial = minimum
			if in.Type == "masque" {
				options = in.connection.quic()
			}
			l, err := listenQUIC(r.ctx, packets, cfg, options)
			if err != nil {
				packets.Close()
				startErr = err
				break
			}
			r.quicListeners[in.Tag] = l
			continue
		}
		listener, err := in.ListenOptions.listen(r.ctx, "tcp", portAddress(host, in.ListenPort))
		if err != nil {
			startErr = err
			break
		}
		if in.Type == "openconnect" && !in.DisableDTLS {
			var packet net.PacketConn
			listener, packet, err = bindPairedUDPWithOptions(r.ctx, listener, in.ListenPort == 0, in.ListenOptions)
			if err != nil {
				startErr = err
				break
			}
			r.ocServers[in.Tag].dtls = newOCDTLSListener(r, packet)
			r.ocServers[in.Tag].dtls.suites, _ = in.dtlsCipherIDs()
			r.ocServers[in.Tag].dtls.version13 = in.DTLSVersion == "1.3"
		}
		if (in.plugin == nil || in.plugin.kcp == nil && in.plugin.cloak == nil) && in.Transport.Type != "mkcp" && (in.Type == "shadowsocks" || in.Type == "shadowsocksr" || in.Type == "dns" || in.Type == "brook" && in.Transport.Type == "" || in.Type == "snell" && snellVersion(in.Version) == 5) {
			var packets net.PacketConn
			listener, packets, err = bindPairedUDPWithOptions(r.ctx, listener, in.ListenPort == 0, in.ListenOptions)
			if err != nil {
				startErr = err
				break
			}
			r.packetListeners = append(r.packetListeners, packets)
		}
		r.listeners[in.Tag] = listener
	}
	if startErr == nil && r.controller != nil {
		startErr = r.controller.start()
	}
	if startErr == nil {
		for _, s := range r.resolved {
			if startErr = s.start(); startErr != nil {
				break
			}
		}
	}
	if startErr != nil {
		r.mu.Unlock()
		_ = r.Close()
		return startErr
	}
	r.started = true
	for _, users := range r.sudokuUsers {
		r.workers.Add(1)
		go users.run()
	}
	for _, p := range r.sudokuReverseServers {
		r.workers.Add(1)
		go p.run()
	}
	for _, p := range r.sudokuReverseClients {
		r.workers.Add(1)
		go p.run()
	}
	for _, c := range r.ocClients {
		eager := c.o.System
		if e := c.o.ocEndpoint; e != nil {
			eager = !e.OnDemand
		}
		if eager {
			r.workers.Add(1)
			go func() { defer r.workers.Done(); c.runSystem() }()
		}
	}
	for _, c := range r.tailscaleClients {
		if !c.o.OnDemand {
			c.start()
		}
	}
	for _, g := range r.groups {
		if g.options.Type == "urltest" {
			r.workers.Add(1)
			go func() { defer r.workers.Done(); g.run() }()
		}
	}

	for _, s := range r.config.Route.RuleSet {
		if s.Type == "remote" || s.Type == "local" {
			r.workers.Add(1)
			go r.updateRuleSets()
			break
		}
	}
	packetIndex := 0
	for _, tunnel := range r.tunnels {
		tunnel.start()
	}
	for _, in := range r.config.Inbounds {
		in = in.pluginTransport()
		if in.Type == "tun" {
			continue
		}
		if in.Type == "direct" {
			if listener := r.listeners[in.Tag]; listener != nil {
				r.workers.Add(1)
				go r.accept(in, listener)
			}
			if packets := r.directPackets[in.Tag]; packets != nil {
				r.workers.Add(1)
				go func() { defer r.workers.Done(); r.serveDirectPackets(in, packets) }()
			}
			continue
		}
		if in.Type == "wireguard" {
			l := r.wgListeners[in.Tag]
			r.workers.Add(1)
			go func() { defer r.workers.Done(); l.run() }()
			for _, p := range l.peers {
				go p.maintain()
			}
			continue
		}
		if l := r.mieruListeners[in.Tag]; l != nil {
			r.workers.Add(1)
			go func() { defer r.workers.Done(); l.run() }()
			continue
		}
		if isQUICInbound(in) {
			r.workers.Add(1)
			go r.acceptQUIC(in, r.quicListeners[in.Tag])
			if in.Type != "naive" && in.Type != "masque" || in.Type == "naive" && in.Network == "udp" || in.Type == "masque" && !in.masqueTCP() {
				continue
			}
		}
		listener := r.listeners[in.Tag]
		if in.Type == "openconnect" && r.ocServers[in.Tag].dtls != nil {
			r.workers.Add(1)
			go func() { defer r.workers.Done(); r.ocServers[in.Tag].dtls.run() }()
		}
		r.workers.Add(1)
		if in.Transport.Type == "xhttp" || in.Transport.usesHTTP2(in.TLS.Enabled) || in.Type == "trusttunnel" || in.Type == "naive" || in.Type == "masque" {
			server := r.newHTTPServer(in)
			if in.TLS.realityEnabled() {
				listener = r.realityHTTPServer(in, server, listener)
			}
			r.httpServers = append(r.httpServers, server)
			go func() {
				defer r.workers.Done()
				if in.Type == "masque" {
					_ = server.Serve(&masqueHTTPListener{Listener: listener, r: r, tls: server.TLSConfig, options: in.TLS})
				} else if (in.TLS.KernelTX || in.TLS.KernelRX) && !in.TLS.realityEnabled() {
					_ = server.Serve(&kernelTLSListener{Listener: listener, config: server.TLSConfig, options: in.TLS})
				} else if in.TLS.Enabled && !in.TLS.realityEnabled() {
					_ = server.ServeTLS(listener, "", "")
				} else {
					_ = server.Serve(listener)
				}
			}()
		} else {
			go r.accept(in, listener)
		}
		if (in.plugin == nil || in.plugin.kcp == nil && in.plugin.cloak == nil) && in.Transport.Type != "mkcp" && (in.Type == "shadowsocks" || in.Type == "shadowsocksr" || in.Type == "dns" || in.Type == "brook" && in.Transport.Type == "" || in.Type == "snell" && snellVersion(in.Version) == 5) {
			packets := r.packetListeners[packetIndex]
			packetIndex++
			r.workers.Add(1)
			go func() {
				defer r.workers.Done()
				if in.Type == "snell" {
					r.serveSnellQUIC(in, packets)
				} else if in.Type == "brook" {
					r.serveBrookPackets(in, packets)
				} else if in.Type == "dns" {
					r.serveDNSPackets(in, packets)
				} else {
					r.serveSSPackets(in, packets)
				}
			}()
		}
		r.logger.Info("listener started", zap.String("inbound", in.Tag), zap.String("protocol", in.Type), zap.String("address", listener.Addr().String()))
	}
	for _, c := range r.masqueClients {
		if len(c.outbound.routes) != 0 || c.outbound.system {
			r.workers.Add(1)
			go func() { defer r.workers.Done(); c.maintain() }()
		}
	}
	r.mu.Unlock()
	return nil
}

// TCP and UDP have separate ephemeral port spaces; keep retrying the pair, not just TCP.
func bindPairedUDP(listener net.Listener, automatic bool) (net.Listener, net.PacketConn, error) {
	return bindPairedUDPWithOptions(context.Background(), listener, automatic, ListenOptions{})
}
func bindPairedUDPWithOptions(ctx context.Context, listener net.Listener, automatic bool, options ListenOptions) (net.Listener, net.PacketConn, error) {
	host, _, _ := net.SplitHostPort(listener.Addr().String())
	for attempt := 0; ; attempt++ {
		packet, err := options.listenPacket(ctx, "udp", listener.Addr().String())
		if err == nil {
			return listener, packet, nil
		}
		listener.Close()
		if !automatic || attempt == 31 {
			return nil, nil, err
		}
		listener, err = options.listen(ctx, "tcp", portAddress(host, 0))
		if err != nil {
			return nil, nil, err
		}
	}
}

// Address reports the bound port, including when listen_port is zero.
func (r *Runtime) Address(tag string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tunnels {
		if t.in.Tag == tag {
			return t.name
		}
	}
	if l := r.mieruListeners[tag]; l != nil {
		return l.packet.LocalAddr().String()
	}
	if ep := r.wgEndpoints[tag]; ep != nil {
		ep.mu.Lock()
		defer ep.mu.Unlock()
		if ep.current != nil {
			return ep.current.packets[0].LocalAddr().String()
		}
		return ""
	}
	if l := r.wgListeners[tag]; l != nil {
		return l.packet.LocalAddr().String()
	}
	if l := r.quicListeners[tag]; l != nil {
		return l.packet.LocalAddr().String()
	}
	if l := r.listeners[tag]; l != nil {
		return l.Addr().String()
	}
	if p := r.directPackets[tag]; p != nil {
		return p.LocalAddr().String()
	}
	return ""
}

func (r *Runtime) Stats() Stats {
	r.mu.Lock()
	count := len(r.connections)
	r.mu.Unlock()
	return Stats{Connections: int64(count), Uplink: r.up.Load(), Downlink: r.down.Load()}
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	if r.closeDone != nil {
		done := r.closeDone
		r.mu.Unlock()
		<-done
		return nil
	}
	r.closeDone = make(chan struct{})
	defer close(r.closeDone)
	r.mu.Unlock()
	// Stop issuers while their configured network exits still work, so DNS01
	// cleanup can delete its own TXT record even if it needs a fresh connection.
	for _, provider := range r.certificateProviders {
		provider.close()
	}
	var reverseStops sync.WaitGroup
	for _, client := range r.sudokuReverseClients {
		reverseStops.Go(client.stop)
	}
	reverseStops.Wait()
	r.mu.Lock()
	r.closed = true
	r.cancel()
	if r.stopParent != nil {
		r.stopParent()
	}
	for _, listener := range r.listeners {
		_ = listener.Close()
	}
	for _, p := range r.sudokuReverseServers {
		_ = p.listener.Close()
	}
	for _, p := range r.packetListeners {
		_ = p.Close()
	}
	for _, p := range r.directPackets {
		_ = p.Close()
	}
	for _, s := range r.ocServers {
		if s.dtls != nil {
			s.dtls.packet.Close()
		}
	}
	connections := make([]net.Conn, 0, len(r.connections))
	for c := range r.connections {
		connections = append(connections, c)
	}
	sudokuHTTP := make([]*sudokuHTTPSession, 0, len(r.sudokuHTTPSessions))
	for _, session := range r.sudokuHTTPSessions {
		sudokuHTTP = append(sudokuHTTP, session)
	}
	r.mu.Unlock()
	if r.controller != nil {
		r.controller.close()
	}
	r.processes.close()
	for _, s := range r.resolved {
		s.close()
	}
	for _, session := range sudokuHTTP {
		session.Close()
	}
	for _, c := range r.kcpClients {
		c.reset()
	}
	for _, p := range r.cloakClients {
		p.reset()
	}
	for _, p := range r.cloakServers {
		p.reset()
	}
	r.closeKCP(true)
	r.closeMKCP(false)
	for _, g := range r.groups {
		g.close()
	}
	for _, c := range r.sshClients {
		c.close()
	}
	for _, l := range r.wgListeners {
		l.close()
	}
	for _, e := range r.wgEndpoints {
		e.close()
	}
	for _, c := range r.wgClients {
		c.close()
	}
	for _, c := range r.tailscaleClients {
		c.close()
	}
	for _, l := range r.quicListeners {
		l.Close()
	}
	for _, c := range r.trustClients {
		c.reset()
	}
	for _, c := range r.quicClients {
		c.close()
	}
	for _, c := range r.quicTransports {
		c.close()
	}
	for _, t := range r.tunnels {
		t.close()
	}
	for _, server := range r.httpServers {
		_ = server.Close()
	}
	for _, in := range r.config.Inbounds {
		if in.naiveFrontend != nil {
			in.naiveFrontend.transport.CloseIdleConnections()
		}
	}
	for _, client := range r.httpClients {
		client.CloseIdleConnections()
	}
	for _, c := range r.xhttpClients {
		c.reset()
	}
	for _, s := range r.xhttpServers {
		s.close()
	}
	for _, c := range r.ocClients {
		c.reset()
	}
	for _, c := range r.masqueClients {
		c.reset()
	}
	for _, s := range r.masqueServers {
		if s.system != nil {
			s.closeSystem()
		}
	}
	for _, c := range r.mieruClients {
		c.reset()
	}
	for _, l := range r.mieruListeners {
		l.close()
	}
	for _, client := range r.trojanMuxClients {
		client.reset()
	}
	for _, client := range r.sudokuMuxClients {
		client.reset()
	}
	for _, client := range r.genericMuxClients {
		client.reset()
	}
	for _, client := range r.proxyMuxClients {
		client.reset()
	}
	for _, client := range r.snellClients {
		client.close()
	}
	for _, client := range r.anyClients {
		client.close()
	}
	for _, c := range connections {
		_ = c.Close()
	}
	for _, t := range r.tunnels {
		t.workers.Wait()
	}
	r.workers.Wait()
	var usageErr error
	for _, users := range r.sudokuUsers {
		if err := users.save(); err != nil {
			usageErr = errors.Join(usageErr, fmt.Errorf("save Sudoku usage: %w", err))
		}
		if users.lock != nil {
			users.lock.Close()
		}
	}
	if r.resolver != nil {
		r.resolver.Close()
	}
	for _, n := range r.namespaces {
		n.close()
	}
	r.closeLogger()
	return usageErr
}

func (r *Runtime) accept(in Inbound, listener net.Listener) {
	defer r.workers.Done()
	for {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		if r.controller != nil && r.controller.readOnly && in.Type == "sudoku" && in.Sudoku.users == nil {
			c = &controllerWireConn{Conn: c, c: r.controller}
		}
		r.mu.Lock()
		if r.closed || len(r.connections) >= 4096 {
			r.mu.Unlock()
			c.Close()
			continue
		}
		r.connections[c] = struct{}{}
		r.workers.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.workers.Done()
			defer func() { c.Close(); r.mu.Lock(); delete(r.connections, c); r.mu.Unlock() }()
			_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
			if err := r.serve(in, c); err != nil {
				if in.Type == "shadowsocks" && isSS2022(in.Method) {
					if tcp, ok := c.(*net.TCPConn); ok {
						// Uniform RST avoids exposing how many probe bytes were consumed.
						_ = tcp.SetLinger(0)
					}
				}
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && r.ctx.Err() == nil {
					r.logger.Debug("session ended", zap.String("inbound", in.Tag), zap.Error(err))
				}
			}
		}()
	}
}

// Dial applies route rules to a TCP stream or a single-destination UDP session.
func (r *Runtime) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, errors.New("network must be tcp or udp")
	}
	if _, err := encodeAddress(address); err != nil {
		return nil, err
	}
	return r.routeDial(ctx, request{network: network, address: address})
}

var buffers = sync.Pool{New: func() any { return make([]byte, 32*1024) }}
var relaySmallBuffers = sync.Pool{New: func() any { return new([2048]byte) }}

func (r *Runtime) relay(a, b net.Conn) {
	if target, ok := b.(*genericMuxTarget); ok {
		if err := r.serveGenericMux(a, target.request, target.options); err != nil {
			r.logger.Debug("multiplex connection closed", zap.Error(err))
		}
		return
	}
	defer b.Close()
	_ = a.SetDeadline(time.Time{})
	_ = b.SetDeadline(time.Time{})
	done := make(chan struct{})
	copyOne := func(dst, src net.Conn, counter *atomic.Int64) {
		err := copyRelay(dst, src, counter)
		if err != nil {
			r.logger.Debug("proxy relay failed", zap.Error(err))
			a.Close()
			b.Close()
		} else if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go func() { copyOne(b, a, &r.up); close(done) }()
	copyOne(a, b, &r.down)
	<-done
}

// Small interactive streams keep a small buffer; sustained transfers borrow the bulk buffer.
func copyRelay(dst io.Writer, src io.Reader, count *atomic.Int64) error {
	small := relaySmallBuffers.Get().(*[2048]byte)
	defer relaySmallBuffers.Put(small)
	buffer := small[:]
	var bulk []byte
	defer func() {
		if bulk != nil {
			buffers.Put(bulk)
		}
	}()
	for {
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			count.Add(int64(written))
			if writeErr != nil {
				return writeErr
			}
			if written != n {
				return io.ErrShortWrite
			}
			if bulk == nil && n == len(buffer) {
				bulk = buffers.Get().([]byte)
				buffer = bulk
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
	}
}
