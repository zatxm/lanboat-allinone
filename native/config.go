// Package native implements Lanboat's independently written network runtime.
package native

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

const Version = "1.0.0"

type Config struct {
	NetworkNamespaces    []NetworkNamespaceOptions    `json:"network_namespaces,omitempty"`
	Services             []ServiceOptions             `json:"services,omitempty"`
	ExternalController   string                       `json:"external_controller,omitempty"`
	Secret               string                       `json:"secret,omitempty"`
	CertificateProviders []CertificateProviderOptions `json:"certificate_providers,omitempty"`
	Endpoints            []Outbound                   `json:"endpoints,omitempty"`
	HTTPClients          []HTTPClientOptions          `json:"http_clients,omitempty"`
	Experimental         ExperimentalOptions          `json:"experimental,omitempty"`
	Log                  LogOptions                   `json:"log,omitempty"`
	Inbounds             []Inbound                    `json:"inbounds,omitempty"`
	Outbounds            []Outbound                   `json:"outbounds,omitempty"`
	Route                Route                        `json:"route,omitempty"`
	DNS                  DNSConfig                    `json:"dns,omitempty"`
}

type LogOptions struct {
	Disabled bool   `json:"disabled,omitempty"`
	Level    string `json:"level,omitempty"`
	Output   string `json:"output,omitempty"`
	// Timestamp prefixes each line with the local time, as in sing-box.
	Timestamp bool `json:"timestamp,omitempty"`
}

type User struct {
	Flow           string   `json:"flow,omitempty"`
	AuthString     string   `json:"auth_str,omitempty"`
	AuthorizedKeys []string `json:"authorized_keys,omitempty"`
	Token          string   `json:"token,omitempty"`
	Name           string   `json:"name,omitempty"`
	Username       string   `json:"username,omitempty"`
	Password       string   `json:"password,omitempty"`
	UUID           string   `json:"uuid,omitempty"`
	AlterID        int      `json:"alterId,omitempty"`
}

type TLSOptions struct {
	UTLS                             *BrowserTLSOptions   `json:"utls,omitempty"`
	KernelTX                         bool                 `json:"kernel_tx,omitempty"`
	KernelRX                         bool                 `json:"kernel_rx,omitempty"`
	CertificateProvider              certificateReference `json:"certificate_provider,omitempty"`
	provider                         *managedCertificate
	Reality                          *RealityOptions `json:"reality,omitempty"`
	Fragment                         bool            `json:"fragment,omitempty"`
	FragmentFallbackDelay            string          `json:"fragment_fallback_delay,omitempty"`
	RecordFragment                   bool            `json:"record_fragment,omitempty"`
	ECH                              *ECHOptions     `json:"ech,omitempty"`
	Engine                           string          `json:"engine,omitempty"`
	DisableSNI                       bool            `json:"disable_sni,omitempty"`
	MinVersion                       string          `json:"min_version,omitempty"`
	MaxVersion                       string          `json:"max_version,omitempty"`
	CipherSuites                     []string        `json:"cipher_suites,omitempty"`
	CurvePreferences                 []string        `json:"curve_preferences,omitempty"`
	CertificateSHA256                []string        `json:"certificate_sha256,omitempty"`
	CertificatePublicKeySHA256       []string        `json:"certificate_public_key_sha256,omitempty"`
	ClientCertificateSHA256          []string        `json:"client_certificate_sha256,omitempty"`
	ClientCertificatePublicKeySHA256 []string        `json:"client_certificate_public_key_sha256,omitempty"`
	Enabled                          bool            `json:"enabled,omitempty"`
	ServerName                       string          `json:"server_name,omitempty"`
	Insecure                         bool            `json:"insecure,omitempty"`
	ALPN                             []string        `json:"alpn,omitempty"`
	Certificate                      []string        `json:"certificate,omitempty"`
	CertificatePath                  string          `json:"certificate_path,omitempty"`
	Key                              []string        `json:"key,omitempty"`
	KeyPath                          string          `json:"key_path,omitempty"`
	ClientAuthentication             string          `json:"client_authentication,omitempty"`
	ClientCertificate                []string        `json:"client_certificate,omitempty"`
	ClientCertificatePath            []string        `json:"client_certificate_path,omitempty"`
	ClientKey                        []string        `json:"client_key,omitempty"`
	ClientKeyPath                    string          `json:"client_key_path,omitempty"`
	PKCS12                           string          `json:"pkcs12,omitempty"`
	PKCS12Path                       string          `json:"pkcs12_path,omitempty"`
	PKCS12Password                   string          `json:"pkcs12_password,omitempty"`
}

type Inbound struct {
	Multiplex MultiplexOptions `json:"multiplex,omitzero"`
	ListenOptions
	QUICCongestionControl string `json:"quic_congestion_control,omitempty"`
	NaiveFrontend         string `json:"naive_frontend,omitempty"`
	naiveFrontend         *naiveFrontend
	Destinations          []ShadowsocksDestination `json:"destinations,omitempty"`
	sudokuAccount         *sudokuAccount
	Sudoku                *SudokuOptions `json:"sudoku,omitempty"`
	OverrideAddress       string         `json:"override_address,omitempty"`
	OverridePort          uint16         `json:"override_port,omitempty"`
	MieruOptions
	endpointSystem bool
	exclusiveTUN   bool
	ShadowTLSOptions
	Detour string `json:"detour,omitempty"`
	SIP003Options
	MasqueOptions
	OpenConnectOptions
	QUICReceiveWindows
	CongestionControl string                    `json:"congestion_control,omitempty"`
	BBRProfile        string                    `json:"bbr_profile,omitempty"`
	Bind              bool                      `json:"bind,omitempty"`
	Network           string                    `json:"network,omitempty"`
	Shadowsocks       *TrojanShadowsocksOptions `json:"shadowsocks,omitempty"`
	HTTPVersion       int                       `json:"http_version,omitempty"`
	BrookOptions
	WireGuardOptions
	SSHOptions
	UpMbps                        int          `json:"up_mbps,omitempty"`
	DownMbps                      int          `json:"down_mbps,omitempty"`
	IgnoreClientBandwidth         bool         `json:"ignore_client_bandwidth,omitempty"`
	DisableLossCompensation       bool         `json:"disable_loss_compensation,omitempty"`
	InterfaceName                 string       `json:"interface_name,omitempty"`
	Address                       []string     `json:"address,omitempty"`
	MTU                           int          `json:"mtu,omitempty"`
	AutoRoute                     bool         `json:"auto_route,omitempty"`
	AutoRedirect                  bool         `json:"auto_redirect,omitempty"`
	AutoRedirectInputMark         FirewallMark `json:"auto_redirect_input_mark,omitempty"`
	AutoRedirectOutputMark        FirewallMark `json:"auto_redirect_output_mark,omitempty"`
	AutoRedirectResetMark         FirewallMark `json:"auto_redirect_reset_mark,omitempty"`
	AutoRedirectTProxyMark        FirewallMark `json:"auto_redirect_tproxy_mark,omitempty"`
	AutoRedirectNFQueue           *uint16      `json:"auto_redirect_nfqueue,omitempty"`
	AutoRedirectFallbackRuleIndex uint32       `json:"auto_redirect_iproute2_fallback_rule_index,omitempty"`
	ExcludeMPTCP                  bool         `json:"exclude_mptcp,omitempty"`
	IncludeInterface              []string     `json:"include_interface,omitempty"`
	ExcludeInterface              []string     `json:"exclude_interface,omitempty"`
	IncludeUID                    []uint32     `json:"include_uid,omitempty"`
	ExcludeUID                    []uint32     `json:"exclude_uid,omitempty"`
	IncludeUIDRange               []string     `json:"include_uid_range,omitempty"`
	ExcludeUIDRange               []string     `json:"exclude_uid_range,omitempty"`
	IncludeMACAddress             []string     `json:"include_mac_address,omitempty"`
	ExcludeMACAddress             []string     `json:"exclude_mac_address,omitempty"`
	DNSMode                       string       `json:"dns_mode,omitempty"`
	DNSAddress                    []string     `json:"dns_address,omitempty"`
	MultiQueue                    bool         `json:"multi_queue,omitempty"`
	RouteAddress                  []string     `json:"route_address,omitempty"`
	RouteExcludeAddress           []string     `json:"route_exclude_address,omitempty"`
	RouteAddressSet               []string     `json:"route_address_set,omitempty"`
	RouteExcludeAddressSet        []string     `json:"route_exclude_address_set,omitempty"`
	LoopbackAddress               []string     `json:"loopback_address,omitempty"`
	UDPTimeout                    string       `json:"udp_timeout,omitempty"`
	IPRoute2TableIndex            uint32       `json:"iproute2_table_index,omitempty"`
	IPRoute2RuleIndex             uint32       `json:"iproute2_rule_index,omitempty"`
	StrictRoute                   bool         `json:"strict_route,omitempty"`
	Type                          string       `json:"type"`
	Tag                           string       `json:"tag,omitempty"`
	Listen                        string       `json:"listen,omitempty"`
	ListenPort                    uint16       `json:"listen_port"`
	Users                         []User       `json:"users,omitempty"`
	Method                        string       `json:"method,omitempty"`
	OTA                           bool         `json:"ota,omitempty"`
	Version                       string       `json:"version,omitempty"`
	Password                      string       `json:"password,omitempty"`
	TLS                           TLSOptions   `json:"tls,omitempty"`
	Transport                     Transport    `json:"transport,omitzero"`
	PaddingScheme                 []string     `json:"padding_scheme,omitempty"`
	Protocol                      string       `json:"protocol,omitempty"`
	ProtocolParam                 string       `json:"protocol_param,omitempty"`
	Obfs                          Obfuscation  `json:"obfs,omitempty"`
	ObfsParam                     string       `json:"obfs_param,omitempty"`
}

type Outbound struct {
	wgEndpoint *wgEndpointOptions
	ocEndpoint *ocEndpointOptions
	DialOptions
	QUICCongestionControl string `json:"quic_congestion_control,omitempty"`
	LuaOptions
	Sudoku *SudokuOptions `json:"sudoku,omitempty"`
	Flow   string         `json:"flow,omitempty"`
	MieruOptions
	Network string `json:"network,omitempty"`
	ShadowTLSOptions
	TailscaleOptions
	HysteriaHopOptions
	SIP003Options
	MasqueOptions
	OpenConnectOptions
	QUICReceiveWindows
	CongestionControl   string                    `json:"congestion_control,omitempty"`
	BBRProfile          string                    `json:"bbr_profile,omitempty"`
	QUIC                bool                      `json:"quic,omitempty"`
	ExtraHeaders        map[string]headerValues   `json:"extra_headers,omitempty"`
	Shadowsocks         *TrojanShadowsocksOptions `json:"shadowsocks,omitempty"`
	GlobalPadding       bool                      `json:"global_padding,omitempty"`
	AuthenticatedLength bool                      `json:"authenticated_length,omitempty"`
	HTTPVersion         int                       `json:"http_version,omitempty"`
	BrookOptions
	DomainResolver            resolverReference `json:"domain_resolver,omitempty"`
	Outbounds                 []string          `json:"outbounds,omitempty"`
	Default                   string            `json:"default,omitempty"`
	URL                       string            `json:"url,omitempty"`
	Interval                  string            `json:"interval,omitempty"`
	Tolerance                 *uint16           `json:"tolerance,omitempty"`
	IdleTimeout               string            `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool              `json:"interrupt_exist_connections,omitempty"`
	PinnedCertchainSHA256     string            `json:"pinned_certchain_sha256,omitempty"`
	AuthString                string            `json:"auth_str,omitempty"`
	MTU                       int               `json:"mtu,omitempty"`
	WireGuardOptions
	SSHOptions
	Token                    string           `json:"token,omitempty"`
	UpMbps                   int              `json:"up_mbps,omitempty"`
	DownMbps                 int              `json:"down_mbps,omitempty"`
	DisableLossCompensation  bool             `json:"disable_loss_compensation,omitempty"`
	Multiplex                MultiplexOptions `json:"multiplex,omitzero"`
	UDPRelayMode             string           `json:"udp_relay_mode,omitempty"`
	Type                     string           `json:"type"`
	Tag                      string           `json:"tag"`
	Server                   string           `json:"server,omitempty"`
	ServerPort               uint16           `json:"server_port,omitempty"`
	Username                 string           `json:"username,omitempty"`
	Password                 string           `json:"password,omitempty"`
	UUID                     string           `json:"uuid,omitempty"`
	Method                   string           `json:"method,omitempty"`
	OTA                      bool             `json:"ota,omitempty"`
	Version                  string           `json:"version,omitempty"`
	Security                 string           `json:"security,omitempty"`
	AlterID                  int              `json:"alter_id,omitempty"`
	IdleSessionTimeout       string           `json:"idle_session_timeout,omitempty"`
	IdleSessionCheckInterval string           `json:"idle_session_check_interval,omitempty"`
	MinIdleSession           *int             `json:"min_idle_session,omitempty"`
	TLS                      TLSOptions       `json:"tls,omitempty"`
	Transport                Transport        `json:"transport,omitzero"`
	Detour                   string           `json:"detour,omitempty"`
	Protocol                 string           `json:"protocol,omitempty"`
	ProtocolParam            string           `json:"protocol_param,omitempty"`
	Obfs                     Obfuscation      `json:"obfs,omitempty"`
	ObfsParam                string           `json:"obfs_param,omitempty"`
}

func Parse(raw []byte) (Config, error) {
	var cfg Config
	if data := bytes.TrimSpace(raw); len(data) == 0 || data[0] != '{' {
		return cfg, errors.New("configuration must be a JSON object")
	}
	raw, endpoints, err := extractNativeEndpoints(raw)
	if err != nil {
		return cfg, err
	}
	if err := decodeOptions(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decode compatible configuration: %w", err)
	}
	if err := validateNamespaces(cfg.NetworkNamespaces); err != nil {
		return cfg, err
	}
	for _, ep := range endpoints.masque {
		if err := ep.appendTo(&cfg); err != nil {
			return cfg, err
		}
	}
	for i := range endpoints.wireguard {
		ep := &endpoints.wireguard[i]
		if ep.Tag == "" {
			ep.Tag = fmt.Sprintf("wireguard-endpoint-%d", i)
		}
		cfg.Outbounds = append(cfg.Outbounds, Outbound{Type: "wireguard", Tag: ep.Tag, DialOptions: ep.DialOptions, Detour: ep.Detour, DomainResolver: ep.DomainResolver, wgEndpoint: ep})
	}
	for i := range endpoints.openconnect {
		ep := &endpoints.openconnect[i]
		if ep.Tag == "" {
			ep.Tag = fmt.Sprintf("openconnect-endpoint-%d", i)
		}
		out, err := ep.outbound()
		if err != nil {
			return cfg, fmt.Errorf("OpenConnect endpoint %q: %w", ep.Tag, err)
		}
		cfg.Outbounds = append(cfg.Outbounds, out)
	}
	for _, ep := range cfg.Endpoints {
		if ep.Type != "tailscale" {
			return cfg, fmt.Errorf("unsupported endpoint type %q", ep.Type)
		}
		cfg.Outbounds = append(cfg.Outbounds, ep)
	}
	cfg.Endpoints = nil
	for i := range cfg.Outbounds {
		o := &cfg.Outbounds[i]
		if err := o.BrookOptions.prepare(o.Type); err != nil {
			return cfg, err
		}
		if err := o.LuaOptions.prepare(o.Type); err != nil {
			return cfg, err
		}
		pluginTLS := o.TLS
		if o.Type == "lua" {
			pluginTLS = TLSOptions{}
		}
		if err := o.SIP003Options.prepare(o.Type, o.Transport, pluginTLS, false); err != nil {
			return cfg, err
		}
		if e := prepareMasqueIdentity(o); e != nil {
			return cfg, e
		}
		if o.Tag == "" {
			o.Tag = fmt.Sprintf("outbound-%d", i)
		}
		if o.Type == "hysteria" {
			if o.Password == "" {
				o.Password = o.AuthString
			} else if o.AuthString != "" && o.Password != o.AuthString {
				return cfg, errors.New("HY1 password conflicts with auth_str")
			}
		}
	}
	for i := range cfg.DNS.Servers {
		if cfg.DNS.Servers[i].Tag == "" {
			cfg.DNS.Servers[i].Tag = fmt.Sprintf("dns-%d", i)
		}
	}
	for i := range cfg.Inbounds {
		in := &cfg.Inbounds[i]
		if err := in.BrookOptions.prepare(in.Type); err != nil {
			return cfg, err
		}
		if err := in.SIP003Options.prepare(in.Type, in.Transport, in.TLS, true); err != nil {
			return cfg, err
		}
		if in.Type == "hysteria" {
			for j := range in.Users {
				u := &in.Users[j]
				if u.Password == "" {
					u.Password = u.AuthString
				} else if u.AuthString != "" && u.Password != u.AuthString {
					return cfg, errors.New("HY1 user password conflicts with auth_str")
				}
			}
		}
	}
	var sets []RuleSet
	for _, s := range cfg.Route.RuleSet {
		tags := s.tags
		if len(tags) == 0 {
			tags = []string{s.Tag}
		}
		if len(tags) > 1 && s.Type == "inline" {
			return cfg, errors.New("inline rule_set cannot have multiple tags")
		}
		for _, tag := range tags {
			item := s
			item.Tag = tag
			item.tags = nil
			item.Path = strings.ReplaceAll(s.Path, "{tag}", tag)
			item.URL = strings.ReplaceAll(s.URL, "{tag}", tag)
			item.InitialPath = strings.ReplaceAll(s.InitialPath, "{tag}", tag)
			if len(tags) > 1 && !strings.Contains(s.Path+s.URL+s.InitialPath, "{tag}") {
				return cfg, errors.New("multiple rule_set tags require a {tag} placeholder")
			}
			sets = append(sets, item)
		}
	}
	cfg.Route.RuleSet = sets
	if err := cfg.prepareResolved(); err != nil {
		return cfg, err
	}
	if len(cfg.Outbounds) == 0 {
		cfg.Outbounds = []Outbound{{Type: "direct", Tag: "direct"}}
	}
	if cfg.Route.Final == "" {
		cfg.Route.Final = cfg.Outbounds[0].Tag
	}
	for _, in := range cfg.Inbounds {
		if in.Type == "masque" && in.endpoint {
			cfg.Outbounds = append(cfg.Outbounds, Outbound{Type: "masque-server", Tag: in.Tag, MasqueOptions: MasqueOptions{reverse: true}})
		}
	}
	return cfg, cfg.validate()
}

func (c Config) validate() error {
	if err := validateNeighborOptions(c.Route); err != nil {
		return err
	}
	if _, err := c.controllerOptions(); err != nil {
		return err
	}
	if err := c.validateCertificateProviders(); err != nil {
		return err
	}
	if _, err := c.Experimental.CacheFile.bufferSize(); err != nil {
		return err
	}
	if _, err := optionDuration(c.Experimental.CacheFile.FlushInterval, 0); err != nil {
		return err
	}
	clients := map[string]bool{}
	for _, o := range c.HTTPClients {
		if o.Tag == "" || clients[o.Tag] {
			return errors.New("HTTP client tags must be unique and nonempty")
		}
		clients[o.Tag] = true
		if e := o.validate(); e != nil {
			return e
		}
	}
	if c.Route.DefaultHTTPClient != "" && !clients[c.Route.DefaultHTTPClient] {
		return errors.New("unknown default_http_client")
	}
	tags := make(map[string]Outbound, len(c.Outbounds))
	for index, o := range c.Outbounds {
		if err := o.DialOptions.validate(); err != nil {
			return fmt.Errorf("outbound %s: %w", o.Tag, err)
		}
		if o.Type == "sudoku" || o.Sudoku != nil {
			if o.Type != "sudoku" {
				return errors.New("sudoku options require sudoku type")
			}
			if err := o.Sudoku.prepareClient(); err != nil {
				return err
			}
		}
		if o.TLS.realityEnabled() && o.Plugin != "" {
			return errors.New("Reality and SIP003 plugins must use separate proxy detours")
		}
		if err := validateRealityTransport(o.Type, o.TLS, o.Transport); err != nil {
			return err
		}
		if e := validateShadowTLSClient(o.Type, o.Version, o.Password, o.TLS, o.ShadowTLSOptions, o.Transport); e != nil {
			return e
		}
		if o.Type != "tailscale" && !o.TailscaleOptions.empty() {
			return errors.New("Tailscale options require tailscale type")
		}
		if err := o.HysteriaHopOptions.validate(o.Type, o.ServerPort); err != nil {
			return err
		}
		if e := o.OpenConnectOptions.validate(o.Type, o.TLS, o.Transport, o.MTU, o.LocalAddress); e != nil {
			return e
		}
		if o.Type == "openconnect" && len(o.LocalAddress) > 0 {
			return errors.New("OpenConnect local addresses are assigned by the server")
		}
		if o.Type == "openconnect" && (len(o.OpenConnectOptions.DNS)+len(o.SearchDomains)+len(o.SplitDNS) > 0 || o.TunnelAllDNS) {
			return errors.New("OpenConnect pushed DNS options are inbound-only")
		}
		if o.RekeyTime != "" || o.RekeyMethod != "" || o.DTLSRekeyTime != "" || o.DTLSRekeyMethod != "" {
			return errors.New("OpenConnect rekey_time and dtls_rekey_time are server options")
		}
		if o.Type == "openconnect" && len(o.SplitInclude)+len(o.SplitExclude) > 0 {
			return errors.New("OpenConnect split_include/split_exclude are inbound-only")
		}
		if o.Type == "openconnect" && (len(o.Username) > 255 || len(o.Password) > 255) {
			return errors.New("OpenConnect username and password must be at most255 bytes")
		}
		if e := c.Outbounds[index].MasqueOptions.validate(o.Type, o.TLS, o.HTTPVersion, o.MTU, o.LocalAddress, false); e != nil {
			return e
		}
		if err := validateNaiveHeaders(o.Type, o.ExtraHeaders, o.QUIC, ""); err != nil {
			return err
		}
		if err := validateNaiveCongestion(o.Type, o.QUICCongestionControl, o.QUIC, false); err != nil {
			return err
		}
		if err := o.Shadowsocks.validate(o.Type); err != nil {
			return err
		}
		if o.GlobalPadding || o.AuthenticatedLength {
			if o.Type != "vmess" {
				return errors.New("global_padding and authenticated_length require vmess type")
			}
			security, err := vmessSecurity(o.Security)
			if err != nil || security != 3 && security != 4 {
				return errors.New("VMess padding and authenticated_length require an AEAD body cipher")
			}
		}
		if err := o.BrookOptions.validate(o.Type, o.Password, o.Transport, o.TLS.Enabled); err != nil {
			return err
		}
		if o.Tag == "" {
			return errors.New("outbound tag is required")
		}
		if _, exists := tags[o.Tag]; exists {
			return fmt.Errorf("duplicate outbound tag %q", o.Tag)
		}
		tags[o.Tag] = o
		if o.Type != "shadowsocksr" && (o.Protocol != "" && o.Type != "hysteria" || o.ProtocolParam != "" || o.Obfs != "" && o.Type != "hysteria2" && o.Type != "hysteria" && o.Type != "snell" || o.ObfsParam != "" && o.Type != "snell") {
			return errors.New("SSR options require shadowsocksr type")
		}
		if o.Type == "shadowsocksr" && o.ObfsParam != "" && (len(o.ObfsParam) > 253 || !validHTTPHost(strings.Split(o.ObfsParam, ",")[0])) {
			return errors.New("invalid SSR obfs_param hostname")
		}
		if err := o.Transport.validateFor(o.Type); err != nil {
			return fmt.Errorf("outbound %s: %w", o.Tag, err)
		}
		if err := validateQUICTransport(o.Transport, o.TLS); err != nil {
			return err
		}
		if err := validateVision(o.Type, o.Flow, o.TLS, o.Transport, o.Multiplex.Enabled, o.Plugin); err != nil {
			return err
		}
		if o.Flow != "" && o.Shadowsocks != nil && o.Shadowsocks.Enabled {
			return errors.New("Vision cannot use secondary Shadowsocks encryption")
		}
		if o.Network != "" && o.Type != "mieru" {
			return errors.New("outbound network requires Mieru")
		}
		if err := o.MieruOptions.validate(o.Type, o.Network, o.TLS, o.MTU); err != nil {
			return err
		}
		if o.Type == "mieru" && (o.Username == "" || len(o.Username) > 64 || o.Password == "" || len(o.Password) > 1024) {
			return errors.New("Mieru username(1-64bytes) and password(1-1024bytes) required")
		}
		switch o.Type {
		case "masque-server":
			if !o.reverse {
				return errors.New("masque-server must be configured as an endpoint")
			}
		case "tailscale":
			if err := o.TailscaleOptions.validate(o); err != nil {
				return err
			}
		case "selector", "urltest":
			if err := validateGroup(o); err != nil {
				return err
			}
		case "direct", "block":
			if o.Server != "" || o.TLS.Enabled || o.Detour != "" {
				return fmt.Errorf("%s outbound cannot have server, TLS or detour options", o.Type)
			}
		case "socks", "http", "shadowsocks", "shadowsocksr", "trojan", "vless", "vmess", "anytls", "relay", "snell", "ssh", "wireguard", "hysteria", "hysteria2", "tuic", "juicity", "brook", "trusttunnel", "naive", "masque", "openconnect", "shadowtls", "mieru", "sudoku", "lua":
			if o.wgEndpoint != nil {
				if err := o.wgEndpoint.validate(); err != nil {
					return err
				}
				break
			}
			if o.Server == "" || o.ServerPort == 0 && len(o.ServerPorts) == 0 {
				return fmt.Errorf("outbound %q requires server and server_port (1-65535)", o.Tag)
			}
		default:
			return fmt.Errorf("independent runtime has no %q outbound implementation", o.Type)
		}
		if o.Type == "lua" {
			if o.Password == "" {
				return errors.New("Lua password required")
			}
			if _, err := newLuaBackend(nil, o, "example.com:443"); err != nil {
				return fmt.Errorf("Lua backend initialization: %w", err)
			}
		}
		if o.Type == "naive" {
			if err := validateNaiveTLS(o.TLS, !o.QUIC, o.QUIC); err != nil {
				return err
			}
		}
		if err := validateTrustOptions(o.Type, o.HTTPVersion, o.TLS); err != nil {
			return err
		}
		if (o.Type == "trusttunnel" || o.Type == "naive" || o.Type == "masque" && (o.Username != "" || o.Password != "")) && (o.Username == "" || o.Password == "" || len(o.Username) > 255 || len(o.Password) > 255 || strings.Contains(o.Username, ":")) {
			return errors.New("TrustTunnel requires username (without colon) and password")
		}
		if o.UDPRelayMode != "" && (o.Type != "tuic" || o.UDPRelayMode != "native" && o.UDPRelayMode != "quic") {
			return errors.New("udp_relay_mode must be native or quic for TUIC")
		}
		if err := validateQUICCongestion(o.Type, o.CongestionControl); err != nil {
			return err
		}
		if err := o.QUICReceiveWindows.validate(); err != nil {
			return err
		}
		if err := validateBBRProfile(o.Type, o.CongestionControl, o.BBRProfile); err != nil {
			return err
		}
		if err := validateHYBandwidth(o.Type, o.UpMbps, o.DownMbps, false, o.DisableLossCompensation); err != nil {
			return err
		}
		if (o.Type == "wireguard" || o.Type == "ssh") && o.TLS.Enabled {
			return errors.New("SSH and WireGuard use their own authenticated transport; tls must be disabled")
		}
		if o.Type == "wireguard" && o.wgEndpoint == nil {
			if err := o.WireGuardOptions.validate(o.PrivateKey, false, o.MTU); err != nil {
				return err
			}
			if len(o.Peers) > 1 {
				return errors.New("WireGuard outbound supports one peer per outbound")
			}
			if o.MTU != 0 && (o.MTU < 1280 || o.MTU > 65507) {
				return errors.New("WireGuard MTU must be 1280-65507")
			}
		}
		if o.Amnezia != nil && o.Type != "wireguard" {
			return errors.New("amnezia options require wireguard type")
		}
		if o.WGObfs != nil && o.Type != "wireguard" {
			return errors.New("wgobfs options require wireguard type")
		}
		if o.Type == "ssh" {
			if err := o.SSHOptions.validate(false); err != nil {
				return err
			}
			if o.Username == "" {
				return errors.New("SSH username required")
			}
			if o.Password == "" && o.PrivateKeyPath == "" && len(o.PrivateKey) == 0 && o.KeyboardInteractive == nil {
				return errors.New("SSH password, private key or interactive answers required")
			}
		}
		if o.Type == "socks" && o.Version != "" && o.Version != "4" && o.Version != "5" {
			return errors.New("SOCKS version must be 5")
		}
		if o.Type == "snell" {
			if _, e := o.Obfs.snellOptions(o.ObfsParam, o.Version); e != nil {
				return e
			}
		}
		if o.Type == "snell" && (snellVersion(o.Version) < 1 || snellVersion(o.Version) > 5 || o.Password == "") {
			return errors.New("Snell requires a password and version 1-5")
		}
		if o.Type == "shadowsocks" {
			if _, err := newSSKey(o.Method, o.Password); err != nil {
				return err
			}
		}
		if o.OTA {
			if err := validateSSOTA(o.Type, o.Method); err != nil {
				return err
			}
		}
		if o.Type == "shadowsocksr" {
			if err := validateSSR(o.Method, o.Password, o.Protocol, o.ProtocolParam, string(o.Obfs)); err != nil {
				return err
			}
		}
		if (o.Type == "trojan" || o.Type == "anytls") && (!o.TLS.Enabled || o.Password == "") {
			return fmt.Errorf("%s requires TLS and a password", o.Type)
		}
		if o.Multiplex.Enabled && o.Type == "snell" && snellVersion(o.Version) != 2 && snellVersion(o.Version) < 4 {
			return errors.New("Snell multiplex requires version 2, 4 or 5")
		}
		if err := o.Multiplex.validate(o.Type, false); err != nil {
			return fmt.Errorf("outbound %q: %w", o.Tag, err)
		}
		if o.Type == "snell" && (o.IdleSessionCheckInterval != "" || o.MinIdleSession != nil) {
			return errors.New("Snell pool uses idle_session_timeout; AnyTLS idle-session settings are not supported")
		}
		if o.Type == "anytls" || o.Type == "snell" {
			for _, value := range []string{o.IdleSessionTimeout, o.IdleSessionCheckInterval} {
				if value != "" {
					d, err := time.ParseDuration(value)
					if err != nil || d <= 0 || d > 24*time.Hour {
						return errors.New("AnyTLS idle durations must be positive and at most 24h")
					}
				}
			}
			if o.MinIdleSession != nil && (*o.MinIdleSession < 0 || *o.MinIdleSession > 64) {
				return errors.New("AnyTLS min_idle_session must be 0-64")
			}
		}
		if o.Type == "hysteria" {
			if o.Protocol != "" && o.Protocol != "udp" && o.Protocol != "wechat-video" && o.Protocol != "faketcp" {
				return errors.New("HY1 protocol must be udp, wechat-video or faketcp")
			}
			if o.Protocol == "faketcp" {
				if err := fakeTCPPlatform(); err != nil {
					return err
				}
				if o.Detour != "" || len(o.ServerPorts) != 0 {
					return errors.New("HY1 FakeTCP uses direct raw TCP; detour and port hopping are UDP-only")
				}
			}
			if len(o.Password) > 4096 || len(o.Obfs) > 4096 || len(o.Obfs) > 0 && o.Obfs[0] == '{' {
				return errors.New("invalid HY1 or XPlus password")
			}
		}
		if o.Type == "hysteria2" {
			if _, e := o.Obfs.quicSettings(); e != nil {
				return e
			}
		}
		if isQUICProxy(o.Type) && (!o.TLS.Enabled || o.Password == "" && o.Token == "") {
			return errors.New("QUIC proxy requires TLS and a password")
		}
		if o.Type == "tuic" && o.Version != "" && o.Version != "4" && o.Version != "5" {
			return errors.New("TUIC version must be 4 or 5")
		}
		if o.PinnedCertchainSHA256 != "" {
			if o.Type != "juicity" {
				return errors.New("pinned_certchain_sha256 requires Juicity")
			}
			if _, e := juicityPin(o.PinnedCertchainSHA256); e != nil {
				return e
			}
		}
		if o.Type == "vless" || o.Type == "vmess" || o.Type == "juicity" || o.Type == "tuic" && o.Version != "4" {
			if _, err := parseUUID(o.UUID); err != nil {
				return err
			}
		}
		if o.Type == "vmess" {
			if o.AlterID < 0 {
				return errors.New("VMess alter_id cannot be negative")
			}
			if _, err := vmessSecurity(o.Security); err != nil {
				return err
			}
		}
		if o.Type == "socks" && (len(o.Username) > 255 || len(o.Password) > 255) {
			return errors.New("SOCKS credentials cannot exceed 255 bytes")
		}
		if o.Type == "socks" && (o.Username == "") != (o.Password == "") {
			return errors.New("SOCKS authentication requires both username and password")
		}
		if o.Type == "relay" && (len(o.Username) > 255 || len(o.Password) > 255) {
			return errors.New("Relay credentials cannot exceed 255 bytes")
		}
		if _, err := o.TLS.config(false, o.Server); err != nil {
			return fmt.Errorf("outbound %s: %w", o.Tag, err)
		}
		if isQUICProxy(o.Type) {
			if err := o.TLS.validateQUICVersion(); err != nil {
				return err
			}
		}
	}
	for tag := range tags {
		seen := map[string]bool{}
		for tag != "" {
			if seen[tag] {
				return errors.New("outbound detour cycle")
			}
			seen[tag] = true
			o, exists := tags[tag]
			if !exists {
				return fmt.Errorf("unknown outbound detour %q", tag)
			}
			tag = o.Detour
		}
	}
	if err := validateOutboundGraph(tags); err != nil {
		return err
	}
	tunCount := 0
	for index, in := range c.Inbounds {
		if err := in.Multiplex.validate(in.Type, true); err != nil {
			return fmt.Errorf("inbound %q: %w", in.Tag, err)
		}
		if in.UDPTimeout != "" {
			if _, err := optionDuration(in.UDPTimeout, udpTimeout); err != nil {
				return fmt.Errorf("inbound %s UDP timeout: %w", in.Tag, err)
			}
		}
		if err := in.ListenOptions.validate(in.Type); err != nil {
			return fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		if len(in.Destinations) > 0 && in.Type != "shadowsocks" {
			return errors.New("destinations requires a Shadowsocks2022 AES relay inbound")
		}
		if in.Type == "sudoku" || in.Sudoku != nil {
			if in.Type != "sudoku" {
				return errors.New("sudoku options require sudoku type")
			}
			if err := in.Sudoku.prepare(); err != nil {
				return err
			}
			if len(in.Users) != 0 {
				return errors.New("Sudoku users must be configured inside sudoku.users")
			}
		}
		if err := in.validateDirect(); err != nil {
			return err
		}
		if len(in.AuthForm) > 0 || in.AuthTimeout != "" || in.DisableExternalAuth {
			return errors.New("auth_form/auth_timeout/disable_external_auth are OpenConnect outbound options")
		}
		if in.System || in.Name != "" {
			return errors.New("system/name are OpenConnect outbound options")
		}
		if in.TLS.realityEnabled() && in.Plugin != "" {
			return errors.New("Reality and SIP003 plugins must use separate inbounds")
		}
		if err := validateRealityTransport(in.Type, in.TLS, in.Transport); err != nil {
			return err
		}
		if in.TLS.realityEnabled() {
			if in.TLS.Reality.Handshake == nil {
				return errors.New("Reality server handshake is required")
			}
			if err := in.TLS.Reality.Handshake.validate(false, tags); err != nil {
				return err
			}
		}
		if e := in.OpenConnectOptions.validate(in.Type, in.TLS, in.Transport, in.MTU, in.Address); e != nil {
			return e
		}
		if e := c.Inbounds[index].MasqueOptions.validate(in.Type, in.TLS, in.HTTPVersion, in.MTU, in.Address, true); e != nil {
			return e
		}
		if in.Type == "masque" {
			for _, v := range in.Address {
				p, e := netip.ParsePrefix(v)
				if e != nil || p != p.Masked() {
					return errors.New("MASQUE assigned prefixes must be canonical")
				}
			}
		}
		if in.Type == "masque" && (len(in.PrivateKey) > 0 || in.MasquePublicKey != "") {
			return errors.New("MASQUE inbound identity andtrust use TLS certificate/client_certificate options")
		}
		if in.Type == "masque" && !in.endpoint && len(in.Users) == 0 && in.TLS.ClientAuthentication != "require-and-verify" {
			return errors.New("MASQUE authenticated users required")
		}
		if err := in.Shadowsocks.validate(in.Type); err != nil {
			return err
		}
		if err := in.BrookOptions.validate(in.Type, in.Password, in.Transport, in.TLS.Enabled); err != nil {
			return err
		}
		if in.Type == "brook" && (len(in.Users) != 0 || in.UDPOverTCP || in.UDPOverStream) {
			return errors.New("Brook inbound uses password; udp_over_tcp/udp_over_stream are outbound options")
		}
		if in.Type != "shadowsocksr" && (in.Protocol != "" && in.Type != "hysteria" || in.ProtocolParam != "" || in.Obfs != "" && in.Type != "hysteria2" && in.Type != "hysteria" && in.Type != "snell" || in.ObfsParam != "" && in.Type != "snell") {
			return errors.New("SSR options require shadowsocksr type")
		}
		if in.Type == "shadowsocksr" && in.ObfsParam != "" && (len(in.ObfsParam) > 253 || !validHTTPHost(strings.Split(in.ObfsParam, ",")[0])) {
			return errors.New("invalid SSR obfs_param hostname")
		}
		if (in.Type == "wireguard" || in.Type == "ssh") && in.TLS.Enabled {
			return errors.New("SSH and WireGuard use their own authenticated transport; tls must be disabled")
		}
		if in.Type == "wireguard" {
			if err := in.WireGuardOptions.validate(in.PrivateKey, true, in.MTU); err != nil {
				return err
			}
			if in.MTU != 0 && (in.MTU < 1280 || in.MTU > 65507) {
				return errors.New("WireGuard MTU must be 1280-65507")
			}
		}
		if in.Amnezia != nil && in.Type != "wireguard" {
			return errors.New("amnezia options require wireguard type")
		}
		if in.WGObfs != nil && in.Type != "wireguard" {
			return errors.New("wgobfs options require wireguard type")
		}
		if in.Type == "ssh" {
			if err := in.SSHOptions.validate(true); err != nil {
				return err
			}
			if len(in.Users) == 0 {
				return errors.New("SSH inbound users required")
			}
			for _, u := range in.Users {
				if sshUserName(u) == "" || u.Password == "" && len(u.AuthorizedKeys) == 0 {
					return errors.New("SSH username and password or authorized_keys required")
				}
			}
		}
		if in.Type == "tun" {
			if err := in.validateRedirect(); err != nil {
				return err
			}
			if in.AutoRedirect && c.Route.DefaultMark != 0 {
				return errors.New("auto_redirect conflicts with route.default_mark")
			}
			tunCount++
			if tunCount > 1 {
				return errors.New("one TUN interface per runtime is supported")
			}
			if err := validateTUNPlatform(in); err != nil {
				return err
			}
			if in.IPRoute2RuleIndex > 0 && in.IPRoute2RuleIndex < 100 {
				return errors.New("TUN rule index must be at least100")
			}
			if in.DNSMode != "" && in.DNSMode != "disabled" && in.DNSMode != "native" && in.DNSMode != "hijack" && in.DNSMode != "routed" {
				return errors.New("invalid TUN dns_mode")
			}
			for _, a := range in.DNSAddress {
				if ip, e := netip.ParseAddr(a); e != nil || !ip.IsGlobalUnicast() || ip.Zone() != "" {
					return errors.New("invalid TUN DNS address")
				}
			}
			for _, a := range in.LoopbackAddress {
				if ip, e := netip.ParseAddr(a); e != nil || !ip.IsGlobalUnicast() || ip.Zone() != "" {
					return errors.New("invalid TUN loopback address")
				}
			}

			for _, tag := range append(append([]string{}, in.RouteAddressSet...), in.RouteExcludeAddressSet...) {
				found := false
				for _, set := range c.Route.RuleSet {
					if set.Tag == tag {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("unknown TUN route rule_set %q", tag)
				}
			}
			for _, a := range append(append([]string{}, in.RouteAddress...), in.RouteExcludeAddress...) {
				if _, e := netip.ParsePrefix(a); e != nil {
					return e
				}
			}
			if in.MTU != 0 && (in.MTU < 1280 || in.MTU > 65535) {
				return errors.New("TUN MTU must be 1280-65535")
			}
			for _, address := range in.Address {
				if p, err := netip.ParsePrefix(address); err != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().Zone() != "" {
					return errors.New("invalid TUN interface address")
				}
			}
			if tunDNSMode(in) != "disabled" && len(in.DNSAddress) == 0 {
				for _, value := range tunAddresses(in) {
					p := netip.MustParsePrefix(value)
					if !p.Addr().Next().IsValid() {
						return errors.New("TUN interface has no next address for default DNS")
					}
				}
			}
		}

		if in.Bind && (in.Type != "relay" || len(in.Users) == 0) {
			return errors.New("Relay BIND requires relay type and authenticated users")
		}
		if err := validateQUICCongestion(in.Type, in.CongestionControl); err != nil {
			return err
		}
		if err := in.QUICReceiveWindows.validate(); err != nil {
			return err
		}
		if err := validateBBRProfile(in.Type, in.CongestionControl, in.BBRProfile); err != nil {
			return err
		}
		if err := validateHYBandwidth(in.Type, in.UpMbps, in.DownMbps, in.IgnoreClientBandwidth, in.DisableLossCompensation); err != nil {
			return err
		}
		network := in.Network
		if in.Type == "direct" {
			network = ""
		}
		if err := validateNaiveHeaders(in.Type, nil, false, network); err != nil {
			return err
		}
		if err := validateNaiveCongestion(in.Type, in.QUICCongestionControl, in.Network != "tcp", true); err != nil {
			return err
		}
		if _, err := parseNaiveFrontend(in.Type, in.NaiveFrontend); err != nil {
			return err
		}
		if err := in.Transport.validateFor(in.Type); err != nil {
			return fmt.Errorf("inbound %s: %w", in.Tag, err)
		}
		if err := validateQUICTransport(in.Transport, in.TLS); err != nil {
			return err
		}
		if err := in.MieruOptions.validate(in.Type, in.Network, in.TLS, in.MTU); err != nil {
			return err
		}
		var visionIDs map[[16]byte]bool
		if hasVision(in) && in.Type == "vless" {
			visionIDs = map[[16]byte]bool{}
		}
		for _, u := range in.Users {
			if err := validateVision(in.Type, u.Flow, in.TLS, in.Transport, false, in.Plugin); err != nil {
				return err
			}
			if u.Flow != "" && in.Shadowsocks != nil && in.Shadowsocks.Enabled {
				return errors.New("Vision cannot use secondary Shadowsocks encryption")
			}
			if in.Type == "trojan" {
				for _, other := range in.Users {
					if other.Password == u.Password && other.Flow != u.Flow {
						return errors.New("Trojan users sharing a password must use the same flow")
					}
				}
			}
			if visionIDs != nil {
				id, e := parseUUID(u.UUID)
				if e != nil {
					return e
				}
				if visionIDs[id] {
					return errors.New("duplicate VLESS user UUID")
				}
				visionIDs[id] = true
			}
		}
		if in.Type == "mieru" {
			if len(in.Users) == 0 || len(in.Users) > 128 {
				return errors.New("Mieru requires1-128 users")
			}
			names := map[string]bool{}
			for _, u := range in.Users {
				name := u.Username
				if name == "" {
					name = u.Name
				}
				if name == "" || len(name) > 64 || names[name] || u.Password == "" || len(u.Password) > 1024 {
					return errors.New("invalid or duplicate Mieru user")
				}
				names[name] = true
			}
		}
		switch in.Type {
		case "direct", "mixed", "socks", "http", "shadowsocks", "shadowsocksr", "trojan", "vless", "vmess", "anytls", "relay", "snell", "ssh", "wireguard", "hysteria", "hysteria2", "tuic", "juicity", "brook", "trusttunnel", "naive", "masque", "openconnect", "dns", "dns-quic", "dns-h3", "tun", "shadowtls", "mieru", "sudoku":
		default:
			return fmt.Errorf("independent runtime has no %q inbound implementation", in.Type)
		}
		if in.Type == "naive" {
			if err := validateNaiveTLS(in.TLS, in.Network != "udp", in.Network != "tcp"); err != nil {
				return err
			}
		}
		if err := validateTrustOptions(in.Type, in.HTTPVersion, in.TLS); err != nil {
			return err
		}
		if in.Listen != "" {
			if _, err := netip.ParseAddr(in.Listen); err != nil {
				return errors.New("inbound listen must be an IP address")
			}
		}
		if in.Type == "snell" {
			if _, e := in.Obfs.snellOptions(in.ObfsParam, in.Version); e != nil {
				return e
			}
		}
		if in.Type == "snell" && (snellVersion(in.Version) < 1 || snellVersion(in.Version) > 5 || in.Password == "") {
			return errors.New("Snell requires a password and version 1-5")
		}
		if in.Type == "hysteria" {
			if in.Protocol != "" && in.Protocol != "udp" && in.Protocol != "wechat-video" && in.Protocol != "faketcp" {
				return errors.New("HY1 protocol must be udp, wechat-video or faketcp")
			}
			if in.Protocol == "faketcp" {
				if err := fakeTCPPlatform(); err != nil {
					return err
				}
			}
			if len(in.Obfs) > 4096 || len(in.Obfs) > 0 && in.Obfs[0] == '{' {
				return errors.New("invalid HY1 or XPlus password")
			}
		}
		if in.Type == "hysteria2" {
			if _, e := in.Obfs.quicSettings(); e != nil {
				return e
			}
		}
		if in.Type == "shadowsocks" {
			if _, err := newSSInboundKey(in); err != nil {
				return err
			}
		}
		if in.OTA {
			if err := validateSSOTA(in.Type, in.Method); err != nil {
				return err
			}
		}
		if in.Type == "shadowsocksr" {
			if err := validateSSR(in.Method, in.Password, in.Protocol, in.ProtocolParam, string(in.Obfs)); err != nil {
				return err
			}
		}
		if (in.Type == "trojan" || in.Type == "anytls" || in.Type == "trusttunnel" || in.Type == "naive" || isQUICProxy(in.Type) || isDNSQUIC(in.Type)) && !in.TLS.Enabled {
			return fmt.Errorf("%s inbound requires TLS", in.Type)
		}
		if in.Type == "anytls" && len(in.PaddingScheme) > 0 {
			if _, err := parseAnyPadding(strings.Join(in.PaddingScheme, "\n")); err != nil {
				return err
			}
		}
		if (in.Type == "trojan" || in.Type == "vless" || in.Type == "vmess" || in.Type == "anytls" || in.Type == "trusttunnel" || in.Type == "naive" || in.Type == "openconnect" || isQUICProxy(in.Type)) && len(in.Users) == 0 {
			return fmt.Errorf("%s inbound requires users", in.Type)
		}
		for _, u := range in.Users {
			if in.Type == "tuic" && in.Version != "" && in.Version != "4" && in.Version != "5" {
				return errors.New("TUIC version must be 4 or 5")
			}
			if in.Type == "vless" || in.Type == "vmess" || in.Type == "juicity" || in.Type == "tuic" && in.Version != "4" {
				if _, err := parseUUID(u.UUID); err != nil {
					return err
				}
				if (in.Type == "tuic" || in.Type == "juicity") && u.Password == "" {
					return errors.New("TUIC user password is required")
				}
				if u.AlterID < 0 || u.AlterID != 0 && in.Type != "vmess" {
					return errors.New("alterId must be nonnegative and requires VMess")
				}
			} else if u.Password == "" && !(in.Type == "ssh" && len(u.AuthorizedKeys) > 0) && !(in.Type == "tuic" && in.Version == "4" && u.Token != "") {
				return errors.New("inbound user password is required")
			}
			if in.Type == "socks" || in.Type == "mixed" || in.Type == "http" || in.Type == "relay" || in.Type == "trusttunnel" || in.Type == "naive" || in.Type == "masque" || in.Type == "openconnect" {
				name := u.Username
				if name == "" {
					name = u.Name
				}
				if name == "" || len(name) > 255 || len(u.Password) > 255 || (in.Type == "trusttunnel" || in.Type == "naive" || in.Type == "masque") && strings.Contains(name, ":") {
					return errors.New("proxy credentials must contain a username and at most 255 bytes")
				}
			}
		}
		if _, err := in.TLS.config(true, ""); err != nil {
			return err
		}
		if isQUICProxy(in.Type) || isDNSQUIC(in.Type) {
			if err := in.TLS.validateQUICVersion(); err != nil {
				return err
			}
		}
	}
	if e := validateShadowTLSInbounds(c, tags); e != nil {
		return e
	}
	if _, err := compileRoute(c.Route, tags); err != nil {
		return err
	}
	for _, o := range c.HTTPClients {
		if o.Detour != "" {
			if _, ok := tags[o.Detour]; !ok {
				return errors.New("unknown HTTP client detour")
			}
		}
	}
	for _, s := range c.Route.RuleSet {
		if len(s.HTTPClient) > 0 && s.HTTPClient[0] == '{' {
			var o HTTPClientOptions
			if e := decodeOptions([]byte(s.HTTPClient), &o); e != nil {
				return e
			}
			if e := o.validate(); e != nil {
				return e
			}
			if o.Detour != "" {
				if _, ok := tags[o.Detour]; !ok {
					return errors.New("unknown HTTP client detour")
				}
			}
		} else if s.HTTPClient != "" && !clients[string(s.HTTPClient)] {
			return errors.New("unknown rule_set http_client")
		}
	}
	for _, s := range c.DNS.Servers {
		if s.Type == "tailscale" {
			if o, ok := tags[s.Endpoint]; !ok || o.Type != "tailscale" {
				return errors.New("Tailscale DNS requires a tailscale endpoint")
			}
		}
		if s.Type == "openconnect" {
			if out, found := tags[s.Endpoint]; !found || out.Type != "openconnect" {
				return errors.New("OpenConnect DNS requires an openconnect endpoint")
			}
		}
		if s.Type == "masque" {
			found := false
			for _, out := range c.Outbounds {
				if out.Tag == s.Endpoint && out.Type == "masque" && out.mode() == "ip" && out.AcceptDNS {
					found = true
				}
			}
			if !found {
				return errors.New("MASQUE DNS endpoint must explicitly enable masque_accept_dns")
			}
		}
		if s.Detour != "" {
			if _, ok := tags[s.Detour]; !ok {
				return fmt.Errorf("unknown DNS detour %q", s.Detour)
			}
		}
	}
	if err := validateDNSNetworkRules(c); err != nil {
		return err
	}
	for _, out := range c.Outbounds {
		if (out.Type != "masque" || !out.AcceptDNS) && out.Type != "openconnect" && out.Type != "tailscale" {
			continue
		}
		if _, err := netip.ParseAddr(out.Server); err == nil {
			continue
		}
		ref := out.DomainResolver
		if ref == "" && out.Type != "tailscale" {
			ref = c.Route.DefaultDomainResolver
		}
		for _, server := range c.DNS.Servers {
			if server.Tag == ref.tag() && (server.Type == "masque" || server.Type == "openconnect" || server.Type == "tailscale") && server.Endpoint == out.Tag {
				return errors.New("tunnel cannot bootstrap its own endpoint through assigned DNS")
			}
		}
	}
	for _, ref := range append(append([]resolverReference{c.Route.DefaultDomainResolver}, outboundResolvers(c.Outbounds)...), shadowTLSResolvers(c.Inbounds)...) {
		if ref == "" {
			continue
		}
		options := ref.options()
		found := false
		for _, server := range c.DNS.Servers {
			if server.Tag == options.Server && server.Type != "fakeip" {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unknown or FakeIP domain_resolver %q", options.Server)
		}
		if _, e := optionDuration(options.Timeout, 10*time.Second); e != nil {
			return e
		}
	}
	if err := c.DNS.validate(); err != nil {
		return err
	}
	_, err := compileDNSRules(c.DNS, c.Route, nil)
	return err
}

func (o TLSOptions) staticConfig(server bool, hostname string) (*tls.Config, error) {
	if err := o.validateBrowser(server); err != nil {
		return nil, err
	}
	if (o.KernelTX || o.KernelRX) && !o.Enabled {
		return nil, errors.New("kernel TLS requires enabled TLS")
	}
	if err := o.validateCertificateProvider(server); err != nil {
		return nil, err
	}
	if (o.RecordFragment || o.Fragment || o.FragmentFallbackDelay != "") && (server || !o.Enabled) {
		return nil, errors.New("TLS fragmentation requires outbound TLS")
	}
	if _, err := o.fragmentDelay(); err != nil {
		return nil, err
	}
	if o.Reality != nil {
		if o.Reality.Enabled {
			return o.realityConfig(server, hostname)
		}
		if o.Reality.PrivateKey != "" || o.Reality.PublicKey != "" || o.Reality.Handshake != nil || len(o.Reality.ShortID) != 0 || o.Reality.MaxTimeDifference != "" || o.Reality.MLDSA65Seed != "" || o.Reality.MLDSA65Verify != "" {
			return nil, errors.New("Reality options require enabled Reality")
		}
	}
	if !o.Enabled {
		return nil, nil
	}
	c := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: o.ALPN}
	if err := o.configureProtocol(c, server); err != nil {
		return nil, err
	}
	identity, err := o.pkcs12Identity(server)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		c.Certificates = []tls.Certificate{*identity}
	}
	cert := []byte(strings.Join(o.Certificate, "\n"))
	key := []byte(strings.Join(o.Key, "\n"))
	if o.CertificatePath != "" {
		cert, err = os.ReadFile(o.CertificatePath)
		if err != nil {
			return nil, err
		}
	}
	if o.KeyPath != "" {
		key, err = os.ReadFile(o.KeyPath)
		if err != nil {
			return nil, err
		}
	}
	if server {
		if o.Insecure {
			return nil, errors.New("insecure is a client-only TLS option")
		}
		if o.CertificateProvider != "" {
			c.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if o.provider == nil {
					return nil, errors.New("certificate provider is not attached to a runtime")
				}
				return o.provider.current(hello.Context(), hello.ServerName)
			}
		} else if identity == nil {
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				return nil, fmt.Errorf("TLS certificate/key: %w", err)
			}
			c.Certificates = []tls.Certificate{pair}
		}
	} else {
		if len(key) != 0 {
			return nil, errors.New("client key requires an explicit mutual-TLS configuration")
		}
		c.ServerName = o.ServerName
		if c.ServerName == "" {
			c.ServerName = hostname
		}
		c.InsecureSkipVerify = o.Insecure
		if len(cert) > 0 {
			c.RootCAs = x509.NewCertPool()
			if !c.RootCAs.AppendCertsFromPEM(cert) {
				return nil, errors.New("invalid TLS trust certificate")
			}
		}
	}
	if err := o.configureClientAuth(c, server); err != nil {
		return nil, err
	}
	if err := o.configurePins(c, server); err != nil {
		return nil, err
	}
	if err := o.configureECH(c, server); err != nil {
		return nil, err
	}
	return c, nil
}

func parseUUID(value string) ([16]byte, error) {
	var id [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	if err != nil || len(b) != 16 {
		return id, errors.New("UUID must contain 16 hexadecimal bytes")
	}
	copy(id[:], b)
	return id, nil
}

func portAddress(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

const handshakeTimeout = 15 * time.Second
