package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
)

// Endpoint JSON is decoded separately because version is a list on servers,
// a number on clients, and a string on several unrelated proxy protocols.
type masqueEndpointOptions struct {
	DialOptions
	masqueConnectionOptions
	masqueNATOptions
	DNS                    []MasqueDNSConfiguration `json:"masque_dns,omitempty"`
	PREF64                 []netip.Prefix           `json:"masque_pref64,omitempty"`
	AcceptDNS              bool                     `json:"masque_accept_dns,omitempty"`
	DatagramContexts       bool                     `json:"masque_contexts,omitempty"`
	AcceptPREF64           bool                     `json:"masque_accept_pref64,omitempty"`
	Type                   string                   `json:"type"`
	Tag                    string                   `json:"tag,omitempty"`
	Server                 string                   `json:"server,omitempty"`
	ServerPort             uint16                   `json:"server_port,omitempty"`
	Username               string                   `json:"username,omitempty"`
	Password               string                   `json:"password,omitempty"`
	Listen                 string                   `json:"listen,omitempty"`
	ListenPort             uint16                   `json:"listen_port,omitempty"`
	Users                  []User                   `json:"users,omitempty"`
	TLS                    TLSOptions               `json:"tls,omitempty"`
	Path                   string                   `json:"path,omitempty"`
	Headers                map[string]headerValues  `json:"headers,omitempty"`
	Version                json.RawMessage          `json:"version,omitempty"`
	DisableVersionFallback bool                     `json:"disable_version_fallback,omitempty"`
	Address                []string                 `json:"address,omitempty"`
	AdvertiseRoutes        []string                 `json:"advertise_routes,omitempty"`
	System                 bool                     `json:"system,omitempty"`
	Name                   string                   `json:"name,omitempty"`
	MTU                    int                      `json:"mtu,omitempty"`
	OnDemand               bool                     `json:"on_demand,omitempty"`
	Detour                 string                   `json:"detour,omitempty"`
	DomainResolver         resolverReference        `json:"domain_resolver,omitempty"`
}

type nativeEndpoints struct {
	masque      []masqueEndpointOptions
	wireguard   []wgEndpointOptions
	openconnect []ocEndpointOptions
}

func extractNativeEndpoints(raw []byte) ([]byte, nativeEndpoints, error) {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, nativeEndpoints{}, err
	}
	data, ok := document["endpoints"]
	if !ok {
		return raw, nativeEndpoints{}, nil
	}
	var items []json.RawMessage
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		items = []json.RawMessage{data}
	} else if err := json.Unmarshal(data, &items); err != nil {
		return nil, nativeEndpoints{}, err
	}
	var keep []json.RawMessage
	var endpoints nativeEndpoints
	for _, item := range items {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(item, &head); err != nil {
			return nil, nativeEndpoints{}, err
		}
		if head.Type == "wireguard" {
			var ep wgEndpointOptions
			if err := decodeOptions(item, &ep); err != nil {
				return nil, nativeEndpoints{}, fmt.Errorf("wireguard endpoint: %w", err)
			}
			endpoints.wireguard = append(endpoints.wireguard, ep)
			continue
		}
		if head.Type == "openconnect" {
			var ep ocEndpointOptions
			if err := decodeOptions(item, &ep); err != nil {
				return nil, nativeEndpoints{}, fmt.Errorf("openconnect endpoint: %w", err)
			}
			endpoints.openconnect = append(endpoints.openconnect, ep)
			continue
		}
		if head.Type != "masque-client" && head.Type != "masque-server" {
			keep = append(keep, item)
			continue
		}
		var ep masqueEndpointOptions
		if err := decodeOptions(item, &ep); err != nil {
			return nil, nativeEndpoints{}, fmt.Errorf("%s endpoint: %w", head.Type, err)
		}
		endpoints.masque = append(endpoints.masque, ep)
	}
	if len(endpoints.masque)+len(endpoints.wireguard)+len(endpoints.openconnect) == 0 {
		return raw, nativeEndpoints{}, nil
	}
	data, _ = json.Marshal(keep)
	document["endpoints"] = data
	raw, err := json.Marshal(document)
	return raw, endpoints, err
}

func (ep masqueEndpointOptions) appendTo(c *Config) error {
	used := func(tag string) bool {
		for _, in := range c.Inbounds {
			if in.Tag == tag {
				return true
			}
		}
		for _, out := range c.Outbounds {
			if out.Tag == tag {
				return true
			}
		}
		return false
	}
	if ep.Tag == "" {
		for index := 0; ; index++ {
			ep.Tag = fmt.Sprintf("masque-endpoint-%d", index)
			if !used(ep.Tag) {
				break
			}
		}
	} else if used(ep.Tag) {
		return fmt.Errorf("duplicate MASQUE endpoint tag %q", ep.Tag)
	}
	if !ep.System && ep.Name != "" {
		return errors.New("MASQUE name requires a system interface")
	}
	if ep.System {
		if err := validateTUNPlatform(Inbound{InterfaceName: ep.Name}); err != nil {
			return err
		}
	}
	connection, err := ep.masqueConnectionOptions.settings()
	if err != nil {
		return err
	}
	nat, err := ep.masqueNATOptions.settings()
	if err != nil {
		return err
	}
	opts := MasqueOptions{DatagramContexts: ep.DatagramContexts, nat: nat, connection: connection, endpoint: true, URI: ep.Path, Headers: ep.Headers, DisableVersionFallback: ep.DisableVersionFallback, onDemand: ep.OnDemand, DNS: ep.DNS, PREF64: ep.PREF64, AcceptDNS: ep.AcceptDNS, AcceptPREF64: ep.AcceptPREF64, system: ep.System, interfaceName: ep.Name}
	if ep.Type == "masque-client" {
		if ep.Listen != "" || ep.ListenPort != 0 || len(ep.Users) != 0 || len(ep.Address) != 0 {
			return errors.New("MASQUE client contains server fields")
		}
		if len(ep.AdvertiseRoutes) > 128 {
			return errors.New("too many MASQUE advertised routes")
		}
		for _, text := range ep.AdvertiseRoutes {
			p, err := netip.ParsePrefix(text)
			if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
				return errors.New("invalid MASQUE advertised route")
			}
			opts.routes = append(opts.routes, p.Masked())
		}
		version := 3
		if len(ep.Version) != 0 {
			if err := json.Unmarshal(ep.Version, &version); err != nil {
				return errors.New("MASQUE client version must be a number")
			}
		}
		c.Outbounds = append(c.Outbounds, Outbound{DialOptions: ep.DialOptions, Type: "masque", Tag: ep.Tag, Server: ep.Server, ServerPort: ep.ServerPort, Username: ep.Username, Password: ep.Password, HTTPVersion: version, TLS: ep.TLS, MTU: ep.MTU, Detour: ep.Detour, DomainResolver: ep.DomainResolver, MasqueOptions: opts})
		return nil
	}
	listen := ListenOptions{NetNS: ep.NetNS, BindInterface: ep.BindInterface, RoutingMark: ep.RoutingMark, ReuseAddr: ep.ReuseAddr, TCPFastOpen: ep.TCPFastOpen, TCPMultiPath: ep.TCPMultiPath, DisableTCPKeepAlive: ep.DisableTCPKeepAlive, TCPKeepAlive: ep.TCPKeepAlive, TCPKeepAliveInterval: ep.TCPKeepAliveInterval, UDPFragment: ep.UDPFragment}
	if !reflect.DeepEqual(ep.DialOptions, listen.dialOptions()) {
		return errors.New("MASQUE server contains client dial fields")
	}
	if ep.Server != "" || ep.ServerPort != 0 || ep.Username != "" || ep.Password != "" || ep.Detour != "" || len(ep.Headers) != 0 || ep.DisableVersionFallback || ep.OnDemand {
		return errors.New("MASQUE server contains client fields")
	}
	if ep.DomainResolver != "" {
		return errors.New("MASQUE server domain_resolver is a client dial field")
	}
	versions := []int{1, 2, 3}
	if len(ep.Version) != 0 {
		if err := decodeOptions(ep.Version, &versions); err != nil {
			return errors.New("MASQUE server version must be a number or list")
		}
		if len(versions) == 0 {
			versions = []int{1, 2, 3}
		}
	}
	seen := map[int]bool{}
	for _, v := range versions {
		if v < 1 || v > 3 || seen[v] {
			return errors.New("MASQUE server versions must be unique values1-3")
		}
		seen[v] = true
	}
	opts.versions = versions
	opts.serverAddress = ep.Address
	version := slices.Max(versions)
	var assigned []string
	families := map[bool]bool{}
	for _, text := range ep.Address {
		p, err := netip.ParsePrefix(text)
		if err != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() || p.Addr().Is4In6() || p.Addr().Zone() != "" || families[p.Addr().Is4()] {
			return errors.New("MASQUE server address requires one valid prefix per family")
		}
		families[p.Addr().Is4()] = true
		// The server owns the configured address; a separate stack per CONNECT-IP
		// session allows the next host address to be reused without crossing flows.
		client := p.Addr().Next()
		if !client.IsValid() || !p.Contains(client) {
			client = p.Masked().Addr()
		}
		if client == p.Addr() || client.IsUnspecified() {
			return errors.New("MASQUE server prefix has no client address")
		}
		assigned = append(assigned, netip.PrefixFrom(client, client.BitLen()).String())
	}
	if len(assigned) == 0 {
		return errors.New("MASQUE server address is required")
	}
	if len(ep.AdvertiseRoutes) != 0 && len(ep.AdvertiseRoutes)+len(ep.Address) > 128 {
		return errors.New("too many MASQUE advertised routes")
	}
	if len(ep.AdvertiseRoutes) != 0 {
		for _, text := range append(slices.Clone(ep.AdvertiseRoutes), ep.Address...) {
			p, err := netip.ParsePrefix(text)
			if err != nil || p.Addr().Is4In6() || p.Addr().Zone() != "" {
				return errors.New("invalid MASQUE advertised route")
			}
			opts.routes = append(opts.routes, p.Masked())
		}
	}
	c.Inbounds = append(c.Inbounds, Inbound{ListenOptions: listen, UDPTimeout: ep.Timeout, Type: "masque", Tag: ep.Tag, Listen: ep.Listen, ListenPort: ep.ListenPort, Users: ep.Users, TLS: ep.TLS, MTU: ep.MTU, Address: assigned, HTTPVersion: version, MasqueOptions: opts})
	return nil
}

func (in Inbound) masqueServes(version int) bool {
	if len(in.versions) != 0 {
		return slices.Contains(in.versions, version)
	}
	if in.HTTPVersion == 0 {
		return version == 3
	}
	return in.HTTPVersion == version
}

func (in Inbound) masqueTCP() bool { return in.masqueServes(1) || in.masqueServes(2) }

// DisconnectMasque releases a caller-managed on-demand endpoint. The next Dial
// negotiates a fresh session, including version fallback when enabled.
func (r *Runtime) DisconnectMasque(tag string) error {
	r.mu.Lock()
	c := r.masqueClients[tag]
	if r.closed || c == nil || !c.outbound.onDemand {
		r.mu.Unlock()
		return errors.New("disconnect requires an active runtime and an on_demand MASQUE endpoint")
	}
	r.mu.Unlock()
	c.disconnect()
	return nil
}
