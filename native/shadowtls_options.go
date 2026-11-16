package native

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

type ShadowTLSHandshake struct {
	Server         string            `json:"server,omitempty"`
	ServerPort     uint16            `json:"server_port,omitempty"`
	Detour         string            `json:"detour,omitempty"`
	DomainResolver resolverReference `json:"domain_resolver,omitempty"`
}
type ShadowTLSOptions struct {
	Handshake              *ShadowTLSHandshake           `json:"handshake,omitempty"`
	HandshakeForServerName map[string]ShadowTLSHandshake `json:"handshake_for_server_name,omitempty"`
	StrictMode             bool                          `json:"strict_mode,omitempty"`
	WildcardSNI            string                        `json:"wildcard_sni,omitempty"`
}

func shadowVersion(v string) int {
	if v == "" {
		return 1
	}
	switch v {
	case "1":
		return 1
	case "2":
		return 2
	case "3":
		return 3
	}
	return 0
}
func (x ShadowTLSOptions) empty() bool {
	return x.Handshake == nil && len(x.HandshakeForServerName) == 0 && !x.StrictMode && x.WildcardSNI == ""
}
func shadowHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, "\r\n\x00 /?#\\[]:@") {
		return net.ParseIP(host) != nil
	}
	return true
}
func (h ShadowTLSHandshake) validate(optional bool, tags map[string]Outbound) error {
	if (!optional || h.Server != "") && (!shadowHost(h.Server) || h.ServerPort == 0) {
		return errors.New("ShadowTLS handshake requires server and server_port")
	}
	if h.Detour != "" {
		if _, ok := tags[h.Detour]; !ok {
			return errors.New("unknown ShadowTLS handshake detour")
		}
	}
	return nil
}
func validateShadowTLSClient(kind, version, password string, o TLSOptions, x ShadowTLSOptions, tr Transport) error {
	if kind != "shadowtls" {
		if !x.empty() {
			return errors.New("ShadowTLS options require shadowtls type")
		}
		return nil
	}
	if !x.empty() {
		return errors.New("ShadowTLS handshake, strict_mode and wildcard_sni are inbound options")
	}
	v := shadowVersion(version)
	if v == 1 && password != "" {
		return errors.New("ShadowTLS1 has no password; authenticate with the inner proxy")
	}
	if v == 0 || v > 1 && (password == "" || len(password) > 4096) {
		return errors.New("ShadowTLS requires version1-3 and a password for2/3")
	}
	if !o.Enabled || tr.Type != "" {
		return errors.New("ShadowTLS requires TLS and no transport override")
	}
	return validateShadowTLSHello(v, o)
}
func validateShadowTLSHello(v int, o TLSOptions) error {
	if o.KernelTX || o.KernelRX {
		return errors.New("ShadowTLS record camouflage cannot use a kernel TLS socket")
	}
	if o.ECH != nil && o.ECH.Enabled {
		return errors.New("ShadowTLS handshake does not support ECH")
	}
	cfg, e := o.config(false, o.ServerName)
	if e != nil {
		return e
	}
	if v == 1 && (cfg.MinVersion > 0x0303 || cfg.MaxVersion != 0 && cfg.MaxVersion < 0x0303) {
		return errors.New("ShadowTLS1 requires TLS1.2")
	}
	if v == 3 {
		for _, c := range cfg.CurvePreferences {
			if c != 29 && c != 23 && c != 24 && c != 25 {
				return errors.New("ShadowTLS3 ClientHello signing requires classical TLS curves")
			}
		}
	}
	return nil
}
func validateShadowTLSInbounds(c Config, tags map[string]Outbound) error {
	byTag := map[string]Inbound{}
	for _, in := range c.Inbounds {
		if in.Tag != "" {
			byTag[in.Tag] = in
		}
	}
	for _, in := range c.Inbounds {
		if in.Type != "shadowtls" {
			if !in.ShadowTLSOptions.empty() || in.Detour != "" {
				return errors.New("inbound handshake and detour require shadowtls type")
			}
			continue
		}
		v := shadowVersion(in.Version)
		if v == 0 || in.TLS.Enabled || in.Transport.Type != "" || in.Network != "" && in.Network != "tcp" {
			return errors.New("ShadowTLS inbound requires version1-3, a handshake backend and no local TLS/transport override")
		}
		if v == 2 && (in.Password == "" || len(in.Password) > 4096) {
			return errors.New("ShadowTLS2 password required")
		}
		if v != 2 && in.Password != "" || v != 3 && len(in.Users) > 0 {
			return errors.New("ShadowTLS2 uses password; ShadowTLS3 uses users")
		}
		if v == 3 && (len(in.Users) == 0 || len(in.Users) > 128) {
			return errors.New("ShadowTLS3 requires1-128 users")
		}
		for _, u := range in.Users {
			if len(u.Password) > 4096 {
				return errors.New("ShadowTLS password exceeds4096bytes")
			}
		}
		if in.StrictMode && v != 3 || in.WildcardSNI != "" && v != 3 || len(in.HandshakeForServerName) > 0 && v == 1 {
			return errors.New("ShadowTLS option does not match protocol version")
		}
		if in.WildcardSNI != "" && in.WildcardSNI != "off" && in.WildcardSNI != "authed" && in.WildcardSNI != "all" {
			return errors.New("invalid ShadowTLS wildcard_sni")
		}
		if in.Handshake == nil {
			return errors.New("ShadowTLS handshake configuration required")
		}
		if e := in.Handshake.validate(in.WildcardSNI == "all", tags); e != nil {
			return e
		}
		if len(in.HandshakeForServerName) > 128 {
			return errors.New("too many ShadowTLS SNI backends")
		}
		seen := map[string]bool{}
		for name, h := range in.HandshakeForServerName {
			key := strings.ToLower(name)
			if seen[key] {
				return errors.New("duplicate ShadowTLS SNI backend")
			}
			seen[key] = true
			if !shadowHost(name) {
				return errors.New("invalid ShadowTLS handshake SNI")
			}
			if e := h.validate(false, tags); e != nil {
				return e
			}
		}
		target, ok := byTag[in.Detour]
		if !ok || in.Detour == "" {
			return errors.New("ShadowTLS inbound detour must name a stream proxy inbound")
		}
		switch target.Type {
		case "mixed", "socks", "http", "shadowsocks", "shadowsocksr", "vless", "vmess", "trojan", "anytls", "relay", "snell", "ssh", "brook":
		default:
			return errors.New("ShadowTLS inbound detour must name a stream proxy inbound")
		}
		if target.Transport.Type != "" || target.Plugin != "" {
			return errors.New("ShadowTLS inbound detour cannot have another transport/plugin")
		}
	}
	return nil
}
func prepareShadowTLSPlugin(m map[string]string, tls TLSOptions, server bool) (*ssPlugin, error) {
	if server && tls.Enabled {
		return nil, errors.New("ShadowTLS inbound plugin uses its handshake backend, not local TLS")
	}
	p := &ssPlugin{tls: tls, shadow: &shadowPlugin{version: 1}}
	for k, v := range m {
		switch k {
		case "version":
			p.shadow.version = shadowVersion(v)
		case "password":
			p.shadow.password = v
		case "host":
			if server {
				return nil, errors.New("ShadowTLS plugin host is an outbound option")
			}
			p.tls.ServerName = v
		case "server":
			if server || !shadowHost(v) {
				return nil, errors.New("invalid ShadowTLS plugin server")
			}
			p.server = v
		case "port":
			n, e := shadowPort(v)
			if server || e != nil {
				return nil, errors.New("invalid ShadowTLS plugin port")
			}
			p.port = n
		case "handshake":
			if !server {
				return nil, errors.New("ShadowTLS handshake is an inbound plugin option")
			}
			host, port, e := net.SplitHostPort(v)
			if e != nil {
				return nil, e
			}
			n, e := shadowPort(port)
			if e != nil || !shadowHost(host) {
				return nil, errors.New("invalid ShadowTLS plugin handshake")
			}
			p.shadow.options.Handshake = &ShadowTLSHandshake{Server: host, ServerPort: n}
		case "strict-mode":
			if !server || v != "true" && v != "false" {
				return nil, errors.New("invalid ShadowTLS strict-mode")
			}
			p.shadow.options.StrictMode = v == "true"
		case "skip-cert-verify":
			if server || v != "true" && v != "false" {
				return nil, errors.New("invalid ShadowTLS skip-cert-verify")
			}
			p.tls.Insecure = v == "true"
		case "cert":
			if server {
				return nil, errors.New("ShadowTLS plugin does not terminate TLS locally")
			}
			p.tls.CertificatePath = v
		case "alpn":
			if server {
				return nil, errors.New("ShadowTLS plugin alpn is an outbound option")
			}
			p.tls.ALPN = strings.Split(v, ",")
		default:
			return nil, fmt.Errorf("unsupported ShadowTLS plugin option %q", k)
		}
	}
	if p.shadow.version == 0 || p.shadow.version > 1 && (p.shadow.password == "" || len(p.shadow.password) > 4096) {
		return nil, errors.New("invalid ShadowTLS plugin version/password")
	}
	if p.shadow.version == 1 && p.shadow.password != "" {
		return nil, errors.New("ShadowTLS1 has no password")
	}
	if server {
		if p.shadow.options.Handshake == nil {
			return nil, errors.New("ShadowTLS inbound plugin requires handshake=host:port")
		}
		if p.shadow.options.StrictMode && p.shadow.version != 3 {
			return nil, errors.New("strict-mode requires ShadowTLS3")
		}
	} else {
		p.tls.Enabled = true
		if e := validateShadowTLSHello(p.shadow.version, p.tls); e != nil {
			return nil, e
		}
	}
	return p, nil
}
