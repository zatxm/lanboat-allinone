package native

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type SIP003Options struct {
	Plugin     string `json:"plugin,omitempty"`
	PluginOpts string `json:"plugin_opts,omitempty"`
	plugin     *ssPlugin
}

type ssPlugin struct {
	cloak      *cloakOptions
	kcp        *kcptunOptions
	shadow     *shadowPlugin
	camouflage snellObfsOptions
	transport  Transport
	tls        TLSOptions
	mux        bool
	muxLimit   int
	hy2        bool
	password   string
	gost       bool
	smux       bool
	server     string
	port       uint16
}

// SIP003 escapes delimiters with a backslash; splitting on semicolons loses
// paths and host values containing escaped characters.
func sip003Options(text string) (map[string]string, error) {
	if len(text) > 8192 {
		return nil, errors.New("plugin_opts exceeds 8192 bytes")
	}
	values := make(map[string]string)
	var key, value strings.Builder
	inValue, escaped := false, false
	finish := func() error {
		if key.Len() == 0 {
			return errors.New("empty SIP003 option name")
		}
		name := key.String()
		if _, ok := values[name]; ok {
			return fmt.Errorf("duplicate SIP003 option %q", name)
		}
		values[name] = value.String()
		key.Reset()
		value.Reset()
		inValue = false
		return nil
	}
	for _, c := range text {
		if c < 32 || c == 127 {
			return nil, errors.New("invalid SIP003 option character")
		}
		if escaped {
			if c != '\\' && c != ';' && c != '=' {
				return nil, errors.New("invalid SIP003 escape")
			}
			escaped = false
		} else {
			switch c {
			case '\\':
				escaped = true
				continue
			case ';':
				if err := finish(); err != nil {
					return nil, err
				}
				continue
			case '=':
				if !inValue {
					inValue = true
					continue
				}
			}
		}
		if inValue {
			value.WriteRune(c)
		} else {
			key.WriteRune(c)
		}
	}
	if escaped {
		return nil, errors.New("unfinished SIP003 escape")
	}
	if key.Len() != 0 || inValue {
		if err := finish(); err != nil {
			return nil, err
		}
	}
	return values, nil
}

func (p *SIP003Options) prepare(kind string, transport Transport, tls TLSOptions, server bool) error {
	if p.Plugin == "" {
		if p.PluginOpts != "" {
			return errors.New("plugin_opts requires plugin")
		}
		return nil
	}
	if kind != "shadowsocks" && (kind != "lua" || server) {
		return errors.New("SIP003 plugin requires shadowsocks type")
	}
	if transport.Type != "" {
		return errors.New("plugin and transport are mutually exclusive")
	}
	options, err := sip003Options(p.PluginOpts)
	if err != nil {
		return err
	}
	if p.Plugin == "cloak" {
		p.plugin, err = prepareCloakPlugin(options, tls, server)
		return err
	}
	if p.Plugin == "kcptun" {
		p.plugin, err = prepareKCPPlugin(options, tls, server)
		return err
	}
	if p.Plugin == "shadow-tls" || p.Plugin == "shadowtls" {
		p.plugin, err = prepareShadowTLSPlugin(options, tls, server)
		return err
	}
	if p.Plugin == "gost" || p.Plugin == "gost-plugin" {
		p.plugin, err = prepareGOSTPlugin(options, tls, server)
		return err
	}
	if p.Plugin == "v2ray-plugin" {
		mode := options["mode"]
		if mode == "" {
			mode = "websocket"
		}
		if mode != "quic" && mode != "websocket" && mode != "hysteria2" {
			return errors.New("v2ray-plugin mode must be websocket, quic or hysteria2")
		}
		mux := mode == "websocket"
		muxLimit := 1
		if value, exists := options["mux"]; exists && mode != "hysteria2" {
			n, e := strconv.ParseUint(value, 10, 16)
			if e != nil || n > 128 {
				return errors.New("v2ray-plugin mux must be 0-128")
			}
			mux = mode == "websocket" && n != 0
			muxLimit = int(n)
		}
		for name, value := range options {
			switch name {
			case "mode", "host", "cert", "certRaw", "mux":
			case "password":
				if mode != "hysteria2" || len(value) > 4096 {
					return errors.New("v2ray-plugin password requires hysteria2 mode and at most 4096 bytes")
				}
			case "path":
				if mode == "quic" {
					return errors.New("v2ray-plugin path requires websocket mode")
				}
			case "key":
				if !server {
					return errors.New("v2ray-plugin key is a server option")
				}
			case "server":
				if !server || value != "" {
					return errors.New("invalid v2ray-plugin server flag")
				}
			case "tls":
				if value != "" {
					return errors.New("v2ray-plugin tls is a flag")
				}
			default:
				return fmt.Errorf("unsupported v2ray-plugin option %q", name)
			}
		}
		host := options["host"]
		if host == "" {
			host = "cloudfront.com"
		}
		if !validHTTPHost(host) || len(host) > 253 {
			return errors.New("invalid v2ray-plugin host")
		}
		_, tlsFlag := options["tls"]
		tls.Enabled = tls.Enabled || tlsFlag || mode != "websocket"
		if tls.ServerName == "" {
			tls.ServerName = host
		}
		if cert := options["cert"]; cert != "" {
			tls.CertificatePath = cert
		} else if cert := options["certRaw"]; cert != "" {
			tls.CertificatePath = ""
			tls.Certificate = []string{"-----BEGIN CERTIFICATE-----\n" + cert + "\n-----END CERTIFICATE-----\n"}
		}
		if key := options["key"]; key != "" {
			tls.KeyPath = key
		}
		if mode != "websocket" {
			if err := tls.validateQUICVersion(); err != nil {
				return err
			}
		}
		if _, err := tls.config(server, host); err != nil {
			return err
		}
		tr := Transport{Type: "quic"}
		if mode == "websocket" {
			path := options["path"]
			if path == "" {
				path = "/"
			}
			tr = Transport{Type: "ws", Path: path, Headers: map[string]headerValues{"Host": {host}}, closeProbe: server}
			if err := tr.validate(); err != nil {
				return err
			}
		}
		p.plugin = &ssPlugin{transport: tr, tls: tls, mux: mux, muxLimit: muxLimit, hy2: mode == "hysteria2", password: options["password"]}
		return nil
	}
	if p.Plugin != "obfs-local" && p.Plugin != "obfs-server" && p.Plugin != "simple-obfs" {
		return fmt.Errorf("independent runtime has no %q plugin", p.Plugin)
	}
	v := snellObfsOptions{Type: options["obfs"], Host: options["obfs-host"], Path: options["obfs-uri"]}
	for name := range options {
		if name != "obfs" && name != "obfs-host" && name != "obfs-uri" {
			return fmt.Errorf("unsupported simple-obfs option %q", name)
		}
	}
	if v.Type != "http" && v.Type != "tls" {
		return errors.New("simple-obfs requires obfs=http or obfs=tls")
	}
	if v.Host == "" {
		v.Host = "cloudfront.net"
	}
	if v.Path == "" {
		v.Path = "/"
	}
	if !validHTTPHost(v.Host) || len(v.Host) > 253 || !strings.HasPrefix(v.Path, "/") || strings.ContainsAny(v.Path, " \r\n\x00") || len(v.Path) > 2048 {
		return errors.New("invalid simple-obfs host or URI")
	}
	p.plugin = &ssPlugin{camouflage: v}
	return nil
}

func (p SIP003Options) wrap(conn net.Conn, server bool) (net.Conn, error) {
	if p.plugin == nil || p.plugin.camouflage.Type == "" {
		return conn, nil
	}
	if server {
		return acceptCamouflage(conn, p.plugin.camouflage)
	}
	return &snellObfsConn{Conn: conn, options: p.plugin.camouflage}, nil
}

func (o Outbound) pluginTransport() Outbound {
	if p := o.plugin; p != nil && p.shadow != nil {
		o.TLS = TLSOptions{}
	}
	if p := o.plugin; p != nil && (p.transport.Type != "" || p.gost) {
		o.Transport, o.TLS = p.transport, p.tls
	}
	return o
}

func (in Inbound) pluginTransport() Inbound {
	if p := in.plugin; p != nil && p.shadow != nil {
		in.TLS = TLSOptions{}
	}
	if p := in.plugin; p != nil && (p.transport.Type != "" || p.gost) {
		in.Transport, in.TLS = p.transport, p.tls
	}
	return in
}
