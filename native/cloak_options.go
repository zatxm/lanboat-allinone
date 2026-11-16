package native

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type cloakOptions struct {
	uid                                                             [16]byte
	public, private                                                 []byte
	encryption                                                      byte
	browser, mode, proxy, host, sni, path, origin, server, redirect string
	port                                                            uint16
	names                                                           []string
	connections                                                     int
	timeout                                                         time.Duration
	tls                                                             TLSOptions
}

func cloakBase64(text string, size int) ([]byte, error) {
	b, e := base64.StdEncoding.DecodeString(text)
	if e != nil {
		b, e = base64.RawStdEncoding.DecodeString(text)
	}
	if e != nil || len(b) != size {
		return nil, fmt.Errorf("Cloak key/UID must encode%d bytes in base64", size)
	}
	return b, nil
}
func prepareCloakPlugin(values map[string]string, tls TLSOptions, inbound bool) (*ssPlugin, error) {
	o := &cloakOptions{encryption: 2, browser: "chrome", mode: "direct", proxy: "/", path: "/", connections: 4, timeout: 300 * time.Second, tls: tls}
	canonical := map[string]string{}
	for k, v := range values {
		name := strings.ToLower(k)
		if _, ok := canonical[name]; ok {
			return nil, errors.New("duplicate Cloak option")
		}
		canonical[name] = v
	}
	var err error
	for name, v := range canonical {
		switch name {
		case "uid":
			b, e := cloakBase64(v, 16)
			if e != nil {
				return nil, e
			}
			copy(o.uid[:], b)
		case "publickey":
			o.public, err = cloakBase64(v, 32)
		case "privatekey":
			o.private, err = cloakBase64(v, 32)
		case "encryptionmethod":
			switch strings.ToLower(v) {
			case "plain":
				o.encryption = 0
			case "aes-gcm", "aes-256-gcm":
				o.encryption = 1
			case "chacha20-poly1305":
				o.encryption = 2
			case "aes-128-gcm":
				o.encryption = 3
			default:
				return nil, errors.New("invalid Cloak encryption method")
			}
		case "browsersig":
			o.browser = strings.ToLower(v)
			if o.browser != "chrome" && o.browser != "firefox" && o.browser != "safari" {
				return nil, errors.New("invalid Cloak BrowserSig")
			}
		case "transport":
			o.mode = strings.ToLower(v)
			if o.mode != "direct" && o.mode != "cdn" && o.mode != "websocket" {
				return nil, errors.New("Cloak Transport must be direct,CDN or websocket")
			}
		case "proxymethod":
			if v == "" || len(v) > 12 || strings.ContainsAny(v, "\x00\r\n") {
				return nil, errors.New("Cloak ProxyMethod must contain1-12 bytes")
			}
			o.proxy = v
		case "servername":
			if !shadowHost(v) {
				return nil, errors.New("invalid Cloak ServerName")
			}
			o.host = v
		case "sni":
			if !shadowHost(v) {
				return nil, errors.New("invalid Cloak SNI")
			}
			o.sni = v
		case "cdnoriginhost":
			if !validHTTPHost(v) || len(v) > 253 {
				return nil, errors.New("invalid Cloak CDNOriginHost")
			}
			o.origin = v
		case "alternativenames":
			for _, host := range strings.Split(v, ",") {
				host = strings.TrimSpace(host)
				if !shadowHost(host) || len(o.names) >= 16 {
					return nil, errors.New("invalid Cloak AlternativeNames")
				}
				o.names = append(o.names, host)
			}
		case "streamtimeout", "numconn":
			n, e := strconv.Atoi(v)
			if e != nil || n < 0 {
				return nil, errors.New("invalid Cloak timeout/connection count")
			}
			if name == "numconn" {
				if n < 1 || n > 8 {
					return nil, errors.New("Cloak NumConn must be1-8")
				}
				o.connections = n
			} else {
				if n > 86400 {
					return nil, errors.New("Cloak StreamTimeout must be0-86400 seconds")
				}
				o.timeout = time.Duration(n) * time.Second
			}
		case "skip-cert-verify":
			o.tls.Insecure, err = strconv.ParseBool(v)
		case "server":
			if inbound || !shadowHost(v) {
				return nil, errors.New("invalid Cloak server override")
			}
			o.server = v
		case "port":
			n, e := shadowPort(v)
			if e != nil || inbound {
				return nil, errors.New("invalid Cloak port override")
			}
			o.port = n
		case "rediraddr":
			host, p, e := net.SplitHostPort(v)
			if !inbound || e != nil || !shadowHost(host) {
				return nil, errors.New("invalid Cloak RedirAddr")
			}
			if _, e = shadowPort(p); e != nil {
				return nil, e
			}
			o.redirect = v
		case "path":
			if v == "" || !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "\r\n \t#") || len(v) > 2048 {
				return nil, errors.New("invalid Cloak WebSocket path")
			}
			o.path = v
		default:
			return nil, fmt.Errorf("unsupported Cloak option %q", name)
		}
		if err != nil {
			return nil, err
		}
	}
	if canonical["uid"] == "" {
		return nil, errors.New("Cloak requires UID")
	}
	if inbound {
		if o.private == nil {
			return nil, errors.New("Cloak server requires PrivateKey")
		}
		if o.public != nil {
			return nil, errors.New("Cloak PublicKey is an outbound option")
		}
		if _, err = ecdh.X25519().NewPrivateKey(o.private); err != nil {
			return nil, err
		}
	} else {
		if o.public == nil {
			return nil, errors.New("Cloak client requires PublicKey")
		}
		if o.private != nil {
			return nil, errors.New("Cloak PrivateKey is an inbound option")
		}
		if _, err = ecdh.X25519().NewPublicKey(o.public); err != nil {
			return nil, err
		}
		o.tls.Enabled = o.mode != "direct"
		if o.tls.Enabled {
			if _, err = o.tls.config(false, o.host); err != nil {
				return nil, err
			}
		}
	}
	if o.mode == "direct" && tls.Enabled {
		return nil, errors.New("Cloak direct carries a camouflage handshake,not an outer TLS connection")
	}
	return &ssPlugin{cloak: o}, nil
}

// GenerateCloakIdentity creates independent server and client configuration secrets.
func GenerateCloakIdentity() (map[string]string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var uid [16]byte
	rand.Read(uid[:])
	return map[string]string{"uid": base64.StdEncoding.EncodeToString(uid[:]), "private_key": base64.StdEncoding.EncodeToString(key.Bytes()), "public_key": base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())}, nil
}
