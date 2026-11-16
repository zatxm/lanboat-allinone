package native

import (
	"errors"
	"strings"
)

type TrojanShadowsocksOptions struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
}

func (o *TrojanShadowsocksOptions) validate(protocol string) error {
	if o == nil {
		return nil
	}
	if protocol != "trojan" {
		return errors.New("shadowsocks transport encryption requires trojan type")
	}
	if !o.Enabled {
		return nil
	}
	_, err := o.key()
	return err
}

func (o *TrojanShadowsocksOptions) key() (*ssKey, error) {
	method := strings.ToLower(o.Method)
	if method == "" {
		method = "aes-128-gcm"
	}
	switch method {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
	default:
		return nil, errors.New("Trojan-Go encryption must use aes-128-gcm, aes-256-gcm or chacha20-ietf-poly1305")
	}
	if o.Password == "" {
		return nil, errors.New("Trojan-Go encryption password required")
	}
	return newSSKey(method, o.Password)
}
