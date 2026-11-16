package native

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

// A signed auth key carries a one-time signing credential, not a trusted root.
// Its authorization is checked against the pinned authority once the map is
// available. Only the base auth key is submitted as the authentication secret.
func (c *tailscaleClient) lockAuth() (string, []byte, error) {
	base, suffix, wrapped := strings.Cut(c.o.AuthKey, "--TL")
	if !wrapped {
		if c.state.TKA != nil && len(c.state.TKA.SelfSignature) > 0 {
			return base, c.state.TKA.SelfSignature, nil
		}
		return base, nil, nil
	}
	encoded, secret, ok := strings.Cut(suffix, "-")
	if !ok || len(suffix) > 32768 {
		return "", nil, errTSAuth
	}
	wire, e := base64.RawStdEncoding.DecodeString(encoded)
	if e != nil {
		return "", nil, errTSAuth
	}
	private, e := base64.RawStdEncoding.DecodeString(secret)
	if e != nil || len(private) != 64 {
		return "", nil, errTSAuth
	}
	defer clear(private)
	key := ed25519.NewKeyFromSeed(private[:32])
	defer clear(key)
	if !bytes.Equal(key, private) {
		return "", nil, errTSAuth
	}
	credential, e := tsCBORDecode(wire)
	if e != nil || credential.num(1) != 3 || !bytes.Equal(credential.bytes(6), key.Public().(ed25519.PublicKey)) {
		return "", nil, errTSAuth
	}
	m := tsCBOR{uint64(1): uint64(2), uint64(2): append([]byte("np"), c.nodeKey.PublicKey().Bytes()...), uint64(5): credential, uint64(6): []byte(c.lockKey().Public().(ed25519.PublicKey))}
	m[uint64(4)] = ed25519.Sign(key, blake2s(tsCBOREncode(nil, m), nil, 32))
	return base, tsCBOREncode(nil, m), nil
}
