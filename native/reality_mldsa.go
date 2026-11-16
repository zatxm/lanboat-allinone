package native

import (
	"crypto/mldsa"
	"encoding/asn1"
	"encoding/base64"
	"errors"
)

var realityMLDSAOID = asn1.ObjectIdentifier{0, 0}

func realityMLDSAPrivate(value string) (*mldsa.PrivateKey, error) {
	seed, err := realityKey(value)
	if err != nil {
		return nil, errors.New("Reality mldsa65_seed must be a32-byte base64url seed")
	}
	defer clear(seed)
	return mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
}
func realityMLDSAPublic(value string) (*mldsa.PublicKey, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(data) != 1952 {
		return nil, errors.New("Reality mldsa65_verify must be a1952-byte base64url public key")
	}
	return mldsa.NewPublicKey(mldsa.MLDSA65(), data)
}

// GenerateRealityMLDSA65KeyPair returns an independent signing seed and its
// public verification key, both in unpadded base64url.
func GenerateRealityMLDSA65KeyPair() (seed, public string, err error) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
