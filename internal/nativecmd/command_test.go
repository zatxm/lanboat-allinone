package nativecmd

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCommands(t *testing.T) {
	for _, name := range []string{"version", "protocols", "help"} {
		var output bytes.Buffer
		if err := Execute(context.Background(), []string{name}, &output); err != nil {
			t.Fatal(err)
		}
		if output.Len() == 0 {
			t.Fatalf("%s produced no output", name)
		}
		if name == "protocols" && !json.Valid(output.Bytes()) {
			t.Fatal("invalid protocol capabilities JSON")
		}
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"log":{"disabled":true},"inbounds":[{"type":"mixed","tag":"local","listen":"127.0.0.1","listen_port":0}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Execute(context.Background(), []string{"check", "-c", path}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"run", "client", "server"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		err := Execute(ctx, []string{name, "-c", path}, &bytes.Buffer{})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"type":"not-a-protocol"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Execute(context.Background(), []string{"check", "-c", path}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not-a-protocol") {
		t.Fatalf("invalid protocol: %v", err)
	}
}

func TestGenerateECH(t *testing.T) {
	var b bytes.Buffer
	if err := Execute(context.Background(), []string{"generate", "ech-keypair", "public.test"}, &b); err != nil {
		t.Fatal(err)
	}
	config, rest := pem.Decode(b.Bytes())
	if config == nil || config.Type != "ECH CONFIGS" {
		t.Fatal("missing ECH config")
	}
	key, rest := pem.Decode(rest)
	if key == nil || key.Type != "ECH KEYS" || len(rest) != 0 {
		t.Fatal("missing ECH keys or extra output")
	}
	for _, args := range [][]string{{"generate"}, {"generate", "unknown", "public.test"}, {"generate", "ech-keypair", "127.0.0.1"}, {"generate", "ech-keypair", "bad/name"}, {"generate", "ech-keypair", "public.test", "extra"}} {
		if err := Execute(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid generate accepted: %v", args)
		}
	}
}

func TestGenerateCloak(t *testing.T) {
	var b bytes.Buffer
	if err := Execute(context.Background(), []string{"generate", "cloak-keypair"}, &b); err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	private, e := base64.StdEncoding.DecodeString(v["private_key"])
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdh.X25519().NewPrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	if v["public_key"] != base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) {
		t.Fatal("key pair does not match")
	}
	uid, e := base64.StdEncoding.DecodeString(v["uid"])
	if e != nil || len(uid) != 16 {
		t.Fatal("invalid UID", e)
	}
}

func TestGenerateReality(t *testing.T) {
	var b bytes.Buffer
	if err := Execute(context.Background(), []string{"generate", "reality-keypair"}, &b); err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	private, err := base64.RawURLEncoding.Strict().DecodeString(v["private_key"])
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if v["public_key"] != base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) {
		t.Fatal("key pair mismatch")
	}
	if err := Execute(context.Background(), []string{"generate", "reality-keypair", "extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unexpected key generation argument accepted")
	}
}

func TestGenerateRealityMLDSA(t *testing.T) {
	var b bytes.Buffer
	if err := Execute(context.Background(), []string{"generate", "reality-mldsa65-keypair"}, &b); err != nil {
		t.Fatal(err)
	}
	var data map[string]string
	if err := json.Unmarshal(b.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	seed, err := base64.RawURLEncoding.Strict().DecodeString(data["mldsa65_seed"])
	if err != nil || len(seed) != 32 {
		t.Fatal("invalid seed", err)
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(data["mldsa65_verify"])
	if err != nil || len(public) != 1952 {
		t.Fatal("invalid public key", err)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil || !bytes.Equal(key.PublicKey().Bytes(), public) {
		t.Fatal("key pair mismatch", err)
	}
	if err := Execute(context.Background(), []string{"generate", "reality-mldsa65-keypair", "extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unexpected argument accepted")
	}
}
