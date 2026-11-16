package native

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
)

type tsLockVectors struct {
	Genesis, Secret, Derived, Node, Rotated, Direct, Rotation, Credential, Local []byte
	Updates, Forks                                                               [][]byte
	Heads                                                                        []string
	ForkHead                                                                     string `json:"fork_head"`
	Wrapped                                                                      string
	ZIP215                                                                       []struct {
		Key, Message, Signature []byte
		Valid                   bool
	}
}

func TestTailscaleTailnetLockSyncAncestors(t *testing.T) {
	a := &tsTKA{updates: map[string]*tsTKAUpdate{}}
	for i := range 8192 {
		hash := strconv.Itoa(i)
		parent := ""
		if i > 0 {
			parent = strconv.Itoa(i - 1)
		}
		a.updates[hash] = &tsTKAUpdate{hash: hash, parent: parent}
	}
	a.root, a.head = a.updates["0"], a.updates["8191"]
	hashes := a.syncAncestors()
	if len(hashes) > 32 || hashes[0] != a.head.hash || hashes[len(hashes)-1] != a.root.hash {
		t.Fatal("long history lost its common checkpoint", hashes)
	}
	previous := 8192
	for i, h := range hashes {
		n, e := strconv.Atoi(h)
		if e != nil || n >= previous {
			t.Fatal("ancestors out of order", hashes)
		}
		if i < 8 && n != 8191-i {
			t.Fatal("recent history was skipped", hashes)
		}
		previous = n
	}
}

func tsLockFixture(t *testing.T) (tsLockVectors, *tailscaleClient, *json.Encoder, *json.Decoder) {
	t.Helper()
	reference := os.Getenv("LANBOAT_TEST_TAILSCALE")
	if reference == "" {
		t.Fatal("LANBOAT_TEST_TAILSCALE required for Tailnet Lock interoperability")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	c := &tailscaleClient{ctx: ctx, stateDir: t.TempDir()}
	c.machine, _ = ecdh.X25519().GenerateKey(rand.Reader)
	c.nodeKey, _ = ecdh.X25519().GenerateKey(rand.Reader)
	cmd := exec.CommandContext(ctx, reference)
	cmd.Env = append(os.Environ(), "LANBOAT_TS_LOCK_ORACLE=1")
	cmd.Stderr = os.Stderr
	in, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { in.Close(); cancel(); cmd.Wait() })
	encoder, decoder := json.NewEncoder(in), json.NewDecoder(out)
	if e = encoder.Encode(map[string]any{"Wrapping": c.lockKey().Public()}); e != nil {
		t.Fatal(e)
	}
	var v tsLockVectors
	if e = decoder.Decode(&v); e != nil {
		t.Fatal(e)
	}
	return v, c, encoder, decoder
}
func TestTailscaleTailnetLockReference(t *testing.T) {
	v, c, enc, dec := tsLockFixture(t)
	a, e := tsTKABootstrap(v.Genesis)
	if e != nil {
		t.Fatal("official genesis", e)
	}
	if !bytes.Equal(v.Genesis, tsCBOREncode(nil, a.root.wire)) {
		t.Fatal("CTAP2 bytes differ from official encoding")
	}
	for name, row := range map[string]struct{ node, signature []byte }{"direct": {v.Node, v.Direct}, "rotation": {v.Rotated, v.Rotation}, "credential": {v.Node, v.Credential}} {
		t.Run(name, func(t *testing.T) {
			if !a.nodeAuthorized(row.node, row.signature) {
				t.Fatal("official signature rejected")
			}
			forged := bytes.Clone(row.signature)
			forged[len(forged)-1] ^= 1
			if a.nodeAuthorized(row.node, forged) {
				t.Fatal("forged node signature accepted")
			}
			if a.nodeAuthorized(make([]byte, 32), row.signature) {
				t.Fatal("signature authorized another node")
			}
		})
	}
	c.o.AuthKey = v.Wrapped
	base, wrapped, e := c.lockAuth()
	if e != nil || base != "test-only-auth" || !a.nodeAuthorized(c.nodeKey.PublicKey().Bytes(), wrapped) {
		t.Fatal("wrapped auth key", e)
	}
	c.o.AuthKey = v.Wrapped + "x"
	if _, _, e = c.lockAuth(); e == nil {
		t.Fatal("invalid wrapping key accepted")
	}
	rotated, e := c.rotateLockSignature(v.Local)
	if e != nil {
		t.Fatal(e)
	}
	if !a.nodeAuthorized(c.nodeKey.PublicKey().Bytes(), rotated) {
		t.Fatal("local rotation failed")
	}
	if e = enc.Encode(map[string]any{"Node": append([]byte("np"), c.nodeKey.PublicKey().Bytes()...), "Signature": rotated}); e != nil {
		t.Fatal(e)
	}
	var result struct{ Valid bool }
	if e = dec.Decode(&result); e != nil || !result.Valid {
		t.Fatal("official authority rejected Lanboat rotation", e)
	}
	c.tka = a
	c.nodes = map[int64]tsNode{1: {Key: "nodekey:" + hex.EncodeToString(v.Node[2:]), KeySignature: v.Direct}, 2: {Key: "nodekey:" + hex.EncodeToString(v.Rotated[2:]), KeySignature: v.Rotation}}
	c.applyLockLocked()
	if !c.nodes[1].lockInvalid || c.nodes[2].lockInvalid {
		t.Fatal("rotation did not retire old node key")
	}
	c.tka = nil
	for i, update := range v.Updates {
		if e = a.add([][]byte{update}); e != nil {
			t.Fatal("official AUM", i, e)
		}
		if a.head.hash != v.Heads[i] {
			t.Fatal("official authority head differs", i, a.head.hash, v.Heads[i])
		}
		if (i < 2) != a.nodeAuthorized(v.Node, v.Direct) {
			t.Fatal("signer removal did not revoke node", i)
		}
	}
	stored := a.stored(rotated)
	restored, e := tsTKARestore(stored)
	if e != nil || restored.head.hash != a.head.hash {
		t.Fatal("durable history", e)
	}
	stored.Head = tsTKAHash([]byte("rollback"))
	if _, e = tsTKARestore(stored); e == nil {
		t.Fatal("wrong pinned head accepted")
	}
	for _, reverse := range []bool{false, true} {
		f, e := tsTKABootstrap(v.Genesis)
		if e != nil {
			t.Fatal(e)
		}
		forks := slices.Clone(v.Forks)
		if reverse {
			slices.Reverse(forks)
		}
		if e = f.add(forks); e != nil || f.head.hash != v.ForkHead {
			t.Fatal("fork resolution differs from official authority", e, f.head.hash, v.ForkHead)
		}
	}
	if got := tsTKADisablement(v.Secret); !bytes.Equal(got, v.Derived) {
		t.Fatalf("Argon2i differs from official KDF: %x / %x", got, v.Derived)
	}
	for i, row := range v.ZIP215 {
		if got := tsTKAVerify(row.Key, row.Message, row.Signature); got != row.Valid {
			t.Fatal("ZIP215 differs from official consensus", i, got, row.Valid)
		}
	}
}
func TestTailscaleTailnetLockBounds(t *testing.T) {
	for _, b := range [][]byte{nil, {0xa2, 1, 1, 1, 2}, {0xbf, 0xff}, {0xa1, 1, 0xc0, 0xf6}, {0xa1, 1, 0x5a, 0xff, 0xff, 0xff, 0xff}, bytes.Repeat([]byte{0x81}, 32)} {
		if _, e := tsCBORDecode(b); e == nil {
			t.Fatalf("malformed CBOR accepted: %x", b)
		}
	}
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	state := tsCBOR{uint64(1): nil, uint64(2): []any{make([]byte, 32)}, uint64(3): []any{tsCBOR{uint64(1): uint64(1), uint64(2): uint64(1), uint64(3): []byte(private.Public().(ed25519.PublicKey))}}}
	genesis := tsCBOR{uint64(1): uint64(5), uint64(2): nil, uint64(5): state}
	sign := func(m tsCBOR) []byte {
		digest := blake2s(tsTKAUnsigned(m, 23), nil, 32)
		m[uint64(23)] = []any{tsCBOR{uint64(1): []byte(private.Public().(ed25519.PublicKey)), uint64(2): ed25519.Sign(private, digest)}}
		return tsCBOREncode(nil, m)
	}
	a, e := tsTKABootstrap(sign(genesis))
	if e != nil {
		t.Fatal(e)
	}
	parent, _ := tsTKAEncoding.DecodeString(a.head.hash)
	valid := sign(tsCBOR{uint64(1): uint64(3), uint64(2): parent})
	forged := bytes.Clone(valid)
	forged[len(forged)-1] ^= 1
	for _, b := range [][]byte{forged, sign(tsCBOR{uint64(1): uint64(3), uint64(2): make([]byte, 32)}), sign(tsCBOR{uint64(1): uint64(5), uint64(2): parent, uint64(5): tsCBOR{uint64(1): nil, uint64(2): state[uint64(2)], uint64(3): state[uint64(3)], uint64(4): uint64(99)}})} {
		if e = a.add([][]byte{valid, b}); e == nil || len(a.updates) != 1 || a.head != a.root {
			t.Fatal("invalid batch partially committed", e)
		}
	}
	if !tsTKALessHash("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "777777777777777777777777777777777777777777777777777Q") {
		t.Fatal("hash tiebreak must compare digest bytes, not base32 alphabet")
	}
}
func TestTailscaleTailnetLockControl(t *testing.T) {
	v, c, _, _ := tsLockFixture(t)
	genesis, _ := tsTKABootstrap(v.Genesis)
	var disabled, badDisable bool
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Error("TKA RPC method")
		}
		requests = append(requests, r.URL.Path)
		var request map[string]any
		if e := json.NewDecoder(r.Body).Decode(&request); e != nil {
			t.Error(e)
		}
		if request["NodeKey"] != tsKeyName(c.nodeKey, "nodekey") {
			t.Error("TKA RPC identity")
		}
		switch r.URL.Path {
		case "/machine/tka/bootstrap":
			if disabled {
				secret := v.Secret
				if badDisable {
					secret = []byte("wrong")
				}
				json.NewEncoder(w).Encode(map[string]any{"DisablementSecret": secret})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"GenesisAUM": v.Genesis})
			}
		case "/machine/tka/sync/offer":
			json.NewEncoder(w).Encode(map[string]any{"Head": v.Heads[len(v.Heads)-1], "Ancestors": []string{genesis.head.hash}, "MissingAUMs": v.Updates})
		case "/machine/tka/sync/send":
			json.NewEncoder(w).Encode(map[string]any{"Head": v.Heads[len(v.Heads)-1]})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dialer := net.Dialer{}
	c.control = &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer c.control.CloseIdleConnections()
	c.o.ControlURL = server.URL
	if e := c.syncLock(&tsTKAInfo{Head: genesis.head.hash}); e != nil {
		t.Fatal(e)
	}
	if len(requests) != 1 {
		t.Fatal("up-to-date genesis caused unnecessary RPCs")
	}
	if e := c.syncLock(&tsTKAInfo{Head: v.Heads[len(v.Heads)-1]}); e != nil {
		t.Fatal(e)
	}
	if c.tka.head.hash != v.Heads[len(v.Heads)-1] {
		t.Fatal("sync head")
	}
	var disk tsState
	b, e := os.ReadFile(filepath.Join(c.stateDir, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &disk); e != nil {
		t.Fatal(e)
	}
	if _, e = tsTKARestore(disk.TKA); e != nil {
		t.Fatal(e)
	}
	disabled, badDisable = true, true
	if e = c.syncLock(&tsTKAInfo{Disabled: true}); !errors.Is(e, errTSTailnetLock) || c.tka == nil {
		t.Fatal("unverified disablement accepted", e)
	}
	badDisable = false
	if e = c.syncLock(&tsTKAInfo{Disabled: true}); e != nil || c.tka != nil {
		t.Fatal("verified disablement failed", e)
	}
	// The stream wrapper is the same independently tested Noise transport; this
	// fixture specifically verifies TKA HTTP payloads, persistence and downgrades.
}

func FuzzTailscaleTailnetLock(f *testing.F) {
	for _, b := range [][]byte{{}, {0xa0}, {0xa1, 1, 1}, {0xa2, 1, 1, 1, 2}, {0xa1, 1, 0x81, 0xf6}} {
		f.Add(b)
	}
	authority := &tsTKA{head: &tsTKAUpdate{state: &tsTKAState{keys: map[string]tsTKAKey{}}}}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		if m, e := tsCBORDecode(b); e == nil {
			wire := tsCBOREncode(nil, m)
			again, e := tsCBORDecode(wire)
			if e != nil || !bytes.Equal(wire, tsCBOREncode(nil, again)) {
				t.Fatal("CBOR round trip")
			}
		}
		tsTKABootstrap(b)
		authority.nodeAuthorized(make([]byte, 32), b)
	})
}
