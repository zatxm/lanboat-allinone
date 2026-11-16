package native

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestTailscaleTailnetLockNoiseReference(t *testing.T) {
	t.Setenv("LANBOAT_TS_LOCK_NOISE", "1")
	control, _, _ := startTSReference(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	r := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: control, StateDirectory: t.TempDir(), ForceDERP: true, Hostname: "lock-native"}}}, Route: Route{Final: "ts"}})
	if _, e := r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	var status TailscaleStatus
	for ctx.Err() == nil {
		var e error
		status, e = r.TailscaleStatus(ctx, "ts")
		if e != nil {
			t.Fatal(e)
		}
		if status.TailnetLock && status.NodeKeySigned {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !status.NodeKeySigned {
		t.Fatal("official signed map did not enable native authority", status)
	}
	c := r.tailscaleClient("ts")
	c.mu.Lock()
	var peer tsNode
	for _, n := range c.nodes {
		if n.Name == "reference.test.ts.net." {
			peer = n
		}
	}
	c.mu.Unlock()
	session, e := c.peer(peer)
	if e != nil {
		t.Fatal("signed peer", e)
	}
	patch, _ := json.Marshal(map[string]any{"PeersChangedPatch": []any{map[string]any{"NodeID": peer.ID, "KeySignature": []byte("invalid signature")}}})
	if e := c.applyMap(patch); e != nil {
		t.Fatal(e)
	}
	if _, e := c.peer(peer); e == nil {
		t.Fatal("unsigned peer remained usable")
	}
	select {
	case <-session.wg.done:
	default:
		t.Fatal("revoked peer session survived")
	}
	// A control-plane-only disablement cannot bypass the pinned authority.
	if e := c.applyMap([]byte(`{"TKAInfo":{"Head":"not-a-hash"}}`)); !errors.Is(e, errTSTailnetLock) {
		t.Fatal("malformed authority head accepted", e)
	}
	c.mu.Lock()
	if !c.nodes[peer.ID].lockInvalid {
		t.Error("signature revocation lost")
	}
	c.mu.Unlock()
}
