package native

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func (c *tailscaleClient) saveState() error {
	b, e := json.Marshal(c.state)
	if e != nil {
		return e
	}
	if c.stateDir == "" {
		return errors.New("Tailscale state directory is unavailable")
	}
	f, e := os.CreateTemp(c.stateDir, ".state-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		e = writeAll(f, b)
	}
	if e == nil {
		e = f.Sync()
	}
	closed := f.Close()
	if e == nil {
		e = closed
	}
	if e == nil {
		e = os.Rename(f.Name(), filepath.Join(c.stateDir, "state.json"))
	}
	return e
}
func (c *tailscaleClient) tkaRPC(path string, body, result any) error {
	if c.control == nil {
		return errTSTailnetLock
	}
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	b, e := json.Marshal(body)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "GET", "http://tailscale-control/machine/tka/"+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	u, _ := url.Parse(c.o.controlURL())
	req.Host = u.Host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, e := c.control.RoundTrip(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("Tailscale Tailnet Lock control request failed")
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 24<<20)).Decode(result)
}
func (c *tailscaleClient) syncLock(info *tsTKAInfo) error {
	if info == nil {
		return nil
	}
	if !info.Disabled && !tsTKAValidHash(info.Head) {
		return errTSTailnetLock
	}
	if c.tka == nil && info.Disabled {
		return nil
	}
	if c.tka != nil && !info.Disabled && info.Head == c.tka.head.hash {
		return nil
	}
	head := ""
	if c.tka != nil {
		head = c.tka.head.hash
	}
	base := map[string]any{"Version": tailscaleCapability, "NodeKey": tsKeyName(c.nodeKey, "nodekey"), "Head": head}
	if c.tka == nil || info.Disabled {
		var result struct{ GenesisAUM, DisablementSecret []byte }
		if e := c.tkaRPC("bootstrap", base, &result); e != nil {
			return e
		}
		if info.Disabled {
			if len(result.DisablementSecret) == 0 || len(result.DisablementSecret) > 4096 {
				return errTSTailnetLock
			}
			derived := tsTKADisablement(result.DisablementSecret)
			valid := false
			for _, candidate := range c.tka.head.state.disable {
				valid = valid || hmac.Equal(derived, candidate)
			}
			if !valid {
				return errTSTailnetLock
			}
			previous := c.state.TKA
			c.state.TKA = nil
			if e := c.saveState(); e != nil {
				c.state.TKA = previous
				return e
			}
			c.tka = nil
			return nil
		}
		t, e := tsTKABootstrap(result.GenesisAUM)
		if e != nil {
			return e
		}
		// Commit the TOFU checkpoint before attempting the rest of the sync.
		// An interrupted download must not permit a different root next time.
		c.state.TKA = t.stored(nil)
		if e = c.saveState(); e != nil {
			c.state.TKA = nil
			return e
		}
		c.tka = t
	}
	if info.Head == c.tka.head.hash {
		return nil
	}
	// Work on an isolated history; failed signature checks and partial writes
	// cannot modify the currently enforced authority.
	t, e := tsTKARestore(c.state.TKA)
	if e != nil {
		return e
	}
	base["Head"], base["Ancestors"] = t.head.hash, t.syncAncestors()
	var offer struct {
		Head        string
		Ancestors   []string
		MissingAUMs [][]byte
	}
	if e = c.tkaRPC("sync/offer", base, &offer); e != nil {
		return e
	}
	if !tsTKAValidHash(offer.Head) || len(offer.Ancestors) > 8192 {
		return errTSTailnetLock
	}
	if e = t.add(offer.MissingAUMs); e != nil {
		return e
	}
	if t.updates[offer.Head] == nil || t.updates[info.Head] == nil {
		return errTSTailnetLock
	}
	// Return locally known history after the newest shared ancestor. This also
	// repairs a control server which lost a branch; it cannot choose the fork.
	shared := map[string]bool{offer.Head: true}
	for _, h := range offer.Ancestors {
		if !tsTKAValidHash(h) {
			return errTSTailnetLock
		}
		shared[h] = true
	}
	var missing [][]byte
	for p := t.head; p != nil && !shared[p.hash]; p = t.updates[p.parent] {
		missing = append(missing, p.raw)
	}
	slicesReverse(missing)
	var sent struct{ Head string }
	if e = c.tkaRPC("sync/send", map[string]any{"Version": tailscaleCapability, "NodeKey": tsKeyName(c.nodeKey, "nodekey"), "Head": t.head.hash, "MissingAUMs": missing}, &sent); e != nil {
		return e
	}
	if !tsTKAValidHash(sent.Head) {
		return errTSTailnetLock
	}
	previous := c.state.TKA
	c.state.TKA = t.stored(previous.SelfSignature)
	if e = c.saveState(); e != nil {
		c.state.TKA = previous
		return e
	}
	c.tka = t
	return nil
}

// Offer recent parents densely and older parents exponentially. Always include
// the pinned checkpoint, so a stale control server can still find an overlap.
func (t *tsTKA) syncAncestors() []string {
	var hashes []string
	step := 1
	for p := t.head; p != nil; {
		hashes = append(hashes, p.hash)
		for i := 0; i < step && p != nil; i++ {
			p = t.updates[p.parent]
		}
		if len(hashes) >= 8 {
			step *= 2
		}
	}
	if hashes[len(hashes)-1] != t.root.hash {
		hashes = append(hashes, t.root.hash)
	}
	return hashes
}
func slicesReverse[T any](v []T) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}

type tsTKAInfo struct {
	Head     string
	Disabled bool
}

func (c *tailscaleClient) applyLockLocked() {
	c.self.lockInvalid = false
	c.lockHead = ""
	if c.tka != nil {
		c.lockHead = c.tka.head.hash
		c.self.lockInvalid = !c.tka.nodeAuthorized(c.nodeKey.PublicKey().Bytes(), c.self.KeySignature)
	}
	obsolete := map[string]bool{}
	if c.tka != nil && !c.self.lockInvalid {
		for _, key := range c.tka.obsolete(c.self.KeySignature) {
			obsolete[string(key)] = true
		}
	}
	for id, n := range c.nodes {
		n.lockInvalid = false
		if c.tka != nil {
			key, e := tsPublic(n.Key, "nodekey")
			n.lockInvalid = e != nil || !c.tka.nodeAuthorized(key, n.KeySignature)
			if !n.lockInvalid {
				for _, old := range c.tka.obsolete(n.KeySignature) {
					obsolete[string(old)] = true
				}
			}
		}
		c.nodes[id] = n
	}
	if len(obsolete) > 0 {
		if obsolete[string(c.nodeKey.PublicKey().Bytes())] {
			c.self.lockInvalid = true
		}
		for id, n := range c.nodes {
			key, _ := tsPublic(n.Key, "nodekey")
			if obsolete[string(key)] {
				n.lockInvalid = true
				c.nodes[id] = n
			}
		}
	}
}

func (c *tailscaleClient) lockHeadSnapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lockHead
}
