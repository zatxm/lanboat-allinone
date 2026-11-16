package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type tsInterruptedReader struct{ *bytes.Reader }

func (r tsInterruptedReader) Read(b []byte) (int, error) {
	n, e := r.Reader.Read(b)
	if e == io.EOF {
		e = io.ErrUnexpectedEOF
	}
	return n, e
}

func tsDropTestClient(t *testing.T, dir string) *tailscaleClient {
	t.Helper()
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct"}})
	c := newTailscaleClient(r, Outbound{TailscaleOptions: TailscaleOptions{TaildropDirectory: dir}})
	if e := c.startPeerAPI(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.cancel(); c.peerAPI.close() })
	if e := c.applyMap([]byte(`{"Node":{"User":1,"Addresses":["100.64.0.1/32"]},"Peers":[{"ID":2,"StableID":"sender-a","User":1,"Addresses":["100.64.0.2/32"]},{"ID":3,"StableID":"sender-b","User":2,"Addresses":["100.64.0.3/32"]}]}`)); e != nil {
		t.Fatal(e)
	}
	return c
}
func tsDropRequest(c *tailscaleClient, method, path, source, rng string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = source
	req.Header.Set("Range", rng)
	w := httptest.NewRecorder()
	c.peerAPI.ServeHTTP(w, req)
	return w
}
func TestTailscaleTaildropResume(t *testing.T) {
	dir := t.TempDir()
	c := tsDropTestClient(t, dir)
	const path = "/v0/put/resume.txt"
	prefix := bytes.Repeat([]byte("x"), 70000)
	w := tsDropRequest(c, "PUT", path, "100.64.0.2:1234", "", tsInterruptedReader{bytes.NewReader(prefix)})
	if w.Code == 200 {
		t.Fatal("interrupted transfer committed")
	}
	if _, e := os.Stat(filepath.Join(dir, "resume.txt")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
	w = tsDropRequest(c, "GET", "/v0/put/", "100.64.0.2:1234", "", nil)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `["resume.txt"]` {
		t.Fatal(w.Code, w.Body.String())
	}
	w = tsDropRequest(c, "GET", path, "100.64.0.2:1234", "", nil)
	dec := json.NewDecoder(w.Body)
	for _, block := range [][]byte{prefix[:65536], prefix[65536:]} {
		var hash struct {
			Checksum, Algo string
			Size           int
		}
		if e := dec.Decode(&hash); e != nil {
			t.Fatal(e)
		}
		want := sha256.Sum256(block)
		if hash.Algo != "sha256" || hash.Size != len(block) || hash.Checksum != hex.EncodeToString(want[:]) {
			t.Fatal(hash)
		}
	}
	if dec.Decode(new(any)) != io.EOF {
		t.Fatal("unexpected extra checksum")
	}
	// A new receiver instance must be able to resume after a process restart.
	c.peerAPI.close()
	c.cancel()
	c = tsDropTestClient(t, dir)
	for _, rng := range []string{"bytes=-1-", "bytes=+1-", "bytes=1-2", "bytes=70001-"} {
		if w := tsDropRequest(c, "PUT", path, "100.64.0.2:1234", rng, strings.NewReader("tail")); w.Code == 200 {
			t.Fatal("invalid range accepted", rng)
		}
	}
	w = tsDropRequest(c, "PUT", path, "100.64.0.2:1234", "bytes=70000-", strings.NewReader("tail"))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	got, e := os.ReadFile(filepath.Join(dir, "resume.txt"))
	if e != nil || !bytes.Equal(got, append(prefix, []byte("tail")...)) {
		t.Fatal("resume data mismatch", len(got), e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal("partials not removed", entries, e)
	}
}

func TestTailscaleTaildropCapabilities(t *testing.T) {
	c := tsDropTestClient(t, t.TempDir())
	if w := tsDropRequest(c, "PUT", "/v0/put/other.txt", "100.64.0.3:1234", "", strings.NewReader("unauthorized")); w.Code != 403 {
		t.Fatal(w.Code)
	}
	grant := `{"PacketFilters":{"grant":[{"SrcIPs":["100.64.0.3"],"CapGrant":[{"Dsts":["100.64.0.1/32"],"CapMap":{"https://tailscale.com/cap/file-send":[]}}]}]}}`
	if e := c.applyMap([]byte(grant)); e != nil {
		t.Fatal(e)
	}
	packet, _ := parseTunPacket(makeUDPPacket(netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("100.64.0.1"), 1234, c.peerAPI.port, nil))
	packet.protocol = 6
	if !c.acceptsPacket(packet) {
		t.Fatal("explicit file-send grant blocked by unrelated IP ACL")
	}
	packet.protocol = 17
	if c.acceptsPacket(packet) {
		t.Fatal("file-send grant authorized ordinary UDP traffic")
	}

	if w := tsDropRequest(c, "PUT", "/v0/put/other.txt", "100.64.0.3:1234", "", strings.NewReader("authorized")); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if e := c.applyMap([]byte(`{"PacketFilters":{"grant":null}}`)); e != nil {
		t.Fatal(e)
	}
	if w := tsDropRequest(c, "GET", "/v0/put/", "100.64.0.3:1234", "", nil); w.Code != 403 {
		t.Fatal("capability revocation ignored", w.Code)
	}
}

func TestTailscaleTaildropResumeReference(t *testing.T) {
	url, dec, input := startTSReference(t, false)
	dir := t.TempDir()
	r := newTestRuntime(t, Config{Log: LogOptions{Disabled: true}, Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{Hostname: "resume-receiver", AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), TaildropDirectory: dir, ForceDERP: true}}}, Route: Route{Final: "ts"}})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, e := r.TailscaleStatus(ctx, "ts"); e != nil {
		t.Fatal(e)
	}
	c := r.tailscaleClient("ts")
	c.mu.Lock()
	source := ""
	for _, n := range c.nodes {
		if len(n.Addresses) > 0 {
			source = n.Addresses[0].Addr().String() + ":1234"
			break
		}
	}
	c.mu.Unlock()
	data := strings.Repeat("resume!", 12000) + "finished"
	w := tsDropRequest(c, "PUT", "/v0/put/official.txt", source, "", tsInterruptedReader{bytes.NewReader([]byte(data[:70000]))})
	if w.Code == 200 {
		t.Fatal("incomplete file committed")
	}
	if e := json.NewEncoder(input).Encode(map[string]string{"op": "push", "hostname": "resume-receiver", "address": "official.txt", "data": data}); e != nil {
		t.Fatal(e)
	}
	var reply struct {
		OK    bool
		Error string
	}
	if e := dec.Decode(&reply); e != nil || !reply.OK || reply.Error != "" {
		t.Fatal(reply, e)
	}
	got, e := os.ReadFile(filepath.Join(dir, "official.txt"))
	if e != nil || string(got) != data {
		t.Fatal("official resume mismatch", len(got), e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatal("official did not consume partial", entries, e)
	}
}

func TestTailscaleTaildropGrantIsolation(t *testing.T) {
	dir := t.TempDir()
	c := tsDropTestClient(t, dir)
	grant := []byte(`{"PacketFilters":{"grant":[{"SrcIPs":["100.64.0.3"],"CapGrant":[{"Dsts":["100.64.0.1/32"],"Caps":["https://tailscale.com/cap/file-send"]}]}]}}`)
	if e := c.applyMap(grant); e != nil {
		t.Fatal(e)
	}
	w := tsDropRequest(c, "PUT", "/v0/put/private.txt", "100.64.0.2:1", "", tsInterruptedReader{bytes.NewReader([]byte("private partial"))})
	if w.Code == 200 {
		t.Fatal("interrupted transfer committed")
	}
	w = tsDropRequest(c, "GET", "/v0/put/", "100.64.0.3:1", "", nil)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("cross-account partial listing", w.Code, w.Body.String())
	}
	w = tsDropRequest(c, "GET", "/v0/put/private.txt", "100.64.0.3:1", "", nil)
	if w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("cross-account partial content leaked", w.Code, w.Body.String())
	}
	if o := newTailscaleClient(c.r, Outbound{}); o.o.TaildropDirectory != "Taildrop" {
		o.cancel()
		t.Fatal("default directory mismatch")
	} else {
		o.cancel()
	}
}
