package native

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTailscaleSSHDelegation(t *testing.T) {
	var requests atomic.Int32
	var host atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		host.Store(r.Host)
		switch r.URL.Path {
		case "/first":
			if r.URL.Query().Get("user") != "alice+tag" || r.URL.Query().Get("source") != "100.64.0.2" {
				t.Error("delegate variables were not URL encoded")
			}
			json.NewEncoder(w).Encode(map[string]any{"holdAndDelegate": "https://ignored.invalid/second?local=$LOCAL_USER"})
		case "/second":
			if r.URL.Query().Get("local") != "local" {
				t.Error("nested delegate variables missing")
			}
			json.NewEncoder(w).Encode(map[string]any{"accept": true, "allowLocalPortForwarding": true, "sessionDuration": int64(time.Minute)})
		case "/deny":
			json.NewEncoder(w).Encode(map[string]any{"reject": true})
		case "/loop":
			json.NewEncoder(w).Encode(map[string]any{"holdAndDelegate": "/loop"})
		case "/invalid-action":
			json.NewEncoder(w).Encode(map[string]any{"accept": true, "holdAndDelegate": "/second"})
		case "/unauthorized":
			w.WriteHeader(http.StatusUnauthorized)
		case "/wait":
			<-r.Context().Done()
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dialer := net.Dialer{}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	c := &tailscaleClient{o: Outbound{TailscaleOptions: TailscaleOptions{ControlURL: server.URL}}, control: transport, self: tsNode{ID: 1}, nodes: map[int64]tsNode{2: {ID: 2}}, addressOwners: map[netip.Addr]int64{netip.MustParseAddr("100.64.0.2"): 2}}
	conn := &tsSSHConnection{server: &tsSSHServer{c: c}, source: netip.MustParseAddr("100.64.0.2"), destination: netip.MustParseAddr("100.64.0.1"), requested: "alice+tag", ctx: context.Background()}
	for _, row := range []struct {
		name, target string
		count        int32
		accept       bool
	}{
		{"chain", "https://never-dial.invalid/first?user=$SSH_USER&source=$SRC_NODE_IP", 2, true},
		{"deny", "/deny", 1, false},
		{"loop", "/loop", 32, false},
		{"invalid-action", "/invalid-action", 1, false},
		{"credentials", "https://u:p@ignored.invalid/second", 0, false},
		{"scheme", "file:///second", 0, false},
		{"unauthorized", "/unauthorized", 1, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			before := requests.Load()
			action, e := conn.delegate(tsSSHGrant{local: "local", action: tsSSHAction{HoldAndDelegate: row.target}}, &sshWire{})
			if row.accept && (e != nil || !action.Accept || !action.AllowLocalPortForwarding || action.SessionDuration != time.Minute) {
				t.Fatal(action, e)
			}
			if !row.accept && e == nil {
				t.Fatal("unsafe delegate accepted", row.target)
			}
			if requests.Load()-before != row.count {
				t.Fatal("unexpected delegated request count", requests.Load()-before)
			}
			if row.count > 0 && host.Load() != server.Listener.Addr().String() {
				t.Fatal("delegate escaped the control authority", host.Load())
			}
		})
	}
	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		copy := &tsSSHConnection{server: conn.server, source: conn.source, destination: conn.destination, requested: conn.requested, ctx: ctx}
		_, e := copy.delegate(tsSSHGrant{action: tsSSHAction{HoldAndDelegate: "/wait"}}, &sshWire{})
		if e == nil || !errors.Is(e, context.DeadlineExceeded) && !strings.Contains(e.Error(), "deadline") {
			t.Fatal("delegate ignored authentication cancellation", e)
		}
	})
}
