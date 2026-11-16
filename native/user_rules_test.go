package native

import (
	"context"
	"encoding/json"
	"testing"
)

func TestUserRulesSemantics(t *testing.T) {
	zero, one := uint32(0), uint32(1)
	for _, v := range []struct {
		name    string
		rule    Rule
		matches []Metadata
		misses  []Metadata
	}{
		{"uid", Rule{UserID: []uint32{0}}, []Metadata{{UserID: &zero}}, []Metadata{{}, {UserID: &one}}},
		{"user", Rule{User: []string{"alice"}}, []Metadata{{User: "alice"}}, []Metadata{{}, {User: "Alice"}, {AuthUser: "alice"}}},
		{"and", Rule{User: []string{"alice"}, UserID: []uint32{0}}, []Metadata{{User: "alice", UserID: &zero}}, []Metadata{{User: "alice"}, {UserID: &zero}, {User: "alice", UserID: &one}}},
	} {
		t.Run(v.name, func(t *testing.T) {
			rule := v.rule
			rule.Outbound = "direct"
			r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{rule}}})
			for _, m := range v.matches {
				_, tag, err := r.routeTarget(WithMetadata(context.Background(), m), request{address: "203.0.113.1:443", network: "tcp", metadata: m})
				if err != nil || tag != "direct" {
					t.Fatal(tag, err, m)
				}
			}
			for _, m := range v.misses {
				_, tag, err := r.routeTarget(WithMetadata(context.Background(), m), request{address: "203.0.113.1:443", network: "tcp", metadata: m})
				if err != nil || tag != "deny" {
					t.Fatal(tag, err, m)
				}
			}
			rule.Invert = true
			compiled, err := compileRoute(Route{Final: "direct", Rules: []Rule{rule}}, map[string]Outbound{"direct": {Type: "direct"}})
			if err != nil {
				t.Fatal(err)
			}
			q := request{preMatch: true, address: "203.0.113.1:443", network: "tcp"}
			if compiled[0].matches(q) || !compiled[0].preMatchNeedsData(q) {
				t.Fatal("unknown identity resolved an inverted pre-match")
			}
		})
	}
	for _, raw := range []string{`{"route":{"rules":[{"user_id":-1,"outbound":"direct"}]}}`, `{"route":{"rules":[{"user":"","outbound":"direct"}]}}`, `{"route":{"rules":[{"user_id":4294967296,"outbound":"direct"}]}}`} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("invalid identity accepted", raw)
		}
	}
	if _, err := Parse([]byte(`{"route":{"rules":[{"user_id":0,"outbound":"direct"}]}}`)); err != nil {
		t.Fatal("scalar root UID", err)
	}
}
func TestUserRulesJSONHeadless(t *testing.T) {
	raw := []byte(`{"version":4,"rules":[{"type":"logical","mode":"or","rules":[{"user_id":0},{"user":"alice"}]}]}`)
	items, err := parseRuleSet(raw, "source")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := compileRuleSet(items)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(0)
	if !snapshot.rules[0].matches(request{metadata: Metadata{UserID: &uid}}) || snapshot.rules[0].matches(request{}) {
		t.Fatal("headless identity match")
	}
	if _, err = CompileRuleSet(raw, "source"); err == nil {
		t.Fatal("SRS silently dropped an identity condition")
	}
	nested := Rule{Type: "logical", Mode: "and", UserID: []uint32{0}, Rules: []Rule{{Network: []string{"tcp"}}}, Outbound: "direct"}
	data, _ := json.Marshal(Config{Route: Route{Rules: []Rule{nested}}})
	if _, err = Parse(data); err == nil {
		t.Fatal("identity outside logical child accepted")
	}
}

func TestUserRulesUDPMappingIdentityIsolation(t *testing.T) {
	allowed, denied := uint32(1001), uint32(0)
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{UserID: []uint32{allowed}, User: []string{"alice"}, Outbound: "direct"}}}})
	flows := newUDPFlows(r)
	defer flows.Close()
	q := request{address: echoUDP(t), metadata: Metadata{UserID: &allowed, User: "alice"}}
	reply := func([]byte, string) error { return nil }
	if err := flows.send("same-udp-port", q, []byte("allowed"), reply); err != nil {
		t.Fatal(err)
	}
	q.metadata.User = "bob"
	if err := flows.send("same-udp-port", q, []byte("other-name"), reply); err == nil {
		t.Fatal("another username inherited an allowed UDP mapping")
	}
	q.metadata.User = "alice"
	q.metadata.UserID = &denied
	if err := flows.send("same-udp-port", q, []byte("denied"), reply); err == nil {
		t.Fatal("UID0 inherited UID1001's UDP mapping")
	}
	q.metadata.UserID = nil
	if err := flows.send("same-udp-port", q, []byte("unknown"), reply); err == nil {
		t.Fatal("unknown UID inherited an allowed UDP mapping")
	}
}
