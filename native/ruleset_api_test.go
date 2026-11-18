package native

import (
	"encoding/json"
	"testing"
)

func TestRuleSetModuleAPIs(t *testing.T) {
	wire, err := CompileRuleSet([]byte(`{"version":4,"rules":[{"domain_suffix":["example.test"]},{"ip_cidr":["192.0.2.0/24"]}]}`), "source")
	if err != nil {
		t.Fatal(err)
	}
	source, err := DecodeRuleSet(wire)
	if err != nil || !json.Valid(source) {
		t.Fatal(err, string(source))
	}
	if _, err = CompileRuleSet(source, "source"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		target string
		want   bool
	}{{"a.example.test", true}, {"192.0.2.10", true}, {"other.test", false}, {"192.0.3.10", false}} {
		got, err := MatchRuleSet(wire, test.target)
		if err != nil || got != test.want {
			t.Fatal(test, got, err)
		}
	}
	if _, err = DecodeRuleSet([]byte("invalid")); err == nil {
		t.Fatal("invalid binary accepted")
	}
}
