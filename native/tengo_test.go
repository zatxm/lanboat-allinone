package native

import (
	"context"
	"strings"
	"testing"
)

func TestTengoIndependentLanguage(t *testing.T) {
	program, err := NewTengoProgram(`
text := import("text")
sum := 0
for i := 0; i < 5; i++ {
    if i == 2 { continue }
    sum += i
}
make_counter := func(n) { return func() { n++; return n } }
next := make_counter(sum)
data := {count: next(), exact: 9007199254740993, items: ["a", "b", "c"]}
data.items[0] = text.to_upper(data.items[0])
out := {count: data.count, exact: data.exact, items: data.items[0:2]}
`, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		value, err := program.Run(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(map[string]any)
		if result["count"] != int64(9) || result["exact"] != int64(9007199254740993) || result["items"].([]any)[0] != "A" {
			t.Fatalf("unexpected result: %#v", result)
		}
	}
}

func TestTengoLimitsAndHostModule(t *testing.T) {
	program, err := NewTengoProgram(`out := import("host").lookup(in_address.domainaddress)`, map[string]map[string]TengoFunction{
		"host": {"lookup": func(ctx context.Context, args []any) (any, error) {
			return map[string]any{"block": args[0] == "blocked.example:443"}, ctx.Err()
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := program.Run(context.Background(), map[string]any{"in_address": map[string]any{"domainaddress": "blocked.example:443"}})
	if err != nil || result.(map[string]any)["block"] != true {
		t.Fatalf("host hook: %#v %v", result, err)
	}
	for _, source := range []string{`for {}`, `out := import("os")`, `a := {}; a.self = a; out := a`} {
		p, err := NewTengoProgram(source, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Run(context.Background(), nil); err == nil {
			t.Fatalf("expected sandbox rejection: %s", source)
		}
	}
}

func TestBrookTengoAddressHook(t *testing.T) {
	o := BrookOptions{Tengo: `
f := func() {
    if in_address {
        text := import("text")
        if text.has_suffix(in_address.domainaddress,"blocked.example:443") { return {block:true} }
        return {address:"127.0.0.1:80",bypass:true}
    }
}
out := f()
`}
	if err := o.prepare("brook"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.addressDecision(context.Background(), "tcp", "blocked.example:443", "", Metadata{}); err != ErrRejected {
		t.Fatalf("blocked target: %v", err)
	}
	decision, err := o.addressDecision(context.Background(), "udp", "example.org:443", "", Metadata{})
	if err != nil || !decision.bypass || decision.address != "127.0.0.1:80" {
		t.Fatalf("rewrite: %#v %v", decision, err)
	}
	ctx, err := brookScriptPath(context.Background(), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brookScriptPath(ctx, "proxy"); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("detour loop: %v", err)
	}
}
