package native

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSRSReferenceCompilation(t *testing.T) {
	reference := os.Getenv("LANBOAT_TEST_REFERENCE")
	if reference == "" {
		t.Skip("LANBOAT_TEST_REFERENCE required")
	}
	source := `{"version":2,"rules":[{"domain":["exact.org"],"domain_suffix":["example.org",".sub-only.org"],"domain_keyword":["needle"],"domain_regex":["^regex[0-9]+\\.org$"]},{"ip_cidr":["192.0.2.0/24","2001:db8::/32"]},{"type":"logical","mode":"and","rules":[{"network":["tcp"]},{"port_range":["8000:8100"]}]}]}`
	path := filepath.Join(t.TempDir(), "input.json")
	os.WriteFile(path, []byte(source), 0600)
	output := path + ".srs"
	cmd := exec.Command(reference, "rule-set", "compile", "--output", output, path)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reference compiler: %v %s", err, b)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	items, err := readSRS(data)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := compileRuleSet(items)
	if err != nil {
		t.Fatal(err)
	}
	set := &ruleCollection{}
	set.current.Store(snapshot)
	for _, test := range []struct {
		address, network string
		want             bool
	}{{"exact.org:443", "tcp", true}, {"a.exact.org:443", "tcp", false}, {"example.org:443", "tcp", true}, {"a.example.org:443", "tcp", true}, {"badexample.org:443", "tcp", false}, {"sub-only.org:443", "tcp", false}, {"a.sub-only.org:443", "tcp", true}, {"needle-host.net:443", "tcp", true}, {"regex42.org:443", "tcp", true}, {"192.0.2.77:443", "tcp", true}, {"[2001:db8::42]:443", "tcp", true}, {"192.0.3.1:443", "tcp", false}, {"other.org:8050", "tcp", true}, {"other.org:8050", "udp", false}} {
		if got := set.matches(request{network: test.network, address: test.address}); got != test.want {
			t.Errorf("%s %s: %v != %v", test.address, test.network, got, test.want)
		}
	}
}
func TestRuleSetAtomicUpdateAndRuntimeRouting(t *testing.T) {
	var body atomic.Value
	body.Store(`{"version":2,"rules":[{"domain_suffix":["blocked.example"]}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, body.Load().(string)) }))
	defer server.Close()
	cache := filepath.Join(t.TempDir(), "cache.json")
	cfg := Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "reject"}}, Route: Route{Final: "direct", RuleSet: []RuleSet{{Type: "remote", Tag: "remote", Format: "source", URL: server.URL, Path: cache}}, Rules: []Rule{{RuleSet: []string{"remote"}, Outbound: "reject"}}}}
	runtime := newTestRuntime(t, cfg)
	if _, err := runtime.Dial(context.Background(), "tcp", "a.blocked.example:443"); err != ErrRejected {
		t.Fatal("rule_set did not block", err)
	}
	body.Store(`{"version":2,"rules":[{"domain_suffix":["new.example"]}]}`)
	if err := runtime.ReloadRuleSets(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.ruleSets["remote"].matches(request{address: "blocked.example:443"}) || !runtime.ruleSets["remote"].matches(request{address: "new.example:443"}) {
		t.Fatal("snapshot did not change")
	}
	previous, _ := os.ReadFile(cache)
	body.Store(`{"version":2,"rules":[{"unsupported":true}]}`)
	if err := runtime.ReloadRuleSets(context.Background()); err == nil {
		t.Fatal("accepted broken update")
	}
	after, _ := os.ReadFile(cache)
	if !bytes.Equal(previous, after) || !runtime.ruleSets["remote"].matches(request{address: "new.example:443"}) {
		t.Fatal("failed update destroyed active rules or cache")
	}
}

func TestRuleSetConcurrentReload(t *testing.T) {
	var calls atomic.Int32
	oldStarted, releaseOld, newArrived := make(chan struct{}), make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := calls.Add(1)
		if n == 2 {
			close(oldStarted)
			<-releaseOld
		}
		if n == 3 {
			close(newArrived)
		}
		io.WriteString(w, `{"version":2,"rules":[{"domain":"revision`+fmt.Sprint(n)+`.test"}]}`)
	}))
	defer server.Close()
	defer func() {
		select {
		case <-releaseOld:
		default:
			close(releaseOld)
		}
	}()
	r := newTestRuntime(t, Config{Route: Route{RuleSet: []RuleSet{{Type: "remote", Tag: "remote", Format: "source", URL: server.URL}}}})
	oldDone, newDone := make(chan error, 1), make(chan error, 1)
	go func() { oldDone <- r.ReloadRuleSets(context.Background()) }()
	<-oldStarted
	go func() { newDone <- r.ReloadRuleSets(context.Background()) }()
	newFinished := false
	select {
	case <-newArrived:
		if err := <-newDone; err != nil {
			t.Fatal(err)
		}
		newFinished = true
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseOld)
	if err := <-oldDone; err != nil {
		t.Fatal(err)
	}
	if !newFinished {
		if err := <-newDone; err != nil {
			t.Fatal(err)
		}
	}
	set := r.ruleSets["remote"]
	if !set.matches(request{address: "revision3.test:443"}) || set.matches(request{address: "revision2.test:443"}) {
		t.Fatal("a stale concurrent reload replaced the newer rules")
	}
}
func FuzzSRS(f *testing.F) {
	f.Add([]byte("SRS\x02"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 1<<20 {
			_, _ = readSRS(data)
		}
	})
}
func TestSourceRuleSetRejectsActions(t *testing.T) {
	data, _ := json.Marshal(map[string]any{"version": 2, "rules": []Rule{{Outbound: "direct"}}})
	items, err := parseRuleSet(data, "source")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compileRuleSet(items); err == nil {
		t.Fatal("headless outbound accepted")
	}
}

func TestRuleSetScheduledUpdate(t *testing.T) {
	var body atomic.Value
	body.Store(`{"version":2,"rules":[{"domain":["before.test"]}]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { io.WriteString(w, body.Load().(string)) }))
	defer server.Close()
	r := newTestRuntime(t, Config{Route: Route{RuleSet: []RuleSet{{Type: "remote", Tag: "auto", URL: server.URL, UpdateInterval: "1s"}}}})
	body.Store(`{"version":2,"rules":[{"domain":["after.test"]}]}`)
	deadline := time.Now().Add(3 * time.Second)
	for !r.ruleSets["auto"].matches(request{address: "after.test:443"}) {
		if time.Now().After(deadline) {
			t.Fatal("scheduled snapshot did not update")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.ruleSets["auto"].matches(request{address: "before.test:443"}) {
		t.Fatal("old rule remained active")
	}
}
