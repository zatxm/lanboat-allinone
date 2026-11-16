package native

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestProcessUserDiscovery(t *testing.T) {
	f := new(processFinder)
	for _, family := range []string{"4", "6"} {
		host := "127.0.0.1"
		if family == "6" {
			host = "::1"
		}
		origin := processTestTCP(t, "tcp"+family, host)
		m := f.lookupIdentity(context.Background(), origin, false)
		if m.UserID == nil || *m.UserID != uint32(os.Geteuid()) || m.ProcessName != "" || len(f.owners) != 0 {
			t.Fatal("UID-only discovery scanned processes or lost identity", m)
		}
		account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		if f.userName(*m.UserID) != account.Username {
			t.Fatal("wrong username")
		}
		origin.destination = net.JoinHostPort(host, "1")
		if f.lookupIdentity(context.Background(), origin, false).UserID != nil {
			t.Fatal("wrong socket attributed to root")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if f.lookupIdentity(ctx, processTestTCP(t, "tcp4", "127.0.0.1"), false).UserID != nil {
		t.Fatal("cancelled identity lookup")
	}
}
func TestProcessUserProxyRouting(t *testing.T) {
	uid := uint32(os.Geteuid())
	account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"uid", "name", "both", "logical", "set", "sniff", "wrong-uid"} {
		t.Run(mode, func(t *testing.T) {
			rule := Rule{UserID: []uint32{uid}, Outbound: "direct"}
			route := Route{Final: "deny"}
			switch mode {
			case "name":
				rule = Rule{User: []string{account.Username}, Outbound: "direct"}
			case "both":
				rule.User = []string{account.Username}
			case "logical":
				rule = Rule{Type: "logical", Mode: "and", Rules: []Rule{{UserID: []uint32{uid}}, {Network: []string{"tcp"}}}, Outbound: "direct"}
			case "set":
				route.RuleSet = []RuleSet{{Type: "inline", Tag: "users", Rules: []Rule{{UserID: []uint32{uid}}}}}
				rule = Rule{RuleSet: []string{"users"}, Outbound: "direct"}
			case "sniff":
				route.Rules = []Rule{{Action: "sniff", Sniffer: []string{"http"}}}
			case "wrong-uid":
				rule.UserID = []uint32{uid + 1}
			}
			route.Rules = append(route.Rules, rule)
			r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "mixed", Tag: "local", Listen: "127.0.0.1"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: route})
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "user-routed") }))
			defer origin.Close()
			proxy, _ := url.Parse("http://" + r.Address("local"))
			transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(origin.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if mode == "wrong-uid" {
				if response.StatusCode == 200 {
					t.Fatal("wrong UID bypassed policy")
				}
				return
			}
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "user-routed" {
				t.Fatal(response.StatusCode, string(body), err)
			}
		})
	}
}
func TestProcessUserDNSRouting(t *testing.T) {
	account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"4", "6"} {
		for _, network := range []string{"tcp", "udp"} {
			for _, field := range []string{"uid", "name"} {
				t.Run(network+family+field, func(t *testing.T) {
					host := "127.0.0.1"
					if family == "6" {
						host = "::1"
					}
					condition := Rule{UserID: []uint32{uint32(os.Geteuid())}, Action: "predefined"}
					if field == "name" {
						condition.UserID = nil
						condition.User = []string{account.Username}
					}
					r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "dns", Tag: "dns", Listen: host}}, DNS: DNSConfig{Rules: []DNSRule{{Rule: condition, Answer: []string{"process.test. 60 IN A 192.0.2.9"}}, {Rule: Rule{Action: "reject"}}}}})
					checkProcessDNS(t, network+family, r.Address("dns"))
				})
			}
		}
	}
}
func TestProcessUserNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_USER_NAMESPACE") != "1" {
		cmd := exec.Command("unshare", "--user", "--map-auto", "--map-root-user", "--setgroups", "allow", "--net", os.Args[0], "-test.run=^TestProcessUserNamespace$", "-test.v", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "LANBOAT_USER_NAMESPACE=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated UID test: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "separate-users") }))
	defer origin.Close()
	r := newTestRuntime(t, Config{Inbounds: []Inbound{{Type: "mixed", Tag: "local", Listen: "127.0.0.1"}}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{UserID: []uint32{1001}, Outbound: "direct"}}}})
	dir, err := os.MkdirTemp("", "lanboat-user-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "user-test")
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	dst, err := os.OpenFile(binary, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(dst, source)
	err = dst.Close()
	if copyErr != nil || err != nil {
		t.Fatal(copyErr, err)
	}
	for _, uid := range []uint32{0, 1001} {
		cmd := exec.Command(binary, "-test.run=^TestProcessUserHelper$", "-test.v")
		cmd.Env = append(os.Environ(), "LANBOAT_USER_HELPER_PROXY=http://"+r.Address("local"), "LANBOAT_USER_HELPER_ORIGIN="+origin.URL, "LANBOAT_USER_HELPER_ALLOWED="+strconv.FormatBool(uid == 1001))
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: uid}}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("UID%d: %v\n%s", uid, err, out)
		}
		t.Logf("UID%d correctly routed", uid)
	}
}
func TestProcessUserHelper(t *testing.T) {
	address := os.Getenv("LANBOAT_USER_HELPER_PROXY")
	if address == "" {
		return
	}
	proxy, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	resp, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(os.Getenv("LANBOAT_USER_HELPER_ORIGIN"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	allowed := os.Getenv("LANBOAT_USER_HELPER_ALLOWED") == "true"
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if (resp.StatusCode == 200) != allowed || allowed && string(body) != "separate-users" {
		t.Fatal(fmt.Sprintf("status=%d body=%q UID=%d", resp.StatusCode, body, os.Geteuid()))
	}
}

func TestProcessUserHotReload(t *testing.T) {
	r := newTestRuntime(t, Config{Outbounds: []Outbound{{Type: "direct", Tag: "direct"}, {Type: "block", Tag: "deny"}}, Route: Route{Final: "deny", Rules: []Rule{{RuleSet: []string{"users"}, Outbound: "direct"}}, RuleSet: []RuleSet{{Type: "inline", Tag: "users", Rules: []Rule{{Domain: []string{"never.test"}}}}}}})
	origin := processTestTCP(t, "tcp4", "127.0.0.1")
	q := request{network: "tcp", address: origin.destination, origin: &origin}
	if r.needsProcess() {
		t.Fatal("unexpected process work before hot reload")
	}
	snapshot, err := compileRuleSet([]Rule{{UserID: []uint32{uint32(os.Geteuid())}}})
	if err != nil {
		t.Fatal(err)
	}
	r.publishRuleSet(r.ruleSets["users"], snapshot)
	if !r.needsProcess() {
		t.Fatal("hot rule not requesting UID")
	}
	matched, tag, err := r.routeTarget(context.Background(), q)
	if err != nil || tag != "direct" || matched.metadata.UserID == nil {
		t.Fatal(tag, err, matched.metadata)
	}
	snapshot, err = compileRuleSet([]Rule{{Domain: []string{"never.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	r.publishRuleSet(r.ruleSets["users"], snapshot)
	if r.needsProcess() {
		t.Fatal("hot removal left identity discovery active")
	}
}
