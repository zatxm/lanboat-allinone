package native

import (
	"os"
	"os/exec"
	"regexp"
	"testing"
)

// This host can allocate29786 as an outgoing ephemeral port. Test callbacks in
// their own namespace so unrelated transports cannot occupy the protocol port.
func isolateOpenConnectSSO(t *testing.T) bool {
	t.Helper()
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if parent := os.Getenv("LANBOAT_TEST_SSO_PARENT_NETNS"); parent != "" {
		if parent == current {
			t.Fatal("SSO test must not modify the host network namespace")
		}
		for _, args := range [][]string{{"ip", "link", "set", "lo", "up"}, {"sysctl", "-qw", "net.ipv4.ip_local_reserved_ports=29786"}} {
			if output, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
				t.Fatalf("isolated SSO setup:%v:%s", err, output)
			}
		}
		return false
	}
	cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "LANBOAT_TEST_SSO_PARENT_NETNS="+current)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated SSO test:%v\n%s", err, output)
	}
	t.Log(string(output))
	return true
}
