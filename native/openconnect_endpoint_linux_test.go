package native

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestOpenConnectEndpointCSTPReferenceNamespace(t *testing.T) {
	t.Setenv("LANBOAT_OC_ENDPOINT", "1")
	testOpenConnectReferenceNamespace(t, false, false, false)
}

func TestOpenConnectEndpointDTLSReferenceNamespace(t *testing.T) {
	t.Setenv("LANBOAT_OC_ENDPOINT", "1")
	testOpenConnectReferenceNamespace(t, false, true, false)
}

func TestOpenConnectEndpointSystemNamespace(t *testing.T) {
	if os.Getenv("LANBOAT_OC_EP_SYSTEM_CHILD") != "1" {
		cmd := exec.Command("unshare", "-Urn", os.Args[0], "-test.run=^TestOpenConnectEndpointSystemNamespace$", "-test.v", "-test.timeout=90s")
		cmd.Env = append(os.Environ(), "LANBOAT_OC_EP_SYSTEM_CHILD=1", "LANBOAT_OC_ENDPOINT=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("OpenConnect endpoint system namespace: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	masqueSystemCommand(t, "link", "set", "lo", "up")
	for _, dtls := range []bool{false, true} {
		t.Run(fmt.Sprint("dtls", dtls), func(t *testing.T) { ocSystemTraffic(t, dtls, true) })
	}
}
