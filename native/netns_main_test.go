package native

import (
	"fmt"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("LANBOAT_NS_NO_DISPATCH") == "1" && len(os.Args) > 1 && os.Args[1] == "network-namespace-worker" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	if handled, err := RunNetworkNamespaceWorker(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
