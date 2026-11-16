package native

import (
	"fmt"
	"os"
	"testing"
)

func TestQUICClientLegacyProbePadding(t *testing.T) {
	for i, want := range []string{"quic-go", "chromium", "chromium", "quic-go", "quic-go"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			wire, err := os.ReadFile(fmt.Sprintf("testdata/quic-client/uquic-chrome115-%d.bin", i))
			if err != nil {
				t.Fatal(err)
			}
			host, client, ok, more := sniffQUICInfo(wire)
			if !ok || more || host != "reference.quic.test" || client != want {
				t.Fatal("captured uQUIC probe", host, client, ok, more)
			}
		})
	}
}
