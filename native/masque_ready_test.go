package native

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestMasqueClientWaitsForRoutes(t *testing.T) {
	for _, order := range []string{"address-first", "route-first", "configured-address"} {
		t.Run(order, func(t *testing.T) {
			r := newTestRuntime(t, Config{})
			m := newMasqueHTTPSession(r.ctx)
			defer m.close()
			var output bytes.Buffer
			raw := memoryNetConn{bytes.NewReader(nil), &output}
			flow, err := m.registerFlow(raw, 0, raw)
			if err != nil {
				t.Fatal(err)
			}
			var local []string
			if order == "configured-address" {
				local = []string{"10.44.0.2/32"}
			}
			p := newMasqueIP(r, flow, "", false, 1280, nil, local, "", nil)
			defer p.stack.close()
			checkWaiting := func() {
				t.Helper()
				select {
				case <-p.ready:
					t.Fatal("client became ready before address and routes were known")
				default:
				}
				packet := makeUDPPacket(netip.MustParseAddr("10.44.0.2"), netip.MustParseAddr("192.0.2.1"), 1234, 53, []byte{1})
				if err := p.writePacket(packet); !errors.Is(err, ErrRejected) || output.Len() != 0 {
					t.Fatal("packet escaped before route negotiation", err, output.Len())
				}
			}
			checkWaiting()
			assignment := masqueAddressBytes([]masqueAssignment{{prefix: netip.MustParsePrefix("10.44.0.2/32")}})
			routes := []byte{4, 192, 0, 2, 0, 192, 0, 2, 255, 0}
			first, second, a, b := uint64(1), uint64(3), assignment, routes
			if order == "route-first" {
				first, second, a, b = second, first, b, a
			}
			if err = p.control(first, a); err != nil {
				t.Fatal(err)
			}
			checkWaiting()
			if err = p.control(second, b); err != nil {
				t.Fatal(err)
			}
			if err = p.waitAddress(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
