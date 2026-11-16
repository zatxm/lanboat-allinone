package native

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestQUICDatagramPayloadBoundary(t *testing.T) {
	l := testQUICListener(t)
	client := testQUICDial(t, l.packet.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	server, e := l.Accept(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, q := range []*quicConn{client, server} {
		want := bytes.Repeat([]byte{7}, q.datagramLimit())
		if e = q.SendDatagram(ctx, want); e != nil {
			t.Fatal(e)
		}
		peer := server
		if q == server {
			peer = client
		}
		got, e := peer.ReceiveDatagram(ctx)
		if e != nil || !bytes.Equal(want, got) {
			t.Fatal("boundary packet stalled or changed", len(got), e)
		}
		if e = q.SendDatagram(ctx, make([]byte, q.datagramLimit()+1)); e == nil {
			t.Fatal("oversized packet queued")
		}
	}
}
func TestQUICMasqueInitialPadding(t *testing.T) {
	cid := []byte("12345678")
	_, key, e := quicInitialKeys(cid, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, minimum := range []int{1200, 1400, 1472} {
		packet := sealQUICPacket([]byte{1}, cid, []byte("abcdefgh"), nil, 0, 0, false, key, minimum)
		if len(packet) < minimum {
			t.Fatal(minimum, len(packet))
		}
	}
	q := quicConn{minInitial: 1400}
	if q.datagramLimit() < 1280+9 {
		t.Fatal("MASQUE cannot carry IPv6 minimum MTU")
	}
}
