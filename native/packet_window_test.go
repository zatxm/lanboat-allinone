package native

import (
	"math/rand"
	"testing"
	"time"
)

func TestPacketWindowPartialWordBoundaries(t *testing.T) {
	var w packetWindow
	for _, id := range []uint64{0, 8191, 1, 2, 3, 8193} {
		if !w.accept(id) {
			t.Fatal("valid packet rejected", id)
		}
	}
	if w.accept(2) || w.accept(3) {
		t.Fatal("replay accepted after partially advancing edge word")
	}
	if !w.accept(8192) {
		t.Fatal("unseen in-window packet mistaken for an old ring slot")
	}
}

func TestPacketWindowAgainstExactHistory(t *testing.T) {
	for _, initial := range []uint64{0, ^uint64(0) - 100000} {
		var w packetWindow
		history := map[uint64]bool{}
		highest := initial
		rng := rand.New(rand.NewSource(7))
		for i := range 100000 {
			id := highest
			if i%3 == 0 && ^uint64(0)-highest >= 100 {
				id += uint64(rng.Intn(100))
			} else if highest >= 10000 {
				id -= uint64(rng.Intn(10000))
			}
			want := !history[id] && (id >= highest || highest-id < 8192)
			if got := w.accept(id); got != want {
				t.Fatalf("iteration%d highest%d packet%d got%v want%v", i, highest, id, got, want)
			}
			if want {
				history[id] = true
				highest = max(highest, id)
			}
		}
	}
}

func TestWireGuardPartialWindowReplay(t *testing.T) {
	key := make([]byte, 32)
	sender := &wgTransport{send: key, remote: 7, at: time.Now()}
	receiver := &wgTransport{receive: key, local: 7, at: time.Now()}
	packets := map[uint64][]byte{}
	for _, id := range []uint64{0, 8191, 1, 2, 3, 8193, 8192} {
		sender.counter = id
		b, err := sender.seal(nil)
		if err != nil {
			t.Fatal(err)
		}
		packets[id] = b
		if _, err := receiver.open(b); err != nil {
			t.Fatal("valid authenticated WireGuard packet rejected", id, err)
		}
	}
	for _, id := range []uint64{2, 3, 8192, 8193} {
		if _, err := receiver.open(packets[id]); err == nil {
			t.Fatal("authenticated WireGuard replay accepted", id)
		}
	}
}
