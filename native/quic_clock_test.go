package native

import (
	"testing"
	"time"
)

func TestQUICClockPrecision(t *testing.T) {
	previous := quicNow()
	smallest := time.Hour
	for range 10000 {
		now := quicNow()
		elapsed := now.Sub(previous)
		if elapsed < 0 {
			t.Fatal("QUIC clock moved backwards", elapsed)
		}
		if elapsed > 0 {
			smallest = min(smallest, elapsed)
		}
		previous = now
	}
	if smallest >= time.Millisecond {
		t.Fatal("QUIC clock cannot resolve sub-millisecond RTTs", smallest)
	}
	if allocs := testing.AllocsPerRun(1000, func() { _ = quicNow() }); allocs != 0 {
		t.Fatal("QUIC clock allocated", allocs)
	}
	before := quicNow()
	time.Sleep(20 * time.Millisecond)
	elapsed := quicNow().Sub(before)
	if elapsed < 10*time.Millisecond {
		t.Fatal("QUIC counter scale", elapsed)
	}
	t.Log("smallest clock step", smallest, "sleep interval", elapsed)
}
