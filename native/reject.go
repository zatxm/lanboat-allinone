package native

import (
	"errors"
	"sync"
	"time"
)

var ErrDropped = errors.New("packet dropped by routing policy")

type rejectWindow struct {
	mu    sync.Mutex
	start time.Time
	count int
}

func (w *rejectWindow) drop(method string, noDrop bool) bool {
	if method == "drop" {
		return true
	}
	if noDrop {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if now.Sub(w.start) >= 30*time.Second {
		w.start = now
		w.count = 0
	}
	w.count++
	return w.count > 50
}
