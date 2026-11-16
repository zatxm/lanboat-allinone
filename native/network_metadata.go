package native

import (
	"context"
	"sync"
	"time"
)

const networkFields = 1<<6 | 1<<7 | 1<<8 | 1<<9 | 1<<11 | 1<<12

// Discovery is demand-driven; snapshots are immutable and shared by connections.
type networkMetadataCache struct {
	mu        sync.Mutex
	fastMu    sync.Mutex
	fallback  map[networkFallbackKey]time.Time
	excluded  map[string]bool
	next      time.Time
	selection bool
	state     Metadata
	read      func(context.Context, *Runtime) Metadata
}

func (c *networkMetadataCache) snapshot(ctx context.Context, r *Runtime) Metadata {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return Metadata{}
	}
	selecting, _ := ctx.Value(networkSelectionKey{}).(bool)
	if now := time.Now(); !now.Before(c.next) || selecting && !c.selection {
		read := c.read
		if read == nil {
			read = systemNetworkMetadata
		}
		call, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		state := read(call, r)
		cancel()
		if ctx.Err() != nil {
			return Metadata{}
		}
		c.state, c.next = state, now.Add(5*time.Second)
		c.selection = selecting
	}
	return c.state
}

func (c *networkMetadataCache) invalidate() {
	c.mu.Lock()
	c.next = time.Time{}
	c.fastMu.Lock()
	clear(c.fallback)
	c.fastMu.Unlock()
	c.mu.Unlock()
}

func (r *Runtime) enrichNetworkMetadata(ctx context.Context, m *Metadata) {
	if !r.needsMetadata(networkFields) {
		return
	}
	s := r.network.snapshot(ctx, r)
	// Supplying the network type makes the caller's platform flags authoritative.
	if m.NetworkType == "" {
		m.NetworkType = s.NetworkType
		m.NetworkIsExpensive = m.NetworkIsExpensive || s.NetworkIsExpensive
		m.NetworkIsConstrained = m.NetworkIsConstrained || s.NetworkIsConstrained
		if m.WiFiSSID == "" {
			m.WiFiSSID = s.WiFiSSID
		}
		if m.WiFiBSSID == "" {
			m.WiFiBSSID = s.WiFiBSSID
		}
	}
	if m.NetworkInterfaceAddress == nil {
		m.NetworkInterfaceAddress = s.NetworkInterfaceAddress
	}
	if m.DefaultInterfaceAddress == nil {
		m.DefaultInterfaceAddress = s.DefaultInterfaceAddress
	}
}
