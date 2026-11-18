package native

import (
	"context"
)

func (t *tunTunnel) serveTransparent() {
	for {
		c, e := t.tpListener.Accept()
		if e != nil {
			return
		}
		r := t.runtime
		r.mu.Lock()
		if r.closed || len(r.connections) >= 4096 {
			r.mu.Unlock()
			c.Close()
			continue
		}
		r.connections[c] = struct{}{}
		r.workers.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.workers.Done()
			defer func() { c.Close(); r.mu.Lock(); delete(r.connections, c); r.mu.Unlock() }()
			ctx, cancel := context.WithTimeout(r.ctx, handshakeTimeout)
			defer cancel()
			remote, e := r.routeDial(ctx, request{network: "tcp", inbound: t.in.Tag, source: c.RemoteAddr().String(), address: c.LocalAddr().String()})
			logDebug(r.logger, e, "tun: transparent connection from ", c.RemoteAddr().String(), " to ", c.LocalAddr().String())
			if e == nil {
				r.relay(c, remote)
			}
		}()
	}
}
