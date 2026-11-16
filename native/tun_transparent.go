package native

import (
	"context"
	"go.uber.org/zap"
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
			r.logger.Debug("TUN transparent connection", zap.String("source", c.RemoteAddr().String()), zap.String("destination", c.LocalAddr().String()), zap.Error(e))
			if e == nil {
				r.relay(c, remote)
			}
		}()
	}
}
