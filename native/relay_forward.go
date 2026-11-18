package native

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
)

// RelayForward forwards a remote bound port to a target on this client.
type RelayForward struct {
	address net.Addr
	cancel  context.CancelFunc
	done    chan struct{}
	err     error
}

func (f *RelayForward) Addr() net.Addr { return f.address }
func (f *RelayForward) Close() error   { f.cancel(); <-f.done; return f.err }
func (f *RelayForward) Wait() error    { <-f.done; return f.err }

// ForwardRelay exposes TCP/UDP target on a Relay server. Targets are explicitly
// client-side direct connections, so the default proxy route cannot loop back.
func (r *Runtime) ForwardRelay(ctx context.Context, tag, network, address, target string) (*RelayForward, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if network != "tcp" && network != "udp" {
		return nil, errors.New("Relay forwarding network must be tcp or udp")
	}
	if _, err := encodeAddress(target); err != nil {
		return nil, err
	}
	child, cancel := context.WithCancel(r.ctx)
	stop := context.AfterFunc(ctx, cancel)
	var closer io.Closer
	var bound net.Addr
	var run func() error
	if network == "tcp" {
		l, err := r.ListenRelay(child, tag, address)
		if err != nil {
			stop()
			cancel()
			return nil, err
		}
		closer, bound = l, l.Addr()
		run = func() error {
			peerCtx, stopPeers := context.WithCancel(child)
			var workers sync.WaitGroup
			defer func() { stopPeers(); workers.Wait() }()
			for {
				peer, err := l.Accept()
				if err != nil {
					return err
				}
				dial, cancelDial := context.WithTimeout(child, handshakeTimeout)
				remote, err := r.direct(dial, "tcp", target)
				cancelDial()
				if err != nil {
					peer.Close()
					logDebug(r.logger, err, "relay: forward to ", target)
					continue
				}
				workers.Go(func() {
					defer peer.Close()
					defer remote.Close()
					stop := context.AfterFunc(peerCtx, func() { peer.Close(); remote.Close() })
					defer stop()
					r.relay(peer, remote)
				})
			}
		}
	} else {
		p, err := r.ListenRelayPacket(child, tag, address)
		if err != nil {
			stop()
			cancel()
			return nil, err
		}
		closer, bound = p, p.LocalAddr()
		run = func() error {
			flows := newUDPFlows(r)
			flows.ctx, flows.direct = child, true
			defer func() { p.Close(); flows.Close() }()
			buffer := make([]byte, 65507)
			for {
				n, from, err := p.ReadFrom(buffer)
				if err != nil {
					return err
				}
				q := request{network: "udp", address: target, source: from.String()}
				if err = flows.send(from.String(), q, buffer[:n], func(data []byte, _ string) error { _, e := p.WriteTo(data, from); return e }); err != nil {
					return err
				}
			}
		}
	}
	f := &RelayForward{address: bound, cancel: cancel, done: make(chan struct{})}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		closer.Close()
		stop()
		cancel()
		return nil, net.ErrClosed
	}
	r.workers.Add(1)
	r.mu.Unlock()
	go func() {
		defer r.workers.Done()
		defer close(f.done)
		defer stop()
		defer cancel()
		defer closer.Close()
		err := run()
		if child.Err() == nil {
			f.err = err
		}
	}()
	return f, nil
}
