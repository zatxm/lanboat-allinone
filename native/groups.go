package native

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

func validateGroup(o Outbound) error {
	if len(o.Outbounds) == 0 || len(o.Outbounds) > 512 {
		return errors.New("group requires 1-512 outbounds")
	}
	if o.Default != "" && !slices.Contains(o.Outbounds, o.Default) {
		return errors.New("group default is not a member")
	}
	if o.Server != "" || o.Detour != "" || o.TLS.Enabled {
		return errors.New("group cannot define a server, TLS or detour")
	}
	if o.Type == "urltest" {
		if _, e := optionDuration(o.Interval, 3*time.Minute); e != nil {
			return e
		}
		if _, e := optionDuration(o.IdleTimeout, 30*time.Minute); e != nil {
			return e
		}
		if o.URL != "" {
			u, e := url.Parse(o.URL)
			if e != nil || u.Host == "" || u.User != nil || u.Scheme != "http" && u.Scheme != "https" {
				return errors.New("invalid urltest URL")
			}
		}
	}
	return nil
}
func validateOutboundGraph(nodes map[string]Outbound) error {
	state := map[string]byte{}
	var visit func(string) error
	visit = func(tag string) error {
		if state[tag] == 1 {
			return fmt.Errorf("outbound dependency cycle at %q", tag)
		}
		if state[tag] == 2 {
			return nil
		}
		o, ok := nodes[tag]
		if !ok {
			return fmt.Errorf("unknown outbound %q", tag)
		}
		state[tag] = 1
		edges := o.Outbounds
		if o.Detour != "" {
			edges = append(append([]string{}, edges...), o.Detour)
		}
		for _, child := range edges {
			if e := visit(child); e != nil {
				return e
			}
		}
		state[tag] = 2
		return nil
	}
	for tag := range nodes {
		if e := visit(tag); e != nil {
			return e
		}
	}
	return nil
}

type inboundRouteKey struct{}
type outboundGroup struct {
	runtime  *Runtime
	options  Outbound
	selected atomic.Pointer[string]
	lastUsed atomic.Int64
	probe    sync.Mutex
	mu       sync.Mutex
	conns    map[*groupConn]bool
	closed   bool
}

func newOutboundGroup(r *Runtime, o Outbound) *outboundGroup {
	g := &outboundGroup{runtime: r, options: o, conns: map[*groupConn]bool{}}
	tag := o.Default
	if tag == "" {
		tag = o.Outbounds[0]
	}
	g.selected.Store(&tag)
	g.lastUsed.Store(time.Now().UnixNano())
	return g
}
func (g *outboundGroup) switchTo(tag string) {
	g.mu.Lock()
	if *g.selected.Load() == tag {
		g.mu.Unlock()
		return
	}
	g.selected.Store(&tag)
	var closeConns []*groupConn
	for c, external := range g.conns {
		if !external || g.options.InterruptExistConnections {
			closeConns = append(closeConns, c)
		}
	}
	g.mu.Unlock()
	for _, c := range closeConns {
		c.Close()
	}
}
func (g *outboundGroup) close() {
	g.mu.Lock()
	g.closed = true
	all := make([]*groupConn, 0, len(g.conns))
	for c := range g.conns {
		all = append(all, c)
	}
	g.mu.Unlock()
	for _, c := range all {
		c.Close()
	}
}
func (g *outboundGroup) dial(ctx context.Context, network, address string) (net.Conn, error) {
	g.lastUsed.Store(time.Now().UnixNano())
	tag := *g.selected.Load()
	c, e := g.runtime.dialOutbound(ctx, tag, network, address)
	if e != nil {
		return nil, e
	}
	wrapped := &groupConn{Conn: c, group: g, member: tag}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		c.Close()
		return nil, net.ErrClosed
	}
	inbound, _ := ctx.Value(inboundRouteKey{}).(bool)
	g.conns[wrapped] = inbound
	changed := *g.selected.Load() != tag
	g.mu.Unlock()
	if changed {
		wrapped.Close()
		return nil, errors.New("group selection changed while dialing")
	}
	return wrapped, nil
}

type groupConn struct {
	net.Conn
	member   string
	observer atomic.Pointer[controllerConn]
	group    *outboundGroup
	once     sync.Once
}

func (c *groupConn) Close() error {
	var e error
	c.once.Do(func() {
		e = c.Conn.Close()
		c.group.mu.Lock()
		delete(c.group.conns, c)
		c.group.mu.Unlock()
		if observer := c.observer.Load(); observer != nil {
			observer.untrack()
		}
	})
	return e
}
func (c *groupConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
func (r *Runtime) SelectOutbound(group, member string) error {
	g := r.groups[group]
	if g == nil || g.options.Type != "selector" {
		return errors.New("selector group not found")
	}
	if !slices.Contains(g.options.Outbounds, member) {
		return errors.New("outbound is not a group member")
	}
	g.switchTo(member)
	return nil
}
func (r *Runtime) SelectedOutbound(group string) (string, error) {
	g := r.groups[group]
	if g == nil {
		return "", errors.New("group not found")
	}
	return *g.selected.Load(), nil
}
func (r *Runtime) URLTest(ctx context.Context, group string) (map[string]uint16, error) {
	g := r.groups[group]
	if g == nil || g.options.Type != "urltest" {
		return nil, errors.New("urltest group not found")
	}
	return g.test(ctx)
}
func (g *outboundGroup) test(ctx context.Context) (map[string]uint16, error) {
	g.probe.Lock()
	defer g.probe.Unlock()
	target := g.options.URL
	if target == "" {
		target = "https://www.gstatic.com/generate_204"
	}
	result := map[string]uint16{}
	var mu sync.Mutex
	var workers sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, tag := range g.options.Outbounds {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			workers.Wait()
			return nil, ctx.Err()
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return g.runtime.dialOutbound(ctx, tag, network, address)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
			if e != nil {
				return
			}
			start := time.Now()
			response, e := client.Do(req)
			if e != nil {
				return
			}
			io.CopyN(io.Discard, response.Body, 4096)
			response.Body.Close()
			if response.StatusCode < 200 || response.StatusCode >= 400 {
				return
			}
			elapsed := uint16(min(65535, max(1, time.Since(start).Milliseconds())))
			mu.Lock()
			result[tag] = elapsed
			mu.Unlock()
		}()
	}
	workers.Wait()
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if len(result) == 0 {
		return result, errors.New("all group URL tests failed")
	}
	best := ""
	delay := uint16(65535)
	for _, tag := range g.options.Outbounds {
		if d, ok := result[tag]; ok && (best == "" || d < delay) {
			best, delay = tag, d
		}
	}
	tolerance := uint16(50)
	if g.options.Tolerance != nil {
		tolerance = *g.options.Tolerance
	}
	current := *g.selected.Load()
	if d, ok := result[current]; !ok || int(d) > int(delay)+int(tolerance) {
		g.switchTo(best)
	}
	return result, nil
}
func (g *outboundGroup) run() {
	interval, _ := optionDuration(g.options.Interval, 3*time.Minute)
	idle, _ := optionDuration(g.options.IdleTimeout, 30*time.Minute)
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-g.runtime.ctx.Done():
			return
		case <-timer.C:
			if time.Since(time.Unix(0, g.lastUsed.Load())) < idle {
				ctx, cancel := context.WithTimeout(g.runtime.ctx, 15*time.Second)
				g.test(ctx)
				cancel()
			}
			timer.Reset(interval)
		}
	}
}
