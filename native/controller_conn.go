package native

import (
	"crypto/rand"
	"fmt"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

type controllerTrace struct {
	rule, payload string
	chain         []string
}

type controllerConn struct {
	net.Conn
	c             *controller
	id            string
	start         time.Time
	metadata      map[string]any
	chains        []string
	rule, payload string
	up, down      atomic.Int64
	once          sync.Once
}

func (c *controller) track(conn net.Conn, q request, tag string) (net.Conn, error) {
	id := [16]byte{}
	if _, err := rand.Read(id[:]); err != nil {
		conn.Close()
		return nil, err
	}
	id[6] = id[6]&15 | 64
	id[8] = id[8]&63 | 128
	host, port, _ := net.SplitHostPort(q.address)
	source, sourcePort, _ := net.SplitHostPort(q.source)
	metadata := map[string]any{
		"network": q.network, "type": q.inbound, "sourceIP": source, "sourcePort": sourcePort,
		"destinationIP": "", "destinationPort": port, "host": host, "dnsMode": "normal",
		"inboundName": q.inbound, "inboundUser": q.metadata.AuthUser,
		"process": q.metadata.ProcessName, "processPath": q.metadata.ProcessPath,
	}
	if net.ParseIP(host) != nil {
		metadata["destinationIP"], metadata["host"] = host, q.metadata.Domain
	}
	if q.metadata.SourceMACAddress != "" {
		metadata["sourceMACAddress"] = q.metadata.SourceMACAddress
	}
	if q.metadata.SourceHostname != "" {
		metadata["sourceHostname"] = q.metadata.SourceHostname
	}
	if q.metadata.Client != "" {
		metadata["client"] = q.metadata.Client
	}
	flow := &controllerConn{Conn: conn, c: c, id: fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), start: time.Now(), metadata: metadata, rule: q.controllerTrace.rule, payload: q.controllerTrace.payload}
	if flow.rule == "" {
		flow.rule = "Match"
	}
	var groups []*groupConn
	chain := []string{tag}
	for inner := conn; inner != nil; {
		switch v := inner.(type) {
		case *groupConn:
			groups = append(groups, v)
			chain = append(chain, v.member)
			inner = v.Conn
		case *ownedConn:
			inner = v.Conn
		case *icmpErrorConn:
			inner = v.Conn
		default:
			inner = nil
		}
	}
	slices.Reverse(chain)
	// Private built-ins have no public identity; the captured alias supplies it.
	if chain[len(chain)-1] == c.directTag || chain[len(chain)-1] == c.blockTag {
		chain = chain[:len(chain)-1]
	}
	for _, alias := range slices.Backward(q.controllerTrace.chain) {
		chain = append(chain, alias)
	}
	flow.chains = chain
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("controller runtime closed")
	}
	// Bound the management inventory without refusing proxy traffic.
	if len(c.flows) >= 4096 {
		c.mu.Unlock()
		flow.id = ""
		flow.metadata = nil
		flow.chains = nil
		return flow, nil
	}
	c.flows[flow.id] = flow
	c.mu.Unlock()
	for _, group := range groups {
		group.observer.Store(flow)
		group.group.mu.Lock()
		_, active := group.group.conns[group]
		group.group.mu.Unlock()
		if !active {
			flow.untrack()
		}
	}
	return flow, nil
}

func (c *controllerConn) untrack() { c.c.mu.Lock(); delete(c.c.flows, c.id); c.c.mu.Unlock() }
func (c *controllerConn) count(up bool, n int) {
	if up {
		c.up.Add(int64(n))
		c.c.up.Add(int64(n))
	} else {
		c.down.Add(int64(n))
		c.c.down.Add(int64(n))
	}
}
func (c *controllerConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.count(false, n)
	return n, err
}
func (c *controllerConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.count(true, n)
	return n, err
}
func (c *controllerConn) Close() (err error) {
	c.once.Do(func() { err = c.Conn.Close(); c.untrack() })
	return
}
func (c *controllerConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}

type controllerUDP struct {
	owner *controllerConn
	inner addressedUDP
}

func (c *controllerUDP) readPacket(p []byte) (int, string, error) {
	n, address, err := c.inner.readPacket(p)
	c.owner.count(false, n)
	return n, address, err
}
func (c *controllerUDP) writePacket(p []byte, address string) (int, error) {
	n, err := c.inner.writePacket(p, address)
	c.owner.count(true, n)
	return n, err
}

func (c *controller) connections() any {
	c.mu.Lock()
	flows := make([]*controllerConn, 0, len(c.flows))
	for _, flow := range c.flows {
		flows = append(flows, flow)
	}
	c.mu.Unlock()
	slices.SortFunc(flows, func(a, b *controllerConn) int { return a.start.Compare(b.start) })
	rows := make([]any, 0, len(flows))
	for _, flow := range flows {
		rows = append(rows, map[string]any{"id": flow.id, "metadata": flow.metadata, "upload": flow.up.Load(), "download": flow.down.Load(), "start": flow.start, "chains": flow.chains, "providerChains": []string{}, "rule": flow.rule, "rulePayload": flow.payload})
	}
	return map[string]any{"uploadTotal": c.up.Load(), "downloadTotal": c.down.Load(), "connections": rows, "memory": controllerMemory()}
}
func (c *controller) closeConnections(id string) {
	c.mu.Lock()
	flows := make([]*controllerConn, 0, len(c.flows))
	for key, flow := range c.flows {
		if id == "" || key == id {
			flows = append(flows, flow)
		}
	}
	c.mu.Unlock()
	for _, flow := range flows {
		_ = flow.Close()
	}
}

type controllerWireConn struct {
	net.Conn
	c *controller
}

func (c *controllerWireConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.c.wireUp.Add(int64(n))
	return n, err
}
func (c *controllerWireConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.c.wireDown.Add(int64(n))
	return n, err
}
func (c *controllerWireConn) CloseWrite() error {
	if h, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return h.CloseWrite()
	}
	return nil
}
