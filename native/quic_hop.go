package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HysteriaHopOptions follows the compatible outbound port-list schema. Ports
// are expanded only when a session is opened; packets never parse configuration.
type HysteriaHopOptions struct {
	ServerPorts    []string `json:"server_ports,omitempty"`
	HopInterval    string   `json:"hop_interval,omitempty"`
	HopIntervalMax string   `json:"hop_interval_max,omitempty"`
}

func (o HysteriaHopOptions) ports() ([]uint16, error) {
	var seen [1024]uint64
	for _, entry := range o.ServerPorts {
		parts := strings.FieldsFunc(entry, func(r rune) bool { return r == ':' || r == '-' })
		if len(parts) < 1 || len(parts) > 2 || strings.TrimSpace(entry) != entry {
			return nil, fmt.Errorf("invalid server_ports entry %q", entry)
		}
		start, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil || start == 0 || entry[0] < '0' || entry[len(entry)-1] < '0' {
			return nil, fmt.Errorf("invalid server_ports entry %q", entry)
		}
		end := start
		if len(parts) == 2 {
			end, err = strconv.ParseUint(parts[1], 10, 16)
			if err != nil || end < start || entry != parts[0]+":"+parts[1] && entry != parts[0]+"-"+parts[1] {
				return nil, fmt.Errorf("invalid server_ports range %q", entry)
			}
		} else if entry != parts[0] {
			return nil, fmt.Errorf("invalid server_ports entry %q", entry)
		}
		for port := start; port <= end; port++ {
			seen[port/64] |= 1 << (port % 64)
		}
	}
	var ports []uint16
	for port := 1; port <= 65535; port++ {
		if seen[port/64]&(1<<uint(port%64)) != 0 {
			ports = append(ports, uint16(port))
		}
	}
	return ports, nil
}

func (o HysteriaHopOptions) intervals() (time.Duration, time.Duration, error) {
	low, high := 30*time.Second, time.Duration(0)
	var err error
	if o.HopInterval != "" {
		low, err = time.ParseDuration(o.HopInterval)
		if err != nil || low < time.Second || low > 24*time.Hour {
			return 0, 0, errors.New("hop_interval must be1s-24h")
		}
	}
	if o.HopIntervalMax != "" {
		high, err = time.ParseDuration(o.HopIntervalMax)
		if err != nil || high < low || high > 24*time.Hour {
			return 0, 0, errors.New("hop_interval_max must be at least hop_interval and at most24h")
		}
	}
	return low, max(low, high), nil
}

func (o HysteriaHopOptions) validate(kind string, port uint16) error {
	if len(o.ServerPorts) == 0 && o.HopInterval == "" && o.HopIntervalMax == "" {
		return nil
	}
	if kind != "hysteria" && kind != "hysteria2" {
		return errors.New("server_ports and hop_interval require Hysteria or Hysteria2")
	}
	if len(o.ServerPorts) == 0 || port != 0 {
		return errors.New("server_ports is required for hopping and conflicts with server_port")
	}
	if o.HopIntervalMax != "" && kind != "hysteria2" {
		return errors.New("hop_interval_max requires Hysteria2")
	}
	if _, _, err := o.intervals(); err != nil {
		return err
	}
	_, err := o.ports()
	return err
}

type hopRead struct {
	data     []byte
	err      error
	conn     *hopSocket
	consumed chan struct{}
}

type hopSocket struct {
	net.Conn
	stop chan struct{}
	once sync.Once
}

func (s *hopSocket) Close() error {
	s.once.Do(func() { close(s.stop); s.Conn.Close() })
	return nil
}

// Each socket owns one reusable read buffer. Unbuffered handoff and the consumed
// signal avoid allocating/copying an additional datagram on the hopping path.
type quicHopConn struct {
	ctx                         context.Context
	cancel                      context.CancelFunc
	dial                        func(context.Context, uint16) (net.Conn, error)
	ports                       []uint16
	low, high                   time.Duration
	local, remote               net.Addr
	mu                          sync.Mutex
	active, previous            *hopSocket
	port                        uint16
	readDeadline, writeDeadline time.Time
	wake                        chan struct{}
	reads                       chan hopRead
	wg                          sync.WaitGroup
	once                        sync.Once
	readMu                      sync.Mutex
}

func newQUICHopConn(ctx context.Context, ports []uint16, low, high time.Duration, dial func(context.Context, uint16) (net.Conn, error)) (*quicHopConn, error) {
	port := ports[geckoRandom(0, len(ports)-1)]
	raw, err := dial(ctx, port)
	if err != nil {
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	c := &quicHopConn{ctx: child, cancel: cancel, dial: dial, ports: ports, low: low, high: high, active: &hopSocket{Conn: raw, stop: make(chan struct{})}, port: port, local: raw.LocalAddr(), remote: raw.RemoteAddr(), wake: make(chan struct{}), reads: make(chan hopRead)}
	c.wg.Add(2)
	go c.readSocket(c.active)
	go c.run()
	return c, nil
}

func (c *quicHopConn) readSocket(raw *hopSocket) {
	defer c.wg.Done()
	buffer := packetBuffers.Get().([]byte)
	defer packetBuffers.Put(buffer)
	consumed := make(chan struct{}, 1)
	for {
		n, err := raw.Read(buffer)
		item := hopRead{buffer[:n], err, raw, consumed}
		select {
		case c.reads <- item:
		case <-c.ctx.Done():
			return
		case <-raw.stop:
			return
		}
		// Once handed off, the reader always acknowledges before leaving Read.
		// Wait for it before recycling the buffer, including during Close.
		<-consumed
		if err != nil {
			return
		}
	}
}

func (c *quicHopConn) run() {
	defer c.wg.Done()
	defer func() {
		c.mu.Lock()
		c.active.Close()
		if c.previous != nil {
			c.previous.Close()
		}
		c.mu.Unlock()
	}()
	for {
		interval := c.low
		if c.high > c.low {
			interval += time.Duration(geckoRandom(0, int((c.high-c.low)/time.Millisecond))) * time.Millisecond
		}
		timer := time.NewTimer(interval)
		select {
		case <-timer.C:
		case <-c.ctx.Done():
			timer.Stop()
			return
		}
		_ = c.hop()
	}
}

func (c *quicHopConn) hop() error {
	c.mu.Lock()
	current := c.port
	c.mu.Unlock()
	index := 0
	if len(c.ports) > 1 {
		index = geckoRandom(0, len(c.ports)-2)
		if index >= sort.Search(len(c.ports), func(i int) bool { return c.ports[i] >= current }) {
			index++
		}
	}
	ctx, cancel := context.WithTimeout(c.ctx, min(c.low, 5*time.Second))
	defer cancel()
	raw, err := c.dial(ctx, c.ports[index])
	if err != nil {
		return err
	} // Preserve the existing session if a new dial fails.
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		raw.Close()
		return net.ErrClosed
	}
	retired := c.previous
	socket := &hopSocket{Conn: raw, stop: make(chan struct{})}
	c.previous, c.active, c.port = c.active, socket, c.ports[index]
	_ = raw.SetWriteDeadline(c.writeDeadline)
	c.wg.Add(1)
	c.mu.Unlock()
	if retired != nil {
		retired.Close()
	}
	go c.readSocket(socket)
	return nil
}

func (c *quicHopConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		c.mu.Lock()
		deadline, wake := c.readDeadline, c.wake
		c.mu.Unlock()
		var expiry <-chan time.Time
		var timer *time.Timer
		if !deadline.IsZero() {
			if !time.Now().Before(deadline) {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.NewTimer(time.Until(deadline))
			expiry = timer.C
		}
		select {
		case item := <-c.reads:
			if timer != nil {
				timer.Stop()
			}
			n := copy(b, item.data)
			item.consumed <- struct{}{}
			if item.err == nil {
				return n, nil
			}
			c.mu.Lock()
			active := item.conn == c.active
			c.mu.Unlock()
			if active {
				return n, item.err
			}
		case <-expiry:
			return 0, os.ErrDeadlineExceeded
		case <-wake:
			if timer != nil {
				timer.Stop()
			}
		case <-c.ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return 0, net.ErrClosed
		}
	}
}

func (c *quicHopConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	raw := c.active
	c.mu.Unlock()
	return raw.Write(b)
}
func (c *quicHopConn) LocalAddr() net.Addr  { return c.local }
func (c *quicHopConn) RemoteAddr() net.Addr { return c.remote }
func (c *quicHopConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	close(c.wake)
	c.wake = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *quicHopConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return c.active.SetWriteDeadline(t)
}
func (c *quicHopConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}
func (c *quicHopConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		c.mu.Lock()
		c.active.Close()
		if c.previous != nil {
			c.previous.Close()
		}
		c.mu.Unlock()
		c.wg.Wait()
	})
	return nil
}

func (r *Runtime) hysteriaEndpoint(ctx context.Context, o Outbound) (net.Conn, error) {
	if o.Type == "hysteria" && o.Protocol == "faketcp" {
		return r.dialFakeTCP(ctx, o)
	}
	if len(o.ServerPorts) == 0 {
		return r.endpoint(ctx, o, "udp")
	}
	ports, _ := o.HysteriaHopOptions.ports()
	low, high, _ := o.HysteriaHopOptions.intervals()
	// The caller's startup deadline applies to the initial dial. Later hops use
	// the runtime lifetime so a completed Dial's canceled context cannot kill it.
	first := true
	dial := func(hopContext context.Context, port uint16) (net.Conn, error) {
		if first {
			first = false
			hopContext = ctx
		}
		o.ServerPort = port
		raw, err := r.endpoint(hopContext, o, "udp")
		if err == nil && o.Detour == "" {
			if address, ok := raw.RemoteAddr().(*net.UDPAddr); ok {
				o.Server = address.IP.String()
				if address.Zone != "" {
					o.Server += "%" + address.Zone
				}
			}
		}
		return raw, err
	}
	return newQUICHopConn(r.ctx, ports, low, high, dial)
}
