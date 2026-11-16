package native

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"time"
)

type NetworkOptions struct {
	NetworkStrategy     string   `json:"network_strategy,omitempty"`
	NetworkType         []string `json:"network_type,omitempty"`
	FallbackNetworkType []string `json:"fallback_network_type,omitempty"`
	FallbackDelay       string   `json:"fallback_delay,omitempty"`
}

func (o NetworkOptions) active() bool {
	return o.NetworkStrategy != "" || len(o.NetworkType) > 0 || len(o.FallbackNetworkType) > 0
}
func (o NetworkOptions) validate() error {
	if !slices.Contains([]string{"", "default", "hybrid", "fallback"}, o.NetworkStrategy) {
		return errors.New("invalid network_strategy")
	}
	for _, list := range [][]string{o.NetworkType, o.FallbackNetworkType} {
		if len(list) > 4 {
			return errors.New("at most four network types are allowed")
		}
		for i, v := range list {
			if !slices.Contains([]string{"wifi", "cellular", "ethernet", "other"}, v) || slices.Contains(list[:i], v) {
				return errors.New("invalid or duplicate network type")
			}
		}
	}
	if len(o.FallbackNetworkType) > 0 && o.NetworkStrategy != "fallback" {
		return errors.New("fallback_network_type requires fallback strategy")
	}
	if o.FallbackDelay != "" {
		d, e := time.ParseDuration(o.FallbackDelay)
		if e != nil || d <= 0 {
			return errors.New("fallback_delay must be a positive duration")
		}
	}
	return nil
}
func (o NetworkOptions) delay() time.Duration {
	d := 300 * time.Millisecond
	if o.FallbackDelay != "" {
		d, _ = time.ParseDuration(o.FallbackDelay)
	}
	return d
}

type networkChoice struct {
	Name, Kind         string
	Addresses          []netip.Addr
	Default4, Default6 bool
}

func (c networkChoice) supports(ip netip.Addr) bool {
	return slices.ContainsFunc(c.Addresses, func(a netip.Addr) bool { return a.Is4() == ip.Is4() })
}

type networkSelectionKey struct{}
type networkRouteKey struct{}
type networkFallbackKey struct {
	preferred, fallback uint8
	ipv6                bool
	namespace           *networkNamespace
}

func networkMask(types []string) (m uint8) {
	for _, s := range types {
		switch s {
		case "wifi":
			m |= 1
		case "cellular":
			m |= 2
		case "ethernet":
			m |= 4
		case "other":
			m |= 8
		}
	}
	return
}
func (o NetworkOptions) key(ip netip.Addr) networkFallbackKey {
	return networkFallbackKey{preferred: networkMask(o.NetworkType), fallback: networkMask(o.FallbackNetworkType), ipv6: ip.Is6()}
}

func (r *Runtime) networkCandidates(ctx context.Context, o NetworkOptions, ip netip.Addr, namespaces ...*networkNamespace) (primary, fallback []networkChoice, err error) {
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	var state Metadata
	scoped := len(namespaces) > 0 && namespaces[0] != nil
	if scoped {
		state.networkChoices, err = namespaces[0].networkChoices(ctx)
		if err != nil {
			return nil, nil, err
		}
	} else {
		state = r.network.snapshot(context.WithValue(ctx, networkSelectionKey{}, true), r)
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	r.network.mu.Lock()
	defer r.network.mu.Unlock()
	if len(state.networkChoices) > 64 {
		return nil, nil, errors.New("too many network interfaces")
	}
	ordered := func(types []string, defaults bool) []networkChoice {
		var list []networkChoice
		add := func(c networkChoice) {
			if !scoped && r.network.excluded[c.Name] || !c.supports(ip) {
				return
			}
			list = append(list, c)
		}
		if len(types) > 0 {
			for _, kind := range types {
				for _, c := range state.networkChoices {
					if c.Kind == kind {
						add(c)
					}
				}
			}
		} else {
			for _, c := range state.networkChoices {
				if !defaults || ip.Is4() && c.Default4 || ip.Is6() && c.Default6 {
					add(c)
				}
			}
		}
		return list
	}
	primary = ordered(o.NetworkType, o.NetworkStrategy != "hybrid")
	if o.NetworkStrategy == "fallback" {
		fallback = ordered(o.FallbackNetworkType, false)
		fallback = slices.DeleteFunc(fallback, func(c networkChoice) bool {
			return slices.ContainsFunc(primary, func(p networkChoice) bool { return c.Name == p.Name })
		})
	}
	if len(primary)+len(fallback) == 0 {
		return nil, nil, errors.New("no eligible network interface")
	}
	return primary, fallback, nil
}
func (c *networkMetadataCache) fastFallback(key networkFallbackKey) bool {
	c.fastMu.Lock()
	defer c.fastMu.Unlock()
	return time.Now().Before(c.fallback[key])
}
func (c *networkMetadataCache) recordFallback(key networkFallbackKey, failed bool) {
	c.fastMu.Lock()
	defer c.fastMu.Unlock()
	if !failed {
		delete(c.fallback, key)
		return
	}
	if c.fallback == nil {
		c.fallback = map[networkFallbackKey]time.Time{}
	}
	c.fallback[key] = time.Now().Add(15 * time.Second)
}
func (c *networkMetadataCache) exclude(name string, exclude bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if exclude {
		if c.excluded == nil {
			c.excluded = map[string]bool{}
		}
		c.excluded[name] = true
	} else {
		delete(c.excluded, name)
	}
	c.next = time.Time{}
}

// An unbuffered result hands ownership to exactly one receiver; canceled losers close themselves.
func raceNetworks[T io.Closer](ctx context.Context, o NetworkOptions, primary, fallback []networkChoice, fast bool, attempt func(context.Context, networkChoice) (T, error), record func(bool)) (zero T, err error) {
	if o.NetworkStrategy == "" || o.NetworkStrategy == "default" {
		for _, choice := range primary {
			if ctx.Err() != nil {
				return zero, ctx.Err()
			}
			c, e := attempt(ctx, choice)
			if ctx.Err() != nil {
				if e == nil {
					c.Close()
				}
				return zero, ctx.Err()
			}
			if e == nil {
				return c, nil
			}
			err = errors.Join(err, e)
		}
		if err == nil {
			err = errors.New("no preferred network interface")
		}
		return zero, err
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn      T
		err       error
		preferred bool
	}
	results := make(chan result)
	running, preferred := 0, 0
	launch := func(list []networkChoice, isPreferred bool) {
		for _, choice := range list {
			running++
			if isPreferred {
				preferred++
			}
			go func() {
				c, e := attempt(child, choice)
				select {
				case results <- result{c, e, isPreferred}:
				case <-child.Done():
					if e == nil {
						c.Close()
					}
				}
			}()
		}
	}
	launch(primary, true)
	var timer *time.Timer
	var after <-chan time.Time
	if o.NetworkStrategy == "fallback" && len(fallback) > 0 {
		if fast || len(primary) == 0 {
			launch(fallback, false)
			fallback = nil
		} else {
			timer = time.NewTimer(o.delay())
			defer timer.Stop()
			after = timer.C
		}
	}
	for running > 0 {
		select {
		case res := <-results:
			if ctx.Err() != nil {
				if res.err == nil {
					res.conn.Close()
				}
				return zero, ctx.Err()
			}
			running--
			if res.preferred {
				preferred--
			}
			if res.err == nil {
				if o.NetworkStrategy == "fallback" {
					record(!res.preferred)
				}
				return res.conn, nil
			}
			err = errors.Join(err, res.err)
			if preferred == 0 && len(fallback) > 0 {
				record(true)
				launch(fallback, false)
				fallback = nil
				after = nil
			}
		case <-after:
			if ctx.Err() != nil {
				return zero, ctx.Err()
			}
			record(true)
			launch(fallback, false)
			fallback = nil
			after = nil
		case <-ctx.Done():
			return zero, ctx.Err()
		}
	}
	if o.NetworkStrategy == "fallback" && ctx.Err() == nil {
		record(true)
	}
	if err == nil {
		err = errors.New("no eligible network interface")
	}
	return zero, err
}
func networkDestination(target string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return netip.Addr{}, err
	}
	ip, err := netip.ParseAddr(host)
	return ip.Unmap(), err
}
func (r *Runtime) selectDial(ctx context.Context, o DialOptions, network, address string) (net.Conn, error) {
	ip, err := networkDestination(address)
	if err != nil {
		return nil, err
	}
	primary, fallback, err := r.networkCandidates(ctx, o.NetworkOptions, ip)
	if err != nil {
		return nil, err
	}
	key := o.NetworkOptions.key(ip)
	return raceNetworks(ctx, o.NetworkOptions, primary, fallback, r.network.fastFallback(key), func(ctx context.Context, c networkChoice) (net.Conn, error) {
		bound := o
		bound.NetworkOptions = NetworkOptions{}
		bound.BindInterface = c.Name
		return r.dialSocket(ctx, bound, network, address)
	}, func(failed bool) { r.network.recordFallback(key, failed) })
}
func (r *Runtime) selectPacket(ctx context.Context, o DialOptions, network, local, target string) (net.PacketConn, error) {
	ip, err := networkDestination(target)
	if err != nil {
		return nil, err
	}
	primary, fallback, err := r.networkCandidates(ctx, o.NetworkOptions, ip)
	if err != nil {
		return nil, err
	}
	key := o.NetworkOptions.key(ip)
	return raceNetworks(ctx, o.NetworkOptions, primary, fallback, r.network.fastFallback(key), func(ctx context.Context, c networkChoice) (net.PacketConn, error) {
		bound := o
		bound.NetworkOptions = NetworkOptions{}
		bound.BindInterface = c.Name
		return r.listenPacketWithOptions(ctx, bound, network, local, target)
	}, func(failed bool) { r.network.recordFallback(key, failed) })
}
func (o DialOptions) routeNetwork(ctx context.Context) DialOptions {
	if o.BindInterface != "" || o.Inet4BindAddress != "" || o.Inet6BindAddress != "" {
		return o
	}
	if rule, _ := ctx.Value(networkRouteKey{}).(*NetworkOptions); rule != nil {
		if rule.NetworkStrategy != "" {
			o.NetworkStrategy = rule.NetworkStrategy
			o.NetworkType = rule.NetworkType
			o.FallbackNetworkType = rule.FallbackNetworkType
		}
		if rule.FallbackDelay != "" {
			o.FallbackDelay = rule.FallbackDelay
		}
	}
	return o
}
func (q request) networkContext(ctx context.Context) context.Context {
	if q.networkOptions != nil {
		return context.WithValue(ctx, networkRouteKey{}, q.networkOptions)
	}
	return ctx
}
func networkRuleOptions(rule *Rule) (*NetworkOptions, error) {
	if rule.NetworkStrategy == "" && len(rule.FallbackNetworkType) == 0 && rule.FallbackDelay == "" {
		return nil, nil
	}
	options := rule.NetworkOptions
	if options.NetworkStrategy != "" {
		options.NetworkType = rule.NetworkType
		rule.NetworkType = nil
	} else {
		options.NetworkType = nil
	}
	if !options.active() && options.FallbackDelay == "" {
		return nil, nil
	}
	if !slices.Contains([]string{"", "route", "route-options", "bypass"}, rule.Action) {
		return nil, errors.New("network options require a routing action")
	}
	if err := options.validate(); err != nil {
		return nil, err
	}
	return &options, nil
}
func mergeNetworkOptions(previous, next *NetworkOptions) *NetworkOptions {
	if previous == nil {
		return next
	}
	merged := *previous
	if next.NetworkStrategy != "" {
		merged.NetworkStrategy = next.NetworkStrategy
		merged.NetworkType = next.NetworkType
		merged.FallbackNetworkType = next.FallbackNetworkType
	}
	if next.FallbackDelay != "" {
		merged.FallbackDelay = next.FallbackDelay
	}
	return &merged
}
