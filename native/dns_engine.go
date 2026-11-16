package native

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type responseReference string

func (v *responseReference) UnmarshalJSON(b []byte) error {
	var flag bool
	if json.Unmarshal(b, &flag) == nil {
		if flag {
			*v = "@last"
		}
		return nil
	}
	var tag string
	if e := json.Unmarshal(b, &tag); e != nil {
		return e
	}
	if tag == "" || tag == "@last" {
		return errors.New("invalid response tag")
	}
	*v = responseReference(tag)
	return nil
}
func (v responseReference) MarshalJSON() ([]byte, error) {
	if v == "@last" {
		return []byte("true"), nil
	}
	if v == "" {
		return []byte("false"), nil
	}
	return json.Marshal(string(v))
}

type optimisticOptions struct {
	Enabled bool   `json:"enabled,omitempty"`
	Timeout string `json:"timeout,omitempty"`
}

func (o *optimisticOptions) UnmarshalJSON(b []byte) error {
	if json.Unmarshal(b, &o.Enabled) == nil {
		return nil
	}
	type plain optimisticOptions
	return decodeOptions(b, (*plain)(o))
}

type dnsWireLookup struct {
	canceled bool
	done     chan struct{}
	reply    []byte
	err      error
}
type dnsWireEntry struct {
	key             string
	reply           []byte
	inserted, until time.Time
	refreshing      bool
}
type dnsPolicyState struct {
	responses map[string][]byte
	selected  []byte
}

func (r *routeRule) responseMatches(q request, state *dnsPolicyState) bool {
	o := r.rule
	if len(r.children) > 0 {
		ok := o.Mode == "and"
		for i := range r.children {
			childState := *state
			hit := r.children[i].responseMatches(q, &childState)
			if o.Mode == "and" {
				state.selected = childState.selected
				if !hit {
					ok = false
					break
				}
			} else if hit {
				state.selected = childState.selected
				ok = true
				break
			}
		}
		if o.Invert {
			ok = !ok
		}
		return ok
	}
	if o.MatchResponse != "" {
		reply := state.responses[string(o.MatchResponse)]
		if reply == nil {
			return false
		}
		state.selected = reply
		sections, e := dnsRecords(reply)
		if e != nil {
			return false
		}
		q.ips = []netip.Addr{}
		for _, rr := range sections[0] {
			if rr.typ == 1 || rr.typ == 28 {
				if ip, ok := netip.AddrFromSlice(rr.data); ok {
					q.ips = append(q.ips, ip)
				}
			}
		}
		hit := true
		if o.ResponseRCode != "" {
			code := dnsRCodes[strings.ToUpper(o.ResponseRCode)]
			hit = reply[3]&15 == code
		}
		for i := range 3 {
			if r.responseRecords == nil || len(r.responseRecords[i]) == 0 {
				continue
			}
			found := false
			for _, want := range r.responseRecords[i] {
				for _, rr := range sections[i] {
					if want.name == rr.name && want.typ == rr.typ && want.class == rr.class && bytes.Equal(want.data, rr.data) {
						found = true
					}
				}
			}
			hit = hit && found
		}
		if o.IPAcceptAny {
			hit = hit && len(q.ips) > 0
		}
		base := *r
		base.rule.Invert = false
		hit = hit && base.evaluateBase(q) == matchYes
		if o.Invert {
			hit = !hit
		}
		return hit
	}
	return r.matches(q)
}
func (r *resolver) exchangePolicy(ctx context.Context, query []byte, real bool) ([]byte, error) {
	host, end, typ, e := dnsQuestion(query)
	if e != nil {
		return nil, e
	}
	inbound, _ := ctx.Value(dnsInboundKey{}).(string)
	q := request{network: "udp", address: net.JoinHostPort(host, "53"), queryType: typ, inbound: inbound, dns: true}
	if metadata, ok := ctx.Value(metadataKey{}).(Metadata); ok {
		q.metadata = metadata
	}
	if len(r.preferredTags) > 0 {
		preferred, err := r.dnsPreferences(ctx, host)
		if err != nil {
			return nil, err
		}
		q.metadata.DNSPreferredBy = preferred
	}
	r.runtime.enrichNetworkMetadata(ctx, &q.metadata)
	r.enrichDNSNetworkMetadata(&q.metadata)
	options := dnsContextOptions(ctx)
	if r.parallelPolicy {
		return r.exchangeParallelDNS(ctx, query, real, q, options, end)
	}
	for _, policy := range r.policies {
		o := policy.options
		if real && r.servers[o.Server].Type == "fakeip" {
			continue
		}
		hit := false
		m := policy.rule.evaluate(q)
		if m == matchUnknown {
			server := o.Server
			if server == "" {
				server = r.server.Tag
			}
			candidate, e := r.exchangeDNSOn(ctx, server, query, options, real)
			if e != nil {
				return nil, e
			}
			ips, _, e := parseDNSReply(query, candidate)
			if e != nil {
				return nil, e
			}
			target := q
			target.ips = append([]netip.Addr{}, ips...)
			hit = policy.rule.matches(target)
			if hit && o.Action != "reject" && (o.Action == "" || o.Action == "route") {
				return candidate, nil
			}
		}
		if m == matchYes {
			hit = true
		}
		if !hit {
			continue
		}
		mergeDNSOptions(&options, o)
		switch o.Action {
		case "route-options":
			continue
		case "predefined":
			return predefinedDNS(query, o)
		case "reject":
			if r.reject.drop(o.Method, o.NoDrop) {
				return nil, ErrDropped
			}
			return dnsResponse(query, end, nil, 0, 5), nil
		default:
			return r.exchangeDNSOn(ctx, o.Server, query, options, real)
		}
	}
	return r.exchangeDNSOn(ctx, r.server.Tag, query, options, real)
}
func hasResponseCondition(r routeRule) bool {
	if r.rule.MatchResponse != "" {
		return true
	}
	for _, c := range r.children {
		if hasResponseCondition(c) {
			return true
		}
	}
	return false
}
func dnsContextOptions(ctx context.Context) DNSRule {
	o := DNSRule{}
	if v, ok := ctx.Value(dnsQueryOptionsKey{}).(resolverOptions); ok {
		o.DisableCache = v.DisableCache
		o.DisableOptimisticCache = v.DisableOptimisticCache
		o.RewriteTTL = v.RewriteTTL
		o.Timeout = v.Timeout
		o.ClientSubnet = v.ClientSubnet
		o.Strategy = v.Strategy
	}
	return o
}
func mergeDNSOptions(dst *DNSRule, src DNSRule) {
	if src.Strategy != "" {
		dst.Strategy = src.Strategy
	}
	if src.DisableCache {
		dst.DisableCache = true
	}
	if src.DisableOptimisticCache {
		dst.DisableOptimisticCache = true
	}
	if src.RewriteTTL != nil {
		dst.RewriteTTL = src.RewriteTTL
	}
	if src.Timeout != "" {
		dst.Timeout = src.Timeout
	}
	if src.ClientSubnet != "" {
		dst.ClientSubnet = src.ClientSubnet
		dst.RemoveClientSubnet = false
	}
	if src.RemoveClientSubnet {
		dst.RemoveClientSubnet = true
		dst.ClientSubnet = ""
	}
}
func (r *resolver) exchangeDNSOn(ctx context.Context, tag string, query []byte, o DNSRule, real bool) (result []byte, resultErr error) {
	server, ok := r.servers[tag]
	if tag == "@local" {
		server = DNSServer{Type: "local", Tag: "@local"}
		ok = true
	}
	if !ok && tag != "" {
		return nil, fmt.Errorf("unknown DNS server %q", tag)
	}
	if real && server.Type == "fakeip" {
		server = DNSServer{Type: "local"}
		for _, s := range r.config.Servers {
			if s.Type != "fakeip" && s.Type != "hosts" {
				server = s
				break
			}
		}
	}
	timeout := r.config.Timeout
	if o.Timeout != "" {
		timeout = o.Timeout
	}
	d, _ := optionDuration(timeout, 10*time.Second)
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	stopRuntime := context.AfterFunc(r.ctx, cancel)
	defer stopRuntime()

	subnet := o.ClientSubnet
	if subnet == "" {
		subnet = r.config.ClientSubnet
	}
	if subnet != "" || o.RemoveClientSubnet {
		var e error
		query, e = dnsClientSubnet(append([]byte(nil), query...), subnet, o.RemoveClientSubnet)
		if e != nil {
			return nil, e
		}
	}
	host, end, typ, e := dnsQuestion(query)
	if e != nil {
		return nil, e
	}
	if o.Strategy == "ipv4_only" && typ == 28 || o.Strategy == "ipv6_only" && typ == 1 {
		return dnsResponse(query, end, nil, 0, 0), nil
	}
	if reply, handled, err := r.neighborDNS(ctx, server, query, host, end, typ); handled || err != nil {
		if err == nil {
			_, err = r.prepareDNSReply(query, reply, host, o.RewriteTTL)
		}
		return reply, err
	}
	key := server.Tag + ":\x00\x00" + string(query[2:])
	epoch := r.cacheEpoch.Load()
	if server.Type == "resolved" {
		state := r.runtime.resolved[server.Service].state.Load()
		key += ":resolved:" + state.key
		if index, ok := ctx.Value(resolvedIfIndexKey{}).(int32); ok {
			key += ":" + strconv.FormatInt(int64(index), 10)
		}
		ctx = context.WithValue(ctx, resolvedDNSKey{server.Service}, state)
	}
	if server.Type == "dhcp" {
		state, err := r.dhcp[server.Tag].snapshot(ctx, server.Interfaces)
		if err != nil {
			return nil, err
		}
		key += ":dhcp:" + state.key
		ctx = context.WithValue(ctx, dhcpDNSKey{}, state)
	}
	if server.Type == "mdns" {
		paths, namespace, err := mdnsPaths(server.Interfaces)
		if err != nil {
			return nil, err
		}
		key += ":mdns:" + namespace
		ctx = context.WithValue(ctx, mdnsPathsKey{}, paths)
	}
	if server.Type == "tailscale" {
		state, err := r.runtime.tailscaleClient(server.Endpoint).dnsSnapshot(ctx)
		if err != nil {
			return nil, err
		}
		key += ":tailscale:" + state.key
		ctx = context.WithValue(ctx, tsDNSKey{}, state)
	}
	if server.Type == "openconnect" {
		t, err := r.runtime.ocClients[server.Endpoint].session(ctx)
		if err != nil {
			return nil, err
		}
		key += ":openconnect:" + t.dnsEpoch
		// Pin the exchange to the same tunnel whose configuration namespaced the cache.
		ctx = context.WithValue(ctx, ocDNSKey{}, t)
	}
	if server.Type == "masque" {
		version, err := r.runtime.masqueDNSVersion(ctx, server)
		if err != nil {
			return nil, err
		}
		key += ":masque:" + version
	}
	if server.Type == "local" || server.Type == "" {
		key += ":local:" + r.localDNSNamespace()
	}
	if o.RewriteTTL != nil {
		key += ":" + strconv.FormatUint(uint64(*o.RewriteTTL), 10)
	}
	noCache, _ := ctx.Value(dnsNoCacheKey{}).(bool)
	cache := !noCache && !o.DisableCache && !r.config.DisableCache && server.Type != "fakeip"
	if cache {
		r.mu.Lock()
		element := r.wireCache[key]
		if element != nil {
			entry := element.Value.(*dnsWireEntry)
			now := time.Now()
			optimisticFor, _ := optionDuration(r.config.Optimistic.Timeout, 72*time.Hour)
			stale := now.After(entry.until)
			valid := !stale || r.config.DisableExpire || r.config.Optimistic.Enabled && !o.DisableOptimisticCache && now.Before(entry.until.Add(optimisticFor))
			if valid {
				r.wireLRU.MoveToFront(element)
				reply := append([]byte(nil), entry.reply...)
				age := uint32(max(0, int64(now.Sub(entry.inserted)/time.Second)))
				refresh := stale && r.config.Optimistic.Enabled && !entry.refreshing
				if refresh {
					entry.refreshing = true
				}
				r.mu.Unlock()
				patchDNSReply(reply, query, age)
				if refresh {
					go r.refreshDNS(tag, key, append([]byte(nil), query...), o, real)
				}
				return reply, nil
			}
		}
		r.mu.Unlock()
	}

	flightKey := key
	if epoch != 0 {
		flightKey += ":flush:" + strconv.FormatUint(epoch, 10)
	}
retryInflight:
	r.mu.Lock()
	if pending := r.wireInflight[flightKey]; pending != nil {
		r.mu.Unlock()
		select {
		case <-pending.done:
			if pending.err != nil && pending.canceled && ctx.Err() == nil {
				goto retryInflight
			}
			reply := append([]byte(nil), pending.reply...)
			if len(reply) >= 2 {
				copy(reply[:2], query[:2])
			}
			return reply, pending.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	pending := &dnsWireLookup{done: make(chan struct{})}
	r.wireInflight[flightKey] = pending
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if resultErr != nil && ctx.Err() != nil {
			resultErr = ctx.Err()
		}
		pending.reply = append([]byte(nil), result...)
		pending.err = resultErr
		pending.canceled = ctx.Err() != nil
		delete(r.wireInflight, flightKey)
		close(pending.done)
		r.mu.Unlock()
	}()

	var reply []byte
	switch server.Type {
	case "fakeip":
		ttl := uint32(60)
		if o.RewriteTTL != nil {
			ttl = *o.RewriteTTL
		}
		var ips []netip.Addr
		if typ == 1 || typ == 28 {
			ip, err := r.pools[server.Tag].allocate(host, typ, ttl)
			if err != nil {
				return nil, err
			}
			if ip.IsValid() {
				ips = append(ips, ip)
			}
		}
		reply = dnsResponse(query, end, ips, ttl, 0)
	case "", "local", "hosts":
		if typ != 1 && typ != 28 {
			if server.Type == "local" || server.Type == "" {
				reply, e = r.localDNSMessage(ctx, query)
			} else {
				reply = dnsResponse(query, end, nil, 0, 0)
			}
		} else {
			var ips []netip.Addr
			ttl := uint32(300)
			var err error
			if server.Type == "local" || server.Type == "" {
				network := "ip4"
				if typ == 28 {
					network = "ip6"
				}
				ips, err = r.system.LookupNetIP(ctx, network, host)
				ttl = 60
			} else {
				for _, v := range server.Predefined[host] {
					ip, _ := netip.ParseAddr(v)
					if typ == 1 && ip.Is4() || typ == 28 && ip.Is6() {
						ips = append(ips, ip)
					}
				}
			}
			if err != nil {
				var de *net.DNSError
				if errors.As(err, &de) && de.IsNotFound {
					reply = dnsResponse(query, end, nil, 0, 3)
				} else {
					return nil, err
				}
			} else {
				reply = dnsResponse(query, end, ips, ttl, 0)
			}
		}
	default:
		reply, e = r.exchangeOn(ctx, server, query)
	}
	if e != nil {
		return nil, e
	}
	ttl, e := r.prepareDNSReply(query, reply, host, o.RewriteTTL)
	if e != nil {
		return nil, e
	}
	if ttl > 0 && cache {
		r.mu.Lock()
		if epoch == r.cacheEpoch.Load() {
			if r.wireLRU == nil {
				r.wireLRU = list.New()
			}
			entry := &dnsWireEntry{key: key, reply: append([]byte(nil), reply...), inserted: time.Now(), until: time.Now().Add(time.Duration(ttl) * time.Second)}
			if old := r.wireCache[key]; old != nil {
				r.wireLRU.Remove(old)
			}
			r.wireCache[key] = r.wireLRU.PushFront(entry)
			r.dirtyDNS(len(key) + len(reply))
			capacity := max(1024, r.config.CacheCapacity)
			for len(r.wireCache) > capacity {
				last := r.wireLRU.Back()
				delete(r.wireCache, last.Value.(*dnsWireEntry).key)
				r.wireLRU.Remove(last)
			}
		}
		r.mu.Unlock()
	}

	return reply, nil
}
func (r *resolver) prepareDNSReply(query, reply []byte, host string, rewrite *uint32) (uint32, error) {
	if _, _, _, e := validateDNSQuestionResponse(query, reply); e != nil {
		return 0, e
	}
	sections, e := dnsRecords(reply)
	if e != nil {
		return 0, e
	}
	ttl := uint32(0xffffffff)
	for _, section := range sections {
		for _, rr := range section {
			if rr.typ == 41 {
				continue
			}
			value := rr.ttl
			if rewrite != nil {
				value = *rewrite
				binary.BigEndian.PutUint32(reply[rr.ttlOffset:], value)
			}
			ttl = min(ttl, value)
		}
	}
	if ttl == 0xffffffff {
		ttl = 0
	}
	if r.config.ReverseMapping {
		r.mu.Lock()
		for _, rr := range sections[0] {
			if rr.typ == 1 || rr.typ == 28 {
				if ip, ok := netip.AddrFromSlice(rr.data); ok {
					if len(r.reverse) >= max(1024, r.config.CacheCapacity) {
						for old := range r.reverse {
							delete(r.reverse, old)
							break
						}
					}
					r.reverse[ip] = fakeEntry{host: host, until: time.Now().Add(time.Duration(rr.ttl) * time.Second)}
				}
			}
		}
		r.mu.Unlock()
	}
	return ttl, nil
}

func (r *resolver) refreshDNS(tag, key string, query []byte, o DNSRule, real bool) {
	o.DisableOptimisticCache = true
	_, _ = r.exchangeDNSOn(r.ctx, tag, query, o, real)
	r.mu.Lock()
	if entry := r.wireCache[key]; entry != nil {
		entry.Value.(*dnsWireEntry).refreshing = false
	}
	r.mu.Unlock()
}

// Cache entries have already passed dnsRecords validation; only walk wire offsets here.
func patchDNSReply(reply, query []byte, age uint32) {
	copy(reply[:2], query[:2])
	pos := 12
	nameEnd := func() {
		for {
			n := int(reply[pos])
			pos++
			if n&0xc0 == 0xc0 {
				pos++
				return
			}
			if n == 0 {
				return
			}
			pos += n
		}
	}
	for range int(binary.BigEndian.Uint16(reply[4:6])) {
		nameEnd()
		pos += 4
	}
	for section := range 3 {
		for range int(binary.BigEndian.Uint16(reply[6+2*section:])) {
			nameEnd()
			if binary.BigEndian.Uint16(reply[pos:]) != 41 {
				ttl := binary.BigEndian.Uint32(reply[pos+4:])
				if ttl > age {
					ttl -= age
				} else {
					ttl = 0
				}
				binary.BigEndian.PutUint32(reply[pos+4:], ttl)
			}
			pos += 10 + int(binary.BigEndian.Uint16(reply[pos+8:]))
		}
	}
}
func dnsClientSubnet(query []byte, value string, remove bool) ([]byte, error) {
	sections, e := dnsRecords(query)
	if e != nil {
		return nil, e
	}
	var option []byte
	if !remove {
		prefix, e := netip.ParsePrefix(value)
		if e != nil {
			ip, e := netip.ParseAddr(value)
			if e != nil {
				return nil, e
			}
			prefix = netip.PrefixFrom(ip, ip.BitLen())
		}
		prefix = prefix.Masked()
		family := uint16(1)
		if prefix.Addr().Is6() {
			family = 2
		}
		data := binary.BigEndian.AppendUint16(nil, family)
		data = append(data, byte(prefix.Bits()), 0)
		data = append(data, prefix.Addr().AsSlice()[:(prefix.Bits()+7)/8]...)
		option = binary.BigEndian.AppendUint16(nil, 8)
		option = binary.BigEndian.AppendUint16(option, uint16(len(data)))
		option = append(option, data...)
	}
	// Rebuild only additional OPT records; all earlier compression offsets stay stable.
	if len(sections[2]) == 0 {
		if remove {
			return query, nil
		}
		binary.BigEndian.PutUint16(query[10:], 1)
		query = append(query, 0, 0, 41, 4, 208, 0, 0, 0, 0)
		query = binary.BigEndian.AppendUint16(query, uint16(len(option)))
		return append(query, option...), nil
	}
	for _, rr := range sections[2] {
		if rr.typ != 41 {
			continue
		}
		start := rr.ttlOffset + 6
		end := start + len(rr.data)
		if end != len(query) {
			return nil, errors.New("OPT must be the last additional RR")
		}
		var data []byte
		b := rr.data
		for len(b) > 0 {
			if len(b) < 4 {
				return nil, errors.New("invalid EDNS option")
			}
			n := int(binary.BigEndian.Uint16(b[2:]))
			if n > len(b)-4 {
				return nil, errors.New("truncated EDNS option")
			}
			if binary.BigEndian.Uint16(b) != 8 {
				data = append(data, b[:n+4]...)
			}
			b = b[n+4:]
		}
		data = append(data, option...)
		binary.BigEndian.PutUint16(query[start-2:], uint16(len(data)))
		return append(query[:start], data...), nil
	}
	if remove {
		return query, nil
	}
	return nil, errors.New("cannot append ECS after existing additional records")
}

func validateDNSAction(o DNSRule) error {
	if o.Action == "respond" && o.Type == "logical" {
		var named func(Rule) bool
		named = func(rule Rule) bool {
			if rule.MatchResponse != "" && rule.MatchResponse != "@last" {
				return true
			}
			for _, child := range rule.Rules {
				if named(child) {
					return true
				}
			}
			return false
		}
		if named(o.Rule) {
			return errors.New("logical respond cannot select a tagged sub-rule response")
		}
	}

	if o.Race && o.Speculative {
		return errors.New("DNS race conflicts with speculative")
	}
	if o.Race && (o.Action != "" && o.Action != "route" && o.Action != "respond" && o.Action != "reject" && o.Action != "predefined" || !ruleHasResponse(o.Rule)) {
		return errors.New("DNS race requires response matching and a terminal action")
	}
	if o.Speculative && o.Action != "" && o.Action != "route" && o.Action != "evaluate" {
		return errors.New("DNS speculative requires route or evaluate")
	}

	if _, e := optionDuration(o.Timeout, 10*time.Second); e != nil {
		return e
	}
	if o.RemoveClientSubnet && o.ClientSubnet != "" {
		return errors.New("remove_client_subnet conflicts with client_subnet")
	}
	if o.ClientSubnet != "" {
		if _, e := dnsClientSubnet(make([]byte, 12), o.ClientSubnet, false); e != nil {
			return e
		}
	}
	if _, ok := dnsRCodes[strings.ToUpper(o.RCode)]; !ok {
		return errors.New("invalid predefined rcode")
	}
	for _, items := range [][]string{o.Answer, o.NS, o.Extra, o.ResponseAnswer, o.ResponseNS, o.ResponseExtra} {
		if len(items) > 4096 {
			return errors.New("too many DNS RRs in one section")
		}
		for _, text := range items {
			if _, e := parseTextRecord(text); e != nil {
				return e
			}
		}
	}
	if o.ResponseRCode != "" {
		if _, ok := dnsRCodes[strings.ToUpper(o.ResponseRCode)]; !ok {
			return errors.New("invalid response_rcode")
		}
	}
	return nil
}

func validateDNSResponses(rules []DNSRule) error {
	known := map[string]bool{}
	evaluations, races := 0, 0
	var check func(Rule) error
	check = func(o Rule) error {
		if o.MatchResponse != "" && !known[string(o.MatchResponse)] {
			return fmt.Errorf("match_response %q must reference an earlier evaluate", o.MatchResponse)
		}
		if (o.ResponseRCode != "" || len(o.ResponseAnswer)+len(o.ResponseNS)+len(o.ResponseExtra) > 0) && o.MatchResponse == "" {
			return errors.New("DNS response conditions require match_response")
		}
		for _, c := range o.Rules {
			if e := check(c); e != nil {
				return e
			}
		}
		return nil
	}
	for _, o := range rules {
		if o.Action == "evaluate" {
			evaluations++
		}
		if o.Race {
			races++
		}
		if evaluations > 64 || races > 64 {
			return errors.New("DNS supports at most64 evaluate and64 race rules per query")
		}
		if e := check(o.Rule); e != nil {
			return e
		}
		if o.Action == "respond" && !ruleHasResponse(o.Rule) && !known["@last"] {
			return errors.New("respond without match_response requires an earlier untagged evaluate")
		}
		if o.Action == "evaluate" {
			if o.Tag != "" && (known[o.Tag] || o.Tag == "@last") {
				return errors.New("duplicate or reserved DNS evaluate tag")
			}
			tag := o.Tag
			if tag == "" {
				tag = "@last"
			}
			known[tag] = true
		}
	}
	return nil
}
