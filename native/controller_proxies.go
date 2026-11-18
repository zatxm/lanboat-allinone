package native

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type controllerDelay struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}
type controllerHistory struct {
	entries []controllerDelay
	urls    map[string][]controllerDelay
	order   []string
}

func (c *controller) names() []string {
	names := []string{}
	if c.virtualProxy {
		names = append(names, "PROXY")
	}
	if c.virtualGlobal {
		names = append(names, "GLOBAL")
	}
	for _, o := range c.r.config.Outbounds {
		if !o.reverse {
			names = append(names, o.Tag)
		}
	}
	for _, name := range []string{"DIRECT", "REJECT"} {
		if _, ok := c.r.outbounds[name]; !ok {
			names = append(names, name)
		}
	}
	return names
}
func (c *controller) kind(name string) string {
	if o, ok := c.r.outbounds[name]; ok {
		switch o.Type {
		case "selector":
			return "Selector"
		case "urltest":
			return "URLTest"
		case "direct":
			return "Direct"
		case "block":
			return "Reject"
		case "sudoku":
			return "Sudoku"
		default:
			return strings.ToUpper(o.Type)
		}
	}
	if c.virtualProxy && name == "PROXY" || c.virtualGlobal && name == "GLOBAL" {
		return "Selector"
	}
	if name == "DIRECT" {
		return "Direct"
	}
	if name == "REJECT" {
		return "Reject"
	}
	return ""
}
func (c *controller) members(name string) []string {
	if g := c.r.groups[name]; g != nil {
		return g.options.Outbounds
	}
	if name == "PROXY" && c.virtualProxy {
		a := []string{}
		for _, o := range c.r.config.Outbounds {
			if !o.reverse {
				a = append(a, o.Tag)
			}
		}
		return a
	}
	if name == "GLOBAL" && c.virtualGlobal {
		a := []string{"PROXY"}
		for _, n := range c.names() {
			if n != "GLOBAL" && n != "PROXY" {
				a = append(a, n)
			}
		}
		return a
	}
	return nil
}
func (c *controller) resolvePath(name string) (string, []string) {
	var aliases []string
	for range 3 {
		if _, ok := c.r.outbounds[name]; ok {
			return name, aliases
		}
		if name == "PROXY" && c.virtualProxy {
			aliases = append(aliases, name)
			name = c.proxy.Load().(string)
			continue
		}
		if name == "GLOBAL" && c.virtualGlobal {
			aliases = append(aliases, name)
			name = c.global.Load().(string)
			continue
		}
		if name == "DIRECT" {
			return c.directTag, append(aliases, name)
		}
		if name == "REJECT" {
			return c.blockTag, append(aliases, name)
		}
		break
	}
	return name, aliases
}
func (c *controller) resolveName(name string) string { tag, _ := c.resolvePath(name); return tag }
func (c *controller) selected(name string) string {
	if g := c.r.groups[name]; g != nil {
		return *g.selected.Load()
	}
	if name == "PROXY" && c.virtualProxy {
		return c.proxy.Load().(string)
	}
	if name == "GLOBAL" && c.virtualGlobal {
		return c.global.Load().(string)
	}
	return ""
}
func (c *controller) selectProxy(name, member string) error {
	if c.kind(name) != "Selector" {
		return errors.New("Must be a Selector")
	}
	if !slices.Contains(c.members(name), member) {
		return errors.New("Selector update error: outbound is not a group member")
	}
	if c.r.groups[name] != nil {
		return c.r.SelectOutbound(name, member)
	}
	if name == "PROXY" {
		c.proxy.Store(member)
	} else {
		c.global.Store(member)
	}
	return nil
}
func (c *controller) proxyInfo(name string) map[string]any {
	kind := c.kind(name)
	if kind == "" {
		return nil
	}
	o := c.r.outbounds[name]
	udp := slices.Contains([]string{"direct", "socks", "shadowsocks", "shadowsocksr", "vmess", "vless", "trojan", "sudoku", "hysteria", "hysteria2", "tuic", "snell", "wireguard", "tailscale", "masque", "openconnect", "trusttunnel", "brook", "mieru", "anytls", "relay"}, o.Type) || name == "DIRECT"
	result := map[string]any{"name": name, "id": name, "type": kind, "history": []controllerDelay{}, "extra": map[string]any{}, "alive": true, "udp": udp, "uot": o.Type == "sudoku", "xudp": false, "tfo": false, "mptcp": false, "smux": o.Multiplex.Enabled, "interface": "", "routing-mark": 0, "provider-name": "", "dialer-proxy": o.Detour}
	if members := c.members(name); members != nil {
		result["all"] = members
		result["now"] = c.selected(name)
		result["testUrl"] = o.URL
		result["hidden"] = false
		result["icon"] = ""
		result["udp"] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.history[name]; h != nil {
		result["history"] = append([]controllerDelay{}, h.entries...)
		result["alive"] = len(h.entries) == 0 || h.entries[len(h.entries)-1].Delay != 0
		extra := map[string]any{}
		for u, entries := range h.urls {
			extra[u] = map[string]any{"history": append([]controllerDelay{}, entries...), "alive": len(entries) > 0 && entries[len(entries)-1].Delay != 0}
		}
		result["extra"] = extra
	}
	return result
}
func (c *controller) recordDelay(name, target string, delay uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	h := c.history[name]
	if h == nil {
		if len(c.history) >= 256 {
			delete(c.history, c.historyOrder[0])
			c.historyOrder = c.historyOrder[1:]
		}
		h = &controllerHistory{urls: map[string][]controllerDelay{}}
		c.history[name] = h
		c.historyOrder = append(c.historyOrder, name)
	}
	entry := controllerDelay{time.Now(), delay}
	add := func(a []controllerDelay) []controllerDelay {
		if len(a) == 10 {
			copy(a, a[1:])
			a = a[:9]
		}
		return append(a, entry)
	}
	h.entries = add(h.entries)
	if _, ok := h.urls[target]; !ok {
		if len(h.order) == 8 {
			delete(h.urls, h.order[0])
			h.order = h.order[1:]
		}
		h.order = append(h.order, target)
	}
	h.urls[target] = add(h.urls[target])
}

func controllerDelayOptions(req *http.Request) (time.Duration, string, func(int) bool, error) {
	n, err := strconv.Atoi(req.URL.Query().Get("timeout"))
	if err != nil || n <= 0 || n > 60000 {
		return 0, "", nil, errors.New("timeout")
	}
	target := req.URL.Query().Get("url")
	if target == "" {
		target = "https://www.gstatic.com/generate_204"
	}
	u, err := url.Parse(target)
	if err != nil || len(target) > 2048 || u.Host == "" || u.User != nil || u.Fragment != "" || u.Scheme != "http" && u.Scheme != "https" {
		return 0, "", nil, errors.New("url")
	}
	expected := req.URL.Query().Get("expected")
	ranges := [][2]int{}
	if expected != "" && expected != "*" {
		if len(expected) > 256 {
			return 0, "", nil, errors.New("expected")
		}
		for _, part := range strings.Split(expected, "/") {
			left, right, span := strings.Cut(part, "-")
			if !span {
				right = left
			}
			a, e := strconv.Atoi(left)
			b, f := strconv.Atoi(right)
			if e != nil || f != nil || a < 100 || b > 599 || a > b {
				return 0, "", nil, errors.New("expected")
			}
			ranges = append(ranges, [2]int{a, b})
		}
	}
	accept := func(status int) bool {
		if len(ranges) == 0 {
			return true
		}
		for _, r := range ranges {
			if status >= r[0] && status <= r[1] {
				return true
			}
		}
		return false
	}
	return time.Duration(n) * time.Millisecond, target, accept, nil
}
func (c *controller) delay(ctx context.Context, name, target string, accept func(int) bool) (uint16, error) {
	select {
	case c.probes <- struct{}{}:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	defer func() { <-c.probes }()
	transport := &http.Transport{DisableKeepAlives: true, MaxResponseHeaderBytes: 32 << 10, TLSHandshakeTimeout: 10 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return c.r.dialOutbound(ctx, c.resolveName(name), network, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "HEAD", target, nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	response, err := client.Do(req)
	var delay uint16
	if err == nil {
		response.Body.Close()
		if accept(response.StatusCode) {
			delay = uint16(min(65535, max(1, time.Since(start).Milliseconds())))
		} else {
			err = errors.New("unexpected status")
		}
	}
	c.recordDelay(name, target, delay)
	return delay, err
}

func (c *controller) serveDelay(w http.ResponseWriter, req *http.Request, name string, group bool) {
	if c.kind(name) == "" || group && c.members(name) == nil {
		controllerError(w, 404, "Resource not found")
		return
	}
	duration, target, accept, err := controllerDelayOptions(req)
	if err != nil {
		controllerError(w, 400, "Body invalid")
		return
	}
	ctx, cancel := context.WithTimeout(req.Context(), duration)
	defer cancel()
	if !group {
		delay, err := c.delay(ctx, name, target, accept)
		if err != nil {
			if ctx.Err() != nil {
				controllerError(w, 504, "Timeout")
			} else {
				controllerError(w, 503, "An error occurred in the delay test")
			}
			return
		}
		controllerJSON(w, map[string]uint16{"delay": delay})
		return
	}
	results := map[string]uint16{}
	var mu sync.Mutex
	var jobs sync.WaitGroup
	members := c.members(name)
	work := make(chan string)
	for range min(8, len(members)) {
		jobs.Go(func() {
			for member := range work {
				delay, err := c.delay(ctx, member, target, accept)
				if err == nil {
					mu.Lock()
					results[member] = delay
					mu.Unlock()
				}
			}
		})
	}
send:
	for _, member := range members {
		select {
		case work <- member:
		case <-ctx.Done():
			break send
		}
	}
	close(work)
	jobs.Wait()
	if len(results) == 0 {
		controllerError(w, 504, "get delay: all proxies timeout")
		return
	}
	controllerJSON(w, results)
}

func (c *controller) configs() any {
	v := map[string]any{"port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0, "mixed-port": 0, "allow-lan": false, "bind-address": "127.0.0.1", "mode": c.modeName(), "log-level": c.r.config.Log.Level, "ipv6": true, "unified-delay": false, "tun": map[string]bool{"enable": false}}
	for _, in := range c.r.config.Inbounds {
		key := ""
		switch in.Type {
		case "mixed":
			key = "mixed-port"
		case "socks":
			key = "socks-port"
		case "http":
			key = "port"
		case "tun":
			v["tun"] = map[string]bool{"enable": true}
		}
		if key != "" {
			_, port, err := net.SplitHostPort(c.r.Address(in.Tag))
			if err == nil {
				v[key], _ = strconv.Atoi(port)
			}
		}
	}
	return v
}
func controllerName(req *http.Request, prefix string) (string, bool) {
	raw := strings.TrimPrefix(req.URL.EscapedPath(), prefix)
	delay := strings.HasSuffix(raw, "/delay")
	if delay {
		raw = strings.TrimSuffix(raw, "/delay")
	}
	name, err := url.PathUnescape(raw)
	return name, delay && err == nil
}
func (c *controller) serveClient(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	switch path {
	case "/configs":
		switch req.Method {
		case "GET":
			controllerJSON(w, c.configs())
		case "PATCH":
			var body map[string]json.RawMessage
			if controllerBody(w, req, &body, 64<<10) != nil || body == nil {
				controllerError(w, 400, "Body invalid")
				return
			}
			if value, ok := body["mode"]; ok {
				var mode string
				if json.Unmarshal(value, &mode) != nil {
					controllerError(w, 400, "Body invalid")
					return
				}
				mode = strings.ToLower(mode)
				if !slices.Contains([]string{"rule", "pac", "global", "proxy", "direct"}, mode) {
					controllerError(w, 400, "Body invalid")
					return
				}
				c.setMode(mode)
				logInfo(c.r.logger, nil, "clash-api: updated mode: ", c.modeName())
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
		return
	case "/proxies":
		if req.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		all := map[string]any{}
		for _, name := range c.names() {
			all[name] = c.proxyInfo(name)
		}
		controllerJSON(w, map[string]any{"proxies": all})
		return
	case "/group":
		if req.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		all := []any{}
		for _, name := range c.names() {
			if c.members(name) != nil {
				all = append(all, c.proxyInfo(name))
			}
		}
		controllerJSON(w, map[string]any{"proxies": all})
		return
	case "/providers/proxies":
		if req.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		controllerJSON(w, map[string]any{"providers": map[string]any{}})
		return
	case "/rules":
		if req.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		controllerJSON(w, c.rules())
		return
	case "/providers/rules":
		if req.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		all := map[string]any{}
		for _, s := range c.r.config.Route.RuleSet {
			all[s.Tag] = c.provider(s)
		}
		controllerJSON(w, map[string]any{"providers": all})
		return
	case "/connections":
		if req.Method == "DELETE" {
			c.closeConnections("")
			w.WriteHeader(204)
		} else if req.Method == "GET" {
			if controllerWS(req) {
				c.stream(w, req, path)
			} else {
				controllerJSON(w, c.connections())
			}
		} else {
			w.WriteHeader(405)
		}
		return
	}
	if strings.HasPrefix(path, "/connections/") {
		if req.Method != "DELETE" {
			w.WriteHeader(405)
			return
		}
		c.closeConnections(strings.TrimPrefix(path, "/connections/"))
		w.WriteHeader(204)
		return
	}
	if strings.HasPrefix(path, "/providers/rules/") {
		name, _ := url.PathUnescape(strings.TrimPrefix(req.URL.EscapedPath(), "/providers/rules/"))
		for _, s := range c.r.config.Route.RuleSet {
			if s.Tag == name {
				if req.Method == "GET" {
					controllerJSON(w, c.provider(s))
					return
				}
				if req.Method != "PUT" {
					w.WriteHeader(405)
					return
				}
				ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
				defer cancel()
				if c.r.loadRuleSet(ctx, s, true) != nil {
					controllerError(w, 500, "Update failed")
					return
				}
				w.WriteHeader(204)
				return
			}
		}
		controllerError(w, 404, "Resource not found")
		return
	}
	group := strings.HasPrefix(path, "/group/")
	if group || strings.HasPrefix(path, "/proxies/") {
		prefix := "/proxies/"
		if group {
			prefix = "/group/"
		}
		name, delay := controllerName(req, prefix)
		if c.kind(name) == "" || group && c.members(name) == nil {
			controllerError(w, 404, "Resource not found")
			return
		}
		if delay {
			if req.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			c.serveDelay(w, req, name, group)
			return
		}
		switch req.Method {
		case "GET":
			controllerJSON(w, c.proxyInfo(name))
		case "PUT":
			if group {
				w.WriteHeader(405)
				return
			}
			var body struct {
				Name string `json:"name"`
			}
			if controllerBody(w, req, &body, 4<<10) != nil || body.Name == "" {
				controllerError(w, 400, "Body invalid")
				return
			}
			if err := c.selectProxy(name, body.Name); err != nil {
				controllerError(w, 400, err.Error())
				return
			}
			logInfo(c.r.logger, nil, "clash-api: ", name, " selected ", body.Name)
			w.WriteHeader(204)
		case "DELETE":
			controllerError(w, 400, "Must be a Selector")
		default:
			w.WriteHeader(405)
		}
		return
	}
	http.NotFound(w, req)
}

type controllerRule struct {
	Index   int    `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Proxy   string `json:"proxy"`
	Size    int    `json:"size"`
}

func ruleDescription(o Rule) controllerRule {
	v := controllerRule{Type: "Rule", Proxy: o.Outbound, Size: -1}
	if o.Action == "reject" {
		v.Proxy = "REJECT"
	}
	switch {
	case o.Type == "logical":
		v.Type = "Logical"
	case len(o.RuleSet) > 0:
		v.Type = "RuleSet"
		v.Payload = strings.Join(o.RuleSet, ",")
	case len(o.Domain) > 0:
		v.Type = "Domain"
		v.Payload = strings.Join(o.Domain, ",")
	case len(o.DomainSuffix) > 0:
		v.Type = "DomainSuffix"
		v.Payload = strings.Join(o.DomainSuffix, ",")
	case len(o.IPCIDR) > 0:
		v.Type = "IPCIDR"
		v.Payload = strings.Join(o.IPCIDR, ",")
	default:
		b, _ := json.Marshal(o)
		v.Payload = string(b)
	}
	return v
}
func (c *controller) rules() any {
	rules := make([]controllerRule, 0, len(c.r.config.Route.Rules)+1)
	for _, o := range c.r.config.Route.Rules {
		if c.mode.Load() != 0 && o.Action != "reject" {
			continue
		}
		v := ruleDescription(o)
		v.Index = len(rules)
		rules = append(rules, v)
	}
	final := c.r.config.Route.Final
	if c.virtualProxy {
		final = "PROXY"
	}
	if c.mode.Load() == 1 {
		final = "GLOBAL"
	}
	if c.mode.Load() == 2 {
		final = "DIRECT"
	}
	rules = append(rules, controllerRule{Index: len(rules), Type: "Match", Proxy: final, Size: -1})
	return map[string]any{"rules": rules}
}
func (c *controller) provider(s RuleSet) any {
	count := 0
	at := time.Time{}
	if snap := c.r.ruleSets[s.Tag].current.Load(); snap != nil {
		count = len(snap.rules)
		at = snap.updatedAt
	}
	vehicle := "Inline"
	if s.Type == "local" {
		vehicle = "File"
	}
	if s.Type == "remote" {
		vehicle = "HTTP"
	}
	format := "Source"
	if s.Format == "binary" {
		format = "SRS"
	}
	return map[string]any{"name": s.Tag, "type": "Rule", "vehicleType": vehicle, "behavior": "Classical", "format": format, "ruleCount": count, "updatedAt": at}
}
