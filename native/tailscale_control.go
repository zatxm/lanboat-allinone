package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

var errTSAuth = errors.New("Tailscale authentication failed or requires device approval")
var errTSNoAddresses = errors.New("Tailscale endpoint has no assigned addresses")

func (c *tailscaleClient) tlsConfig(host string) (*tls.Config, error) {
	o := c.o.TLS
	o.Enabled = true
	o.ServerName = host
	o.ALPN = []string{"http/1.1"}
	return o.config(false, host)
}

func (c *tailscaleClient) controlDirect(ctx context.Context, network, address string) (net.Conn, error) {
	if ref := c.o.DomainResolver; ref != "" {
		var cancel context.CancelFunc
		ctx, cancel = ref.apply(ctx)
		defer cancel()
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, ref.tag())
	} else {
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, "@local")
	}
	if c.o.Detour != "" {
		return c.r.dialOutbound(ctx, c.o.Detour, network, address)
	}
	return c.r.directWithOptions(ctx, c.o.DialOptions, network, address)
}

func (c *tailscaleClient) transports() (*http.Transport, *http.Transport) {
	key := &http.Transport{DialContext: c.controlDirect, ForceAttemptHTTP2: false, MaxConnsPerHost: 2, IdleConnTimeout: time.Minute, ResponseHeaderTimeout: handshakeTimeout, MaxResponseHeaderBytes: 32768}
	key.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		raw, e := c.controlDirect(ctx, network, address)
		if e != nil {
			return nil, e
		}
		host, _, _ := net.SplitHostPort(address)
		cfg, e := c.tlsConfig(host)
		if e != nil {
			raw.Close()
			return nil, e
		}
		t := clientTLS(raw, cfg, c.o.TLS)
		if e = t.HandshakeContext(ctx); e != nil {
			raw.Close()
			return nil, e
		}
		return t, nil
	}
	p := new(http.Protocols)
	p.SetUnencryptedHTTP2(true)
	control := &http.Transport{Protocols: p, DialContext: c.dialControl, MaxConnsPerHost: 2, IdleConnTimeout: time.Minute, MaxResponseHeaderBytes: 32768, ResponseHeaderTimeout: 2 * time.Minute, HTTP2: &http.HTTP2Config{MaxReceiveBufferPerConnection: 1 << 20, MaxReceiveBufferPerStream: 128 << 10, WriteByteTimeout: handshakeTimeout}}
	return control, key
}

func (c *tailscaleClient) dialControl(ctx context.Context, _, _ string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	u, _ := url.Parse(c.o.controlURL())
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String()+"/key?v="+strconv.Itoa(tailscaleCapability), nil)
	resp, e := c.keyHTTP.RoundTrip(req)
	if e != nil {
		return nil, e
	}
	var keys struct{ PublicKey string }
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Tailscale control key request returned HTTP%d", resp.StatusCode)
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&keys); e != nil {
		return nil, e
	}
	pub, e := tsPublic(keys.PublicKey, "mkey")
	if e != nil {
		return nil, e
	}
	handshake, init, e := tsNoiseInit(c.machine, pub)
	if e != nil {
		return nil, e
	}
	port := u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	address := net.JoinHostPort(u.Hostname(), port)
	var raw net.Conn
	if u.Scheme == "https" {
		raw, e = c.keyHTTP.DialTLSContext(ctx, "tcp", address)
	} else {
		raw, e = c.controlDirect(ctx, "tcp", address)
	}
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	up := *u
	up.Path = strings.TrimRight(up.Path, "/") + "/ts2021"
	r, _ := http.NewRequest("POST", up.String(), nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "tailscale-control-protocol")
	r.Header.Set("X-Tailscale-Handshake", base64.StdEncoding.EncodeToString(init))
	if e = r.Write(raw); e != nil {
		return nil, e
	}
	reader := bufio.NewReaderSize(raw, 4096)
	response, e := http.ReadResponse(reader, r)
	if e != nil {
		return nil, e
	}
	if response.StatusCode != 101 || !strings.EqualFold(response.Header.Get("Upgrade"), "tailscale-control-protocol") {
		response.Body.Close()
		return nil, errors.New("Tailscale control upgrade rejected")
	}
	secured, e := handshake.finish(raw, reader)
	if e != nil {
		return nil, e
	}
	// New control servers can precede HTTP/2 with an optional bounded early payload.
	br := bufio.NewReaderSize(secured, 4096)
	prefix, e := br.Peek(9)
	if e != nil {
		return nil, e
	}
	if string(prefix[:5]) == "\xff\xff\xffTS" {
		n := int(binary.BigEndian.Uint32(prefix[5:]))
		if n > 65536 {
			return nil, errors.New("Tailscale early payload too large")
		}
		if _, e = br.Discard(9); e != nil {
			return nil, e
		}
		if _, e = io.CopyN(io.Discard, br, int64(n)); e != nil {
			return nil, e
		}
	}
	raw.SetDeadline(time.Time{})
	ok = true
	return &bufferedConn{Conn: secured, reader: br}, nil
}

func (c *tailscaleClient) controlRequest(ctx context.Context, path string, body any) (*http.Response, error) {
	b, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "http://tailscale-control"+path, bytes.NewReader(b))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	u, _ := url.Parse(c.o.controlURL())
	req.Host = u.Host
	req.Header.Set("Accept-Encoding", "identity")
	response, e := c.control.RoundTrip(req)
	if e != nil {
		return nil, e
	}
	if response.StatusCode != 200 {
		response.Body.Close()
		if response.StatusCode == 401 || response.StatusCode == 403 {
			return nil, errTSAuth
		}
		return nil, fmt.Errorf("Tailscale control request returned HTTP%d", response.StatusCode)
	}
	return response, nil
}

func (c *tailscaleClient) hostinfo() map[string]any {
	host := c.o.Hostname
	if host == "" {
		host, _ = os.Hostname()
	}
	c.mu.Lock()
	home := c.home
	c.mu.Unlock()
	routes := make([]string, 0, len(c.o.AdvertiseRoutes)+2)
	for _, raw := range c.o.AdvertiseRoutes {
		p, _ := netip.ParsePrefix(raw)
		routes = append(routes, p.Masked().String())
	}
	if c.o.AdvertiseExitNode {
		routes = append(routes, "0.0.0.0/0", "::/0")
	}
	slices.Sort(routes)
	routes = slices.Compact(routes)
	info := map[string]any{"IPNVersion": "lanboat-" + Version, "Hostname": host, "OS": runtime.GOOS, "GoArch": runtime.GOARCH, "NetInfo": map[string]any{"PreferredDERP": home}, "RoutableIPs": routes, "RequestTags": c.o.AdvertiseTags}
	info["PeerRelay"] = c.o.RelayServerPort != 0
	if c.ssh != nil {
		info["sshHostKeys"] = []string{c.ssh.publicKey()}
	}
	if c.peerAPI != nil {
		info["Services"] = []map[string]any{{"Proto": "peerapi4", "Port": c.peerAPI.port}, {"Proto": "peerapi6", "Port": c.peerAPI.port}}
	}
	return info
}

func (c *tailscaleClient) controlSession() error {
	request := map[string]any{"Version": tailscaleCapability, "NodeKey": tsKeyName(c.nodeKey, "nodekey"), "Hostinfo": c.hostinfo(), "Ephemeral": c.o.Ephemeral, "NLKey": c.lockPublic()}
	c.mu.Lock()
	if c.authURL != "" {
		request["Followup"] = c.authURL
	}
	c.mu.Unlock()
	authKey, credential, e := c.lockAuth()
	if e != nil {
		return e
	}
	if authKey != "" {
		request["Auth"] = map[string]string{"AuthKey": authKey}
	}
	if len(credential) > 0 {
		request["NodeKeySignature"] = credential
	}
	for {
		ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
		resp, e := c.controlRequest(ctx, "/machine/register", request)
		if e != nil {
			cancel()
			return e
		}
		var result struct {
			MachineAuthorized, NodeKeyExpired bool
			AuthURL, Error                    string
			NodeKeySignature                  []byte
		}
		e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result)
		resp.Body.Close()
		cancel()
		if e != nil {
			return e
		}
		if len(result.NodeKeySignature) > 0 {
			if request["NodeKeySignature"] != nil {
				return errTSAuth
			}
			sig, err := c.rotateLockSignature(result.NodeKeySignature)
			if err != nil {
				return err
			}
			request["NodeKeySignature"] = sig
			if result.NodeKeyExpired {
				continue
			}
		}
		if result.Error != "" || result.NodeKeyExpired {
			return errTSAuth
		}
		if result.AuthURL == "" {
			if !result.MachineAuthorized {
				return errTSAuth
			}
			c.mu.Lock()
			c.authURL = ""
			c.mu.Unlock()
			break
		}
		u, err := url.Parse(result.AuthURL)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
			return errors.New("invalid Tailscale authentication URL")
		}
		c.mu.Lock()
		changed := c.authURL != result.AuthURL
		c.authURL = result.AuthURL
		c.mu.Unlock()
		if changed {
			c.r.logger.Info("Tailscale login required", zap.String("tag", c.o.Tag), zap.String("url", result.AuthURL))
		}
		select {
		case c.authChanged <- struct{}{}:
		default:
		}
		request["Followup"] = result.AuthURL
		timer := time.NewTimer(time.Second)
		select {
		case <-c.ctx.Done():
			timer.Stop()
			return c.ctx.Err()
		case <-timer.C:
		}
	}
	if e := c.updateEndpoints(); e != nil {
		return e
	}
	body := map[string]any{"Version": tailscaleCapability, "NodeKey": tsKeyName(c.nodeKey, "nodekey"), "DiscoKey": tsKeyName(c.discoKey, "discokey"), "Stream": true, "KeepAlive": true, "Hostinfo": c.hostinfo(), "TKAHead": c.lockHeadSnapshot()}
	c.mu.Lock()
	c.resetMap = true
	c.mu.Unlock()
	resp, e := c.controlRequest(c.ctx, "/machine/map", body)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	// The server sends little-endian lengths followed by uncompressed JSON maps.
	for {
		var header [4]byte
		if _, e = io.ReadFull(resp.Body, header[:]); e != nil {
			return e
		}
		n := binary.LittleEndian.Uint32(header[:])
		if n == 0 || n > 16<<20 {
			return errors.New("invalid Tailscale map frame size")
		}
		b := make([]byte, int(n))
		if _, e = io.ReadFull(resp.Body, b); e != nil {
			return e
		}
		if e = c.applyMap(b); e != nil {
			return e
		}
	}
}

func (c *tailscaleClient) updateEndpoints() error {
	c.mu.Lock()
	endpoints := slices.Clone(c.endpoints)
	c.mu.Unlock()
	body := map[string]any{"Version": tailscaleCapability, "NodeKey": tsKeyName(c.nodeKey, "nodekey"), "DiscoKey": tsKeyName(c.discoKey, "discokey"), "Endpoints": endpoints, "Hostinfo": c.hostinfo(), "OmitPeers": true, "TKAHead": c.lockHeadSnapshot()}
	ctx, cancel := context.WithTimeout(c.ctx, handshakeTimeout)
	defer cancel()
	resp, e := c.controlRequest(ctx, "/machine/map", body)
	if e != nil {
		return e
	}
	_, e = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<20))
	resp.Body.Close()
	return e
}

type tsMap struct {
	DNSConfig    *tsDNSConfig
	SSHPolicy    *tsSSHPolicy
	UserProfiles []struct {
		ID        int64
		LoginName string
	}
	KeepAlive         bool
	Node              *tsNode
	Peers             *[]tsNode
	PeersChanged      []tsNode
	PeersRemoved      []int64
	PeersChangedPatch []struct {
		NodeID       int64
		Key          *string
		DiscoKey     *string
		DERPRegion   *int
		Endpoints    *[]netip.AddrPort
		KeyExpiry    *time.Time
		KeySignature *[]byte
	}
	DERPMap *struct {
		Regions            map[int]tsDERPRegion
		OmitDefaultRegions bool
	}
	TKAInfo       *tsTKAInfo
	PacketFilter  *[]tsFilterRule
	PacketFilters map[string][]tsFilterRule
}

func (c *tailscaleClient) applyMap(raw []byte) error {
	var m tsMap
	if e := json.Unmarshal(raw, &m); e != nil {
		return e
	}
	if m.KeepAlive {
		return nil
	}
	if m.DNSConfig != nil {
		if err := m.DNSConfig.validate(); err != nil {
			if s := c.dns.Load(); s != nil {
				s.close()
			}
			return err
		}
	}
	info := m.TKAInfo
	if info == nil && c.resetMap && c.tka != nil {
		info = &tsTKAInfo{Disabled: true}
	}
	if e := c.syncLock(info); e != nil {
		return e
	}
	if m.Node != nil && c.tka != nil && c.tka.nodeAuthorized(c.nodeKey.PublicKey().Bytes(), m.Node.KeySignature) && !bytes.Equal(c.state.TKA.SelfSignature, m.Node.KeySignature) {
		previous := c.state.TKA.SelfSignature
		c.state.TKA.SelfSignature = bytes.Clone(m.Node.KeySignature)
		if e := c.saveState(); e != nil {
			c.state.TKA.SelfSignature = previous
			return e
		}
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return net.ErrClosed
	}
	addressesChanged := m.Node != nil && !slices.Equal(c.self.Addresses, m.Node.Addresses)
	if c.resetMap {
		c.dnsConfig = tsDNSConfig{}
		c.sshPolicy = nil
		c.userLogins = map[int64]string{}
	}
	sshChanged := m.SSHPolicy != nil && !reflect.DeepEqual(c.sshPolicy, m.SSHPolicy)
	if m.SSHPolicy != nil {
		c.sshPolicy = m.SSHPolicy
	}
	if c.userLogins == nil {
		c.userLogins = map[int64]string{}
	}
	for _, u := range m.UserProfiles {
		c.userLogins[u.ID] = u.LoginName
	}
	if m.Node != nil {
		c.self = *m.Node
	}
	if m.DNSConfig != nil {
		c.dnsConfig = *m.DNSConfig
	}
	if m.Peers != nil || c.resetMap {
		c.nodes = map[int64]tsNode{}
	}
	previousFilter := c.filter
	if c.resetMap || c.filters == nil {
		c.filters = map[string][]tsFilterRule{}
		c.filter = nil
	}
	c.resetMap = false
	filterChanged := m.PacketFilter != nil || m.PacketFilters != nil
	if m.PacketFilter != nil {
		c.filters["base"] = *m.PacketFilter
	}
	for name, rules := range m.PacketFilters {
		if rules == nil {
			delete(c.filters, name)
		} else {
			c.filters[name] = rules
		}
	}
	if filterChanged {
		c.filter = nil
		names := make([]string, 0, len(c.filters))
		for name := range c.filters {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			c.filter = append(c.filter, tsCompileFilters(c.filters[name])...)
		}
	}
	filterChanged = !reflect.DeepEqual(previousFilter, c.filter)
	if m.Peers != nil {
		for _, n := range *m.Peers {
			c.nodes[n.ID] = n
		}
	}
	for _, n := range m.PeersChanged {
		c.nodes[n.ID] = n
	}
	for _, id := range m.PeersRemoved {
		delete(c.nodes, id)
	}
	for _, p := range m.PeersChangedPatch {
		n, ok := c.nodes[p.NodeID]
		if !ok {
			continue
		}
		if p.Key != nil {
			n.Key = *p.Key
		}
		if p.DiscoKey != nil {
			n.DiscoKey = *p.DiscoKey
		}
		if p.Endpoints != nil {
			n.Endpoints = *p.Endpoints
		}
		if p.DERPRegion != nil {
			n.HomeDERP = *p.DERPRegion
		}
		if p.KeySignature != nil {
			n.KeySignature = *p.KeySignature
		}
		if p.KeyExpiry != nil {
			n.KeyExpiry = *p.KeyExpiry
		}
		c.nodes[n.ID] = n
	}
	if m.DERPMap != nil {
		for id, r := range m.DERPMap.Regions {
			if r.RegionID == 0 {
				delete(c.regions, id)
			} else {
				c.regions[id] = r
			}
		}
	}
	oldHome := c.home
	previousLockHead := c.lockHead
	c.applyLockLocked()
	lockChanged := previousLockHead != c.lockHead
	c.updateOwnersLocked()
	if _, ok := c.regions[c.home]; !ok {
		c.home = 0
		for id, r := range c.regions {
			if !r.Avoid && (c.home == 0 || id < c.home) {
				c.home = id
			}
		}
	}
	var removed []*tsPeer
	clear(c.nodeKeys)
	clear(c.discoKeys)
	for id, n := range c.nodes {
		if pub, e := tsPublic(n.Key, "nodekey"); e == nil {
			c.nodeKeys[[32]byte(pub)] = id
		}
		if pub, e := tsPublic(n.DiscoKey, "discokey"); e == nil {
			c.discoKeys[[32]byte(pub)] = id
		}
	}
	for key, p := range c.peers {
		n, ok := c.nodes[p.id]
		if filterChanged || addressesChanged || c.self.Expired || c.self.lockInvalid || !ok || n.restricted() || n.Key != key || n.DiscoKey != p.disco || n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) {
			delete(c.peers, key)
			for _, index := range p.indices {
				delete(c.indices, index)
			}
			removed = append(removed, p)
		}
	}
	c.pruneRelayPathsLocked()
	ready := len(c.self.Addresses) > 0
	home := c.home
	retired := c.publishDNSLocked()
	c.mu.Unlock()
	if retired != nil {
		retired.close()
	}
	if sshChanged && c.ssh != nil {
		c.ssh.close()
	}
	for _, p := range removed {
		p.wg.close()
	}
	if c.o.SystemInterface {
		if e := c.syncSystemInterface(); e != nil {
			return e
		}
	}
	if ready && home != 0 && oldHome != home && c.o.ForceDERP {
		if _, e := c.derp(home); e != nil {
			return e
		}
		if e := c.updateEndpoints(); e != nil {
			return e
		}
	}
	if ready {
		c.readyOnce.Do(func() { close(c.ready) })
	}
	if lockChanged && oldHome == home {
		c.spawn(func() { _ = c.updateEndpoints() })
	}
	if home != 0 && oldHome != home {
		c.spawn(func() {
			_, _ = c.derp(home)
			_ = c.updateEndpoints()
			if !c.o.ForceDERP {
				c.probeSTUN()
			}
		})
	}
	return nil
}
