package native

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

type OpenConnectOptions struct {
	System              bool                         `json:"system,omitempty"`
	Name                string                       `json:"name,omitempty"`
	SplitInclude        []string                     `json:"split_include,omitempty"`
	SplitExclude        []string                     `json:"split_exclude,omitempty"`
	AuthForm            map[string]map[string]string `json:"auth_form,omitempty"`
	AuthTimeout         string                       `json:"auth_timeout,omitempty"`
	DisableExternalAuth bool                         `json:"disable_external_auth,omitempty"`
	Group               string                       `json:"group,omitempty"`
	DTLSMode            string                       `json:"dtls_mode,omitempty"`
	DTLSVersion         string                       `json:"dtls_version,omitempty"`
	DisableDTLS         bool                         `json:"disable_dtls,omitempty"`
	RekeyTime           string                       `json:"rekey_time,omitempty"`
	RekeyMethod         string                       `json:"rekey_method,omitempty"`
	DTLSRekeyTime       string                       `json:"dtls_rekey_time,omitempty"`
	DTLSRekeyMethod     string                       `json:"dtls_rekey_method,omitempty"`
	DTLSCipherSuites    []string                     `json:"dtls_cipher_suites,omitempty"`
	DNS                 []string                     `json:"dns,omitempty"`
	SearchDomains       []string                     `json:"search_domains,omitempty"`
	SplitDNS            []string                     `json:"split_dns,omitempty"`
	TunnelAllDNS        bool                         `json:"tunnel_all_dns,omitempty"`
}

func (o OpenConnectOptions) validate(kind string, tls TLSOptions, transport Transport, mtu int, addresses []string) error {
	if kind != "openconnect" {
		if o.DTLSMode != "" || o.DTLSVersion != "" || o.System || o.Name != "" || len(o.SplitInclude)+len(o.SplitExclude) > 0 || o.Group != "" || o.DisableDTLS || o.DTLSCipherSuites != nil || len(o.DNS)+len(o.SearchDomains)+len(o.SplitDNS) > 0 || o.TunnelAllDNS || len(o.AuthForm) > 0 || o.AuthTimeout != "" || o.DisableExternalAuth || o.RekeyTime != "" || o.RekeyMethod != "" || o.DTLSRekeyTime != "" || o.DTLSRekeyMethod != "" {
			return errors.New("OpenConnect options require openconnect type")
		}
		return nil
	}
	if err := o.validateAuth(); err != nil {
		return err
	}
	if _, err := ocRekeyDuration(o.RekeyTime); err != nil {
		return err
	}
	if o.RekeyMethod != "" && (o.RekeyMethod != "ssl" && o.RekeyMethod != "new-tunnel" || o.RekeyTime == "" || o.RekeyMethod == "ssl" && tls.MaxVersion != "1.2") {
		return errors.New("OpenConnect rekey_method requires rekey_time and ssl(TLS max_version1.2) or new-tunnel")
	}
	if _, err := ocRekeyDuration(o.DTLSRekeyTime); err != nil {
		return err
	}
	if o.DisableDTLS && o.DTLSRekeyTime != "" {
		return errors.New("OpenConnect dtls_rekey_time conflicts with disable_dtls")
	}
	if o.DTLSRekeyMethod != "" && (o.DTLSRekeyMethod != "ssl" && o.DTLSRekeyMethod != "new-tunnel" || o.DTLSRekeyTime == "" || o.DisableDTLS || o.DTLSRekeyMethod == "ssl" && (o.DTLSVersion == "1.3" || o.dtlsResume())) {
		return errors.New("OpenConnect dtls_rekey_method requires dtls_rekey_time and ssl(DTLS1.2) or new-tunnel")
	}
	if o.DTLSVersion != "" && o.DTLSVersion != "0.9" && o.DTLSVersion != "1.2" && o.DTLSVersion != "1.3" {
		return errors.New("OpenConnect dtls_version must be 0.9, 1.2 or 1.3")
	}
	if o.DTLSMode != "" && o.DTLSMode != "psk" && o.DTLSMode != "resume" || o.DTLSVersion == "0.9" && o.DTLSMode == "psk" || o.DTLSVersion == "1.3" && o.dtlsResume() {
		return errors.New("invalid OpenConnect dtls_mode for this version")
	}
	if o.DisableDTLS && (o.DTLSVersion != "" || o.DTLSMode != "") {
		return errors.New("OpenConnect dtls_version conflicts with disable_dtls")
	}
	if _, err := o.dtlsCipherIDs(); err != nil {
		return err
	}
	if o.DisableDTLS && o.DTLSCipherSuites != nil {
		return errors.New("OpenConnect dtls_cipher_suites conflicts with disable_dtls")
	}
	if !o.System && o.Name != "" {
		return errors.New("OpenConnect name requires system")
	}
	if o.System {
		if err := validateTUNPlatform(Inbound{InterfaceName: o.Name}); err != nil {
			return err
		}
	}
	if _, _, err := ocParseRoutes(o.routeHeaders()); err != nil {
		return err
	}
	if !tls.Enabled || transport.Type != "" {
		return errors.New("OpenConnect requires TLS and its native CSTP transport")
	}
	if len(tls.ALPN) > 0 && !slices.Contains(tls.ALPN, "http/1.1") {
		return errors.New("OpenConnect ALPN must include http/1.1")
	}
	if tls.MaxVersion == "1.0" || tls.MaxVersion == "1.1" || tls.MinVersion == "1.0" || tls.MinVersion == "1.1" {
		return errors.New("OpenConnect requires TLS1.2 or newer")
	}
	if len(o.Group) > 255 || strings.ContainsAny(o.Group, "\x00\r\n") {
		return errors.New("invalid OpenConnect group")
	}
	if _, err := ocParseDNS(o.dnsHeaders()); err != nil {
		return err
	}
	if mtu != 0 && (mtu < 1280 || mtu > 16376) {
		return errors.New("OpenConnect MTU must be 1280-16376 (one CSTP frame per TLS record)")
	}
	if len(addresses) > 2 {
		return errors.New("OpenConnect permits one assigned address per IP family")
	}
	seen := map[bool]bool{}
	for _, v := range addresses {
		p, e := netip.ParsePrefix(v)
		if e != nil || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() || p.Addr().Zone() != "" || seen[p.Addr().Is4()] {
			return errors.New("invalid OpenConnect assigned address")
		}
		seen[p.Addr().Is4()] = true
	}
	return nil
}
func (o OpenConnectOptions) group() string {
	if o.Group == "" {
		return "all"
	}
	return o.Group
}

type ocClient struct {
	nat           *masqueNAT
	resetting     atomic.Int32
	authCancel    atomic.Pointer[context.CancelFunc]
	r             *Runtime
	o             Outbound
	gate          chan struct{}
	tunnel        atomic.Pointer[ocTunnel]
	cookie        string
	strap         *ocStrap
	wake          chan struct{}
	connectMaster [48]byte
}

func (c *ocClient) reset() {
	c.resetting.Add(1)
	defer c.resetting.Add(-1)
	if cancel := c.authCancel.Load(); cancel != nil {
		(*cancel)()
	}
	c.gate <- struct{}{}
	t := c.tunnel.Swap(nil)
	<-c.gate
	if t != nil {
		t.close()
		<-t.finished
	}
}
func (c *ocClient) session(ctx context.Context) (*ocTunnel, error) {
	if ref := c.o.DomainResolver; ref != "" {
		call, cancel := ref.apply(ctx)
		defer cancel()
		ctx = context.WithValue(call, dnsBootstrapKey{}, ref.tag())
	} else if c.r.config.Route.DefaultDomainResolver == "" && ctx.Value(dnsBootstrapKey{}) == nil {
		// Authentication and the CSTP connection cannot resolve themselves through this tunnel.
		ctx = context.WithValue(ctx, dnsBootstrapKey{}, "@local")
	}
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.r.ctx.Done():
		return nil, c.r.ctx.Err()
	}
	defer func() { <-c.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t := c.tunnel.Load(); t != nil {
		select {
		case <-t.done:
			select {
			case <-t.finished:
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-c.r.ctx.Done():
				return nil, c.r.ctx.Err()
			}
			c.tunnel.Store(nil)
		default:
			return t, nil
		}
	}
	call, cancel := context.WithTimeout(ctx, c.o.authDuration())
	defer cancel()
	c.authCancel.Store(&cancel)
	defer c.authCancel.Store(nil)
	if c.resetting.Load() > 0 {
		cancel()
	}
	stop := context.AfterFunc(c.r.ctx, cancel)
	defer stop()
	if c.o.System {
		// Protect the initial CSTP socket before installing any pushed routes.
		c.r.retainTUNProtection(0x4c420001)
		defer c.r.releaseTUNProtection()
		if err := c.r.prepareEndpointTUN(); err != nil {
			return nil, err
		}
	}
	raw, headers, e := c.connect(call)
	defer clear(c.connectMaster[:])
	if e != nil {
		return nil, e
	}
	addresses, e := ocAddresses(headers)
	if e != nil {
		raw.Close()
		return nil, e
	}
	if ep := c.o.ocEndpoint; ep != nil && ep.IPv6Disabled {
		addresses = slices.DeleteFunc(addresses, netip.Addr.Is6)
		if len(addresses) == 0 {
			raw.Close()
			return nil, errors.New("OpenConnect server supplied no IPv4 address")
		}
	}
	dns, e := ocParseDNS(headers)
	if e != nil {
		raw.Close()
		return nil, e
	}
	if ep := c.o.ocEndpoint; ep != nil && ep.IPv6Disabled {
		dns.servers = slices.DeleteFunc(dns.servers, netip.Addr.Is6)
	}
	mtu := 1280
	if c.o.MTU > 0 {
		mtu = c.o.MTU
	}
	if value := headers.Get("X-CSTP-MTU"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 576 || n > 65535 {
			raw.Close()
			return nil, errors.New("invalid OpenConnect tunnel MTU")
		}
		mtu = min(mtu, n)
	}
	rekey, method, err := ocRekeyAdvice(headers, "CSTP")
	if err != nil {
		raw.Close()
		return nil, err
	}
	var dtlsRekey time.Duration
	var dtlsMethod string
	if !c.o.DisableDTLS && c.o.dtlsAccepted(headers) {
		dtlsRekey, dtlsMethod, err = ocRekeyAdvice(headers, "DTLS")
		if err != nil {
			raw.Close()
			return nil, err
		}
	}
	// TLS1.3 KeyUpdate is processed by crypto/tls; TLS1.2 ssl keeps this CSTP connection.
	if method == "ssl" && ocTLSVersion(raw) >= 0x0304 {
		rekey = 0
	}
	dpd := ocSeconds(headers.Get("X-CSTP-DPD"), 30)
	if e := c.o.ocEndpoint; e != nil && e.dpd > 0 {
		dpd = e.dpd
	}
	t := newOCTunnel(c.r, raw, "", addresses, mtu, "", dpd, c.configureEndpointIP)
	t.rekeyAfter, t.dtlsRekeyAfter = rekey, dtlsRekey
	t.rekeyMethod = method
	if secured := ocCSTPTLS(raw); method == "ssl" && ocTLSVersion(raw) == 0x0303 && (secured == nil || !secured.secure || !secured.ems) {
		t.rekeyMethod = "new-tunnel"
	}
	t.dtlsRekeyMethod = dtlsMethod
	if c.o.dtlsResume() && t.dtlsRekeyMethod == "ssl" {
		t.dtlsRekeyMethod = "new-tunnel"
	}
	t.dns = dns
	t.dnsEpoch = newMasqueCacheEpoch()
	if c.o.System {
		if e = t.openSystem(c.o, headers, mtu); e != nil {
			t.close()
			t.stack.close()
			return nil, e
		}
	}
	c.tunnel.Store(t)
	c.startDTLS(t, headers)
	t.start()
	if c.o.System || c.o.ocEndpoint != nil {
		select {
		case c.wake <- struct{}{}:
		default:
		}
	}
	return t, nil
}
func (c *ocClient) dial(ctx context.Context, network, address string) (net.Conn, error) {
	t, e := c.session(ctx)
	if e != nil {
		return nil, e
	}
	conn, e := t.stack.dial(ctx, network, address)
	if e != nil {
		return nil, e
	}
	return c.r.own(conn)
}
func ocSeconds(value string, fallback int) time.Duration {
	n, e := strconv.Atoi(value)
	if e != nil || n < 1 || n > 86400 {
		n = fallback
	}
	return time.Duration(n) * time.Second
}

type ocTunnel struct {
	system                     *tunTunnel
	systemWorkers              sync.WaitGroup
	dns                        ocDNSConfig
	dnsEpoch                   string
	r                          *Runtime
	conn                       net.Conn
	reader                     *bufio.Reader
	local                      []netip.Addr
	server                     bool
	stack                      *wgIPStack
	done, finished             chan struct{}
	once                       sync.Once
	writeMu                    sync.Mutex
	writeBuffer                []byte
	lastReceive                atomic.Int64
	dpd                        time.Duration
	rekeyAfter, dtlsRekeyAfter time.Duration
	dtlsRekeyMethod            string
	rekeyMethod                string
	packetID                   atomic.Uint32
	ctx                        context.Context
	cancel                     context.CancelFunc
	dtlsMu                     sync.Mutex
	inputMu                    sync.Mutex
	dtls                       *ocDTLS
	dtlsMTU                    int
	dtlsPath                   atomic.Bool
	dtlsWorkers                sync.WaitGroup
	onClose                    func()
}

func newOCTunnel(r *Runtime, raw net.Conn, inbound string, local []netip.Addr, mtu int, user string, dpd time.Duration, configure ...func(*ipEndpoint)) *ocTunnel {
	t := &ocTunnel{r: r, conn: raw, reader: bufio.NewReaderSize(raw, 4096), local: local, server: inbound != "", done: make(chan struct{}), finished: make(chan struct{}), writeBuffer: make([]byte, 8, mtu+8), dpd: dpd}
	t.ctx, t.cancel = context.WithCancel(r.ctx)
	if secured := ocCSTPTLS(raw); secured != nil {
		secured.enabled.Store(true)
	}
	t.dtlsMTU = 1180
	t.lastReceive.Store(time.Now().UnixNano())
	peer := &ipEndpoint{runtime: r, inbound: inbound, local: local, authUser: user, mtu: mtu, done: t.done, sendIP: func(b []byte) error {
		t.dtlsMu.Lock()
		d := t.dtls
		t.dtlsMu.Unlock()
		if d != nil && d.ready.Load() && t.dtlsPath.Load() && time.Since(time.Unix(0, d.lastReceive.Load())) < 20*time.Second {
			if err := writeIPFragments(b, d.packetMTU(min(mtu, t.dtlsMTU)), t.packetID.Add(1), func(packet []byte) error { return d.write(0, packet) }); err == nil {
				return nil
			}
			d.ready.Store(false)
		}
		return writeIPFragments(b, mtu, t.packetID.Add(1), func(packet []byte) error { return t.write(0, packet) })
	}, ensure: func(context.Context) error {
		select {
		case <-t.done:
			return net.ErrClosed
		default:
			return nil
		}
	}, udpIdleTimeout: 30 * time.Second}
	for _, fn := range configure {
		fn(peer)
	}
	t.stack = newIPStack(peer)
	return t
}
func (t *ocTunnel) close() {
	t.once.Do(func() {
		close(t.done)
		t.cancel()
		t.conn.Close()
		t.dtlsMu.Lock()
		if t.dtls != nil {
			t.dtls.conn.Close()
		}
		t.dtlsMu.Unlock()
		if t.onClose != nil {
			t.onClose()
		}
		if t.system != nil {
			t.system.close()
		}
	})
}
func (t *ocTunnel) write(kind byte, payload []byte) error {
	if len(payload) > 65535 {
		return errors.New("OpenConnect packet exceeds 65535 bytes")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	select {
	case <-t.done:
		return net.ErrClosed
	default:
	}
	b := t.writeBuffer[:8]
	copy(b, "STF\x01")
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6], b[7] = kind, 0
	b = append(b, payload...)
	t.writeBuffer = b[:8]
	t.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	e := writeAll(t.conn, b)
	if e != nil {
		t.conn.Close()
	}
	return e
}
func (t *ocTunnel) start() { t.startSystem(); go t.run() }
func (t *ocTunnel) run() {
	if secured := ocCSTPTLS(t.conn); secured != nil {
		secured.onRekey = func(generation uint64) {
			t.r.logger.Debug("OpenConnect CSTP rekeyed", zap.Uint64("generation", generation))
		}
		if !t.server && t.rekeyMethod == "ssl" {
			secured.scheduleRekey(t.rekeyAfter * 9 / 10)
		}
	}
	defer close(t.finished)
	defer t.stack.close()
	defer t.systemWorkers.Wait()
	defer t.dtlsWorkers.Wait()
	defer t.close()
	stop := context.AfterFunc(t.r.ctx, t.close)
	defer stop()
	keepDone := make(chan struct{})
	go func() {
		defer close(keepDone)
		period := min(t.dpd, 10*time.Second)
		probePeriod := period
		lastProbe := time.Now()
		var renew time.Time
		if t.rekeyAfter > 0 && t.rekeyMethod != "ssl" {
			renew = time.Now().Add(t.rekeyAfter * 9 / 10)
			period = min(period, t.rekeyAfter/10)
		}
		ticker := time.NewTicker(period)
		defer ticker.Stop()
		for {
			select {
			case <-t.done:
				return
			case now := <-ticker.C:
				if !renew.IsZero() && !now.Before(renew) {
					t.close()
					return
				}
				t.stack.expire(now)
				if now.Sub(time.Unix(0, t.lastReceive.Load())) >= t.dpd*3 {
					t.close()
					return
				}
				if now.Sub(lastProbe) < probePeriod {
					continue
				}
				lastProbe = now
				if e := t.write(3, nil); e != nil {
					t.close()
					return
				}
				t.dtlsMu.Lock()
				d := t.dtls
				t.dtlsMu.Unlock()
				if d != nil && d.ready.Load() {
					_ = d.write(3, nil)
				}
			}
		}
	}()
	defer func() { t.close(); <-keepDone }()
	b := make([]byte, 65535)
	for {
		kind, packetBytes, e := ocReadFrame(t.reader, b)
		if e != nil {
			t.r.logger.Debug("OpenConnect CSTP channel closed", zap.Error(e))
			return
		}
		if !t.handlePacket(kind, packetBytes, nil) {
			return
		}
	}
}

func (t *ocTunnel) handlePacket(kind byte, packetBytes []byte, dtls *ocDTLS) bool {
	t.lastReceive.Store(time.Now().UnixNano())
	switch kind {
	case 0:
		packet, e := parseTunPacket(packetBytes)
		if e != nil {
			return true
		}
		address := packet.destination
		if t.server {
			address = packet.source
		}
		if !slices.Contains(t.local, address) {
			return true
		}
		// A client may still receive queued CSTP replies after DTLS becomes ready.
		// Only the server mirrors an incoming fallback path; the client probes DTLS again.
		if t.server || dtls != nil {
			t.dtlsPath.Store(dtls != nil)
		}
		t.inputMu.Lock()
		t.stack.input(packet)
		t.inputMu.Unlock()
	case 3:
		var e error
		if dtls != nil {
			e = dtls.write(4, packetBytes)
		} else {
			e = t.write(4, packetBytes)
		}
		if e != nil {
			return false
		}
	case 4:
		if dtls != nil {
			t.dtlsPath.Store(true)
		}
	case 7:
		if len(packetBytes) != 0 {
			return false
		}
	case 5, 9:
		return false
	default:
		return false // Compression is never advertised or negotiated.
	}
	return true
}
func ocReadFrame(r io.Reader, buffer []byte) (byte, []byte, error) {
	if len(buffer) < 8 {
		return 0, nil, io.ErrShortBuffer
	}
	h := buffer[:8]
	if _, e := io.ReadFull(r, h); e != nil {
		return 0, nil, e
	}
	if string(h[:4]) != "STF\x01" || h[7] != 0 {
		return 0, nil, errors.New("invalid CSTP header")
	}
	n := int(binary.BigEndian.Uint16(h[4:6]))
	kind := h[6]
	if n > len(buffer) {
		return 0, nil, errors.New("CSTP frame exceeds receive capacity")
	}
	b := buffer[:n]
	_, e := io.ReadFull(r, b)
	return kind, b, e
}
func ocDefaultAddresses(configured []string) []netip.Prefix {
	if len(configured) == 0 {
		configured = []string{"10.44.0.2/32", "fd44::2/128"}
	}
	out := make([]netip.Prefix, 0, len(configured))
	for _, v := range configured {
		p, _ := netip.ParsePrefix(v)
		out = append(out, p)
	}
	return out
}
func ocHTTPError(status int) error { return fmt.Errorf("OpenConnect request failed: HTTP%d", status) }
