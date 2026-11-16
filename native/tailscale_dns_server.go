package native

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// An approved exit may answer DNS only for authenticated peers permitted by IP ACLs.
// Taildrop grants do not confer DNS or routed-network access.
func (c *tailscaleClient) canServeDNSLocked(p tunPacket) bool {
	n, ok := c.nodes[c.addressOwners[p.source]]
	now := time.Now()
	return c.o.AdvertiseExitNode && ok && !n.restricted() && !n.Expired && (n.KeyExpiry.IsZero() || now.Before(n.KeyExpiry)) && !c.self.restricted() && !c.self.Expired && (c.self.KeyExpiry.IsZero() || now.Before(c.self.KeyExpiry)) && slices.ContainsFunc(c.self.AllowedIPs, func(p netip.Prefix) bool { return p.Bits() == 0 }) && slices.ContainsFunc(c.filter, func(f tsFilter) bool { return f.allows(p) })
}

func (a *tsPeerAPI) serveDNS(w http.ResponseWriter, r *http.Request) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	var dest netip.AddrPort
	if ok {
		dest, _ = netip.ParseAddrPort(local.String())
	}
	p := tunPacket{source: peer.Addr(), destination: dest.Addr(), protocol: 6, data: binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, peer.Port()), dest.Port())}
	a.c.mu.Lock()
	allowed := err == nil && dest.IsValid() && dest.Port() == a.port && slices.ContainsFunc(a.c.self.Addresses, func(p netip.Prefix) bool { return p.Addr() == dest.Addr() }) && a.c.canServeDNSLocked(p)
	a.c.mu.Unlock()
	if !allowed || r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		http.Error(w, "DNS not authorized", http.StatusForbidden)
		return
	}
	select {
	case a.dnsSlots <- struct{}{}:
		defer func() { <-a.dnsSlots }()
	default:
		http.Error(w, "too many DNS queries", 429)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(a.c.ctx, cancel)
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	ctl := http.NewResponseController(w)
	_ = ctl.SetReadDeadline(deadline)
	_ = ctl.SetWriteDeadline(deadline)
	defer ctl.SetReadDeadline(time.Time{})
	defer ctl.SetWriteDeadline(time.Time{})
	var q []byte
	switch r.Method {
	case "GET":
		if len(r.URL.RawQuery) > 90000 || r.ContentLength > 0 {
			http.Error(w, "invalid DNS query", 400)
			return
		}
		q, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
	case "POST":
		if !dnsMediaType(r.Header.Get("Content-Type")) {
			http.Error(w, "expected DNS message", 415)
			return
		}
		q, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 65535))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "expected GET or POST", 405)
		return
	}
	if err != nil || len(q) < 12 || len(q) > 65535 {
		http.Error(w, "invalid DNS query", 400)
		return
	}
	host, end, _, err := dnsQuestion(q)
	if err != nil {
		http.Error(w, "invalid DNS question", 400)
		return
	}
	var reply []byte
	if s := a.c.dns.Load(); s != nil && slices.ContainsFunc(s.config.ExitNodeFilteredSet, func(v string) bool {
		v = strings.ToLower(v)
		if strings.HasPrefix(v, ".") {
			return strings.HasSuffix(host, strings.TrimSuffix(v, "."))
		}
		return host == canonicalDomain(v)
	}) {
		reply = dnsResponse(q, end, nil, 0, 3)
	} else {
		reply, err = a.c.r.ExchangeDNS(ctx, q, a.c.o.Tag)
		if err != nil {
			reply = dnsResponse(q, end, nil, 0, 2)
		}
	}
	// Recheck after potentially blocking resolution: a live connection is no grant.
	a.c.mu.Lock()
	allowed = a.c.canServeDNSLocked(p)
	a.c.mu.Unlock()
	if !allowed {
		http.Error(w, "DNS not authorized", 403)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(reply)
}
