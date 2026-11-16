package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Wire declarations are independent; server-provided forms never execute code.
type ocXML struct {
	XMLName      xml.Name        `xml:"config-auth"`
	Client       string          `xml:"client,attr,omitempty"`
	Type         string          `xml:"type,attr"`
	Version      string          `xml:"version,attr,omitempty"`
	Aggregate    string          `xml:"aggregate-auth-version,attr,omitempty"`
	Agent        *ocAgentVersion `xml:"version,omitempty"`
	Device       string          `xml:"device-id,omitempty"`
	Group        string          `xml:"group-select,omitempty"`
	Token        string          `xml:"session-token,omitempty"`
	Auth         *ocAuth         `xml:"auth,omitempty"`
	Opaque       *ocOpaque       `xml:"opaque,omitempty"`
	Capabilities *ocCapabilities `xml:"capabilities,omitempty"`
	HostScan     *ocHostScan     `xml:"host-scan,omitempty"`
	CSD          *ocCSD          `xml:"csd,omitempty"`
	CSDLinux     *ocCSDPlatform  `xml:"csdLinux,omitempty"`
	CSDMac       *ocCSDPlatform  `xml:"csdMac,omitempty"`
	CSDWindows   *ocCSDPlatform  `xml:"csdWindows,omitempty"`
}
type ocAgentVersion struct {
	Who   string `xml:"who,attr"`
	Value string `xml:",chardata"`
}
type ocCapabilities struct {
	Methods []string `xml:"auth-method"`
}
type ocOpaque struct {
	Attrs []xml.Attr `xml:",any,attr"`
	Data  string     `xml:",innerxml"`
}
type ocAuth struct {
	Title          string         `xml:"title,omitempty"`
	Message        string         `xml:"message,omitempty"`
	Error          string         `xml:"error,omitempty"`
	ID             string         `xml:"id,attr,omitempty"`
	Form           *ocForm        `xml:"form,omitempty"`
	Fields         []ocField      `xml:",any"`
	CSD            *ocCSD         `xml:"csd,omitempty"`
	CSDLinux       *ocCSDPlatform `xml:"csdLinux,omitempty"`
	CSDMac         *ocCSDPlatform `xml:"csdMac,omitempty"`
	CSDWindows     *ocCSDPlatform `xml:"csdWindows,omitempty"`
	SSOLogin       string         `xml:"sso-v2-login,omitempty"`
	SSOFinal       string         `xml:"sso-v2-login-final,omitempty"`
	SSOTokenCookie string         `xml:"sso-v2-token-cookie-name,omitempty"`
	SSOErrorCookie string         `xml:"sso-v2-error-cookie-name,omitempty"`
	SSOBrowser     string         `xml:"sso-v2-browser-mode,omitempty"`
}
type ocField struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}
type ocForm struct {
	Action  string     `xml:"action,attr,omitempty"`
	Method  string     `xml:"method,attr,omitempty"`
	Inputs  []ocInput  `xml:"input"`
	Selects []ocSelect `xml:"select"`
}
type ocInput struct {
	Type  string `xml:"type,attr"`
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr,omitempty"`
	Label string `xml:"label,attr,omitempty"`
}
type ocSelect struct {
	Name    string     `xml:"name,attr"`
	Label   string     `xml:"label,attr,omitempty"`
	Options []ocOption `xml:"option"`
}
type ocOption struct {
	Value    string `xml:"value,attr"`
	Selected string `xml:"selected,attr,omitempty"`
	Text     string `xml:",chardata"`
}

func (o *ocOption) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v struct {
		Value    *string `xml:"value,attr"`
		Selected string  `xml:"selected,attr"`
		Text     string  `xml:",chardata"`
	}
	if err := d.DecodeElement(&v, &start); err != nil {
		return err
	}
	o.Text, o.Selected = v.Text, v.Selected
	if v.Value != nil {
		o.Value = *v.Value
	} else {
		o.Value = strings.TrimSpace(v.Text)
	}
	return nil
}

func ocMarshal(value ocXML) ([]byte, error) {
	b, e := xml.Marshal(value)
	if e != nil {
		return nil, e
	}
	b = append([]byte(xml.Header), b...)
	return b, nil
}
func ocBody(r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, 65537))
	if e == nil && len(b) > 65536 {
		e = errors.New("OpenConnect authentication body exceeds 64KiB")
	}
	return b, e
}
func ocResponse(reader *bufio.Reader, request *http.Request) (*http.Response, *bufio.Reader, error) {
	h, e := readHTTPHeader(reader)
	if e != nil {
		return nil, nil, e
	}
	next := bufio.NewReader(io.MultiReader(bytes.NewReader(h), reader))
	response, e := http.ReadResponse(next, request)
	return response, next, e
}
func (c *ocClient) tls(ctx context.Context) (net.Conn, error) {
	raw, e := c.endpointTransport(ctx, c.o, "tcp")
	if e != nil {
		return nil, e
	}
	cfg, e := c.r.outboundTLS(ctx, c.o)
	if e != nil {
		raw.Close()
		return nil, e
	}
	cfg = cloneTLSConfig(cfg)
	if e := c.o.ocEndpoint; e != nil {
		if err := e.configureTLS(cfg); err != nil {
			raw.Close()
			return nil, err
		}
	}
	cfg.NextProtos = []string{"http/1.1"}
	cfg.DynamicRecordSizingDisabled = true
	if cfg.MinVersion < 0x0303 {
		cfg.MinVersion = 0x0303
	}
	secured, e := handshakeOCTLS(ctx, raw, cfg, c.o.TLS, false)
	if e != nil {
		raw.Close()
		return nil, e
	}
	if p := secured.ConnectionState().NegotiatedProtocol; p != "" && p != "http/1.1" {
		raw.Close()
		return nil, errors.New("OpenConnect requires HTTP/1.1")
	}
	return secured, nil
}
func (c *ocClient) login(ctx context.Context) error {
	origin := c.endpointOrigin()
	current := *origin
	jar, _ := cookiejar.New(nil)
	var peer atomic.Pointer[tls.ConnectionState]
	negotiate := c.negotiate(ctx)
	defer negotiate.close()
	transport := &http.Transport{DialTLSContext: func(call context.Context, _, _ string) (net.Conn, error) {
		conn, err := c.tls(call)
		if err == nil {
			if secured, ok := conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
				state := secured.ConnectionState()
				peer.Store(&state)
			}
		}
		return conn, err
	}, MaxConnsPerHost: 1, MaxIdleConns: 1, IdleConnTimeout: c.o.authDuration(), MaxResponseHeaderBytes: 65536, DisableCompression: true}
	if e := c.o.ocEndpoint; e != nil {
		transport.DisableKeepAlives = e.HTTPKeepaliveDisabled
	}
	defer transport.CloseIdleConnections()
	message := ocXML{Client: "vpn", Type: "init", Aggregate: "2", Agent: &ocAgentVersion{Who: "vpn", Value: Version}, Device: "linux"}
	c.endpointIdentity(&message)
	c.strap = nil
	if !c.o.DisableExternalAuth {
		strap, err := newOCStrap()
		if err != nil {
			return err
		}
		c.strap = strap
		defer func() {
			strap.dh = nil
			if c.cookie == "" {
				c.strap = nil
			}
		}()
		message.Capabilities = &ocCapabilities{Methods: []string{"single-sign-on-v2", "single-sign-on-external-browser"}}
	}
	sent := map[string]bool{}
	if c.o.Group != "" {
		message.Group = c.o.Group
	}
	initial := message
	method, completedScan := "POST", ""
	if e := c.o.ocEndpoint; e != nil && e.XMLPostDisabled {
		method = "GET"
	}
	scanning := false
	for range 32 {
		if err := ctx.Err(); err != nil {
			return err
		}
		body, e := ocMarshal(message)
		if e != nil {
			return e
		}
		if method == "GET" {
			body = nil
		}
		if len(body) > 65536 {
			return errors.New("OpenConnect authentication request exceeds64KiB")
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, handshakeTimeout)
		req, e := http.NewRequestWithContext(requestCtx, method, current.String(), bytes.NewReader(body))
		if e != nil {
			requestCancel()
			return e
		}
		if method == "POST" {
			req.Header.Set("Content-Type", "application/xml; charset=utf-8")
		}
		req.Header.Set("User-Agent", c.userAgent())
		req.Header.Set("X-Transcend-Version", "1")
		req.Header.Set("X-Aggregate-Auth", "1")
		if negotiate.handler != nil {
			req.Header.Set("X-Support-HTTP-Auth", "true")
			if negotiate.authorization != "" {
				req.Header.Set("Authorization", negotiate.authorization)
			}
		}
		if c.strap != nil {
			c.strap.headers(req.Header)
		}
		req.Header.Set("X-Pad", strings.Repeat("0", 128-len(body)%128))
		for _, cookie := range jar.Cookies(&current) {
			req.AddCookie(cookie)
		}
		response, e := transport.RoundTrip(req)
		var data []byte
		if e == nil {
			data, e = ocBody(response.Body)
			response.Body.Close()
		}
		requestCancel()
		if e != nil {
			return e
		}
		jar.SetCookies(&current, response.Cookies())
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			next, e := ocSameOrigin(origin, &current, response.Header.Get("Location"))
			if e != nil {
				return e
			}
			current = *next
			continue
		}
		if response.StatusCode == 401 && negotiate.handler != nil {
			err := negotiate.challenge(ctx, c, current.String(), response.Header, peer.Load())
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if !strings.EqualFold(response.Header.Get("X-Support-HTTP-Auth"), "fallback") {
					return err
				}
				negotiate.close()
				negotiate.handler = nil
				message, current, method = initial, *origin, "POST"
			}
			continue
		}
		if response.StatusCode != 200 {
			return ocHTTPError(response.StatusCode)
		}
		if err := negotiate.finish(ctx, response.Header, peer.Load()); err != nil {
			return err
		}
		if scanning && method == "GET" {
			target, delay, refresh, err := ocHostScanRefresh(response.Header, data)
			if err != nil {
				return err
			}
			if refresh {
				u, err := ocSameOrigin(origin, &current, target)
				if err != nil {
					return err
				}
				timer := time.NewTimer(max(delay, 100*time.Millisecond))
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
				current = *u
				continue
			}
		}
		var form ocXML
		if e = xml.Unmarshal(data, &form); e != nil {
			return errors.New("invalid OpenConnect authentication XML")
		}
		scan, err := ocHostScanForm(origin, &current, form)
		if err != nil {
			return err
		}
		if scan != nil {
			wait, _ := url.Parse(scan.WaitURL)
			key := scan.Ticket + "\x00" + scan.Token
			if completedScan != key {
				if err := c.hostScan(ctx, &current, origin, scan, transport, jar, negotiate); err != nil {
					return err
				}
				completedScan = key
			}
			current, method, scanning = *wait, "GET", true
			continue
		}
		if form.Type == "complete" || form.Type == "auth-complete" {
			for _, cookie := range jar.Cookies(origin) {
				if cookie.Name == "webvpn" && ocValidCookie(cookie.Value) {
					c.cookie = cookie.Value
				}
			}
			if c.cookie == "" && ocValidCookie(form.Token) {
				c.cookie = form.Token
			}
			if c.cookie == "" {
				return errors.New("OpenConnect authentication returned no session cookie")
			}
			return nil
		}
		if form.Auth == nil || form.Auth.Form == nil {
			return errors.New("OpenConnect server requires an unsupported authentication flow")
		}
		if form.Type != "auth-request" {
			return errors.New("invalid OpenConnect authentication message type")
		}
		if e := c.o.ocEndpoint; e != nil && e.PasswordAuthenticationDisabled {
			return errors.New("OpenConnect password authentication is disabled")
		}
		f := form.Auth.Form
		if f.Method != "" && !strings.EqualFold(f.Method, "post") {
			return errors.New("unsupported OpenConnect form method")
		}
		next, e := ocSameOrigin(origin, &current, f.Action)
		if e != nil {
			return e
		}
		current = *next
		message, e = c.answer(ctx, &current, form.Auth, sent)
		if e != nil {
			return e
		}
		message.Opaque = form.Opaque
		method = "POST"
	}
	return errors.New("too many OpenConnect authentication exchanges")
}
func ocSameOrigin(origin, current *url.URL, action string) (*url.URL, error) {
	u, e := url.Parse(action)
	if e != nil {
		return nil, errors.New("invalid OpenConnect authentication action")
	}
	u = current.ResolveReference(u)
	port := func(v *url.URL) string {
		if v.Port() == "" {
			return "443"
		}
		return v.Port()
	}
	if u.Scheme != origin.Scheme || !strings.EqualFold(u.Hostname(), origin.Hostname()) || port(u) != port(origin) || u.User != nil || u.Fragment != "" {
		return nil, errors.New("OpenConnect authentication action changed origin")
	}
	return u, nil
}
func ocValidCookie(value string) bool {
	if len(value) == 0 || len(value) > 8192 {
		return false
	}
	for _, b := range []byte(value) {
		if b <= 32 || b >= 127 || strings.ContainsRune("\";,\\", rune(b)) {
			return false
		}
	}
	return true
}
func (c *ocClient) connect(ctx context.Context) (net.Conn, http.Header, error) {
	for range 2 {
		if c.cookie == "" {
			if e := c.login(ctx); e != nil {
				return nil, nil, e
			}
		}
		requestCtx, requestCancel := context.WithTimeout(ctx, handshakeTimeout)
		raw, e := c.tls(requestCtx)
		if e != nil {
			requestCancel()
			return nil, nil, e
		}
		stop := context.AfterFunc(requestCtx, func() { raw.Close() })
		deadline, _ := requestCtx.Deadline()
		raw.SetDeadline(deadline)
		mtu := c.o.MTU
		if mtu == 0 {
			mtu = 1280
		}
		h := http.Header{"Host": {portAddress(c.o.Server, c.o.ServerPort)}, "User-Agent": {c.userAgent()}, "Cookie": {"webvpn=" + c.cookie}, "X-CSTP-Version": {"1"}, "X-CSTP-Address-Type": {"IPv4,IPv6"}, "X-CSTP-MTU": {fmt.Sprint(mtu)}, "X-CSTP-Base-MTU": {fmt.Sprint(min(65535, mtu+80))}}
		h["X-CSTP-Full-IPv6-Capability"] = []string{"true"}
		if e := c.o.ocEndpoint; e != nil {
			if e.IPv6Disabled {
				h["X-CSTP-Address-Type"] = []string{"IPv4"}
				delete(h, "X-CSTP-Full-IPv6-Capability")
			}
			if e.BaseMTU != 0 {
				h["X-CSTP-Base-MTU"] = []string{strconv.Itoa(e.BaseMTU)}
			}
			if e.LocalHostname != "" {
				h["X-CSTP-Hostname"] = []string{e.LocalHostname}
			}
		}
		if c.strap != nil {
			e = c.strap.verify(raw, h)
			if e != nil {
				stop()
				requestCancel()
				raw.Close()
				return nil, nil, e
			}
		}
		if !c.o.DisableDTLS {
			// Reference peers match these prefixes case-sensitively; Header.Set changes DTLS to Dtls.
			c.o.dtlsOffer(h)
			if c.o.dtlsResume() {
				rand.Read(c.connectMaster[:])
				h["X-DTLS-Master-Secret"] = []string{hex.EncodeToString(c.connectMaster[:])}
			}
		}
		e = writeAll(raw, []byte("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"))
		if e == nil {
			e = h.Write(raw)
		}
		if e == nil {
			e = writeAll(raw, []byte("\r\n"))
		}
		var response *http.Response
		var reader *bufio.Reader
		if e == nil {
			response, reader, e = ocResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"})
		}
		if e == nil && response.StatusCode != 200 {
			e = ocHTTPError(response.StatusCode)
		}
		stop()
		requestCancel()
		if e != nil {
			raw.Close()
			if response != nil && response.StatusCode == 401 {
				c.cookie = ""
				continue
			}
			return nil, nil, e
		}
		raw.SetDeadline(time.Time{})
		return &bufferedConn{Conn: raw, reader: reader}, response.Header, nil
	}
	return nil, nil, errors.New("OpenConnect session authentication failed")
}
func ocAddresses(h http.Header) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, key := range []string{"X-CSTP-Address", "X-CSTP-Address-IP6"} {
		for _, value := range h.Values(key) {
			var a netip.Addr
			var e error
			if strings.Contains(value, "/") {
				var p netip.Prefix
				p, e = netip.ParsePrefix(value)
				a = p.Addr()
			} else {
				a, e = netip.ParseAddr(value)
			}
			if e != nil || !a.IsGlobalUnicast() || a.Is4In6() || a.Zone() != "" {
				return nil, errors.New("invalid OpenConnect assigned IP address")
			}
			for _, old := range out {
				if old.Is4() == a.Is4() {
					return nil, errors.New("duplicate OpenConnect address family")
				}
			}
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("OpenConnect server supplied no assigned IP address")
	}
	return out, nil
}
