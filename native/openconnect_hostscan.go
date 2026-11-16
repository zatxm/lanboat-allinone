package native

import (
	"bytes"
	"context"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type ocHostScan struct {
	Ticket  string `xml:"host-scan-ticket"`
	Token   string `xml:"host-scan-token"`
	BaseURI string `xml:"host-scan-base-uri"`
	WaitURI string `xml:"host-scan-wait-uri"`
}
type ocCSD struct {
	Ticket string `xml:"ticket,attr"`
	Token  string `xml:"token,attr"`
}
type ocCSDPlatform struct {
	Stub  string `xml:"stuburl,attr"`
	Start string `xml:"starturl,attr"`
	Wait  string `xml:"waiturl,attr"`
}

// The handler chooses a trusted scanner. The core never executes gateway code.
type OpenConnectHostScan struct {
	BaseURL string `json:"base_url"`
	WaitURL string `json:"wait_url"`
	StubURL string `json:"stub_url,omitempty"`
	Ticket  string `json:"ticket"`
	Token   string `json:"token"`
	request func(context.Context, string, string, string, []byte) (OpenConnectHostScanResponse, error)
}

type OpenConnectHostScanResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// Request shares this login's TLS policy/cookies and permits only same-origin
// GET/POST, bounded reports/manifests, and the lifetime of the scanner callback.
func (s *OpenConnectHostScan) Request(ctx context.Context, method, target, contentType string, body []byte) (OpenConnectHostScanResponse, error) {
	if s.request == nil {
		return OpenConnectHostScanResponse{}, errors.New("OpenConnect host scan request is unavailable")
	}
	return s.request(ctx, method, target, contentType, body)
}

func ocHostScanForm(origin, current *url.URL, form ocXML) (*OpenConnectHostScan, error) {
	if form.CSD == nil && form.Auth != nil {
		form.CSD, form.CSDLinux, form.CSDMac, form.CSDWindows = form.Auth.CSD, form.Auth.CSDLinux, form.Auth.CSDMac, form.Auth.CSDWindows
	}
	var ticket, token, base, wait, stub string
	if h := form.HostScan; h != nil {
		ticket, token, base, wait = h.Ticket, h.Token, h.BaseURI, h.WaitURI
	} else if form.CSD != nil {
		p := form.CSDLinux
		if runtime.GOOS == "darwin" {
			p = form.CSDMac
		}
		if runtime.GOOS == "windows" {
			p = form.CSDWindows
		}
		if p == nil {
			return nil, errors.New("OpenConnect host scan has no scanner for this platform")
		}
		ticket, token, base, wait, stub = form.CSD.Ticket, form.CSD.Token, p.Start, p.Wait, p.Stub
	} else {
		return nil, nil
	}
	if len(ticket) == 0 || len(ticket) > 8192 || strings.ContainsAny(ticket, "\x00\r\n") || !ocValidCookie(token) || base == "" || wait == "" {
		return nil, errors.New("invalid OpenConnect host scan challenge")
	}
	resolve := func(value string) (string, error) {
		if len(value) > 8192 {
			return "", errors.New("OpenConnect host scan URL exceeds8KiB")
		}
		u, err := ocSameOrigin(origin, current, value)
		if err != nil {
			return "", err
		}
		return u.String(), nil
	}
	s := &OpenConnectHostScan{Ticket: ticket, Token: token}
	var err error
	if s.BaseURL, err = resolve(base); err != nil {
		return nil, err
	}
	if s.WaitURL, err = resolve(wait); err != nil {
		return nil, err
	}
	if stub != "" {
		if s.StubURL, err = resolve(stub); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (c *ocClient) hostScan(ctx context.Context, current, origin *url.URL, scan *OpenConnectHostScan, transport *http.Transport, jar http.CookieJar, auth *ocNegotiate) error {
	h, explicit := ctx.Value(ocAuthHandlerKey{}).(OpenConnectAuthHandler)
	if !explicit {
		if p := c.r.ocAuthHandler.Load(); p != nil {
			h = *p
		}
	}
	form := OpenConnectAuthForm{Endpoint: c.o.Tag, URL: current.String(), ID: "host-scan", HostScan: scan}
	if h == nil {
		return &OpenConnectAuthRequiredError{Form: form}
	}
	scanCtx, stop := context.WithCancel(ctx)
	defer stop()
	base := *current
	authorization := auth.authorization
	jar.SetCookies(origin, []*http.Cookie{{Name: "sdesktop", Value: scan.Token, Path: "/", Secure: true, HttpOnly: true}})
	scan.request = func(call context.Context, method, target, contentType string, body []byte) (OpenConnectHostScanResponse, error) {
		var result OpenConnectHostScanResponse
		if scanCtx.Err() != nil {
			return result, scanCtx.Err()
		}
		if method != "GET" && method != "POST" || len(body) > 65536 || method == "GET" && len(body) != 0 || len(contentType) > 255 || strings.ContainsAny(contentType, "\r\n\x00") {
			return result, errors.New("invalid OpenConnect host scan request")
		}
		u, err := ocSameOrigin(origin, &base, target)
		if err != nil {
			return result, err
		}
		call, cancel := context.WithTimeout(call, handshakeTimeout)
		defer cancel()
		linked := context.AfterFunc(scanCtx, cancel)
		defer linked()
		req, err := http.NewRequestWithContext(call, method, u.String(), bytes.NewReader(body))
		if err != nil {
			return result, err
		}
		req.Header.Set("User-Agent", "Open AnyConnect VPN Agent Lanboat/1.0")
		req.Header.Set("X-Transcend-Version", "1")
		req.Header.Set("X-Aggregate-Auth", "1")
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		for _, cookie := range jar.Cookies(u) {
			req.AddCookie(cookie)
		}
		response, err := transport.RoundTrip(req)
		if err != nil {
			if call.Err() != nil {
				return result, call.Err()
			}
			return result, errors.New("OpenConnect host scan HTTP request failed")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
		if err != nil {
			return result, err
		}
		if len(data) > 1<<20 {
			return result, errors.New("OpenConnect host scan response exceeds1MiB")
		}
		jar.SetCookies(u, response.Cookies())
		return OpenConnectHostScanResponse{Status: response.StatusCode, Header: response.Header.Clone(), Body: data}, nil
	}
	answer, err := h(scanCtx, form)
	if err != nil {
		return err
	}
	if len(answer) != 0 {
		return errors.New("OpenConnect host scan callback must complete scanner requests without form answers")
	}
	return scanCtx.Err()
}

var ocMetaRefresh = regexp.MustCompile(`(?is)<meta\b[^>]*>`)
var ocHTMLAttribute = regexp.MustCompile(`([a-zA-Z_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)

func ocHostScanRefresh(header http.Header, body []byte) (string, time.Duration, bool, error) {
	value := header.Get("Refresh")
	if value == "" {
		for _, tag := range ocMetaRefresh.FindAll(body, -1) {
			attributes := map[string]string{}
			for _, a := range ocHTMLAttribute.FindAllStringSubmatch(string(tag), -1) {
				v := a[2]
				if v == "" {
					v = a[3]
				}
				if v == "" {
					v = a[4]
				}
				attributes[strings.ToLower(a[1])] = html.UnescapeString(v)
			}
			if strings.EqualFold(attributes["http-equiv"], "refresh") {
				value = attributes["content"]
				break
			}
		}
	}
	if value == "" {
		return "", 0, false, nil
	}
	seconds, target, split := strings.Cut(value, ";")
	n, err := strconv.ParseFloat(strings.TrimSpace(seconds), 64)
	if err != nil || !(n >= 0 && n <= 30) {
		return "", 0, true, errors.New("invalid OpenConnect host scan refresh interval")
	}
	if split {
		key, v, ok := strings.Cut(strings.TrimSpace(target), "=")
		if !ok || !strings.EqualFold(key, "url") {
			return "", 0, true, errors.New("invalid OpenConnect host scan refresh target")
		}
		target = strings.Trim(strings.TrimSpace(v), "\"'")
	}
	return target, time.Duration(n * float64(time.Second)), true, nil
}
