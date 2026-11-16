package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func xSet(req *http.Request, place, key, value string) {
	switch place {
	case "path":
		req.URL.Path += value
	case "query":
		q := req.URL.Query()
		q.Set(key, value)
		req.URL.RawQuery = q.Encode()
	case "header":
		req.Header.Set(key, value)
	case "cookie":
		req.AddCookie(&http.Cookie{Name: key, Value: value})
	}
}
func xGet(req *http.Request, place, key string) (string, error) {
	var values []string
	switch place {
	case "query":
		values = req.URL.Query()[key]
	case "header":
		values = req.Header.Values(key)
	case "cookie":
		for _, c := range req.Cookies() {
			if c.Name == key {
				values = append(values, c.Value)
			}
		}
	}
	if len(values) > 1 {
		return "", errors.New("duplicate XHTTP field")
	}
	if len(values) == 0 {
		return "", nil
	}
	return values[0], nil
}
func (x XHTTPOptions) paddingRequest(req *http.Request, basePath string) {
	place, key, header, method := x.XPaddingPlacement, x.XPaddingKey, x.XPaddingHeader, x.XPaddingMethod
	if !x.XPaddingObfsMode {
		place, key, header, method = "queryInHeader", "x_padding", "Referer", "repeat-x"
	}
	value := xPadding(x.XPaddingBytes.pick(100, 1000), method)
	if place == "queryInHeader" {
		u := url.URL{Scheme: req.URL.Scheme, Host: req.Host, Path: basePath}
		if u.Host == "" {
			u.Host = req.URL.Host
		}
		u.RawQuery = url.Values{key: {value}}.Encode()
		req.Header.Set(header, u.String())
	} else if place == "header" {
		req.Header.Set(header, value)
	} else {
		xSet(req, place, key, value)
	}
}
func (x XHTTPOptions) paddingResponse(h http.Header) {
	place, key, header, method := x.XPaddingPlacement, x.XPaddingKey, x.XPaddingHeader, x.XPaddingMethod
	if !x.XPaddingObfsMode {
		place, header, method = "header", "X-Padding", "repeat-x"
	}
	value := xPadding(x.XPaddingBytes.pick(100, 1000), method)
	switch place {
	case "cookie":
		h.Add("Set-Cookie", (&http.Cookie{Name: key, Value: value, Path: "/", HttpOnly: true}).String())
	case "queryInHeader":
		h.Set(header, "?"+url.Values{key: {value}}.Encode())
	case "header":
		h.Set(header, value)
	case "query":
		h.Set("X-Padding", value)
	}
}
func (x XHTTPOptions) checkPadding(req *http.Request) bool {
	place, key, header, method := x.XPaddingPlacement, x.XPaddingKey, x.XPaddingHeader, x.XPaddingMethod
	if !x.XPaddingObfsMode {
		place, key, header, method = "queryInHeader", "x_padding", "Referer", "repeat-x"
	}
	var v string
	var e error
	if place == "header" {
		v = req.Header.Get(header)
	} else if place == "queryInHeader" {
		u, err := url.Parse(req.Header.Get(header))
		if err != nil {
			return false
		}
		v = u.Query().Get(key)
	} else {
		v, e = xGet(req, place, key)
	}
	if e != nil || len(v) > 32768 {
		return false
	}
	n := xPaddingLength(v, method)
	a, b, _ := x.XPaddingBytes.bounds(100, 1000)
	if method == "tokenish" {
		a = max(1, a-2)
		b += 2
	}
	return n >= a && n <= b
}
func (x XHTTPOptions) request(ctx context.Context, o Outbound, basePath, session string, seq *uint64, body io.Reader) (*http.Request, error) {
	scheme := "http"
	if o.TLS.Enabled {
		scheme = "https"
	}
	u := url.URL{Scheme: scheme, Host: portAddress(o.Server, o.ServerPort), Path: basePath}
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), body)
	if e != nil {
		return nil, e
	}
	host := o.Transport.Host
	if host == "" {
		host = o.TLS.ServerName
	}
	if host == "" {
		host = o.Server
	}
	req.Host = host
	for key, values := range o.Transport.Headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "")
	if session != "" {
		xSet(req, x.SessionPlacement, x.SessionKey, session)
	}
	if seq != nil {
		if x.SeqPlacement == "path" {
			req.URL.Path += "/"
		}
		xSet(req, x.SeqPlacement, x.SeqKey, strconv.FormatUint(*seq, 10))
	}
	if body != nil {
		req.Method = x.UplinkHTTPMethod
		// An H1 streaming upload owns its connection. Connection: close also
		// prevents servers from draining its body before flushing a response.
		req.Close = seq == nil && o.Transport.xhttpVersion(o.TLS) == 1
		if seq == nil && !x.NoGRPCHeader {
			req.Header.Set("Content-Type", "application/grpc")
		}
	}
	x.paddingRequest(req, basePath)
	return req, nil
}
func (x XHTTPOptions) putData(req *http.Request, data []byte) {
	if x.UplinkDataPlacement == "body" {
		req.Body = io.NopCloser(bytes.NewReader(data))
		req.ContentLength = int64(len(data))
		return
	}
	req.Body = http.NoBody
	req.ContentLength = 0
	encoded := base64.RawURLEncoding.EncodeToString(data)
	size := x.UplinkChunkSize.pick(0, 0)
	if size == 0 {
		size = 4096
		if x.UplinkDataPlacement == "cookie" {
			size = 3072
		}
	}
	for i, offset := 0, 0; offset < len(encoded); i, offset = i+1, offset+size {
		key := x.UplinkDataKey
		separator := "-"
		if x.UplinkDataPlacement == "cookie" {
			separator = "_"
		}
		xSet(req, x.UplinkDataPlacement, key+separator+strconv.Itoa(i), encoded[offset:min(offset+size, len(encoded))])
	}
}
func (x XHTTPOptions) dataHeaders(req *http.Request, limit int) ([]byte, error) {
	var chunks map[int]string = map[int]string{}
	put := func(name, value, prefix string) error {
		if !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			return nil
		}
		n, e := strconv.Atoi(name[len(prefix):])
		if e != nil || n < 0 || n > 1024 {
			return errors.New("invalid XHTTP upload chunk index")
		}
		if _, ok := chunks[n]; ok {
			return errors.New("duplicate XHTTP upload chunk")
		}
		chunks[n] = value
		return nil
	}
	if x.UplinkDataPlacement == "header" {
		for key, values := range req.Header {
			for _, v := range values {
				if e := put(key, v, x.UplinkDataKey+"-"); e != nil {
					return nil, e
				}
			}
		}
	} else {
		for _, c := range req.Cookies() {
			if e := put(c.Name, c.Value, x.UplinkDataKey+"_"); e != nil {
				return nil, e
			}
		}
	}
	var b strings.Builder
	for i := 0; i < len(chunks); i++ {
		v, ok := chunks[i]
		if !ok {
			return nil, errors.New("missing XHTTP upload chunk")
		}
		if b.Len()+len(v) > base64.RawURLEncoding.EncodedLen(limit) {
			return nil, errors.New("XHTTP upload exceeds limit")
		}
		b.WriteString(v)
	}
	return base64.RawURLEncoding.Strict().DecodeString(b.String())
}
func (t Transport) xhttpFields(req *http.Request) (string, *uint64, error) {
	x := t.XHTTPOptions.normalized()
	base := t.xhttpPath()
	if !strings.HasPrefix(req.URL.Path, base) {
		return "", nil, errors.New("XHTTP path mismatch")
	}
	parts := strings.SplitN(strings.TrimPrefix(req.URL.Path, base), "/", 4)
	session, sequence := "", ""
	if x.SessionPlacement == "path" {
		session = parts[0]
		parts = parts[1:]
	} else {
		var e error
		session, e = xGet(req, x.SessionPlacement, x.SessionKey)
		if e != nil {
			return "", nil, e
		}
	}
	if x.SeqPlacement == "path" {
		if len(parts) > 0 {
			sequence = parts[0]
			parts = parts[1:]
		}
	} else {
		var e error
		sequence, e = xGet(req, x.SeqPlacement, x.SeqKey)
		if e != nil {
			return "", nil, e
		}
	}
	if len(parts) > 0 && !(len(parts) == 1 && parts[0] == "") {
		return "", nil, errors.New("extra XHTTP path components")
	}
	if len(session) > 128 {
		return "", nil, errors.New("XHTTP session ID too long")
	}
	for _, c := range []byte(session) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", nil, errors.New("invalid XHTTP session ID")
		}
	}
	if sequence == "" {
		return session, nil, nil
	}
	if session == "" {
		return "", nil, errors.New("XHTTP sequence without session")
	}
	n, e := strconv.ParseUint(sequence, 10, 64)
	if e != nil {
		return "", nil, fmt.Errorf("invalid XHTTP sequence: %w", e)
	}
	return session, &n, nil
}
