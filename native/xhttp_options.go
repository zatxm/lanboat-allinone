package native

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
)

// Numbers and inclusive ranges have the same meaning on the wire.
type xRange string

func (v *xRange) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if e := json.Unmarshal(b, &s); e != nil {
			return e
		}
		*v = xRange(s)
		return nil
	}
	n, e := strconv.ParseInt(string(b), 10, 32)
	if e != nil {
		return errors.New("XHTTP range must be an integer or inclusive range string")
	}
	*v = xRange(strconv.FormatInt(n, 10))
	return nil
}
func (v xRange) bounds(a, b int) (int, int, error) {
	if v == "" {
		return a, b, nil
	}
	s := string(v)
	left, right, rangeValue := strings.Cut(s, "-")
	if !rangeValue {
		right = left
	}
	x, e := strconv.Atoi(left)
	if e != nil {
		return 0, 0, errors.New("invalid XHTTP range")
	}
	y, e := strconv.Atoi(right)
	if e != nil || x < 0 || y < x {
		return 0, 0, errors.New("invalid XHTTP range")
	}
	return x, y, nil
}
func (v xRange) pick(a, b int) int {
	a, b, _ = v.bounds(a, b)
	if a == b {
		return a
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(b-a+1)))
	return a + int(n.Int64())
}

type XHTTPMux struct {
	MaxConcurrency   xRange `json:"max_concurrency,omitempty"`
	MaxConnections   xRange `json:"max_connections,omitempty"`
	CMaxReuseTimes   xRange `json:"c_max_reuse_times,omitempty"`
	HMaxRequestTimes xRange `json:"h_max_request_times,omitempty"`
	HMaxReusableSecs xRange `json:"h_max_reusable_secs,omitempty"`
	HKeepAlivePeriod int    `json:"h_keep_alive_period,omitempty"`
}

func (x XHTTPMux) defaults() bool {
	if x.HKeepAlivePeriod != 0 {
		return false
	}
	for _, v := range []xRange{x.MaxConcurrency, x.MaxConnections, x.CMaxReuseTimes, x.HMaxRequestTimes, x.HMaxReusableSecs} {
		_, b, _ := v.bounds(0, 0)
		if b != 0 {
			return false
		}
	}
	return true
}

type XHTTPOptions struct {
	Mode                 string      `json:"mode,omitempty"`
	NoGRPCHeader         bool        `json:"no_grpc_header,omitempty"`
	NoSSEHeader          bool        `json:"no_sse_header,omitempty"`
	XPaddingObfsMode     bool        `json:"x_padding_obfs_mode,omitempty"`
	XPaddingBytes        xRange      `json:"x_padding_bytes,omitempty"`
	XPaddingKey          string      `json:"x_padding_key,omitempty"`
	XPaddingHeader       string      `json:"x_padding_header,omitempty"`
	XPaddingPlacement    string      `json:"x_padding_placement,omitempty"`
	XPaddingMethod       string      `json:"x_padding_method,omitempty"`
	UplinkHTTPMethod     string      `json:"uplink_http_method,omitempty"`
	SessionPlacement     string      `json:"session_placement,omitempty"`
	SessionKey           string      `json:"session_key,omitempty"`
	SeqPlacement         string      `json:"seq_placement,omitempty"`
	SeqKey               string      `json:"seq_key,omitempty"`
	UplinkDataPlacement  string      `json:"uplink_data_placement,omitempty"`
	UplinkDataKey        string      `json:"uplink_data_key,omitempty"`
	UplinkChunkSize      xRange      `json:"uplink_chunk_size,omitempty"`
	ScMaxEachPostBytes   xRange      `json:"sc_max_each_post_bytes,omitempty"`
	ScMinPostsIntervalMs xRange      `json:"sc_min_posts_interval_ms,omitempty"`
	ScMaxBufferedPosts   int         `json:"sc_max_buffered_posts,omitempty"`
	ScStreamUpServerSecs xRange      `json:"sc_stream_up_server_secs,omitempty"`
	XMux                 XHTTPMux    `json:"xmux,omitempty"`
	DownloadTargetHost   string      `json:"download_target_host,omitempty"`
	DownloadTargetPort   uint16      `json:"download_target_port,omitempty"`
	DownloadServerName   string      `json:"download_server_name,omitempty"`
	DownloadHTTPHost     string      `json:"download_http_host,omitempty"`
	DownloadTLS          *TLSOptions `json:"download_tls,omitempty"`
}

func (x XHTTPOptions) normalized() XHTTPOptions {
	if x.Mode == "" {
		x.Mode = "auto"
	}
	if x.XPaddingKey == "" {
		x.XPaddingKey = "x_padding"
	}
	if x.XPaddingHeader == "" {
		x.XPaddingHeader = "X-Padding"
	}
	if x.XPaddingPlacement == "" {
		x.XPaddingPlacement = "queryInHeader"
	}
	if x.XPaddingMethod == "" {
		x.XPaddingMethod = "repeat-x"
	}
	if x.UplinkHTTPMethod == "" {
		x.UplinkHTTPMethod = "POST"
	}
	if x.SessionPlacement == "" {
		x.SessionPlacement = "path"
	}
	if x.SeqPlacement == "" {
		x.SeqPlacement = "path"
	}
	if x.UplinkDataPlacement == "" || x.UplinkDataPlacement == "auto" {
		x.UplinkDataPlacement = "body"
	}
	if x.SessionKey == "" {
		x.SessionKey = xFieldKey(x.SessionPlacement, "session")
	}
	if x.SeqKey == "" {
		x.SeqKey = xFieldKey(x.SeqPlacement, "seq")
	}
	if x.UplinkDataKey == "" {
		x.UplinkDataKey = xFieldKey(x.UplinkDataPlacement, "data")
	}
	if x.ScMaxBufferedPosts == 0 {
		x.ScMaxBufferedPosts = 30
	}
	return x
}
func xFieldKey(placement, name string) string {
	if placement == "header" {
		return "X-" + strings.ToUpper(name[:1]) + name[1:]
	}
	return "x_" + name
}
func (t Transport) xhttpPath() string { return strings.TrimRight(t.httpPath(), "/") + "/" }
func (t Transport) xhttp3(tls TLSOptions) bool {
	return t.Type == "xhttp" && tls.Enabled && len(tls.ALPN) == 1 && tls.ALPN[0] == "h3"
}
func (t Transport) xhttpVersion(tls TLSOptions) int {
	if t.xhttp3(tls) {
		return 3
	}
	if !tls.Enabled || len(tls.ALPN) == 1 && tls.ALPN[0] == "http/1.1" {
		return 1
	}
	return 2
}
func (x XHTTPOptions) validate(t Transport) error {
	if t.Type != "xhttp" {
		if x != (XHTTPOptions{}) {
			return errors.New("XHTTP options require xhttp transport")
		}
		return nil
	}
	x = x.normalized()
	for name := range t.Headers {
		if strings.EqualFold(name, "Host") {
			return errors.New("XHTTP uses host instead of a Host header")
		}
	}
	if x.Mode != "auto" && x.Mode != "packet-up" && x.Mode != "stream-up" && x.Mode != "stream-one" {
		return errors.New("invalid XHTTP mode")
	}
	for _, p := range []string{x.SessionPlacement, x.SeqPlacement} {
		if p != "path" && p != "header" && p != "query" && p != "cookie" {
			return errors.New("invalid XHTTP session/sequence placement")
		}
	}
	if x.SessionPlacement == "path" && x.SeqPlacement != "path" {
		return errors.New("XHTTP path sessions require path sequences")
	}
	if x.XPaddingPlacement != "header" && x.XPaddingPlacement != "query" && x.XPaddingPlacement != "cookie" && x.XPaddingPlacement != "queryInHeader" {
		return errors.New("invalid XHTTP padding placement")
	}
	if x.XPaddingMethod != "repeat-x" && x.XPaddingMethod != "tokenish" {
		return errors.New("invalid XHTTP padding method")
	}
	if x.UplinkDataPlacement != "body" && x.UplinkDataPlacement != "header" && x.UplinkDataPlacement != "cookie" {
		return errors.New("invalid XHTTP uplink data placement")
	}
	if (x.UplinkDataPlacement != "body" || x.UplinkHTTPMethod == "GET") && x.Mode != "packet-up" {
		return errors.New("XHTTP GET/header/cookie uploads require packet-up mode")
	}
	if x.UplinkHTTPMethod != "POST" && x.UplinkHTTPMethod != "PUT" && x.UplinkHTTPMethod != "PATCH" && x.UplinkHTTPMethod != "GET" && x.UplinkHTTPMethod != "DELETE" {
		return errors.New("invalid XHTTP uplink method")
	}
	for _, v := range []struct {
		value          xRange
		min, max, a, b int
	}{{x.XPaddingBytes, 1, 16384, 100, 1000}, {x.UplinkChunkSize, 0, 16384, 0, 0}, {x.ScMaxEachPostBytes, 1, 8 << 20, 1000000, 1000000}, {x.ScMinPostsIntervalMs, 0, 60000, 30, 30}, {x.XMux.MaxConcurrency, 0, 128, 0, 0}, {x.XMux.MaxConnections, 0, 64, 0, 0}, {x.XMux.CMaxReuseTimes, 0, 1 << 30, 0, 0}, {x.XMux.HMaxRequestTimes, 0, 1 << 30, 0, 0}, {x.XMux.HMaxReusableSecs, 0, 86400 * 365, 0, 0}} {
		a, b, e := v.value.bounds(v.a, v.b)
		if e != nil || a < v.min || b > v.max {
			return fmt.Errorf("XHTTP range %q exceeds allowed limits", v.value)
		}
	}
	if x.ScStreamUpServerSecs != "-1" {
		a, b, e := x.ScStreamUpServerSecs.bounds(20, 80)
		if e != nil || a < 1 || b > 86400 {
			return errors.New("invalid XHTTP stream-up keepalive interval")
		}
	}
	_, a, _ := x.XMux.MaxConcurrency.bounds(0, 0)
	_, b, _ := x.XMux.MaxConnections.bounds(0, 0)
	if a > 0 && b > 0 {
		return errors.New("XHTTP max_concurrency and max_connections are mutually exclusive")
	}
	if x.ScMaxBufferedPosts < 1 || x.ScMaxBufferedPosts > 128 || x.XMux.HKeepAlivePeriod < -1 || x.XMux.HKeepAlivePeriod > 86400 {
		return errors.New("invalid XHTTP buffer/keepalive setting")
	}
	for _, key := range []string{x.XPaddingKey, x.SessionKey, x.SeqKey, x.UplinkDataKey} {
		if len(key) == 0 || len(key) > 128 {
			return errors.New("invalid XHTTP field key")
		}
		for _, c := range []byte(key) {
			if c < 33 || c > 126 || strings.ContainsRune("()<>@,;:\\\"/[]?={} %", rune(c)) {
				return errors.New("invalid XHTTP field key")
			}
		}
	}
	for _, key := range []string{x.XPaddingHeader, x.SessionKey, x.SeqKey, x.UplinkDataKey} {
		if e := transportHeaderName(key, false); e != nil {
			return e
		}
		if strings.EqualFold(key, "Host") {
			return errors.New("XHTTP field cannot replace Host")
		}
	}
	if t.Path != "" {
		u, e := url.ParseRequestURI(t.Path)
		if e != nil || u.RawQuery != "" || strings.Contains(u.Path, "//") {
			return errors.New("XHTTP path must not contain query or empty components")
		}
	}
	if x.DownloadHTTPHost != "" && !validHTTPHost(x.DownloadHTTPHost) {
		return errors.New("invalid XHTTP download Host")
	}
	if strings.ContainsAny(x.DownloadTargetHost, "\r\n\x00 /?#") || strings.ContainsAny(x.DownloadServerName, "\r\n\x00 /?#") {
		return errors.New("invalid XHTTP download endpoint")
	}
	if x.Mode == "stream-one" && (x.DownloadTargetHost != "" || x.DownloadTargetPort != 0 || x.DownloadServerName != "" || x.DownloadHTTPHost != "" || x.DownloadTLS != nil) {
		return errors.New("XHTTP stream-one cannot split upload and download")
	}
	if x.DownloadTLS != nil {
		if _, e := x.DownloadTLS.config(false, x.DownloadTargetHost); e != nil {
			return e
		}
	}
	return nil
}
func xPadding(n int, method string) string {
	if method == "repeat-x" {
		return strings.Repeat("X", n)
	}
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	// Match the encoded Huffman byte length, rather than the ASCII length.
	b := make([]byte, n*2+8)
	rand.Read(b)
	out := b[:0]
	bits := 0
	for _, v := range b {
		c := alphabet[int(v)%len(alphabet)]
		size := int(h3HuffmanBits[c])
		if (bits+size+7)/8 > n {
			break
		}
		out = append(out, c)
		bits += size
	}
	for (bits+7)/8 < n {
		out = append(out, 'X')
		bits += 8
	}
	return string(out)
}
func xPaddingLength(value, method string) int {
	if method == "repeat-x" {
		return len(value)
	}
	bits := 0
	for _, b := range []byte(value) {
		bits += int(h3HuffmanBits[b])
	}
	return (bits + 7) / 8
}
