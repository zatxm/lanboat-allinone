package native

import (
	"context"
	"encoding/binary"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
)

func chromiumH2Settings() []byte {
	var out []byte
	for _, item := range [][2]uint32{{1, 65536}, {2, 0}, {4, naiveH2StreamWindow}, {6, 262144}} {
		out = binary.BigEndian.AppendUint16(out, uint16(item[0]))
		out = binary.BigEndian.AppendUint32(out, item[1])
	}
	return out
}

func chromiumPreamble(o Outbound) [][2]string {
	host := o.Server
	if o.TLS.ServerName != "" {
		host = o.TLS.ServerName
	}
	authority := net.JoinHostPort(host, "443")
	if o.ServerPort != 443 {
		authority = portAddress(host, o.ServerPort)
	} else {
		authority = host
		if strings.Contains(host, ":") {
			authority = "[" + strings.Trim(host, "[]") + "]"
		}
	}
	platform, agent := "Linux", "X11; Linux x86_64"
	switch runtime.GOOS {
	case "darwin":
		platform, agent = "macOS", "Macintosh; Intel Mac OS X 10_15_7"
	case "windows":
		platform, agent = "Windows", "Windows NT 10.0; Win64; x64"
	}
	return [][2]string{
		{":method", "GET"}, {":authority", authority}, {":scheme", "https"}, {":path", "/"},
		{"sec-ch-ua", `"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"`},
		{"sec-ch-ua-mobile", "?0"}, {"sec-ch-ua-platform", `"` + platform + `"`}, {"upgrade-insecure-requests", "1"},
		{"user-agent", "Mozilla/5.0 (" + agent + ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"},
		{"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"},
		{"sec-fetch-site", "none"}, {"sec-fetch-mode", "navigate"}, {"sec-fetch-user", "?1"}, {"sec-fetch-dest", "document"},
		{"accept-encoding", "gzip, deflate, br, zstd"}, {"accept-language", "en-US,en;q=0.9"}, {"priority", "u=0, i"},
	}
}

func chromiumH2Preamble(block []byte) []byte {
	priority := binary.BigEndian.AppendUint32(nil, 0x80000000)
	priority = append(priority, 255)
	return masqueHeaderFrames(1, 0x21, append(priority, block...))
}

func (m *naiveH2Session) awaitPreamble(ctx context.Context) error {
	s := m.preamble
	for {
		m.mu.Lock()
		ready, err := s.ready, s.err
		m.mu.Unlock()
		if ready {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.done:
			return net.ErrClosed
		case <-s.readWake:
		}
	}
}

func (c *trustClient) chromiumConnectHeaders(authority string) [][2]string {
	fields := [][2]string{{":method", "CONNECT"}, {":authority", authority}, {"padding", naiveHeader(false)}, {"padding-type-request", "1, 0"}, {"proxy-authorization", c.authorization()}}
	var names []string
	for name := range c.outbound.ExtraHeaders {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	for _, name := range names {
		separator := ", "
		if strings.EqualFold(name, "Cookie") {
			separator = "; "
		}
		fields = append(fields, [2]string{strings.ToLower(name), strings.Join(c.outbound.ExtraHeaders[name], separator)})
	}
	return fields
}

// Large advertised flow windows do not preallocate buffers. Memory pressure
// pauses socket reads until an application consumes queued payload.
type naiveBufferBudget struct {
	mu   sync.Mutex
	used int
	wake chan struct{}
}

const naiveBufferedLimit = 32 << 20

func (b *naiveBufferBudget) reserve(n int, session, stream <-chan struct{}) error {
	if b == nil || n == 0 {
		return nil
	}
	for {
		b.mu.Lock()
		if b.used+n <= naiveBufferedLimit {
			b.used += n
			b.mu.Unlock()
			return nil
		}
		if b.wake == nil {
			b.wake = make(chan struct{})
		}
		wake := b.wake
		b.mu.Unlock()
		select {
		case <-session:
			return net.ErrClosed
		case <-stream:
			return net.ErrClosed
		case <-wake:
		}
	}
}

func (b *naiveBufferBudget) release(n int) {
	if b == nil || n == 0 {
		return
	}
	b.mu.Lock()
	b.used -= n
	if b.wake != nil {
		close(b.wake)
		b.wake = nil
	}
	b.mu.Unlock()
}
