package native

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.uber.org/zap"
)

type tsPeerListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *tsPeerListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *tsPeerListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *tsPeerListener) Addr() net.Addr { return streamAddr("tailscale-peerapi") }

type tsServiceConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *tsServiceConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

type tsPeerAPI struct {
	c        *tailscaleClient
	port     uint16
	root     *os.Root
	listener *tsPeerListener
	server   *http.Server
	mu       sync.Mutex
	closing  bool
	jobs     sync.WaitGroup
	slots    chan struct{}
	dnsSlots chan struct{}
	active   map[string]bool
}

func (c *tailscaleClient) startPeerAPI() error {
	if e := os.MkdirAll(c.o.TaildropDirectory, 0700); e != nil {
		return e
	}
	root, e := os.OpenRoot(c.o.TaildropDirectory)
	if e != nil {
		return e
	}
	var b [2]byte
	rand.Read(b[:])
	a := &tsPeerAPI{c: c, port: 20000 + binary.BigEndian.Uint16(b[:])%40000, root: root, listener: &tsPeerListener{connections: make(chan net.Conn), done: make(chan struct{})}, slots: make(chan struct{}, 4), active: map[string]bool{}}
	a.dnsSlots = make(chan struct{}, 32)
	a.server = &http.Server{Handler: a, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384, ErrorLog: zap.NewStdLog(c.r.logger.With(zap.String("tag", c.o.Tag)))}
	c.peerAPI = a
	c.spawn(func() { _ = a.server.Serve(a.listener) })
	return nil
}

func (a *tsPeerAPI) close() {
	a.mu.Lock()
	a.closing = true
	a.mu.Unlock()
	a.server.Close()
	a.listener.Close()
	a.jobs.Wait()
	a.root.Close()
}

func (a *tsPeerAPI) service(destination netip.AddrPort) (func(net.Conn), bool) {
	if destination.Port() != a.port {
		return nil, false
	}
	a.c.mu.Lock()
	self := false
	for _, p := range a.c.self.Addresses {
		self = self || p.Addr() == destination.Addr()
	}
	a.c.mu.Unlock()
	if !self {
		return nil, false
	}
	return func(raw net.Conn) {
		conn := &tsServiceConn{Conn: raw, done: make(chan struct{})}
		defer conn.Close()
		select {
		case a.listener.connections <- conn:
		case <-a.listener.done:
			return
		case <-a.c.ctx.Done():
			return
		}
		select {
		case <-conn.done:
		case <-a.c.ctx.Done():
		}
	}, true
}

func (a *tsPeerAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	if a.closing {
		a.mu.Unlock()
		http.Error(w, "service closed", 503)
		return
	}
	a.jobs.Add(1)
	a.mu.Unlock()
	defer a.jobs.Done()
	if r.URL.Path == "/dns-query" {
		a.serveDNS(w, r)
		return
	}
	peer, e := netip.ParseAddrPort(r.RemoteAddr)
	a.c.mu.Lock()
	allowed := e == nil && a.c.canReceiveFileLocked(peer.Addr())
	node := a.c.nodes[a.c.addressOwners[peer.Addr()]]
	a.c.mu.Unlock()
	if !allowed || r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
		http.Error(w, "file transfer not authorized", http.StatusForbidden)
		return
	}
	raw, ok := strings.CutPrefix(r.URL.EscapedPath(), "/v0/put/")
	name, e := url.PathUnescape(raw)
	if !ok || e != nil || !(r.Method == "GET" && name == "") && !tsDropName(name) {
		http.Error(w, "invalid file name", http.StatusBadRequest)
		return
	}
	if r.Method != "GET" && r.Method != "PUT" {
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "expected GET or PUT", 405)
		return
	}
	// Stable identity scopes partial files to the authenticated sender, across reconnects.
	identity := node.StableID
	if identity == "" {
		identity = node.Key
	}
	if identity == "" {
		identity = strconv.FormatInt(node.ID, 10)
	}
	id := sha256.Sum256([]byte(identity))
	dir := ".lanboat-partial-" + hex.EncodeToString(id[:])
	if r.Method == "GET" && name == "" {
		a.listPartials(w, dir)
		return
	}
	key := sha256.Sum256([]byte(name))
	base := filepath.Join(dir, hex.EncodeToString(key[:]))
	a.mu.Lock()
	if a.active[base] {
		a.mu.Unlock()
		http.Error(w, "file transfer in progress", 409)
		return
	}
	a.active[base] = true
	a.mu.Unlock()
	defer func() { a.mu.Lock(); delete(a.active, base); a.mu.Unlock() }()
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		http.Error(w, "too many transfers", 429)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "GET" {
		a.hashPartial(w, base+".part")
		return
	}
	var offset int64
	if h := r.Header.Get("Range"); h != "" {
		value, found := strings.CutPrefix(h, "bytes=")
		value, trailing := strings.CutSuffix(value, "-")
		if !found || !trailing || value == "" || strings.ContainsAny(value, "+- ,") {
			http.Error(w, "invalid Range", 400)
			return
		}
		offset, e = strconv.ParseInt(value, 10, 64)
		if e != nil || offset < 0 || offset > 1<<40 {
			http.Error(w, "invalid Range", 400)
			return
		}
	}
	if r.ContentLength > (1<<40)-offset {
		http.Error(w, "file too large", 413)
		return
	}
	a.mu.Lock()
	e = a.root.Mkdir(dir, 0700)
	if errors.Is(e, os.ErrExist) {
		e = nil
	}
	info, statErr := a.root.Lstat(dir)
	a.mu.Unlock()
	if e != nil || statErr != nil || !info.IsDir() {
		http.Error(w, "cannot open partial directory", 500)
		return
	}
	path := base + ".part"
	if info, err := a.root.Lstat(path); err == nil && !info.Mode().IsRegular() {
		http.Error(w, "invalid partial file", 500)
		return
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		http.Error(w, "cannot inspect partial file", 500)
		return
	}
	f, e := a.root.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if e != nil {
		http.Error(w, "cannot open partial file", 500)
		return
	}
	defer f.Close()
	fi, e := f.Stat()
	if e != nil || !fi.Mode().IsRegular() || offset > fi.Size() {
		http.Error(w, "invalid resume offset", 416)
		return
	}
	if e = f.Truncate(offset); e == nil {
		_, e = f.Seek(offset, io.SeekStart)
	}
	if e != nil {
		http.Error(w, "cannot seek partial file", 500)
		return
	}
	// Metadata contains no path and is never followed when listing or committing files.
	if e = a.root.WriteFile(base+".name", []byte(name), 0600); e != nil {
		http.Error(w, "cannot save partial metadata", 500)
		return
	}
	n, e := io.Copy(f, http.MaxBytesReader(w, r.Body, (1<<40)-offset))
	if e == nil && r.ContentLength >= 0 && n != r.ContentLength {
		e = io.ErrUnexpectedEOF
	}
	syncErr := f.Sync()
	closeErr := f.Close()
	if e == nil {
		e = errors.Join(syncErr, closeErr)
	}
	if e != nil {
		http.Error(w, "file transfer interrupted; retry to resume", 400)
		return
	}
	// A control update can revoke a transfer while its body is streaming.
	a.c.mu.Lock()
	allowed = a.c.canReceiveFileLocked(peer.Addr())
	a.c.mu.Unlock()
	if !allowed {
		http.Error(w, "file transfer not authorized", 403)
		return
	}
	for i := 0; i < 1000; i++ {
		dst := name
		if i > 0 {
			dst = name + " (" + strconv.Itoa(i) + ")"
		}
		e = a.root.Link(path, dst)
		if !errors.Is(e, os.ErrExist) {
			break
		}
	}
	if e != nil {
		http.Error(w, "cannot save file", 500)
		return
	}
	a.mu.Lock()
	a.root.Remove(path)
	a.root.Remove(base + ".name")
	a.root.Remove(dir)
	a.mu.Unlock()
	a.c.r.logger.Info("Tailscale file received", zap.String("tag", a.c.o.Tag), zap.String("name", name))
	io.WriteString(w, "{}\n")
}

func (a *tsPeerAPI) listPartials(w http.ResponseWriter, dir string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	names := []string{}
	info, e := a.root.Lstat(dir)
	if e == nil && info.IsDir() {
		d, err := a.root.Open(dir)
		if err != nil {
			http.Error(w, "cannot list partial files", 500)
			return
		}
		defer d.Close()
		for {
			entries, err := d.ReadDir(64)
			for _, entry := range entries {
				if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".name") {
					continue
				}
				file, err := a.root.Open(filepath.Join(dir, entry.Name()))
				if err != nil {
					continue
				}
				b, err := io.ReadAll(io.LimitReader(file, 221))
				file.Close()
				if err == nil && tsDropName(string(b)) {
					names = append(names, string(b))
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, "cannot list partial files", 500)
				return
			}
		}
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		http.Error(w, "cannot list partial files", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(names)
}

func (a *tsPeerAPI) hashPartial(w http.ResponseWriter, path string) {
	info, e := a.root.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return
	}
	if e != nil || !info.Mode().IsRegular() {
		http.Error(w, "invalid partial file", 500)
		return
	}
	f, e := a.root.Open(path)
	if e != nil {
		http.Error(w, "cannot read partial file", 500)
		return
	}
	defer f.Close()
	b := make([]byte, 64<<10)
	enc := json.NewEncoder(w)
	for {
		n, err := io.ReadFull(f, b)
		if n > 0 {
			sum := sha256.Sum256(b[:n])
			if enc.Encode(struct {
				Checksum  string `json:"checksum"`
				Algorithm string `json:"algo"`
				Size      int    `json:"size"`
			}{fmt.Sprintf("%x", sum), "sha256", n}) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func tsDropName(name string) bool {
	if name == "" || len(name) > 220 || !utf8.ValidString(name) || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".partial") || strings.HasSuffix(name, ".deleted") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return false
	}
	for _, ch := range name {
		if ch < 32 || ch == 127 || strings.ContainsRune(`/\:*?"<>|`, ch) {
			return false
		}
	}
	stem, _, _ := strings.Cut(strings.ToUpper(name), ".")
	return stem != "CON" && stem != "NUL" && stem != "PRN" && stem != "AUX" && !(len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '0' && stem[3] <= '9')
}
