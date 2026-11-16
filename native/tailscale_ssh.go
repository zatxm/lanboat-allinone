package native

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

type TailscaleSSHOptions struct {
	Enabled           bool `json:"enabled,omitempty"`
	DisablePTY        bool `json:"disable_pty,omitempty"`
	DisableSFTP       bool `json:"disable_sftp,omitempty"`
	DisableForwarding bool `json:"disable_forwarding,omitempty"`
}

func (o *TailscaleSSHOptions) UnmarshalJSON(b []byte) error {
	if string(b) == "true" || string(b) == "false" {
		*o = TailscaleSSHOptions{Enabled: string(b) == "true"}
		return nil
	}
	type options TailscaleSSHOptions
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	return d.Decode((*options)(o))
}

type tsSSHPolicy struct{ Rules []*tsSSHRule }
type tsSSHRule struct {
	RuleExpires *time.Time
	Principals  []*tsSSHPrincipal
	SSHUsers    map[string]string
	Action      *tsSSHAction
	AcceptEnv   []string
}
type tsSSHPrincipal struct {
	Node, NodeIP, UserLogin string
	Any                     bool
}
type tsSSHAction struct {
	Message                                                                   string
	Reject, Accept                                                            bool
	SessionDuration                                                           time.Duration
	AllowAgentForwarding, AllowLocalPortForwarding, AllowRemotePortForwarding bool
	HoldAndDelegate                                                           string
	Recorders                                                                 []netip.AddrPort
	OnRecordingFailure                                                        *struct{ RejectSessionWithMessage, TerminateSessionWithMessage, NotifyURL string }
}
type tsSSHGrant struct {
	local  string
	rule   *tsSSHRule
	action tsSSHAction
}

func (c *tailscaleClient) sshGrantLocked(source netip.Addr, requested string, identityAllowed bool) (tsSSHGrant, bool) {
	n, exists := c.nodes[c.addressOwners[source]]
	if !exists || n.restricted() || n.Expired || !n.KeyExpiry.IsZero() && time.Now().After(n.KeyExpiry) || c.self.Expired || c.self.lockInvalid || !c.self.KeyExpiry.IsZero() && time.Now().After(c.self.KeyExpiry) || c.sshPolicy == nil || !tsSSHName(requested) {
		return tsSSHGrant{}, false
	}
	for _, rule := range c.sshPolicy.Rules {
		if rule == nil || rule.RuleExpires != nil && !time.Now().Before(*rule.RuleExpires) {
			continue
		}
		match := false
		for _, p := range rule.Principals {
			if p != nil && (p.Any || p.Node != "" && p.Node == n.StableID || p.NodeIP != "" && p.NodeIP == source.String() || p.UserLogin != "" && p.UserLogin == c.userLogins[n.User]) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		local, ok := rule.SSHUsers[requested]
		if !ok {
			local = rule.SSHUsers["*"]
		}
		if local == "" && !(rule.Action != nil && rule.Action.Reject && len(rule.SSHUsers) == 0) {
			continue
		}
		if local == "=" {
			// The controller uses identity mapping for autogroup:nonroot.
			if !identityAllowed {
				continue
			}
			local = requested
		}
		if rule.Action == nil || rule.Action.Reject || !tsSSHName(local) {
			return tsSSHGrant{}, false
		}
		a := *rule.Action
		if a.SessionDuration < 0 || !a.Accept && a.HoldAndDelegate == "" {
			return tsSSHGrant{}, false
		}
		return tsSSHGrant{local, rule, a}, true
	}
	return tsSSHGrant{}, false
}
func tsSSHName(s string) bool {
	return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n\t /:\\")
}

type tsSSHServer struct {
	c         *tailscaleClient
	key       ed25519.PrivateKey
	mu        sync.Mutex
	active    map[*tsSSHConnection]bool
	worker    string
	processes chan struct{}
}
type tsSSHConnection struct {
	id                  string
	server              *tsSSHServer
	source, destination netip.Addr
	nodeKey, requested  string
	identityAllowed     bool
	grant               tsSSHGrant
	user                *user.User
	ctx                 context.Context
	cancel              context.CancelFunc
	session             *sshSession
	mu                  sync.Mutex
	listeners           map[string]net.Listener
	forwards            sync.WaitGroup
}

func (c *tailscaleClient) startSSH() error {
	if !c.o.SSHServer.Enabled {
		return nil
	}
	if !tsSSHPlatform() {
		return errors.New("Tailscale SSH server requires Linux or macOS")
	}
	h := hmac.New(sha256.New, c.state.Machine)
	h.Write([]byte("lanboat/tailscale/ssh-host-ed25519/v1"))
	worker, e := os.Executable()
	if e != nil {
		return e
	}
	c.ssh = &tsSSHServer{c: c, key: ed25519.NewKeyFromSeed(h.Sum(nil)), active: map[*tsSSHConnection]bool{}, worker: worker, processes: make(chan struct{}, 8)}
	return nil
}
func (s *tsSSHServer) publicKey() string {
	b, _ := sshPubKey(s.key.Public())
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b)
}
func (s *tsSSHServer) close() {
	s.mu.Lock()
	for conn := range s.active {
		conn.cancel()
		conn.session.close(net.ErrClosed)
	}
	s.mu.Unlock()
}
func (c *tailscaleClient) tcpService(dst netip.AddrPort) (func(net.Conn), bool) {
	if c.ssh != nil && dst.Port() == 22 {
		c.mu.Lock()
		self := false
		for _, a := range c.self.Addresses {
			self = self || a.Addr() == dst.Addr()
		}
		c.mu.Unlock()
		if self {
			return c.ssh.serve, true
		}
	}
	if c.peerAPI != nil {
		return c.peerAPI.service(dst)
	}
	return nil, false
}
func (s *tsSSHServer) serve(raw net.Conn) {
	remote, e := netip.ParseAddrPort(raw.RemoteAddr().String())
	local, le := netip.ParseAddrPort(raw.LocalAddr().String())
	if e != nil || le != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.c.ctx)
	defer cancel()
	var id [16]byte
	rand.Read(id[:])
	conn := &tsSSHConnection{id: hex.EncodeToString(id[:]), server: s, source: remote.Addr(), destination: local.Addr(), ctx: ctx, cancel: cancel, listeners: map[string]net.Listener{}}
	w := &sshWire{Conn: raw, reader: bufio.NewReaderSize(raw, 4096)}
	conn.session = newSSHSession(w)
	s.mu.Lock()
	if len(s.active) >= 32 {
		s.mu.Unlock()
		return
	}
	s.active[conn] = true
	s.mu.Unlock()
	defer func() {
		cancel()
		conn.session.close(net.ErrClosed)
		conn.mu.Lock()
		for _, l := range conn.listeners {
			l.Close()
		}
		conn.mu.Unlock()
		conn.session.wg.Wait()
		conn.forwards.Wait()
		s.mu.Lock()
		delete(s.active, conn)
		s.mu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(30 * time.Second))
	if e = w.handshake(true, s.key, nil, false); e != nil {
		return
	}
	if e = conn.auth(w); e != nil {
		s.c.r.logger.Debug("Tailscale SSH authentication rejected", zap.Error(e))
		return
	}
	raw.SetDeadline(time.Time{})
	conn.session.requestsEnabled = true
	conn.session.accept = conn.accept
	conn.session.global = conn.global
	conn.forwards.Add(1)
	go func() { defer conn.forwards.Done(); conn.watchPolicy() }()
	conn.session.run()
}
func (conn *tsSSHConnection) auth(w *sshWire) error {
	b, e := w.next()
	if e != nil {
		return e
	}
	r := sshReader{b: b}
	kind := r.take(1)
	if r.err != nil || len(kind) != 1 || kind[0] != 5 || string(r.str()) != "ssh-userauth" || r.err != nil || len(r.b) != 0 {
		return errors.New("SSH userauth required")
	}
	if e = w.writePacket(sshText([]byte{6}, "ssh-userauth")); e != nil {
		return e
	}
	for range 6 {
		b, e = w.next()
		if e != nil {
			return e
		}
		r = sshReader{b: b}
		kind = r.take(1)
		requested, service, method := string(r.str()), string(r.str()), string(r.str())
		if r.err != nil || len(kind) != 1 || kind[0] != 50 || service != "ssh-connection" {
			return errors.New("invalid SSH authentication")
		}
		if method != "none" || len(r.b) != 0 {
			if e = w.writePacket(append(sshText([]byte{51}, "none"), 0)); e != nil {
				return e
			}
			continue
		}
		if !tsSSHName(requested) {
			return errors.New("invalid SSH user")
		}
		requestedAccount, _ := user.Lookup(requested)
		if requestedAccount != nil {
			uid, e := strconv.ParseUint(requestedAccount.Uid, 10, 32)
			conn.identityAllowed = e == nil && uid != 0
		}
		c := conn.server.c
		c.mu.Lock()
		grant, ok := c.sshGrantLocked(conn.source, requested, conn.identityAllowed)
		conn.nodeKey = c.nodes[c.addressOwners[conn.source]].Key
		c.mu.Unlock()
		if !ok {
			return errors.New("Tailscale SSH policy denied")
		}
		account := requestedAccount
		if account == nil || grant.local != requested {
			account, e = user.Lookup(grant.local)
		}
		if e != nil || account == nil {
			return errors.New("Tailscale SSH local account not found")
		}
		if e = tsSSHCanSwitch(account); e != nil {
			return e
		}
		conn.requested = requested
		if grant.action.Message != "" {
			w.writePacket(sshText(sshText([]byte{53}, grant.action.Message), ""))
		}
		if grant.action.HoldAndDelegate != "" {
			w.SetDeadline(time.Time{})
			a, e := conn.delegate(grant, w)
			if e != nil {
				return e
			}
			grant.action = a
		}
		conn.grant, conn.user = grant, account
		if e = w.writePacket([]byte{52}); e != nil {
			return e
		}
		return nil
	}
	return errors.New("too many SSH authentication attempts")
}
func (conn *tsSSHConnection) delegate(grant tsSSHGrant, w *sshWire) (tsSSHAction, error) {
	c := conn.server.c
	c.mu.Lock()
	src := c.nodes[c.addressOwners[conn.source]]
	self := c.self
	c.mu.Unlock()
	expand := strings.NewReplacer("$SRC_NODE_IP", url.QueryEscape(conn.source.String()), "$SRC_NODE_ID", strconv.FormatInt(src.ID, 10), "$DST_NODE_IP", url.QueryEscape(conn.destination.String()), "$DST_NODE_ID", strconv.FormatInt(self.ID, 10), "$SSH_USER", url.QueryEscape(conn.requested), "$LOCAL_USER", url.QueryEscape(grant.local))
	// A client abandoning an interactive check must not occupy an authentication slot forever.
	ctx, cancel := context.WithTimeout(conn.ctx, 2*time.Minute)
	defer cancel()
	target := grant.action.HoldAndDelegate
	for attempts := 0; attempts < 32; attempts++ {
		raw := expand.Replace(target)
		u, e := url.Parse(raw)
		if e != nil || len(raw) > 16384 || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" || !strings.HasPrefix(u.Path, "/") {
			return tsSSHAction{}, errors.New("invalid SSH delegate URL")
		}
		req, e := http.NewRequestWithContext(ctx, "GET", "http://tailscale-control"+u.RequestURI(), nil)
		if e != nil {
			return tsSSHAction{}, e
		}
		base, _ := url.Parse(c.o.controlURL())
		req.Host = base.Host
		response, e := c.control.RoundTrip(req)
		if e == nil {
			var action tsSSHAction
			if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
				response.Body.Close()
				return tsSSHAction{}, errTSAuth
			}
			if response.StatusCode == 200 {
				e = json.NewDecoder(io.LimitReader(response.Body, 65537)).Decode(&action)
			} else {
				e = errors.New("SSH delegate rejected")
			}
			response.Body.Close()
			if e == nil {
				if action.Message != "" {
					w.writePacket(sshText(sshText([]byte{53}, action.Message), ""))
				}
				if action.Reject {
					return action, errors.New("SSH delegate denied")
				}
				if action.SessionDuration < 0 || action.Accept && action.HoldAndDelegate != "" {
					return action, errors.New("invalid SSH delegate action")
				}
				if action.Accept {
					return action, nil
				}
				if action.HoldAndDelegate != "" {
					target = action.HoldAndDelegate
					continue
				}
			}
		}
		select {
		case <-ctx.Done():
			return tsSSHAction{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return tsSSHAction{}, errors.New("SSH delegation chain exceeded limit")
}
func (conn *tsSSHConnection) watchPolicy() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	started := time.Now()
	for {
		select {
		case <-conn.ctx.Done():
			return
		case <-tick.C:
			c := conn.server.c
			c.mu.Lock()
			allowed := conn.authorizedLocked()
			c.mu.Unlock()
			if !allowed || conn.grant.action.SessionDuration > 0 && time.Since(started) >= conn.grant.action.SessionDuration {
				conn.cancel()
				return
			}
		}
	}
}
func (conn *tsSSHConnection) authorizedLocked() bool {
	c := conn.server.c
	grant, ok := c.sshGrantLocked(conn.source, conn.requested, conn.identityAllowed)
	return ok && grant.local == conn.grant.local && c.nodes[c.addressOwners[conn.source]].Key == conn.nodeKey && reflect.DeepEqual(grant.rule, conn.grant.rule)
}
func (conn *tsSSHConnection) confirm(ch *sshChannel) error {
	return conn.session.send(sshInt(sshInt(sshInt(sshInt([]byte{91}, ch.remote), ch.id), sshWindow), sshChannelPacket))
}
func (conn *tsSSHConnection) deny(ch *sshChannel) {
	conn.session.send(sshText(sshText(sshInt(sshInt([]byte{92}, ch.remote), 1), "channel denied"), ""))
}
func (conn *tsSSHConnection) accept(ch *sshChannel, kind string, extra []byte) {
	defer ch.Close()
	conn.server.c.mu.Lock()
	allowed := conn.authorizedLocked()
	conn.server.c.mu.Unlock()
	if !allowed {
		conn.deny(ch)
		return
	}
	if kind == "session" && len(extra) == 0 {
		if conn.confirm(ch) != nil {
			return
		}
		conn.command(ch)
		return
	}
	if kind == "direct-streamlocal@openssh.com" {
		if conn.server.c.o.SSHServer.DisableForwarding || !conn.grant.action.AllowLocalPortForwarding {
			conn.deny(ch)
			return
		}
		r := sshReader{b: extra}
		path := string(r.str())
		r.str()
		r.u32()
		if r.err != nil || len(r.b) != 0 {
			conn.deny(ch)
			return
		}
		target, e := conn.unixWorker("unix-dial", path)
		if e != nil {
			conn.deny(ch)
			return
		}
		defer target.Close()
		if conn.confirm(ch) == nil {
			conn.server.c.r.relay(ch, target)
		}
		return
	}
	if kind != "direct-tcpip" || conn.server.c.o.SSHServer.DisableForwarding || !conn.grant.action.AllowLocalPortForwarding {
		conn.deny(ch)
		return
	}
	r := sshReader{b: extra}
	host, port := string(r.str()), r.u32()
	r.str()
	r.u32()
	if r.err != nil || len(r.b) != 0 || port == 0 || port > 65535 || strings.ContainsAny(host, "\x00\r\n") {
		conn.deny(ch)
		return
	}
	dialer := net.Dialer{Timeout: handshakeTimeout, Control: conn.server.c.r.socketControl}
	dst, e := dialer.DialContext(conn.ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if e != nil {
		conn.deny(ch)
		return
	}
	defer dst.Close()
	if conn.confirm(ch) == nil {
		conn.server.c.r.relay(ch, dst)
	}
}
func (conn *tsSSHConnection) global(name string, b []byte) ([]byte, bool) {
	if name == "keepalive@openssh.com" {
		return nil, true
	}
	if conn.server.c.o.SSHServer.DisableForwarding || !conn.grant.action.AllowRemotePortForwarding {
		return nil, false
	}
	if name == "streamlocal-forward@openssh.com" || name == "cancel-streamlocal-forward@openssh.com" {
		return conn.unixGlobal(name, b)
	}
	r := sshReader{b: b}
	host, port := string(r.str()), r.u32()
	if r.err != nil || len(r.b) != 0 || port > 65535 {
		return nil, false
	}
	if host == "localhost" || host == "" {
		host = "127.0.0.1"
	}
	ip, e := netip.ParseAddr(host)
	if e != nil || !ip.IsLoopback() {
		return nil, false
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	conn.mu.Lock()
	defer conn.mu.Unlock()
	switch name {
	case "cancel-tcpip-forward":
		l, ok := conn.listeners[address]
		if !ok {
			return nil, false
		}
		l.Close()
		delete(conn.listeners, address)
		return nil, true
	case "tcpip-forward":
		if len(conn.listeners) >= 16 || conn.listeners[address] != nil {
			return nil, false
		}
		if port > 0 && port < 1024 && conn.user.Uid != "0" {
			return nil, false
		}
		l, e := net.Listen("tcp", address)
		if e != nil {
			return nil, false
		}
		actual := l.Addr().(*net.TCPAddr).Port
		bound := net.JoinHostPort(host, strconv.Itoa(actual))
		conn.listeners[bound] = l
		conn.forwards.Add(1)
		go func() {
			defer conn.forwards.Done()
			for {
				in, e := l.Accept()
				if e != nil {
					return
				}
				conn.forwards.Add(1)
				go func() {
					defer conn.forwards.Done()
					defer in.Close()
					from := in.RemoteAddr().(*net.TCPAddr)
					extra := sshInt(sshText(nil, host), uint32(actual))
					extra = sshInt(sshText(extra, from.IP.String()), uint32(from.Port))
					ch, e := conn.session.open(conn.ctx, "forwarded-tcpip", extra)
					if e != nil {
						return
					}
					defer ch.Close()
					conn.server.c.r.relay(in, ch)
				}()
			}
		}()
		if port == 0 {
			return sshInt(nil, uint32(actual)), true
		}
		return nil, true
	}
	return nil, false
}
func (conn *tsSSHConnection) command(ch *sshChannel) {
	ctx, cancel := context.WithCancel(conn.ctx)
	defer cancel()
	env := map[string]string{}
	term := ""
	var width, height uint32
	var process *exec.Cmd
	var pty *os.File
	var slave *os.File
	var closeAgent func()
	var record *tsSSHRecording
	var auditRead, auditWrite *os.File
	acquired := false
	exited := make(chan uint32, 1)
	defer func() {
		if auditWrite != nil {
			auditWrite.Close()
		}
		if auditRead != nil {
			auditRead.Close()
		}
		if record != nil {
			record.close()
		}
		if closeAgent != nil {
			closeAgent()
		}
		if pty != nil {
			pty.Close()
		}
		if slave != nil {
			slave.Close()
		}
		if process != nil && process.Process != nil {
			tsSSHKill(process)
		}
		if acquired {
			<-conn.server.processes
		}
	}()
	reply := func(req sshRequest, ok bool) {
		if req.reply {
			kind := byte(100)
			if ok {
				kind = 99
			}
			conn.session.send(sshInt([]byte{kind}, ch.remote))
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.session.done:
			return
		case <-ch.closedSignal:
			return
		case status := <-exited:
			conn.session.send(sshInt(append(sshText(sshInt([]byte{98}, ch.remote), "exit-status"), 0), status))
			ch.CloseWrite()
			return
		case req := <-ch.requests:
			r := sshReader{b: req.data}
			ok := false
			switch req.name {
			case "auth-agent-req@openssh.com":
				if len(r.b) == 0 && process == nil && closeAgent == nil && !conn.server.c.o.SSHServer.DisableForwarding && conn.grant.action.AllowAgentForwarding {
					socket, cleanup, e := conn.agent(ctx)
					if e == nil {
						env["SSH_AUTH_SOCK"] = socket
						closeAgent = cleanup
						ok = true
					}
				}
			case "env":
				key, value := string(r.str()), string(r.str())
				if r.err == nil && len(r.b) == 0 && process == nil && len(env) < 64 && len(value) <= 4096 && !strings.ContainsAny(key+value, "\x00") && key != "" && !strings.Contains(key, "=") {
					for _, pattern := range conn.grant.rule.AcceptEnv {
						if match, _ := path.Match(pattern, key); match {
							env[key] = value
							ok = true
							break
						}
					}
				}
			case "pty-req":
				name := string(r.str())
				w, h := r.u32(), r.u32()
				r.u32()
				r.u32()
				modes := r.str()
				if r.err == nil && len(r.b) == 0 && len(name) <= 128 && !strings.ContainsAny(name, "\x00\r\n") && process == nil && pty == nil && !conn.server.c.o.SSHServer.DisablePTY {
					var e error
					pty, slave, e = tsSSHOpenPTY(conn.user, w, h, modes)
					if e == nil {
						term, width, height = name, w, h
						ok = true
					} else {
						pty, slave = nil, nil
					}
				}
			case "window-change":
				w, h := r.u32(), r.u32()
				r.u32()
				r.u32()
				if r.err == nil && len(r.b) == 0 && pty != nil {
					ok = tsSSHResize(pty, w, h) == nil
					width, height = w, h
					if record != nil && ok {
						record.resize(w, h)
					}
				}
			case "signal":
				name := string(r.str())
				if r.err == nil && len(r.b) == 0 && process != nil {
					ok = tsSSHSignal(process, name) == nil
				}
			case "shell", "exec", "subsystem":
				command := ""
				if req.name != "shell" {
					command = string(r.str())
				}
				sftp := req.name == "subsystem" && command == "sftp"
				if r.err != nil || len(r.b) != 0 || strings.ContainsRune(command, 0) || process != nil || req.name == "subsystem" && (!sftp || conn.server.c.o.SSHServer.DisableSFTP) || sftp && pty != nil {
					break
				}
				if !acquired {
					select {
					case conn.server.processes <- struct{}{}:
						acquired = true
					default:
						reply(req, false)
						continue
					}
				}
				var e error
				if record != nil {
					record.close()
					record = nil
				}
				if auditRead != nil {
					auditRead.Close()
					auditRead = nil
				}
				if auditWrite != nil {
					auditWrite.Close()
					auditWrite = nil
				}
				record, e = conn.startRecording(ctx, cancel, command, term, width, height)
				if e != nil {
					reply(req, false)
					return
				}
				process, e = tsSSHProcess(ctx, conn.user, command, req.name == "shell", sftp, conn.server.worker, env, term, slave)
				if e != nil {
					process = nil
					break
				}
				var input io.WriteCloser
				var output io.Writer = ch
				var stderr io.Writer = sshExtendedWriter{ch}
				if record != nil && !sftp {
					output = tsSSHRecordedOutput{record, ch, false}
					stderr = tsSSHRecordedOutput{record, ch, true}
				}
				if sftp && record != nil {
					auditRead, auditWrite, e = os.Pipe()
					if e != nil {
						process = nil
						break
					}
					process.Args = append(process.Args, "sftp-audit")
					process.ExtraFiles = []*os.File{auditWrite}
				}
				if pty == nil {
					input, e = process.StdinPipe()
					if e != nil {
						process = nil
						break
					}
					process.Stdout = output
					process.Stderr = stderr
				}
				conn.server.c.mu.Lock()
				if conn.authorizedLocked() && ctx.Err() == nil {
					e = process.Start()
				} else {
					e = net.ErrClosed
				}
				conn.server.c.mu.Unlock()
				if e != nil {
					if auditRead != nil {
						auditRead.Close()
						auditRead = nil
					}
					if auditWrite != nil {
						auditWrite.Close()
						auditWrite = nil
					}
					if input != nil {
						input.Close()
					}
					process = nil
					break
				}
				var outputDone chan struct{}
				var auditDone chan struct{}
				if record != nil {
					record.started.Store(true)
				}
				if auditWrite != nil {
					auditWrite.Close()
					auditWrite = nil
					auditDone = make(chan struct{})
					reader, rec := auditRead, record
					go func() {
						defer close(auditDone)
						scanner := bufio.NewScanner(reader)
						scanner.Buffer(make([]byte, 4096), 65536)
						for scanner.Scan() {
							if e := rec.event(append(append([]byte(nil), scanner.Bytes()...), '\n')); e != nil {
								return
							}
						}
						if e := scanner.Err(); e != nil && !rec.closing.Load() {
							rec.fail(e, false)
						}
					}()
				}
				if pty != nil {
					outputDone = make(chan struct{})
					go func() { io.Copy(output, pty); close(outputDone) }()
					go io.Copy(pty, ch)
				} else {
					go func() { io.Copy(input, ch); input.Close() }()
				}
				if slave != nil {
					slave.Close()
					slave = nil
				}
				ok = true
				cmd := process
				go func() {
					e := cmd.Wait()
					if outputDone != nil {
						select {
						case <-outputDone:
						case <-ctx.Done():
						case <-time.After(time.Second):
						}
					}
					if auditDone != nil {
						select {
						case <-auditDone:
						case <-ctx.Done():
						case <-time.After(5 * time.Second):
							record.fail(errors.New("SFTP audit did not finish"), false)
						}
					}
					status := uint32(0)
					if e != nil {
						status = 255
						if code := cmd.ProcessState; code != nil && code.ExitCode() >= 0 {
							status = uint32(code.ExitCode())
						}
					}
					exited <- status
				}()
			}
			reply(req, ok)
		}
	}
}
func (conn *tsSSHConnection) agent(ctx context.Context) (string, func(), error) {
	dir, e := os.MkdirTemp("", "lanboat-ssh-agent-")
	if e != nil {
		return "", nil, e
	}
	failed := true
	defer func() {
		if failed {
			os.RemoveAll(dir)
		}
	}()
	socket := filepath.Join(dir, "agent")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		return "", nil, e
	}
	uid, e := strconv.Atoi(conn.user.Uid)
	if e != nil {
		listener.Close()
		return "", nil, e
	}
	gid, e := strconv.Atoi(conn.user.Gid)
	if e != nil {
		listener.Close()
		return "", nil, e
	}
	if e = os.Chmod(socket, 0600); e == nil && os.Geteuid() == 0 {
		e = os.Chown(socket, uid, gid)
		if e == nil {
			e = os.Chown(dir, uid, gid)
		}
	}
	if e != nil {
		listener.Close()
		return "", nil, e
	}
	conn.forwards.Add(1)
	go func() {
		defer conn.forwards.Done()
		for {
			in, e := listener.Accept()
			if e != nil {
				return
			}
			conn.forwards.Add(1)
			go func() {
				defer conn.forwards.Done()
				defer in.Close()
				ch, e := conn.session.open(ctx, "auth-agent@openssh.com", nil)
				if e != nil {
					return
				}
				defer ch.Close()
				stop := context.AfterFunc(ctx, func() { in.Close(); ch.Close() })
				defer stop()
				conn.server.c.r.relay(in, ch)
			}()
		}
	}()
	cleanup := func() { listener.Close(); os.RemoveAll(dir) }
	failed = false
	return socket, cleanup, nil
}

type sshExtendedWriter struct{ ch *sshChannel }

func (w sshExtendedWriter) Write(b []byte) (int, error) { return w.ch.write(b, true) }
func tsSSHTerminalModes(b []byte, apply func(byte, uint32)) error {
	for len(b) > 0 {
		op := b[0]
		b = b[1:]
		if op == 0 || op >= 160 {
			return nil
		}
		if len(b) < 4 {
			return errors.New("truncated SSH terminal modes")
		}
		apply(op, binary.BigEndian.Uint32(b))
		b = b[4:]
	}
	return nil
}
