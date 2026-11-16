package native

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type SSHOptions struct {
	PrivateKey           keyLines `json:"private_key,omitempty"`
	PrivateKeyPath       string   `json:"private_key_path,omitempty"`
	PrivateKeyPassphrase string   `json:"private_key_passphrase,omitempty"`
	KeyboardInteractive  []string `json:"keyboard_interactive,omitempty"`
	HostKey              []string `json:"host_key,omitempty"`
	HostKeyInsecure      bool     `json:"host_key_insecure,omitempty"`
}

func (o SSHOptions) validate(server bool) error {
	if len(o.PrivateKey) > 0 || o.PrivateKeyPath != "" {
		if _, e := sshPrivate(o.PrivateKey, o.PrivateKeyPath, o.PrivateKeyPassphrase); e != nil {
			return e
		}
	} else if server {
		return errors.New("SSH inbound requires private_key or private_key_path")
	}
	if !server && !o.HostKeyInsecure && len(o.HostKey) == 0 {
		return errors.New("SSH requires pinned host_key or explicit host_key_insecure")
	}
	return nil
}
func sshUserName(u User) string {
	if u.Username != "" {
		return u.Username
	}
	return u.Name
}
func (w *sshWire) authClient(o Outbound) error {
	if e := w.writePacket(sshText([]byte{5}, "ssh-userauth")); e != nil {
		return e
	}
	b, e := w.next()
	if e != nil {
		return e
	}
	if b[0] != 6 {
		return errors.New("SSH authentication service rejected")
	}
	base := sshText(sshText([]byte{50}, o.Username), "ssh-connection")
	if len(o.PrivateKey) > 0 || o.PrivateKeyPath != "" {
		key := w.host
		pub, e := sshPubKey(key.Public())
		if e != nil {
			return e
		}
		r := sshReader{b: pub}
		algorithm := string(r.str())
		if algorithm == "ssh-rsa" {
			algorithm = "rsa-sha2-512"
		}
		request := append(sshText(base, "publickey"), 1)
		request = sshString(sshText(request, algorithm), pub)
		message := append(sshString(nil, w.sessionID), request...)
		signature, e := sshSign(key, algorithm, message)
		if e != nil {
			return e
		}
		if e = w.writePacket(sshString(request, signature)); e != nil {
			return e
		}
	} else if o.KeyboardInteractive != nil {
		if e = w.writePacket(sshText(sshText(sshText(base, "keyboard-interactive"), ""), "")); e != nil {
			return e
		}
	} else {
		request := append(sshText(base, "password"), 0)
		if e = w.writePacket(sshText(request, o.Password)); e != nil {
			return e
		}
	}
	interactive, responses, challenges := o.KeyboardInteractive != nil && len(o.PrivateKey) == 0 && o.PrivateKeyPath == "", 0, 0
	for {
		b, e = w.next()
		if e != nil {
			return e
		}
		switch b[0] {
		case 52:
			return nil
		case 51:
			r := sshReader{b: b[1:]}
			methods, partial := string(r.str()), r.take(1)
			if r.err != nil || len(r.b) != 0 || len(partial) != 1 {
				return errors.New("invalid SSH authentication failure")
			}
			if !interactive && (o.Password != "" || o.KeyboardInteractive != nil) && sshChoose("keyboard-interactive", methods) != "" {
				interactive = true
				if e = w.writePacket(sshText(sshText(sshText(base, "keyboard-interactive"), ""), "")); e != nil {
					return e
				}
				continue
			}
			return errors.New("SSH authentication rejected")
		case 60:
			if !interactive || challenges >= 8 {
				return errors.New("unexpected SSH interactive challenge")
			}
			challenges++
			r := sshReader{b: b[1:]}
			r.str()
			r.str()
			r.str()
			count := r.u32()
			if r.err != nil || count > 32 {
				return errors.New("invalid SSH interactive challenge")
			}
			reply := sshInt([]byte{61}, count)
			for range count {
				prompt, echo := string(r.str()), r.take(1)
				if r.err != nil || len(echo) != 1 {
					return errors.New("invalid SSH interactive prompt")
				}
				answer := ""
				if responses < len(o.KeyboardInteractive) {
					answer = o.KeyboardInteractive[responses]
				} else if o.KeyboardInteractive == nil && count == 1 && echo[0] == 0 && strings.Contains(strings.ToLower(prompt), "password") {
					answer = o.Password
				} else {
					return errors.New("SSH interactive answer is not configured")
				}
				responses++
				reply = sshText(reply, answer)
			}
			if len(r.b) != 0 {
				return errors.New("invalid SSH interactive challenge trailing data")
			}
			if e = w.writePacket(reply); e != nil {
				return e
			}
		case 53:
			continue
		default:
			return fmt.Errorf("unexpected SSH authentication packet %d", b[0])
		}
	}
}
func (w *sshWire) authServer(in Inbound) error {
	b, e := w.next()
	if e != nil {
		return e
	}
	r := sshReader{b: b}
	kind := r.take(1)
	service := string(r.str())
	if r.err != nil || kind[0] != 5 || service != "ssh-userauth" || len(r.b) != 0 {
		return errors.New("SSH userauth service required")
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
		username := string(r.str())
		service = string(r.str())
		method := string(r.str())
		if r.err != nil || kind[0] != 50 || service != "ssh-connection" {
			return errors.New("invalid SSH authentication request")
		}
		valid := 0
		switch method {
		case "password":
			change := r.take(1)
			password := r.str()
			if r.err != nil || change[0] != 0 || len(r.b) != 0 {
				return errors.New("invalid SSH password authentication")
			}
			for _, u := range in.Users {
				if u.Password != "" {
					valid |= subtle.ConstantTimeCompare([]byte(sshUserName(u)), []byte(username)) & subtle.ConstantTimeCompare([]byte(u.Password), password)
				}
			}
		case "publickey":
			signed := r.take(1)
			algorithm := string(r.str())
			public := r.str()
			if r.err != nil || len(signed) != 1 {
				return errors.New("invalid SSH publickey authentication")
			}
			matched := false
			for _, u := range in.Users {
				if sshUserName(u) != username {
					continue
				}
				for _, text := range u.AuthorizedKeys {
					parts := strings.Fields(text)
					if len(parts) >= 2 {
						key, e := base64.StdEncoding.DecodeString(parts[1])
						if e == nil && bytes.Equal(key, public) {
							matched = true
						}
					}
				}
			}
			if signed[0] == 0 {
				if matched && r.err == nil && len(r.b) == 0 {
					if e = w.writePacket(sshString(sshText([]byte{60}, algorithm), public)); e != nil {
						return e
					}
					continue
				}
			} else if signed[0] == 1 {
				offset := len(b) - len(r.b)
				signature := r.str()
				message := append(sshString(nil, w.sessionID), b[:offset]...)
				if matched && r.err == nil && len(r.b) == 0 && sshVerify(public, algorithm, message, signature) == nil {
					valid = 1
				}
			}
		case "none":
		case "keyboard-interactive":
			r.str()
			r.str()
			if r.err != nil || len(r.b) != 0 {
				return errors.New("invalid SSH interactive request")
			}
			challenge := sshInt(sshText(sshText(sshText([]byte{60}, "Lanboat"), ""), ""), 1)
			if e = w.writePacket(append(sshText(challenge, "Password: "), 0)); e != nil {
				return e
			}
			response, err := w.next()
			if err != nil {
				return err
			}
			r = sshReader{b: response}
			kind := r.take(1)
			count := r.u32()
			password := r.str()
			if r.err != nil || kind[0] != 61 || count != 1 || len(r.b) != 0 {
				return errors.New("invalid SSH interactive response")
			}
			for _, u := range in.Users {
				if u.Password != "" {
					valid |= subtle.ConstantTimeCompare([]byte(sshUserName(u)), []byte(username)) & subtle.ConstantTimeCompare([]byte(u.Password), password)
				}
			}
		default:
		}
		if valid == 1 {
			return w.writePacket([]byte{52})
		}
		if e = w.writePacket(append(sshText([]byte{51}, "publickey,password,keyboard-interactive"), 0)); e != nil {
			return e
		}
	}
	return errors.New("SSH authentication attempt limit exceeded")
}

const sshWindow = 256 * 1024
const sshChannelPacket = 32768

// One reader owns packet decoding. Channel windows bound queued plaintext memory.
type sshSession struct {
	gate            sync.RWMutex
	wire            *sshWire
	mu              sync.Mutex
	channels        map[uint32]*sshChannel
	next            uint32
	done            chan struct{}
	once            sync.Once
	err             error
	accept          func(*sshChannel, string, []byte)
	global          func(string, []byte) ([]byte, bool)
	requestsEnabled bool
	wg              sync.WaitGroup
}
type sshChannel struct {
	session                              *sshSession
	id, remote, maxPacket                uint32
	mu                                   sync.Mutex
	window                               uint32
	receiveWindow                        uint32
	queue                                [][]byte
	bytes                                int
	eof, closed, remoteEOF, remoteClosed bool
	abandoned                            bool
	opened                               chan error
	wake, writeWake                      chan struct{}
	readDeadline, writeDeadline          time.Time
	writeMu                              sync.Mutex
	requests                             chan sshRequest
	closedSignal                         chan struct{}
	closeOnce                            sync.Once
}
type sshRequest struct {
	name  string
	reply bool
	data  []byte
}

func newSSHSession(w *sshWire) *sshSession {
	return &sshSession{wire: w, channels: map[uint32]*sshChannel{}, done: make(chan struct{})}
}
func (s *sshSession) close(err error) {
	s.once.Do(func() { s.mu.Lock(); s.err = err; s.mu.Unlock(); close(s.done); s.wire.Close() })
}
func (s *sshSession) channel(id, remote, window, maxPacket uint32) *sshChannel {
	c := &sshChannel{session: s, id: id, remote: remote, window: window, receiveWindow: sshWindow, maxPacket: min(maxPacket, sshChannelPacket), opened: make(chan error, 1), wake: make(chan struct{}, 1), writeWake: make(chan struct{}, 1), closedSignal: make(chan struct{})}
	return c
}
func (s *sshSession) send(b []byte) error {
	s.gate.RLock()
	e := s.wire.writePacket(b)
	s.gate.RUnlock()
	if e != nil {
		s.close(e)
	}
	return e
}
func (s *sshSession) rekey(peerInit []byte) error {
	s.gate.Lock()
	defer s.gate.Unlock()
	s.wire.SetDeadline(time.Now().Add(handshakeTimeout))
	e := s.wire.exchange(peerInit)
	s.wire.SetDeadline(time.Time{})
	return e
}
func (s *sshSession) run() {
	defer s.close(net.ErrClosed)
	for {
		var b []byte
		var e error
		if len(s.wire.deferred) > 0 {
			b = s.wire.deferred[0]
			s.wire.deferred[0] = nil
			s.wire.deferred = s.wire.deferred[1:]
		} else {
			b, e = s.wire.next()
		}
		if e != nil {
			s.close(e)
			return
		}
		if b[0] == 20 {
			if e = s.rekey(b); e != nil {
				s.close(e)
				return
			}
			continue
		}
		if e = s.handle(b); e != nil {
			s.close(e)
			return
		}
		if s.wire.read > 1<<30 || s.wire.written.Load() > 1<<30 {
			if e = s.rekey(nil); e != nil {
				s.close(e)
				return
			}
		}
	}
}
func (s *sshSession) handle(b []byte) error {
	r := sshReader{b: b}
	v := r.take(1)
	if len(v) != 1 {
		return io.ErrUnexpectedEOF
	}
	kind := v[0]
	if kind == 80 {
		name := string(r.str())
		reply := r.take(1)
		if r.err != nil {
			return r.err
		}
		if s.global != nil {
			data, ok := s.global(name, r.b)
			if reply[0] == 0 {
				return nil
			}
			if ok {
				return s.send(append([]byte{81}, data...))
			}
		}
		if reply[0] != 0 {
			return s.send([]byte{82})
		}
		return nil
	}
	if kind == 81 || kind == 82 {
		return nil
	}
	if kind == 90 {
		name := string(r.str())
		remote, window, maxPacket := r.u32(), r.u32(), r.u32()
		if r.err != nil || window == 0 || maxPacket == 0 {
			return errors.New("invalid SSH channel open")
		}
		s.mu.Lock()
		id := s.next
		s.next++
		if s.accept == nil || len(s.channels) >= 128 {
			s.mu.Unlock()
			return s.send(sshText(sshText(sshInt(sshInt([]byte{92}, remote), 1), "channel denied"), ""))
		}
		c := s.channel(id, remote, window, maxPacket)
		if s.requestsEnabled && name == "session" {
			c.requests = make(chan sshRequest, 16)
		}
		s.channels[id] = c
		s.mu.Unlock()
		extra := append([]byte{}, r.b...)
		s.wg.Add(1)
		go func() { defer s.wg.Done(); s.accept(c, name, extra) }()
		return nil
	}
	id := r.u32()
	if r.err != nil {
		return r.err
	}
	s.mu.Lock()
	c := s.channels[id]
	retired := id < s.next
	s.mu.Unlock()
	if c == nil {
		if retired && (kind == 93 || kind == 96 || kind == 97) {
			return nil
		}
		return errors.New("SSH packet for unknown channel")
	}
	switch kind {
	case 91:
		remote, window, maxPacket := r.u32(), r.u32(), r.u32()
		if r.err != nil || len(r.b) != 0 || window == 0 || maxPacket == 0 {
			return errors.New("invalid SSH channel confirmation")
		}
		c.mu.Lock()
		c.remote, c.window, c.maxPacket = remote, window, min(maxPacket, sshChannelPacket)
		abandoned := c.abandoned
		c.mu.Unlock()
		if abandoned {
			return c.Close()
		}
		select {
		case c.opened <- nil:
		default:
			return errors.New("duplicate SSH channel confirmation")
		}
	case 92:
		r.u32()
		message := string(r.str())
		r.str()
		if r.err != nil {
			return r.err
		}
		select {
		case c.opened <- fmt.Errorf("SSH channel rejected: %s", message):
		default:
		}
		c.mu.Lock()
		c.remoteClosed = true
		c.closeOnce.Do(func() { close(c.closedSignal) })
		c.mu.Unlock()
		s.mu.Lock()
		delete(s.channels, id)
		s.mu.Unlock()
	case 93:
		n := r.u32()
		if r.err != nil || len(r.b) != 0 || n == 0 {
			return errors.New("invalid SSH channel window")
		}
		c.mu.Lock()
		if uint64(c.window)+uint64(n) > 1<<32-1 {
			c.mu.Unlock()
			return errors.New("SSH channel window overflow")
		}
		c.window += n
		c.mu.Unlock()
	case 94, 95:
		if kind == 95 {
			r.u32()
		}
		data := r.str()
		if r.err != nil || len(r.b) != 0 || len(data) > sshChannelPacket {
			return errors.New("invalid SSH channel data")
		}
		c.mu.Lock()
		if c.remoteEOF || uint32(len(data)) > c.receiveWindow {
			c.mu.Unlock()
			return errors.New("SSH receive window exceeded")
		}
		c.receiveWindow -= uint32(len(data))
		if !c.closed && len(data) > 0 {
			c.queue = append(c.queue, append([]byte{}, data...))
			c.bytes += len(data)
		}
		c.mu.Unlock()
	case 96:
		c.mu.Lock()
		c.remoteEOF = true
		c.mu.Unlock()
	case 97:
		c.mu.Lock()
		c.remoteEOF = true
		c.remoteClosed = true
		c.closeOnce.Do(func() { close(c.closedSignal) })
		sendClose := !c.closed
		c.closed = true
		c.mu.Unlock()
		if sendClose {
			if e := s.send(sshInt([]byte{97}, c.remote)); e != nil {
				return e
			}
		}
		s.mu.Lock()
		delete(s.channels, id)
		s.mu.Unlock()
	case 98:
		name := string(r.str())
		reply := r.take(1)
		if r.err != nil {
			return r.err
		}
		if c.requests != nil {
			select {
			case c.requests <- sshRequest{name, reply[0] != 0, bytes.Clone(r.b)}:
				return nil
			default:
				return errors.New("too many queued SSH channel requests")
			}
		}
		if reply[0] != 0 {
			return s.send(sshInt([]byte{100}, c.remote))
		}
	case 99, 100:
	default:
		return fmt.Errorf("unsupported SSH connection message %d", kind)
	}
	c.signal()
	return nil
}
func (s *sshSession) open(ctx context.Context, kind string, extra []byte) (*sshChannel, error) {
	s.mu.Lock()
	if len(s.channels) >= 128 {
		s.mu.Unlock()
		return nil, errors.New("SSH channel capacity reached")
	}
	id := s.next
	s.next++
	c := s.channel(id, 0, 0, sshChannelPacket)
	s.channels[id] = c
	s.mu.Unlock()
	b := sshInt(sshInt(sshInt(sshText([]byte{90}, kind), id), sshWindow), sshChannelPacket)
	if e := s.send(append(b, extra...)); e != nil {
		return nil, e
	}
	select {
	case e := <-c.opened:
		if e != nil {
			return nil, e
		}
		return c, nil
	case <-ctx.Done():
		c.mu.Lock()
		c.abandoned = true
		confirmed := c.maxPacket != 0 && c.window != 0
		c.mu.Unlock()
		if confirmed {
			c.Close()
		}
		return nil, ctx.Err()
	case <-s.done:
		s.mu.Lock()
		e := s.err
		s.mu.Unlock()
		return nil, e
	}
}
func (c *sshChannel) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		c.mu.Lock()
		if len(c.queue) > 0 {
			n := copy(b, c.queue[0])
			c.queue[0] = c.queue[0][n:]
			if len(c.queue[0]) == 0 {
				c.queue[0] = nil
				c.queue = c.queue[1:]
			}
			c.bytes -= n
			c.receiveWindow += uint32(n)
			update := !c.remoteClosed && !c.closed
			c.mu.Unlock()
			if update {
				if e := c.session.send(sshInt(sshInt([]byte{93}, c.remote), uint32(n))); e != nil {
					return n, e
				}
			}
			return n, nil
		}
		eof, closed, d := c.remoteEOF, c.closed, c.readDeadline
		c.mu.Unlock()
		if eof {
			return 0, io.EOF
		}
		if closed {
			return 0, net.ErrClosed
		}
		if e := c.wait(d, false); e != nil {
			return 0, e
		}
	}
}
func (c *sshChannel) signal() { signalQUIC(c.wake); signalQUIC(c.writeWake) }
func (c *sshChannel) wait(d time.Time, writing bool) error {
	wake := c.wake
	if writing {
		wake = c.writeWake
	}
	var timer *time.Timer
	var timeout <-chan time.Time
	if !d.IsZero() {
		timer = time.NewTimer(max(0, time.Until(d)))
		timeout = timer.C
		defer timer.Stop()
	}
	select {
	case <-wake:
		return nil
	case <-c.session.done:
		c.session.mu.Lock()
		e := c.session.err
		c.session.mu.Unlock()
		return e
	case <-timeout:
		return context.DeadlineExceeded
	}
}
func (c *sshChannel) Write(b []byte) (int, error) {
	return c.write(b, false)
}
func (c *sshChannel) write(b []byte, extended bool) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(b) > 0 {
		c.mu.Lock()
		if c.closed || c.eof {
			c.mu.Unlock()
			return total, net.ErrClosed
		}
		d := c.writeDeadline
		if !d.IsZero() && time.Now().After(d) {
			c.mu.Unlock()
			return total, context.DeadlineExceeded
		}
		n := min(len(b), int(c.window), int(c.maxPacket))
		if n > 0 {
			c.window -= uint32(n)
		}
		c.mu.Unlock()
		if n == 0 {
			if e := c.wait(d, true); e != nil {
				return total, e
			}
			continue
		}
		header := sshInt([]byte{94}, c.remote)
		if extended {
			header[0] = 95
			header = sshInt(header, 1)
		}
		if e := c.session.send(sshString(header, b[:n])); e != nil {
			return total, e
		}
		total += n
		b = b[n:]
	}
	return total, nil
}
func (c *sshChannel) CloseWrite() error {
	c.mu.Lock()
	if c.eof || c.closed {
		c.mu.Unlock()
		return nil
	}
	c.eof = true
	c.mu.Unlock()
	return c.session.send(sshInt([]byte{96}, c.remote))
}
func (c *sshChannel) Close() error {
	c.closeOnce.Do(func() { close(c.closedSignal) })
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.queue = nil
	c.bytes = 0
	c.mu.Unlock()
	c.signal()
	return c.session.send(sshInt([]byte{97}, c.remote))
}
func (c *sshChannel) LocalAddr() net.Addr  { return c.session.wire.LocalAddr() }
func (c *sshChannel) RemoteAddr() net.Addr { return c.session.wire.RemoteAddr() }
func (c *sshChannel) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	c.signal()
	return nil
}
func (c *sshChannel) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	c.signal()
	return nil
}
func (c *sshChannel) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

type sshClient struct {
	runtime  *Runtime
	outbound Outbound
	mu       sync.Mutex
	current  *sshSession
}

func (p *sshClient) close() {
	p.mu.Lock()
	s := p.current
	p.current = nil
	p.mu.Unlock()
	if s != nil {
		s.close(net.ErrClosed)
	}
}
func (p *sshClient) session(ctx context.Context) (*sshSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.current; s != nil {
		select {
		case <-s.done:
			p.current = nil
		default:
			return s, nil
		}
	}
	r, o := p.runtime, p.outbound
	raw, e := r.endpoint(ctx, o, "tcp")
	if e != nil {
		return nil, e
	}
	good := false
	defer func() {
		if !good {
			raw.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	raw.SetDeadline(time.Now().Add(handshakeTimeout))
	if d, ok := ctx.Deadline(); ok {
		raw.SetDeadline(d)
	}
	w := &sshWire{Conn: raw, reader: bufio.NewReaderSize(raw, 4096)}
	if e = w.handshake(false, r.sshKeys["out:"+o.Tag], o.HostKey, o.HostKeyInsecure); e != nil {
		return nil, e
	}
	if e = w.authClient(o); e != nil {
		return nil, e
	}
	raw.SetDeadline(time.Time{})
	s := newSSHSession(w)
	p.current = s
	good = true
	go s.run()
	return s, nil
}
func (r *Runtime) sshDial(ctx context.Context, o Outbound, network, address string) (net.Conn, error) {
	s, e := r.sshClients[o.Tag].session(ctx)
	if e != nil {
		return nil, e
	}
	kind := "direct-tcpip"
	var extra []byte
	if network == "tcp" {
		h, p, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		port, e := strconv.ParseUint(p, 10, 16)
		if e != nil {
			return nil, e
		}
		extra = sshInt(sshText(sshInt(sshText(nil, h), uint32(port)), "127.0.0.1"), 0)
	} else {
		kind = "udp-forward@lanboat"
	}
	c, e := s.open(ctx, kind, extra)
	if e != nil {
		return nil, e
	}
	owned := c
	if network == "udp" {
		return r.own(&streamPacketConn{Conn: owned, trojan: true, address: address})
	}
	return r.own(owned)
}
func (r *Runtime) serveSSH(in Inbound, raw net.Conn, q request) error {
	key := r.sshKeys["in:"+in.Tag]
	w := &sshWire{Conn: raw, reader: bufio.NewReaderSize(raw, 4096)}
	if e := w.handshake(true, key, nil, false); e != nil {
		return e
	}
	if e := w.authServer(in); e != nil {
		return e
	}
	raw.SetDeadline(time.Time{})
	s := newSSHSession(w)
	s.accept = func(c *sshChannel, kind string, extra []byte) {
		defer c.Close()
		var remote net.Conn
		var e error
		query := q
		if kind == "direct-tcpip" {
			reader := sshReader{b: extra}
			host := string(reader.str())
			port := reader.u32()
			reader.str()
			reader.u32()
			if reader.err == nil && len(reader.b) == 0 && port > 0 && port < 65536 {
				query.address = net.JoinHostPort(host, strconv.Itoa(int(port)))
				query.network = "tcp"
				remote, e = r.routeDial(r.ctx, query)
			} else {
				e = errors.New("invalid SSH forwarding address")
			}
		} else if kind != "udp-forward@lanboat" || len(extra) != 0 {
			e = errors.New("SSH channel type denied")
		}
		if e != nil {
			s.send(sshText(sshText(sshInt(sshInt([]byte{92}, c.remote), 1), "channel denied"), ""))
			return
		}
		if e = s.send(sshInt(sshInt(sshInt(sshInt([]byte{91}, c.remote), c.id), sshWindow), sshChannelPacket)); e != nil {
			if remote != nil {
				remote.Close()
			}
			return
		}
		if kind == "udp-forward@lanboat" {
			r.serveStreamPackets(c, query, true)
		} else {
			r.relay(c, remote)
		}
	}
	s.run()
	s.wg.Wait()
	s.mu.Lock()
	e := s.err
	s.mu.Unlock()
	return e
}
