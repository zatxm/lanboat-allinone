package native

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// RunTailscaleSSHWorker dispatches credential-dropped roles in the same executable.
// Embedders call it before starting their UI or interpreting other arguments.
func RunTailscaleSSHWorker(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "tailscale-ssh-worker" {
		return false, nil
	}
	switch {
	case len(args) == 1:
		return true, tsSFTP(os.Stdin, os.Stdout, nil)
	case len(args) == 2 && args[1] == "sftp-audit":
		audit := os.NewFile(3, "sftp-audit")
		defer audit.Close()
		return true, tsSFTP(os.Stdin, os.Stdout, audit)
	case len(args) == 3 && (args[1] == "unix-dial" || args[1] == "unix-listen"):
		if !tsSSHPlatform() {
			return true, errors.New("Unix forwarding requires Linux or macOS")
		}
		return true, tsSSHUnixWorker(args[1], args[2])
	}
	return true, errors.New("invalid SSH worker role")
}

type tsSSHStdio struct {
	read, write *os.File
	once        sync.Once
}

func (c *tsSSHStdio) Read(b []byte) (int, error)  { return c.read.Read(b) }
func (c *tsSSHStdio) Write(b []byte) (int, error) { return c.write.Write(b) }
func (c *tsSSHStdio) Close() error                { c.once.Do(func() { c.read.Close(); c.write.Close() }); return nil }
func (c *tsSSHStdio) CloseWrite() error           { return c.write.Close() }
func (c *tsSSHStdio) LocalAddr() net.Addr         { return streamAddr("ssh-worker") }
func (c *tsSSHStdio) RemoteAddr() net.Addr        { return streamAddr("ssh-parent") }
func (c *tsSSHStdio) SetReadDeadline(t time.Time) error {
	e := c.read.SetReadDeadline(t)
	if errors.Is(e, os.ErrNoDeadline) {
		return nil
	}
	return e
}
func (c *tsSSHStdio) SetWriteDeadline(t time.Time) error {
	e := c.write.SetWriteDeadline(t)
	if errors.Is(e, os.ErrNoDeadline) {
		return nil
	}
	return e
}
func (c *tsSSHStdio) SetDeadline(t time.Time) error {
	if e := c.SetReadDeadline(t); e != nil {
		return e
	}
	return c.SetWriteDeadline(t)
}
func tsSSHRelayUser(a, b net.Conn) {
	defer a.Close()
	defer b.Close()
	done := make(chan struct{})
	copy := func(dst, src net.Conn) {
		_, e := io.Copy(dst, src)
		if e != nil {
			a.Close()
			b.Close()
			return
		}
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go func() { copy(a, b); close(done) }()
	copy(b, a)
	<-done
}
func tsSSHUnixPath(path string) bool {
	return path != "" && len(path) <= 4096 && !strings.ContainsRune(path, 0) && !strings.HasPrefix(path, "@")
}
func tsSSHUnixWorker(mode, path string) error {
	ready := os.NewFile(3, "ssh-worker-ready")
	defer ready.Close()
	announce := func(e error) {
		b := byte(0)
		if e != nil {
			b = 1
		}
		ready.Write([]byte{b})
		ready.Close()
	}
	if !tsSSHUnixPath(path) {
		e := errors.New("filesystem Unix socket path required")
		announce(e)
		return e
	}
	stdio := &tsSSHStdio{read: os.Stdin, write: os.Stdout}
	if mode == "unix-dial" {
		raw, e := net.DialTimeout("unix", path, 5*time.Second)
		announce(e)
		if e != nil {
			return e
		}
		tsSSHRelayUser(raw, stdio)
		return nil
	}
	listener, e := net.Listen("unix", path)
	if e == nil {
		e = os.Chmod(path, 0600)
	}
	if e != nil {
		if listener != nil {
			listener.Close()
		}
		announce(e)
		return e
	}
	announce(nil)
	mux := newSMUX(context.Background(), stdio, true)
	go func() { <-mux.done; listener.Close() }()
	var jobs sync.WaitGroup
	defer func() { mux.close(net.ErrClosed); listener.Close(); jobs.Wait() }()
	for {
		raw, e := listener.Accept()
		if e != nil {
			return nil
		}
		stream, e := mux.open(mux.ctx)
		if e != nil {
			raw.Close()
			continue
		}
		jobs.Add(1)
		go func() { defer jobs.Done(); tsSSHRelayUser(raw, stream) }()
	}
}

type tsSSHChildConn struct {
	*tsSSHStdio
	cancel context.CancelFunc
	cmd    *exec.Cmd
	done   chan struct{}
	once   sync.Once
}

func (c *tsSSHChildConn) Close() error {
	c.once.Do(func() { c.tsSSHStdio.Close(); c.cancel() })
	select {
	case <-c.done:
	case <-time.After(1200 * time.Millisecond):
		tsSSHKill(c.cmd)
	}
	return nil
}
func (conn *tsSSHConnection) unixWorker(mode, path string) (*tsSSHChildConn, error) {
	if !tsSSHUnixPath(path) {
		return nil, errors.New("invalid Unix socket path")
	}
	select {
	case conn.server.processes <- struct{}{}:
	default:
		return nil, errors.New("SSH worker capacity exhausted")
	}
	started := false
	defer func() {
		if !started {
			<-conn.server.processes
		}
	}()
	ctx, cancel := context.WithCancel(conn.ctx)
	fail := true
	defer func() {
		if fail {
			cancel()
		}
	}()
	cmd, e := tsSSHWorkerProcess(ctx, conn.user, conn.server.worker, mode, path)
	if e != nil {
		return nil, e
	}
	inRead, inWrite, e := os.Pipe()
	if e != nil {
		return nil, e
	}
	defer inRead.Close()
	outRead, outWrite, e := os.Pipe()
	if e != nil {
		inWrite.Close()
		return nil, e
	}
	defer outWrite.Close()
	readyRead, readyWrite, e := os.Pipe()
	if e != nil {
		inWrite.Close()
		outRead.Close()
		return nil, e
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inRead, outWrite, io.Discard
	cmd.ExtraFiles = []*os.File{readyWrite}
	if e = cmd.Start(); e != nil {
		inWrite.Close()
		outRead.Close()
		return nil, e
	}
	started = true
	child := &tsSSHChildConn{tsSSHStdio: &tsSSHStdio{read: outRead, write: inWrite}, cancel: cancel, cmd: cmd, done: make(chan struct{})}
	inRead.Close()
	outWrite.Close()
	readyWrite.Close()
	stop := context.AfterFunc(ctx, func() { child.Close() })
	go func() { cmd.Wait(); close(child.done); <-conn.server.processes; stop(); cancel() }()
	readyRead.SetReadDeadline(time.Now().Add(5 * time.Second))
	var status [1]byte
	_, e = io.ReadFull(readyRead, status[:])
	if e != nil || status[0] != 0 {
		child.Close()
		return nil, errors.New("Unix forwarding worker could not open socket")
	}
	fail = false
	return child, nil
}

type tsSSHUnixListener struct {
	worker *tsSSHChildConn
	mux    *smuxSession
	path   string
}

func (l *tsSSHUnixListener) Accept() (net.Conn, error) {
	select {
	case stream := <-l.mux.accept:
		return stream, nil
	case <-l.mux.done:
		return nil, net.ErrClosed
	}
}
func (l *tsSSHUnixListener) Close() error   { l.mux.close(net.ErrClosed); return l.worker.Close() }
func (l *tsSSHUnixListener) Addr() net.Addr { return streamAddr(l.path) }
func (conn *tsSSHConnection) unixGlobal(name string, b []byte) ([]byte, bool) {
	r := sshReader{b: b}
	path := string(r.str())
	if r.err != nil || len(r.b) != 0 || !tsSSHUnixPath(path) {
		return nil, false
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	key := "unix:" + path
	if name == "cancel-streamlocal-forward@openssh.com" {
		l := conn.listeners[key]
		if l == nil {
			return nil, false
		}
		l.Close()
		delete(conn.listeners, key)
		return nil, true
	}
	if len(conn.listeners) >= 16 || conn.listeners[key] != nil {
		return nil, false
	}
	child, e := conn.unixWorker("unix-listen", path)
	if e != nil {
		return nil, false
	}
	listener := &tsSSHUnixListener{worker: child, mux: newSMUX(conn.ctx, child, false), path: path}
	conn.listeners[key] = listener
	conn.forwards.Add(1)
	go func() {
		defer conn.forwards.Done()
		for {
			stream, e := listener.Accept()
			if e != nil {
				return
			}
			conn.forwards.Add(1)
			go func() {
				defer conn.forwards.Done()
				defer stream.Close()
				extra := sshText(sshText(nil, path), "")
				ch, e := conn.session.open(conn.ctx, "forwarded-streamlocal@openssh.com", extra)
				if e != nil {
					return
				}
				defer ch.Close()
				conn.server.c.r.relay(stream, ch)
			}()
		}
	}()
	return nil, true
}
