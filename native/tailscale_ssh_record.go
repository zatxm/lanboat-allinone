package native

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

type tsSSHRecordingAttempt struct {
	Recorder       netip.AddrPort
	FailureMessage string
}
type tsSSHRecording struct {
	conn        *tsSSHConnection
	cancel      context.CancelFunc
	stopProcess context.CancelFunc
	pipe        *io.PipeWriter
	transport   *http.Transport
	done        chan struct{}
	result      error // published by closing done
	started     atomic.Bool
	closing     atomic.Bool
	failure     atomic.Pointer[error]
	fatal       atomic.Bool
	once        sync.Once
	mu          sync.Mutex
	at          time.Time
	carry       []byte
	attempts    []tsSSHRecordingAttempt
}
type tsSSHRecordingSocket struct {
	net.Conn
	abort func(error)
}

func (c tsSSHRecordingSocket) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if e != nil {
		c.abort(e)
	}
	return n, e
}
func (c tsSSHRecordingSocket) Close() error { c.abort(io.ErrClosedPipe); return c.Conn.Close() }

func (c tsSSHRecordingSocket) Write(b []byte) (int, error) {
	c.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return c.Conn.Write(b)
}
func (conn *tsSSHConnection) recordingHeader(command, term string, width, height uint32) map[string]any {
	c := conn.server.c
	c.mu.Lock()
	n := c.nodes[c.addressOwners[conn.source]]
	login := c.userLogins[n.User]
	c.mu.Unlock()
	header := map[string]any{"version": 2, "width": width, "height": height, "timestamp": time.Now().Unix(), "command": command, "srcNode": strings.TrimSuffix(n.Name, "."), "srcNodeID": n.StableID, "sshUser": conn.requested, "localUser": conn.user.Username, "connectionID": conn.id, "env": map[string]string{"TERM": term}}
	if len(n.Tags) > 0 {
		header["srcNodeTags"] = n.Tags
	} else {
		header["srcNodeUserID"] = n.User
		header["srcNodeUser"] = login
	}
	return header
}
func (conn *tsSSHConnection) startRecording(ctx context.Context, stop context.CancelFunc, command, term string, width, height uint32) (*tsSSHRecording, error) {
	if len(conn.grant.action.Recorders) == 0 {
		return nil, nil
	}
	budget, cancelBudget := context.WithTimeout(ctx, 30*time.Second)
	defer cancelBudget()
	var attempts []tsSSHRecordingAttempt
	header := conn.recordingHeader(command, term, width, height)
	for _, address := range conn.grant.action.Recorders {
		if budget.Err() != nil {
			break
		}
		attempt := tsSSHRecordingAttempt{Recorder: address}
		if !address.IsValid() || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
			attempt.FailureMessage = "invalid recorder address"
			attempts = append(attempts, attempt)
			continue
		}
		requestCtx, cancel := context.WithCancel(ctx)
		reader, writer := io.Pipe()
		record := &tsSSHRecording{conn: conn, cancel: cancel, stopProcess: stop, pipe: writer, done: make(chan struct{}), at: time.Now()}
		record.transport = &http.Transport{ExpectContinueTimeout: 30 * time.Second, ResponseHeaderTimeout: 30 * time.Second, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
			defer dialCancel()
			raw, e := conn.server.c.dial(dialCtx, network, target)
			if e != nil {
				return nil, e
			}
			return tsSSHRecordingSocket{Conn: raw, abort: func(e error) { reader.CloseWithError(e) }}, nil
		}}
		ready := make(chan struct{})
		var announced atomic.Bool
		trace := &httptrace.ClientTrace{Got100Continue: func() {
			if announced.CompareAndSwap(false, true) {
				close(ready)
			}
		}}
		requestCtx = httptrace.WithClientTrace(requestCtx, trace)
		req, e := http.NewRequestWithContext(requestCtx, "POST", "http://"+address.String()+"/record", reader)
		if e != nil {
			cancel()
			reader.Close()
			writer.Close()
			return nil, e
		}
		req.Header.Set("Expect", "100-continue")
		req.Header.Set("Content-Type", "application/x-asciicast")
		go func() {
			response, e := record.transport.RoundTrip(req)
			if e == nil {
				if response.StatusCode != http.StatusOK {
					e = errors.New("SSH recorder rejected upload")
				}
				io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
				response.Body.Close()
			}
			reader.Close()
			record.result = e
			close(record.done)
		}()
		select {
		case <-ready:
			record.at = time.Now()
			header["timestamp"] = record.at.Unix()
			e = json.NewEncoder(writer).Encode(header)
		case <-record.done:
			e = errors.New("SSH recorder did not accept streaming upload")
		case <-budget.Done():
			e = budget.Err()
		}
		if e == nil {
			select {
			case <-record.done:
				e = errors.New("SSH recorder closed before session start")
			default:
			}
		}
		if e != nil {
			cancel()
			writer.CloseWithError(e)
			record.transport.CloseIdleConnections()
			attempt.FailureMessage = "recorder connection failed"
			attempts = append(attempts, attempt)
			continue
		}
		record.attempts = append(attempts, attempt)
		conn.server.c.spawn(func() {
			<-record.done
			if !record.closing.Load() {
				e := record.result
				if e == nil {
					e = errors.New("SSH recorder ended upload prematurely")
				}
				record.fail(e, !record.started.Load())
			}
		})
		return record, nil
	}
	err := errors.New("no SSH recorder available")
	closed := conn.recordingFailure(true, attempts)
	if closed {
		return nil, err
	}
	return nil, nil
}
func (r *tsSSHRecording) fail(e error, initial bool) {
	r.once.Do(func() {
		policy := r.conn.grant.action.OnRecordingFailure
		fatal := policy != nil && (initial && policy.RejectSessionWithMessage != "" || !initial && policy.TerminateSessionWithMessage != "")
		r.fatal.Store(fatal)
		r.failure.Store(&e)
		r.pipe.CloseWithError(e)
		if fatal {
			r.stopProcess()
		}
		logDebug(r.conn.server.c.r.logger, e, "tailscale: SSH recording failed")
		r.conn.recordingFailure(initial, r.attempts)
	})
}
func (conn *tsSSHConnection) recordingFailure(initial bool, attempts []tsSSHRecordingAttempt) bool {
	policy := conn.grant.action.OnRecordingFailure
	event, message := 3, ""
	if policy != nil {
		if initial {
			message = policy.RejectSessionWithMessage
			if message != "" {
				event = 1
			}
		} else {
			message = policy.TerminateSessionWithMessage
			if message != "" {
				event = 2
			}
		}
	}
	if policy != nil && policy.NotifyURL != "" {
		c := conn.server.c
		c.spawn(func() {
			u, e := url.Parse(policy.NotifyURL)
			if e != nil || u.User != nil || u.Fragment != "" || len(policy.NotifyURL) > 16384 || !strings.HasPrefix(u.Path, "/") {
				return
			}
			c.mu.Lock()
			source := c.nodes[c.addressOwners[conn.source]]
			c.mu.Unlock()
			payload := map[string]any{"EventType": event, "ConnectionID": conn.id, "CapVersion": tailscaleCapability, "NodeKey": tsKeyName(c.nodeKey, "nodekey"), "SrcNode": source.ID, "SSHUser": conn.requested, "LocalUser": conn.grant.local, "RecordingAttempts": attempts}
			ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
			defer cancel()
			response, e := c.controlRequest(ctx, u.RequestURI(), payload)
			if e == nil {
				response.Body.Close()
			}
		})
	}
	if message == "" {
		return false
	}
	conn.server.c.spawn(func() {
		end := time.AfterFunc(250*time.Millisecond, conn.cancel)
		defer end.Stop()
		defer conn.cancel()
		conn.session.wire.SetWriteDeadline(time.Now().Add(250 * time.Millisecond))
		conn.session.send(sshText(sshText(sshInt([]byte{1}, 11), message[:min(len(message), 4096)]), ""))
	})
	return true
}
func (r *tsSSHRecording) outputLocked(b []byte) error {
	if failure := r.failure.Load(); failure != nil {
		if r.fatal.Load() {
			return *failure
		}
		return nil
	}
	if len(r.carry) > 0 {
		b = append(append([]byte(nil), r.carry...), b...)
		r.carry = nil
	}
	end := len(b)
	for start := max(0, len(b)-3); start < len(b); start++ {
		if utf8.RuneStart(b[start]) && !utf8.FullRune(b[start:]) {
			end = start
			r.carry = append(r.carry[:0], b[start:]...)
			break
		}
	}
	if end == 0 {
		return nil
	}
	e := json.NewEncoder(r.pipe).Encode([]any{time.Since(r.at).Seconds(), "o", string(b[:end])})
	if e != nil {
		r.fail(e, !r.started.Load())
		if r.fatal.Load() {
			return e
		}
	}
	return nil
}
func (r *tsSSHRecording) event(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.outputLocked(b)
}
func (r *tsSSHRecording) resize(width, height uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure.Load() != nil {
		return
	}
	if e := json.NewEncoder(r.pipe).Encode([]any{time.Since(r.at).Seconds(), "r", strconv.FormatUint(uint64(width), 10) + "x" + strconv.FormatUint(uint64(height), 10)}); e != nil {
		r.fail(e, !r.started.Load())
	}
}
func (r *tsSSHRecording) close() {
	r.closing.Store(true)
	r.mu.Lock()
	if len(r.carry) > 0 {
		json.NewEncoder(r.pipe).Encode([]any{time.Since(r.at).Seconds(), "o", string(r.carry)})
		r.carry = nil
	}
	r.pipe.Close()
	r.mu.Unlock()
	select {
	case <-r.done:
		if r.result != nil {
			r.fail(r.result, !r.started.Load())
		}
	case <-time.After(5 * time.Second):
		r.fail(errors.New("SSH recorder did not finish upload"), !r.started.Load())
	}
	r.cancel()
	r.transport.CloseIdleConnections()
}

type tsSSHRecordedOutput struct {
	record   *tsSSHRecording
	channel  *sshChannel
	extended bool
}

func (w tsSSHRecordedOutput) Write(b []byte) (int, error) {
	w.record.mu.Lock()
	defer w.record.mu.Unlock()
	if e := w.record.outputLocked(b); e != nil {
		return 0, e
	}
	return w.channel.write(b, w.extended)
}
