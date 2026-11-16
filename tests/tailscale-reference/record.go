package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"

	"tailscale.com/sessionrecording"
	"tailscale.com/tsnet"
)

type sshRecordSession struct {
	Header sessionrecording.CastHeader
	Events []json.RawMessage
}
type sshRecordHarness struct {
	mu       sync.Mutex
	mode     string
	sessions []sshRecordSession
	listener net.Listener
}

func (h *sshRecordHarness) start(s *tsnet.Server) error {
	l, e := s.Listen("tcp", ":8188")
	if e != nil {
		return e
	}
	h.listener = l
	go http.Serve(l, h)
	return nil
}
func (h *sshRecordHarness) close()              { h.listener.Close() }
func (h *sshRecordHarness) setMode(mode string) { h.mu.Lock(); h.mode = mode; h.mu.Unlock() }
func (h *sshRecordHarness) snapshot() []sshRecordSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]sshRecordSession, len(h.sessions))
	for i, s := range h.sessions {
		out[i] = sshRecordSession{Header: s.Header, Events: append([]json.RawMessage(nil), s.Events...)}
	}
	return out
}
func (h *sshRecordHarness) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	mode := h.mode
	h.mu.Unlock()
	if mode == "reject" {
		http.Error(w, "recorder unavailable", 503)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/record" || r.Header.Get("Expect") != "100-continue" {
		http.Error(w, "bad record request", 400)
		return
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	var session sshRecordSession
	if e := decoder.Decode(&session.Header); e != nil {
		http.Error(w, "bad cast header", 400)
		return
	}
	if session.Header.Version != 2 || session.Header.SSHUser == "" || session.Header.LocalUser == "" || session.Header.ConnectionID == "" {
		http.Error(w, "invalid cast header fields", 400)
		return
	}
	defer func() { h.mu.Lock(); h.sessions = append(h.sessions, session); h.mu.Unlock() }()
	for {
		var event json.RawMessage
		e := decoder.Decode(&event)
		if e == io.EOF {
			break
		}
		if e != nil {
			return
		}
		session.Events = append(session.Events, event)
		if mode == "drop" {
			raw, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				raw.Close()
			}
			return
		}
		if len(session.Events) > 4096 {
			http.Error(w, "too many events", 400)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}
