package native

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Keys identify the authenticated KIP hello; they are never exposed by the API.
type SudokuUserOptions struct {
	Alias     string    `json:"alias,omitempty"`
	Key       string    `json:"key"`
	Bandwidth []float64 `json:"bandwidth,omitempty"`
	Data      float64   `json:"data,omitempty"`
	Blocked   bool      `json:"blocked,omitempty"`
}

func sudokuUserHash(key string) (string, error) {
	key = strings.TrimSpace(key)
	if len(key) == 64 || len(key) == 128 {
		s, raw, err := sudokuParsePrivate(key)
		defer clear(raw)
		if err != nil || s == (sudokuScalar{}) {
			return "", errors.New("invalid Sudoku user private key")
		}
		h := sha256.Sum256(raw)
		return hex.EncodeToString(h[:8]), nil
	}
	if len(key) < 8 || len(key) > 16 {
		return "", errors.New("Sudoku user key must be a private key or8-16 hexadecimal hash characters")
	}
	for _, c := range key {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", errors.New("invalid Sudoku user hash prefix")
		}
	}
	return strings.ToLower(key), nil
}

func (o *SudokuOptions) validateUsers(client bool) error {
	if client && (len(o.Users) > 0 || o.UsagePath != "") {
		return errors.New("Sudoku users/usage_path are inbound-only")
	}
	if len(o.Users) > 1024 || o.UsagePath != "" && len(o.Users) == 0 {
		return errors.New("Sudoku usage_path requires1-1024 users")
	}
	seen := make(map[string]bool, len(o.Users))
	for i, u := range o.Users {
		hash, err := sudokuUserHash(u.Key)
		if err != nil {
			return fmt.Errorf("Sudoku users[%d]: %w", i, err)
		}
		if seen[hash] {
			return fmt.Errorf("duplicate Sudoku user at index%d", i)
		}
		seen[hash] = true
		if len(u.Alias) > 256 || strings.ContainsAny(u.Alias, "\r\n\x00") {
			return errors.New("invalid Sudoku user alias")
		}
		if len(u.Bandwidth) != 0 && len(u.Bandwidth) != 2 {
			return errors.New("Sudoku bandwidth requires[download,upload] Mbps")
		}
		for _, rate := range u.Bandwidth {
			if math.IsNaN(rate) || math.IsInf(rate, 0) || rate != 0 && (rate < 0.001 || rate > 1e6) {
				return errors.New("Sudoku bandwidth must be0 or0.001-1000000 Mbps")
			}
		}
		if math.IsNaN(u.Data) || math.IsInf(u.Data, 0) || u.Data < 0 || u.Data >= float64(math.MaxInt64)/1e9 || u.Data > 0 && u.Data*1e9 < 1 {
			return errors.New("Sudoku data quota is outside the supported byte range")
		}
		if u.Data > 0 && o.UsagePath == "" {
			return errors.New("Sudoku data quotas require usage_path for restart-safe accounting")
		}
	}
	return nil
}

type sudokuUsers struct {
	r           *Runtime
	inbound     string
	path        string
	all         []*sudokuUser
	exact       map[string]*sudokuUser
	prefixes    []*sudokuUser
	storeMu     sync.Mutex
	sequence    atomic.Uint64
	saved       uint64
	flush       chan struct{}
	lock        *os.File
	writeFailed atomic.Bool
}

type sudokuUser struct {
	registry         *sudokuUsers
	hash             string
	name             string
	blocked          bool
	limit            uint64
	rate             [2]sudokuBandwidth // upload,download
	mu               sync.Mutex
	sessions         map[*sudokuAccount]struct{}
	month            string
	resetAt          int64
	used             uint64
	up, down         atomic.Uint64
	upRate, downRate atomic.Uint64
}

func newSudokuUsers(r *Runtime, in Inbound) (*sudokuUsers, error) {
	o := in.Sudoku
	s := &sudokuUsers{r: r, inbound: in.Tag, path: o.UsagePath, exact: map[string]*sudokuUser{}, flush: make(chan struct{}, 1)}
	if s.path != "" {
		if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
			return nil, err
		}
		var err error
		s.lock, err = lockStateFile(s.path + ".lock")
		if err != nil {
			return nil, fmt.Errorf("lock Sudoku usage: %w", err)
		}
	}
	for _, spec := range o.Users {
		hash, _ := sudokuUserHash(spec.Key) // Parse has already validated credentials and bounds.
		name := strings.TrimSpace(spec.Alias)
		if name == "" {
			name = hash
		}
		u := &sudokuUser{registry: s, hash: hash, name: name, blocked: spec.Blocked, limit: uint64(spec.Data * 1e9), sessions: map[*sudokuAccount]struct{}{}}
		u.rollMonth(time.Now())
		if len(spec.Bandwidth) != 0 {
			u.rate[0].init(spec.Bandwidth[1])
			u.rate[1].init(spec.Bandwidth[0])
		}
		s.all = append(s.all, u)
		if len(hash) == 16 {
			s.exact[hash] = u
		} else {
			s.prefixes = append(s.prefixes, u)
		}
	}
	if err := s.load(); err != nil {
		if s.lock != nil {
			s.lock.Close()
		}
		return nil, fmt.Errorf("Sudoku inbound %s usage: %w", in.Tag, err)
	}
	return s, nil
}

func (s *sudokuUsers) authorize(a *sudokuAccount, hash []byte) error {
	key := hex.EncodeToString(hash)
	u := s.exact[key]
	if u == nil {
		for _, candidate := range s.prefixes {
			if strings.HasPrefix(key, candidate.hash) {
				u = candidate
				break
			}
		}
	}
	if u == nil || u.blocked {
		return errors.New("Sudoku user is not authorized")
	}
	if u.limit != 0 && s.writeFailed.Load() {
		return errors.New("Sudoku quota storage is unavailable")
	}
	return a.bind(u)
}

func (u *sudokuUser) rollMonth(now time.Time) {
	if now.Unix() < u.resetAt {
		return
	}
	u.month, u.used = now.Format("2006-01"), 0
	u.resetAt = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location()).Unix()
	if u.registry != nil {
		u.registry.sequence.Add(1)
	}
}

var errSudokuQuota = errors.New("Sudoku monthly data quota exceeded")

func (u *sudokuUser) record(up, down uint64) error {
	u.up.Add(up)
	u.down.Add(down)
	u.mu.Lock()
	u.rollMonth(time.Now())
	u.used += up + down
	exceeded := u.limit != 0 && u.used >= u.limit
	var closeList []*sudokuAccount
	if exceeded {
		for a := range u.sessions {
			closeList = append(closeList, a)
		}
	}
	u.mu.Unlock()
	u.registry.sequence.Add(1)
	for _, a := range closeList {
		a.Close()
	}
	if exceeded {
		select {
		case u.registry.flush <- struct{}{}:
		default:
		}
		return errSudokuQuota
	}
	return nil
}

// SudokuUserStat exposes counters and public aliases, never connection credentials.
type SudokuUserStat struct {
	Name      string `json:"name"`
	Inbound   string `json:"inbound"`
	Blocked   bool   `json:"blocked"`
	Exceeded  bool   `json:"exceeded"`
	Conns     int    `json:"conns"`
	Up        uint64 `json:"up"`
	Down      uint64 `json:"down"`
	UpTotal   uint64 `json:"upTotal"`
	DownTotal uint64 `json:"downTotal"`
	Used      uint64 `json:"used"`
	Limit     uint64 `json:"limit"`
}

// SudokuUserStats works without enabling the optional HTTP controller.
func (r *Runtime) SudokuUserStats() []SudokuUserStat {
	stats := make([]SudokuUserStat, 0)
	for _, registry := range r.sudokuUsers {
		for _, user := range registry.all {
			stats = append(stats, user.stat())
		}
	}
	return stats
}

func (u *sudokuUser) stat() SudokuUserStat {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.rollMonth(time.Now())
	return SudokuUserStat{u.name, u.registry.inbound, u.blocked, u.limit > 0 && u.used >= u.limit, len(u.sessions), u.upRate.Load(), u.downRate.Load(), u.up.Load(), u.down.Load(), u.used, u.limit}
}
