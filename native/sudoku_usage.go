package native

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

const sudokuUsageMax = 1 << 20

type sudokuSavedUsage struct {
	Version int                           `json:"version"`
	Users   map[string]sudokuMonthlyUsage `json:"users"`
}
type sudokuMonthlyUsage struct {
	Month string `json:"month"`
	Used  uint64 `json:"used"`
}

func (s *sudokuUsers) load() error {
	if s.path == "" {
		return nil
	}
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, sudokuUsageMax+1))
	if err != nil {
		return err
	}
	if len(data) > sudokuUsageMax {
		return errors.New("usage file exceeds1MiB")
	}
	var saved sudokuSavedUsage
	if err = decodeOptions(data, &saved); err != nil {
		return fmt.Errorf("decode usage: %w", err)
	}
	if saved.Version != 1 || saved.Users == nil || len(saved.Users) > 1024 {
		return errors.New("invalid Sudoku usage schema")
	}
	for hash, entry := range saved.Users {
		prefix, e := sudokuUserHash(hash)
		if e != nil || hash != prefix || len(hash) > 16 || entry.Used > math.MaxInt64 {
			return errors.New("invalid Sudoku usage entry")
		}
		if _, err := time.Parse("2006-01", entry.Month); err != nil {
			return errors.New("invalid Sudoku usage month")
		}
		if entry.Month > time.Now().Format("2006-01") {
			return errors.New("Sudoku usage is dated in the future")
		}
	}
	for _, u := range s.all {
		entry, ok := saved.Users[u.hash]
		if ok && entry.Month == u.month {
			u.used = entry.Used
		}
	}
	return nil
}

func (s *sudokuUsers) save() error {
	if s.path == "" {
		return nil
	}
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	sequence := s.sequence.Load()
	if sequence == s.saved {
		return nil
	}
	saved := sudokuSavedUsage{Version: 1, Users: make(map[string]sudokuMonthlyUsage, len(s.all))}
	for _, u := range s.all {
		u.mu.Lock()
		u.rollMonth(time.Now())
		saved.Users[u.hash] = sudokuMonthlyUsage{u.month, u.used}
		u.mu.Unlock()
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".lanboat-sudoku-usage-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = json.NewEncoder(f).Encode(saved); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	s.saved = sequence
	return nil
}

func (s *sudokuUsers) persist() error {
	err := s.save()
	s.writeFailed.Store(err != nil)
	if err == nil {
		return nil
	}
	var sessions []*sudokuAccount
	for _, u := range s.all {
		if u.limit == 0 {
			continue
		}
		u.mu.Lock()
		for a := range u.sessions {
			sessions = append(sessions, a)
		}
		u.mu.Unlock()
	}
	for _, a := range sessions {
		a.Close()
	}
	return err
}

func (s *sudokuUsers) run() {
	defer s.r.workers.Done()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	before := time.Now()
	previous := make([][2]uint64, len(s.all))
	for i, u := range s.all {
		previous[i] = [2]uint64{u.up.Load(), u.down.Load()}
	}
	lastSave := before
	for {
		select {
		case <-s.r.ctx.Done():
			return
		case <-s.flush:
			if err := s.persist(); err != nil {
				logError(s.r.logger, err, s.r.inboundLabel(s.inbound), ": save usage")
			}
		case now := <-tick.C:
			elapsed := now.Sub(before).Seconds()
			for i, u := range s.all {
				up, down := u.up.Load(), u.down.Load()
				u.upRate.Store(uint64(float64(up-previous[i][0]) / elapsed))
				u.downRate.Store(uint64(float64(down-previous[i][1]) / elapsed))
				previous[i] = [2]uint64{up, down}
				u.mu.Lock()
				u.rollMonth(now)
				u.mu.Unlock()
			}
			before = now
			if now.Sub(lastSave) >= time.Minute {
				if err := s.persist(); err != nil {
					logError(s.r.logger, err, s.r.inboundLabel(s.inbound), ": save usage")
				}
				lastSave = now
			}
		}
	}
}
