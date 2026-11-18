package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type RuleSet struct {
	tags           []string
	InitialPath    string          `json:"initial_path,omitempty"`
	HTTPClient     clientReference `json:"http_client,omitempty"`
	Type           string          `json:"type"`
	Tag            string          `json:"tag"`
	Format         string          `json:"format,omitempty"`
	Path           string          `json:"path,omitempty"`
	URL            string          `json:"url,omitempty"`
	DownloadDetour string          `json:"download_detour,omitempty"`
	UpdateInterval string          `json:"update_interval,omitempty"`
	Rules          []Rule          `json:"rules,omitempty"`
}

func (s *RuleSet) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	var tags []string
	if b := fields["tag"]; len(b) > 0 && b[0] == '[' {
		if e := json.Unmarshal(b, &tags); e != nil {
			return e
		}
		if len(tags) == 0 {
			return errors.New("empty rule_set tags")
		}
		fields["tag"], _ = json.Marshal(tags[0])
	}
	data, e := json.Marshal(fields)
	if e != nil {
		return e
	}
	type plain RuleSet
	if e = decodeOptions(data, (*plain)(s)); e != nil {
		return e
	}
	s.tags = tags
	if s.Type == "" {
		s.Type = "inline"
	}
	return nil
}

func (s RuleSet) validate() error {
	if s.Tag == "" {
		return errors.New("rule_set tag is required")
	}
	switch s.Type {
	case "inline":
		if s.Path != "" || s.URL != "" {
			return errors.New("inline rule_set cannot have path or URL")
		}
	case "local":
		if s.Path == "" {
			return errors.New("local rule_set requires path")
		}
	case "remote":
		u, err := url.Parse(s.URL)
		if err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" || u.User != nil {
			return errors.New("remote rule_set requires an HTTP(S) URL")
		}
	default:
		return fmt.Errorf("invalid rule_set type %q", s.Type)
	}
	if s.Format != "" && s.Format != "source" && s.Format != "binary" {
		return errors.New("rule_set format must be source or binary")
	}
	if s.UpdateInterval != "" {
		d, err := optionDuration(s.UpdateInterval, 24*time.Hour)
		if err != nil || d < time.Second {
			return errors.New("rule_set update_interval must be at least 1s")
		}
	}
	return nil
}

type ruleSnapshot struct {
	updatedAt      time.Time
	preMatchFields uint32
	rules          []routeRule
	hasIP          bool
}
type ruleCollection struct {
	update  sync.Mutex
	current atomic.Pointer[ruleSnapshot]
}

func (s *ruleCollection) store(snapshot *ruleSnapshot) {
	snapshot.updatedAt = time.Now()
	s.current.Store(snapshot)
}

func (s *ruleCollection) matches(q request) bool        { return s.eval(&q) == matchYes }
func (s *ruleCollection) evaluate(q request) routeMatch { return s.eval(&q) }
func (s *ruleCollection) eval(q *request) routeMatch {
	snapshot := s.current.Load()
	if snapshot == nil {
		return matchNo
	}
	result := matchNo
	for i := range snapshot.rules {
		rule := &snapshot.rules[i]
		m := rule.eval(q)
		if m == matchYes {
			return matchYes
		}
		if m == matchUnknown {
			result = m
		}
	}
	return result
}
func (s *ruleCollection) needsIP() bool { v := s.current.Load(); return v != nil && v.hasIP }

func parseRuleSet(data []byte, format string) ([]Rule, error) {
	if len(data) > 64<<20 {
		return nil, errors.New("rule_set exceeds 64MiB")
	}
	if format == "binary" || format == "" && bytes.HasPrefix(data, []byte("SRS")) {
		return readSRS(data)
	}
	var file struct {
		Version int    `json:"version"`
		Rules   []Rule `json:"rules"`
	}
	if err := decodeOptions(data, &file); err != nil {
		return nil, err
	}
	if file.Version < 1 || file.Version > 5 {
		return nil, errors.New("unsupported rule_set source version")
	}
	return file.Rules, nil
}
func compileRuleSet(items []Rule) (*ruleSnapshot, error) {
	var checkMode func([]Rule) bool
	checkMode = func(items []Rule) bool {
		for _, o := range items {
			if o.ClashMode != "" || len(o.Client) > 0 || checkMode(o.Rules) {
				return true
			}
		}
		return false
	}
	if checkMode(items) {
		return nil, errors.New("clash_mode/client belong to route/DNS rules, not headless rule sets")
	}
	if len(dnsNetworkTags(items))+len(dnsPreferredTags(items)) > 0 {
		return nil, errors.New("DNS network conditions belong to route/DNS rules, not headless rule sets")
	}
	prepared := make([]Rule, len(items))
	copy(prepared, items)
	for i := range prepared {
		if prepared[i].NetworkStrategy != "" || len(prepared[i].FallbackNetworkType) > 0 || prepared[i].FallbackDelay != "" || prepared[i].Action != "" || prepared[i].Outbound != "" || len(prepared[i].RuleSet) > 0 {
			return nil, errors.New("headless rule_set rules cannot select outbounds or reference other rule sets")
		}
		prepared[i].Outbound = "_"
	}
	rules, err := compileRoute(Route{Final: "_", Rules: prepared}, map[string]Outbound{"_": {Type: "direct", Tag: "_"}})
	if err != nil {
		return nil, err
	}
	snapshot := &ruleSnapshot{rules: rules}
	for _, rule := range rules {
		snapshot.hasIP = snapshot.hasIP || rule.needsIP()
		snapshot.preMatchFields |= rule.preMatchFields
	}
	return snapshot, nil
}
func (r *Runtime) loadRuleSet(ctx context.Context, s RuleSet, refresh bool) error {
	set := r.ruleSets[s.Tag]
	// Serialize reads as well as publication: an older slow load must not
	// overwrite a newer manual reload or its on-disk cache.
	set.update.Lock()
	defer set.update.Unlock()
	var data []byte
	var err error
	if s.Type == "inline" {
		snapshot, err := compileRuleSet(s.Rules)
		if err == nil {
			r.publishRuleSet(set, snapshot)
		}
		return err
	}
	if s.Type == "local" {
		data, err = readRuleFile(s.Path)
	} else {
		cache := r.ruleSetCachePath(s)
		initial := s.InitialPath
		if initial == "" {
			initial = s.Path
		}
		if !refresh && (cache != "" || initial != "") {
			data, err = readRuleFile(cache)
			if err != nil && initial != "" {
				data, err = readRuleFile(initial)
			}
			if err == nil {
				if items, e := parseRuleSet(data, s.Format); e == nil {
					if snap, e := compileRuleSet(items); e == nil {
						r.ruleSets[s.Tag].store(snap)
						return nil
					}
				}
			}
		}
		client, transport, e := r.ruleHTTPClient(s)
		if e != nil {
			return e
		}
		defer transport.CloseIdleConnections()
		req, e := http.NewRequestWithContext(ctx, "GET", s.URL, nil)
		if e != nil {
			return e
		}
		options, e := r.httpClientOptions(s.HTTPClient)
		if e != nil {
			return e
		}
		for k, v := range options.Headers {
			if strings.EqualFold(k, "Host") {
				req.Host = v[0]
			} else {
				req.Header[http.CanonicalHeaderKey(k)] = []string(v)
			}
		}
		response, e := client.Do(req)
		if e != nil {
			return e
		}
		defer response.Body.Close()
		requiredVersion := options.Version
		if requiredVersion == 0 {
			requiredVersion = 2
		}
		if options.DisableVersionFallback && requiredVersion > response.ProtoMajor {
			return errors.New("HTTP version fallback is disabled")
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("rule_set download HTTP %d", response.StatusCode)
		}
		data, err = io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	}
	if err != nil {
		return err
	}
	items, err := parseRuleSet(data, s.Format)
	if err != nil {
		return fmt.Errorf("rule_set %s: %w", s.Tag, err)
	}
	snapshot, err := compileRuleSet(items)
	if err != nil {
		return err
	}
	if s.Type == "remote" && r.ruleSetCachePath(s) != "" {
		if err := saveRuleCache(r.ruleSetCachePath(s), data); err != nil {
			return err
		}
	}
	r.publishRuleSet(set, snapshot)
	return nil
}
func (r *Runtime) ruleSetCachePath(s RuleSet) string {
	if s.Path != "" {
		return s.Path
	}
	if !r.config.Experimental.CacheFile.Enabled {
		return ""
	}
	root := r.config.Experimental.CacheFile.Path
	if root == "" {
		root = "cache.db"
	}
	options, _ := r.httpClientOptions(s.HTTPClient)
	encoded, _ := json.Marshal(options)
	h := sha256.Sum256([]byte(s.URL + "\x00" + string(encoded) + "\x00" + r.config.Experimental.CacheFile.CacheID))
	return filepath.Join(root+".rules", fmt.Sprintf("%x.srs", h))
}
func readRuleFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, (64<<20)+1))
}
func saveRuleCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".lanboat-rule-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
func (r *Runtime) updateRuleSets() {
	defer r.workers.Done()
	next := map[string]time.Time{}
	fingerprints := map[string]string{}
	fingerprint := func(path string) string {
		st, e := os.Stat(path)
		if e != nil {
			return ""
		}
		return fmt.Sprintf("%d:%d", st.ModTime().UnixNano(), st.Size())
	}
	for _, s := range r.config.Route.RuleSet {
		if s.Type == "local" {
			next[s.Tag] = time.Now().Add(time.Second)
			fingerprints[s.Tag] = ""
		}
		if s.Type == "remote" {
			interval := 24 * time.Hour
			if s.UpdateInterval != "" {
				interval, _ = optionDuration(s.UpdateInterval, 24*time.Hour)
			}
			next[s.Tag] = time.Now().Add(interval)
		}
	}
	for {
		var earliest time.Time
		for _, at := range next {
			if earliest.IsZero() || at.Before(earliest) {
				earliest = at
			}
		}
		if earliest.IsZero() {
			return
		}
		timer := time.NewTimer(time.Until(earliest))
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case now := <-timer.C:
			for _, s := range r.config.Route.RuleSet {
				at, ok := next[s.Tag]
				if !ok || now.Before(at) {
					continue
				}
				observed := ""
				interval := 24 * time.Hour
				if s.Type == "local" {
					interval = time.Second
					observed = fingerprint(s.Path)
					if observed == fingerprints[s.Tag] && observed != "" {
						next[s.Tag] = time.Now().Add(interval)
						continue
					}
				}
				if s.UpdateInterval != "" {
					interval, _ = optionDuration(s.UpdateInterval, 24*time.Hour)
				}
				if err := r.loadRuleSet(r.ctx, s, true); err != nil {
					logWarn(r.logger, err, "router: update rule-set ", s.Tag, ", retaining current rules")
					interval = min(interval, time.Minute)
				} else if s.Type == "local" {
					fingerprints[s.Tag] = observed
				}
				next[s.Tag] = time.Now().Add(interval)
			}
		}
	}
}

// ReloadRuleSets validates complete snapshots before publishing each replacement.
func (r *Runtime) ReloadRuleSets(ctx context.Context) error {
	for _, s := range r.config.Route.RuleSet {
		if err := r.loadRuleSet(ctx, s, true); err != nil {
			return err
		}
	}
	return nil
}
