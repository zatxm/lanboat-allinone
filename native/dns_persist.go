package native

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go.uber.org/zap"
	"net/netip"
	"os"
	"strconv"
	"time"
)

type savedFakeEntry struct {
	IP    netip.Addr `json:"ip"`
	Host  string     `json:"host"`
	Until time.Time  `json:"until"`
}

func (r *resolver) fakeCachePath() string {
	if r.runtime == nil {
		return ""
	}
	options := r.runtime.config.Experimental.CacheFile
	if !options.Enabled || !options.StoreFakeIP {
		return ""
	}
	path := options.Path
	if path == "" {
		path = "cache.db"
	}
	sum := sha256.Sum256([]byte(options.CacheID))
	return fmt.Sprintf("%s.%x.fakeip.json", path, sum[:8])
}
func (r *resolver) loadFakeCache() error {
	path := r.fakeCachePath()
	if path == "" {
		return nil
	}
	data, e := readRuleFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if len(data) > 64<<20 {
		return fmt.Errorf("FakeIP cache exceeds64MiB")
	}
	var saved map[string][]savedFakeEntry
	if e = json.Unmarshal(data, &saved); e != nil {
		return e
	}
	for tag, entries := range saved {
		p := r.pools[tag]
		if p == nil {
			continue
		}
		for _, entry := range entries {
			if len(p.byIP) >= p.capacity {
				break
			}
			if time.Now().After(entry.Until) || !p.v4.Contains(entry.IP) && !p.v6.Contains(entry.IP) {
				continue
			}
			if _, e := makeDNSQuery(entry.Host, 1); e != nil {
				continue
			}
			typ := 1
			if entry.IP.Is6() {
				typ = 28
			}
			key := entry.Host + ":" + strconv.Itoa(typ)
			if _, ok := p.byHost[key]; ok {
				continue
			}
			if _, ok := p.byIP[entry.IP]; ok {
				continue
			}
			p.byIP[entry.IP] = fakeEntry{host: entry.Host, until: entry.Until}
			p.byHost[key] = entry.IP
		}
	}
	return nil
}
func (r *resolver) saveFakeCache() {
	path := r.fakeCachePath()
	if path == "" {
		return
	}
	saved := map[string][]savedFakeEntry{}
	for tag, p := range r.pools {
		p.mu.Lock()
		for ip, entry := range p.byIP {
			if time.Now().Before(entry.until) {
				saved[tag] = append(saved[tag], savedFakeEntry{IP: ip, Host: entry.host, Until: entry.until})
			}
		}
		p.mu.Unlock()
	}
	data, e := json.Marshal(saved)
	if e == nil {
		e = saveRuleCache(path, data)
	}
	if e != nil {
		r.runtime.logger.Warn("FakeIP cache save failed", zap.Error(e))
	}
}
