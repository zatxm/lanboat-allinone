package native

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const dnsStoreLimit = 64 << 20

type dnsStoreHeader struct {
	Version     int    `json:"version"`
	Fingerprint string `json:"fingerprint"`
}
type savedDNSEntry struct {
	Key      []byte    `json:"key"`
	Reply    []byte    `json:"reply"`
	Inserted time.Time `json:"inserted"`
	Until    time.Time `json:"until"`
}

func (o CacheFileOptions) bufferSize() (int, error) {
	value := strings.ToUpper(strings.TrimSpace(o.BufferSize))
	if value == "" {
		return 1 << 20, nil
	}
	units := []struct {
		suffix string
		size   float64
	}{{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30}, {"KB", 1000}, {"MB", 1000000}, {"GB", 1000000000}, {"B", 1}}
	multiplier := float64(1)
	for _, unit := range units {
		if strings.HasSuffix(value, unit.suffix) {
			value = strings.TrimSpace(strings.TrimSuffix(value, unit.suffix))
			multiplier = unit.size
			break
		}
	}
	n, e := strconv.ParseFloat(value, 64)
	n *= multiplier
	if e != nil || !(n >= 1 && n <= dnsStoreLimit) {
		return 0, errors.New("cache_file.buffer_size must be1 byte to64MiB")
	}
	return int(n), nil
}
func (r *resolver) dnsStorePath() string {
	if r.runtime == nil {
		return ""
	}
	o := r.runtime.config.Experimental.CacheFile
	if !o.Enabled || !o.StoreDNS {
		return ""
	}
	path := o.Path
	if path == "" {
		path = "cache.db"
	}
	id := sha256.Sum256([]byte(o.CacheID))
	return fmt.Sprintf("%s.%x.dns.jsonl", path, id[:8])
}
func (r *resolver) dnsStoreHeader() dnsStoreHeader {
	if r.persistHeader.Fingerprint != "" {
		return r.persistHeader
	}
	// A changed DNS, route or outbound identity must not reuse another policy's answers.
	data, _ := json.Marshal(struct {
		DNS       DNSConfig
		Servers   map[string]DNSServer
		Route     Route
		Outbounds []Outbound
	}{r.config, r.servers, r.runtime.config.Route, r.runtime.config.Outbounds})
	fingerprint := sha256.Sum256(data)
	r.persistHeader = dnsStoreHeader{Version: 1, Fingerprint: fmt.Sprintf("%x", fingerprint)}
	return r.persistHeader
}
func (r *resolver) retainDNS(until time.Time) bool {
	if r.config.DisableExpire {
		return true
	}
	if r.config.Optimistic.Enabled {
		d, _ := optionDuration(r.config.Optimistic.Timeout, 72*time.Hour)
		until = until.Add(d)
	}
	return time.Now().Before(until)
}
func (r *resolver) loadDNSCache() error {
	path := r.dnsStorePath()
	if path == "" {
		return nil
	}
	file, e := os.Open(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	defer file.Close()
	stat, e := file.Stat()
	if e != nil {
		return e
	}
	if stat.Size() > dnsStoreLimit {
		return errors.New("DNS cache exceeds64MiB")
	}
	scanner := bufio.NewScanner(io.LimitReader(file, dnsStoreLimit+1))
	scanner.Buffer(make([]byte, 4096), 256<<10)
	var header dnsStoreHeader
	if !scanner.Scan() {
		return errors.New("empty DNS cache header")
	}
	if e = json.Unmarshal(scanner.Bytes(), &header); e != nil {
		return fmt.Errorf("decode DNS cache header: %w", e)
	}
	if header != r.dnsStoreHeader() {
		return nil
	}
	r.wireLRU = list.New()
	for scanner.Scan() {
		var entry savedDNSEntry
		if e = json.Unmarshal(scanner.Bytes(), &entry); e != nil {
			return fmt.Errorf("decode DNS cache entry: %w", e)
		}
		if len(r.wireCache) >= max(1024, r.config.CacheCapacity) {
			return errors.New("DNS cache entry limit exceeded")
		}
		if !r.retainDNS(entry.Until) {
			continue
		}
		if len(entry.Key) > 65600 || len(entry.Reply) > 65535 || entry.Inserted.After(time.Now()) || !entry.Until.After(entry.Inserted) {
			return errors.New("invalid DNS cache entry")
		}
		var query []byte
		if bytes.HasPrefix(entry.Key, []byte("@local:")) {
			query = entry.Key[len("@local:"):]
		}
		servers := r.servers
		if len(servers) == 0 {
			servers = map[string]DNSServer{"": {}}
		}
		for tag := range servers {
			prefix := []byte(tag + ":")
			if bytes.HasPrefix(entry.Key, prefix) && (query == nil || len(entry.Key)-len(prefix) < len(query)) {
				query = entry.Key[len(prefix):]
			}
		}
		if len(query) < 12 {
			return errors.New("unknown DNS cache server")
		}
		reply := append([]byte(nil), entry.Reply...)
		copy(reply[:min(2, len(reply))], query[:2])
		host, _, _, err := validateDNSQuestionResponse(query, reply)
		if err != nil {
			return err
		}
		sections, err := dnsRecords(reply)
		if err != nil {
			return err
		}
		key := string(entry.Key)
		if _, exists := r.wireCache[key]; exists {
			return errors.New("duplicate DNS cache key")
		}
		r.wireCache[key] = r.wireLRU.PushBack(&dnsWireEntry{key: key, reply: entry.Reply, inserted: entry.Inserted, until: entry.Until})
		if r.config.ReverseMapping && time.Now().Before(entry.Until) {
			for _, rr := range sections[0] {
				if rr.typ == 1 || rr.typ == 28 {
					if ip, ok := netip.AddrFromSlice(rr.data); ok {
						if _, exists := r.reverse[ip]; !exists && len(r.reverse) < max(1024, r.config.CacheCapacity) {
							r.reverse[ip] = fakeEntry{host: host, until: entry.Until}
						}
					}
				}
			}
		}
	}
	return scanner.Err()
}
func (r *resolver) startDNSPersistence() {
	if r.dnsStorePath() == "" {
		return
	}
	_ = r.dnsStoreHeader()
	o := r.runtime.config.Experimental.CacheFile
	r.persistBuffer, _ = o.bufferSize()
	r.persistWake = make(chan struct{}, 1)
	interval, _ := optionDuration(o.FlushInterval, 0)
	r.persistWorkers.Add(1)
	go func() {
		defer r.persistWorkers.Done()
		var tick <-chan time.Time
		if interval > 0 {
			timer := time.NewTicker(interval)
			defer timer.Stop()
			tick = timer.C
		}
		for {
			select {
			case <-r.ctx.Done():
				return
			case <-r.persistWake:
			case <-tick:
			}
			if r.ctx.Err() != nil {
				return
			}
			r.saveDNSCache(false)
		}
	}()
}

// Called under the cache lock; a full buffer schedules one atomic snapshot.
func (r *resolver) dirtyDNS(bytes int) {
	if r.persistWake == nil {
		return
	}
	r.persistBytes += uint64(bytes)
	if r.persistBytes >= uint64(r.persistBuffer) {
		select {
		case r.persistWake <- struct{}{}:
		default:
		}
	}
}
func (r *resolver) saveDNSCache(force bool) {
	path := r.dnsStorePath()
	if path == "" {
		return
	}
	r.mu.Lock()
	dirty := r.persistBytes
	if !force && dirty == 0 {
		r.mu.Unlock()
		return
	}
	var entries []savedDNSEntry
	if r.wireLRU != nil {
		for p := r.wireLRU.Front(); p != nil; p = p.Next() {
			e := p.Value.(*dnsWireEntry)
			if r.retainDNS(e.until) {
				entries = append(entries, savedDNSEntry{Key: []byte(e.key), Reply: e.reply, Inserted: e.inserted, Until: e.until})
			}
		}
	}
	r.mu.Unlock()
	if e := r.writeDNSCache(path, entries); e != nil {
		logWarn(r.runtime.logger, e, "dns: save cache")
		return
	}
	r.mu.Lock()
	r.persistBytes -= min(r.persistBytes, dirty)
	r.mu.Unlock()
}
func (r *resolver) writeDNSCache(path string, entries []savedDNSEntry) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	file, e := os.CreateTemp(filepath.Dir(path), ".lanboat-dns-*")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	defer file.Close()
	size, _ := r.runtime.config.Experimental.CacheFile.bufferSize()
	writer := bufio.NewWriterSize(file, size)
	header, e := json.Marshal(r.dnsStoreHeader())
	if e != nil {
		return e
	}
	header = append(header, '\n')
	if _, e = writer.Write(header); e != nil {
		return e
	}
	total := len(header)
	for _, entry := range entries {
		data, e := json.Marshal(entry)
		if e != nil {
			return e
		}
		data = append(data, '\n')
		// Persist the most recently used prefix when the on-disk budget is full.
		if total+len(data) > dnsStoreLimit {
			break
		}
		total += len(data)
		if _, e = writer.Write(data); e != nil {
			return e
		}
	}
	if e = writer.Flush(); e != nil {
		return e
	}
	if e = file.Sync(); e != nil {
		return e
	}
	if e = file.Close(); e != nil {
		return e
	}
	return os.Rename(file.Name(), path)
}
