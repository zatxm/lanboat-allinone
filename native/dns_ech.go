package native

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type echLookupKey struct{}
type echLookupTrail struct {
	name   string
	parent *echLookupTrail
}

type dnsSVCB struct {
	priority uint16
	target   string
	params   map[uint16][]byte
}

func parseSVCB(data []byte) (dnsSVCB, error) {
	var s dnsSVCB
	if len(data) < 3 {
		return s, errors.New("short SVCB record")
	}
	s.priority = binary.BigEndian.Uint16(data)
	pos := 2
	for {
		if pos == len(data) || data[pos] > 63 {
			return s, errors.New("invalid or compressed SVCB target")
		}
		n := int(data[pos])
		pos++
		if n == 0 {
			break
		}
		if pos+n > len(data) {
			return s, errors.New("truncated SVCB target")
		}
		pos += n
	}
	name, _, err := dnsName(data, 2)
	if err != nil {
		return s, err
	}
	s.target = name
	s.params = make(map[uint16][]byte)
	r := echReader{b: data[pos:]}
	last := -1
	for len(r.b) > 0 && r.err == nil {
		key, value := r.u16(), r.vec()
		if int(key) <= last {
			return s, errors.New("SVCB keys must be unique and increasing")
		}
		last = int(key)
		s.params[key] = value
	}
	if r.err != nil {
		return s, r.err
	}
	if s.priority != 0 {
		return s, validateSVCBParams(s.params)
	}
	return s, nil
}

func (s dnsSVCB) echUsable() bool {
	mandatory := s.params[0]
	if _, exists := s.params[0]; exists && len(mandatory) == 0 {
		return false
	}
	if len(mandatory)%2 != 0 {
		return false
	}
	last := uint16(0)
	for len(mandatory) > 0 {
		key := binary.BigEndian.Uint16(mandatory)
		mandatory = mandatory[2:]
		_, present := s.params[key]
		if key <= last || key > 6 || !present {
			return false
		}
		last = key
	}
	return len(s.params[5]) > 0 // ech SvcParamKey is5, IPv6 hints use6.
}

func (r *resolver) lookupECH(ctx context.Context, name string) ([]byte, error) {
	name = strings.ToLower(name)
	if !echDomain(name) {
		return nil, errors.New("invalid ECH lookup name")
	}
	trail, _ := ctx.Value(echLookupKey{}).(*echLookupTrail)
	for p, depth := trail, 0; p != nil; p, depth = p.parent, depth+1 {
		if p.name == name || depth == 7 {
			return nil, errors.New("ECH DNS discovery cycle")
		}
	}
	ctx, cancel := context.WithTimeout(context.WithValue(ctx, echLookupKey{}, &echLookupTrail{name, trail}), handshakeTimeout)
	defer cancel()
	var records []dnsRecord
	seen := make(map[string]bool)
	for range 8 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, errors.New("ECH DNS alias cycle")
		}
		seen[name] = true
		has := false
		for _, rr := range records {
			has = has || rr.name == name && (rr.typ == 65 || rr.typ == 5)
		}
		if !has {
			query, err := makeDNSQuery(name, 65)
			if err != nil {
				return nil, err
			}
			var reply []byte
			if forced, _ := ctx.Value(dnsBootstrapKey{}).(string); forced != "" {
				reply, err = r.exchangeDNSOn(ctx, forced, query, dnsContextOptions(ctx), true)
			} else {
				reply, err = r.exchangePolicy(ctx, query, true)
			}
			if err != nil {
				return nil, fmt.Errorf("ECH HTTPS lookup: %w", err)
			}
			if len(reply) < 12 || reply[3]&15 != 0 {
				return nil, errors.New("ECH HTTPS lookup returned a DNS error")
			}
			sections, err := dnsRecords(reply)
			if err != nil {
				return nil, err
			}
			records = sections[0]
		}
		var next string
		priority := 65536
		var selected []byte
		for _, rr := range records {
			if rr.name != name {
				continue
			}
			if rr.typ == 5 {
				alias, _, err := dnsName(rr.data, 0)
				if err != nil {
					return nil, err
				}
				if next != "" && next != alias {
					return nil, errors.New("conflicting ECH DNS aliases")
				}
				next = alias
				continue
			}
			if rr.typ != 65 {
				continue
			}
			s, err := parseSVCB(rr.data)
			if err != nil {
				return nil, err
			}
			if s.priority == 0 {
				if s.target != "" && next != "" && next != s.target {
					return nil, errors.New("conflicting ECH HTTPS aliases")
				}
				next = s.target
			} else if s.echUsable() && int(s.priority) < priority {
				if validateECHList(s.params[5]) == nil {
					selected, priority = s.params[5], int(s.priority)
				}
			}
		}
		if next != "" {
			if !echDomain(next) {
				return nil, errors.New("invalid ECH alias name")
			}
			name = next
			continue
		}
		if selected != nil {
			return selected, nil
		}
		return nil, errors.New("HTTPS response has no usable ECH configuration")
	}
	return nil, errors.New("ECH DNS aliases exceed8 hops")
}

func (r *resolver) prepareTLS(ctx context.Context, s DNSServer, c *tls.Config) (*tls.Config, error) {
	if s.TLS.ECH == nil || !s.TLS.ECH.Enabled {
		return c, nil
	}
	child, cancel := s.DomainResolver.apply(ctx)
	defer cancel()
	tag := s.DomainResolver.tag()
	if tag == "" {
		tag = "@local"
	}
	return prepareClientTLS(context.WithValue(child, dnsBootstrapKey{}, tag), c, s.TLS, r)
}
