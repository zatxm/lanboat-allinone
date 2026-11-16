package native

import (
	"errors"
	"net/netip"
	"time"
)

type tunRouteState struct {
	current     map[netip.Prefix]bool
	add, remove func(netip.Prefix) error
}

func (s *tunRouteState) replace(prefixes []netip.Prefix) error {
	wanted := make(map[netip.Prefix]bool, len(prefixes))
	for _, p := range prefixes {
		wanted[p] = true
	}
	var added, removed []netip.Prefix
	rollback := func(cause error) error {
		var errs []error
		errs = append(errs, cause)
		for _, p := range removed {
			errs = append(errs, s.add(p))
		}
		for _, p := range added {
			errs = append(errs, s.remove(p))
		}
		return errors.Join(errs...)
	}
	for p := range wanted {
		if !s.current[p] {
			if e := s.add(p); e != nil {
				return rollback(e)
			}
			added = append(added, p)
		}
	}
	for p := range s.current {
		if !wanted[p] {
			if e := s.remove(p); e != nil {
				return rollback(e)
			}
			removed = append(removed, p)
		}
	}
	s.current = wanted
	return nil
}
func (t *tunTunnel) routePlan(in Inbound) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range tunRoutePrefixes(in) {
		if in.StrictRoute || p.Addr().Is4() && t.local4.IsValid() || p.Addr().Is6() && t.local6.IsValid() {
			out = append(out, p)
		}
	}
	return out
}
func (t *tunTunnel) installRouteRefresh() {
	if t.routes == nil || t.refreshRoutes != nil || !t.in.AutoRoute {
		return
	}
	base := t.in
	for _, in := range t.runtime.config.Inbounds {
		if in.Tag == t.in.Tag {
			base = in
			break
		}
	}
	tags := append(append([]string{}, base.RouteAddressSet...), base.RouteExcludeAddressSet...)
	if len(tags) == 0 {
		return
	}
	last := make([]*ruleSnapshot, len(tags))
	for i, tag := range tags {
		last[i] = t.runtime.ruleSets[tag].current.Load()
	}
	var retry time.Time
	t.refreshRoutes = func() error {
		if time.Now().Before(retry) {
			return nil
		}
		changed := false
		now := make([]*ruleSnapshot, len(tags))
		for i, tag := range tags {
			now[i] = t.runtime.ruleSets[tag].current.Load()
			changed = changed || last[i] != now[i]
		}
		if !changed {
			return nil
		}
		in, e := t.runtime.tunRouteSets(base)
		if e == nil {
			e = t.routes.replace(t.routePlan(in))
		}
		if e != nil {
			retry = time.Now().Add(30 * time.Second)
			return e
		}
		last = now
		return nil
	}
}
