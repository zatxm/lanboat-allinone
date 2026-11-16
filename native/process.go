package native

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
)

type socketOrigin struct {
	network, source, destination string
}

const processPathFields = 1<<3 | 1<<4
const processUserFields = 1<<13 | 1<<14
const processFields = processPathFields | processUserFields

func (r *Runtime) initMetadataRules() {
	sets := map[*ruleCollection]bool{}
	var add func(*routeRule)
	add = func(rule *routeRule) {
		r.metadataFields |= rule.preMatchFields
		for _, set := range rule.sets {
			if !sets[set] {
				sets[set] = true
				r.metadataSets = append(r.metadataSets, set)
			}
		}
		for i := range rule.children {
			add(&rule.children[i])
		}
	}
	for i := range r.rules {
		add(&r.rules[i])
	}
	for i := range r.resolver.policies {
		add(&r.resolver.policies[i].rule)
	}
}

func (r *Runtime) needsMetadata(fields uint32) bool {
	if r.metadataFields&fields != 0 {
		return true
	}
	for _, set := range r.metadataSets {
		if snapshot := set.current.Load(); snapshot != nil && snapshot.preMatchFields&fields != 0 {
			return true
		}
	}
	return false
}

func (r *Runtime) needsProcess() bool {
	return r.config.Route.FindProcess || r.needsMetadata(processFields)
}

func (r *Runtime) socketOrigin(source, destination net.Addr) *socketOrigin {
	if !r.needsProcess() {
		return nil
	}
	network := source.Network()
	if network != "tcp" && network != "udp" {
		return nil
	}
	return &socketOrigin{network: network, source: source.String(), destination: destination.String()}
}

func (r *Runtime) enrichProcess(ctx context.Context, q *request) {
	wantPath := q.metadata.ProcessName == "" && q.metadata.ProcessPath == "" && (r.config.Route.FindProcess || r.needsMetadata(processPathFields))
	wantUID := q.metadata.UserID == nil && r.needsMetadata(processUserFields)
	wantUser := q.metadata.User == "" && r.needsMetadata(1<<13)
	if wantUser && q.metadata.UserID != nil {
		q.metadata.User = r.processes.userName(*q.metadata.UserID)
		wantUser = false
	}
	if !wantPath && !wantUID && !wantUser {
		return
	}
	apply := func(m Metadata) {
		if wantPath {
			q.metadata.ProcessName, q.metadata.ProcessPath = m.ProcessName, m.ProcessPath
		}
		if q.metadata.UserID == nil {
			q.metadata.UserID = m.UserID
		}
		if wantUser && m.UserID != nil {
			q.metadata.User = r.processes.userName(*m.UserID)
		}
	}
	origin := q.origin
	namespace := r.inboundNamespace(q.inbound)
	if origin == nil {
		// Only a TUN carries the application's original tuple in the request.
		for _, in := range r.config.Inbounds {
			if in.Tag == q.inbound && in.Type == "tun" {
				origin = &socketOrigin{network: q.network, source: q.source, destination: q.address}
				if q.network == "icmp" {
					source, err := netip.ParseAddrPort(q.source)
					if err != nil || len(q.payload) < 8 {
						return
					}
					if destination, err := netip.ParseAddrPort(q.address); namespace == nil && err == nil && destination.Port() == 0 {
						identity, observed := r.processes.lookupICMPIdentity(ctx, source.Addr(), destination.Addr(), q.payload)
						if observed {
							apply(identity)
							return
						}
					}
					if q.payload[1] != 0 || source.Addr().Is4() && q.payload[0] != 8 || source.Addr().Is6() && q.payload[0] != 128 {
						return
					}
					origin.source = netip.AddrPortFrom(source.Addr(), binary.BigEndian.Uint16(q.payload[4:])).String()
				}
				break
			}
		}
	}
	if origin != nil {
		if namespace != nil {
			apply(namespace.processIdentity(ctx, &r.processes, *origin, wantPath))
		} else {
			apply(r.processes.lookupIdentity(ctx, *origin, wantPath))
		}
	}
}

// Prepare tracing before a live rule starts depending on process identity.
func (r *Runtime) publishRuleSet(set *ruleCollection, snapshot *ruleSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	active := r.started && r.closeDone == nil
	if active && snapshot.preMatchFields&processFields != 0 {
		for _, used := range r.metadataSets {
			if used == set {
				r.startProcessTracking(true)
				break
			}
		}
	}
	set.store(snapshot)
	if active && !r.needsProcess() {
		r.startProcessTracking(false)
	}
}
