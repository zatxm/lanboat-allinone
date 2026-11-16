package native

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type namespaceTUNInfo struct {
	ID            string
	Name          string
	Mark          uint32
	Addresses     []netip.Addr
	HostAddresses []netip.Addr
	Queues        int
	TProxy        bool
	Queue         bool
	Monitor       bool
	NetworkKey    string
}
type namespaceTUNs struct {
	mu   sync.Mutex
	all  map[string]*tunTunnel
	next uint64
}

func (t *tunTunnel) startFilter() {
	if t.namespaceQueue != nil {
		q := &tunQueue{file: t.namespaceQueue, number: t.in.queueNumber(), tunnel: t}
		t.workers.Go(q.run)
	}
}

func validateNamespaceTUN(in Inbound) error {
	if in.Type != "tun" {
		return errors.New("namespace interface requires tun type")
	}
	return (Config{Inbounds: []Inbound{in}, Outbounds: []Outbound{{Type: "direct", Tag: "direct"}}, Route: Route{Final: "direct"}}).validate()
}

func namespaceTUNInfoFor(id string, t *tunTunnel) *namespaceTUNInfo {
	i := &namespaceTUNInfo{ID: id, Name: t.name, Mark: t.mark, Addresses: t.localAddresses, Queues: len(t.queues), TProxy: t.tpListener != nil, Queue: t.namespaceQueue != nil, Monitor: t.namespaceMonitor != nil, NetworkKey: t.physicalNetworkKey()}
	addresses, _ := net.InterfaceAddrs()
	for _, a := range addresses {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			i.HostAddresses = append(i.HostAddresses, p.Addr())
		}
	}
	return i
}
func namespaceTUNClose(t *tunTunnel) {
	if t.cleanup != nil {
		t.cleanup()
	}
	for _, q := range t.queues {
		q.Close()
	}
	t.runtime.network.exclude(t.name, false)
}
func (s *namespaceTUNs) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, t := range s.all {
		namespaceTUNClose(t)
		delete(s.all, id)
	}
}

func (s *namespaceTUNs) request(r *Runtime, q namespaceRequest) (*namespaceTUNInfo, []*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q.Op == "tun-open" {
		in := q.Inbound
		in.NetNS, in.namespace = "", nil
		in.RouteAddressSet, in.RouteExcludeAddressSet = nil, nil
		if len(s.all) >= 64 {
			return nil, nil, errors.New("too many namespace TUN interfaces")
		}
		if err := validateNamespaceTUN(in); err != nil {
			return nil, nil, err
		}
		previous := r.config.Inbounds
		r.config.Inbounds = []Inbound{in}
		t, err := openTUN(r, in)
		r.config.Inbounds = previous
		if err != nil {
			return nil, nil, err
		}
		success := false
		defer func() {
			if !success {
				namespaceTUNClose(t)
			}
		}()
		if err = t.configureDNS(); err != nil {
			return nil, nil, err
		}
		if err = t.configureMonitor(); err != nil {
			return nil, nil, err
		}
		s.next++
		id := strconv.FormatUint(s.next, 10)
		var files []*os.File
		defer func() {
			if !success {
				closeNamespaceFiles(files)
			}
		}()
		duplicate := func(f *os.File) error {
			fd, err := syscall.Dup(int(f.Fd()))
			if err != nil {
				return err
			}
			syscall.CloseOnExec(fd)
			files = append(files, os.NewFile(uintptr(fd), f.Name()))
			return nil
		}
		for _, queue := range t.queues {
			if err = duplicate(queue.(*os.File)); err != nil {
				return nil, nil, err
			}
		}
		if t.tpListener != nil {
			f, e := t.tpListener.(interface{ File() (*os.File, error) }).File()
			if e != nil {
				return nil, nil, e
			}
			files = append(files, f)
		}
		for _, f := range []*os.File{t.namespaceQueue, t.namespaceMonitor} {
			if f != nil {
				if err = duplicate(f); err != nil {
					return nil, nil, err
				}
			}
		}
		s.all[id] = t
		success = true
		return namespaceTUNInfoFor(id, t), files, nil
	}
	t := s.all[q.ID]
	if t == nil {
		return nil, nil, errors.New("unknown namespace TUN interface")
	}
	switch q.Op {
	case "tun-close":
		namespaceTUNClose(t)
		delete(s.all, q.ID)
		return nil, nil, nil
	case "tun-snapshot":
		return namespaceTUNInfoFor(q.ID, t), nil, nil
	case "tun-update":
		in := t.in
		in.RouteAddress, in.RouteExcludeAddress = q.Inbound.RouteAddress, q.Inbound.RouteExcludeAddress
		if err := validateNamespaceTUN(in); err != nil {
			return nil, nil, err
		}
		if in.AutoRedirect {
			table := fmt.Sprintf("lanboat_%d_%x", os.Getpid(), t.mark)
			if _, err := tunCommand("/usr/sbin/nft", "delete table inet "+table+"\n"+t.redirectRulesFor(in, table), "-f", "-"); err != nil {
				return nil, nil, err
			}
		} else if t.routes != nil {
			if err := t.routes.replace(t.routePlan(in)); err != nil {
				return nil, nil, err
			}
		}
		t.in = in
		return nil, nil, nil
	default:
		return nil, nil, errors.New("unknown namespace operation")
	}
}

func (n *networkNamespace) openTUN(r *Runtime, in Inbound) (*tunTunnel, error) {
	wire := in
	wire.NetNS, wire.namespace = "", nil
	wire.RouteAddressSet, wire.RouteExcludeAddressSet = nil, nil
	response, files, err := n.call(r.ctx, namespaceRequest{Op: "tun-open", Inbound: wire})
	if err != nil {
		return nil, err
	}
	info := response.Tun
	if info == nil {
		closeNamespaceFiles(files)
		return nil, errors.New("missing namespace TUN information")
	}
	expected := info.Queues
	for _, has := range []bool{info.TProxy, info.Queue, info.Monitor} {
		if has {
			expected++
		}
	}
	if info.Queues < 1 || info.Queues > 4 || len(files) != expected {
		closeNamespaceFiles(files)
		return nil, errors.New("invalid namespace TUN descriptors")
	}
	t := &tunTunnel{runtime: r, in: in, name: info.Name, mark: info.Mark, namespace: n, namespaceID: info.ID, hostAddresses: info.HostAddresses}
	for _, ip := range info.Addresses {
		t.addLocal(ip)
	}
	for _, f := range files[:info.Queues] {
		t.queues = append(t.queues, f)
	}
	t.device = t.queues[0]
	owned := false
	t.cleanup = func() {
		for _, f := range []*os.File{t.namespaceQueue, t.namespaceMonitor} {
			if f != nil {
				f.Close()
			}
		}
		if t.tpListener != nil {
			t.tpListener.Close()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, extra, err := n.call(ctx, namespaceRequest{Op: "tun-close", ID: info.ID})
		closeNamespaceFiles(extra)
		if err != nil && r.ctx.Err() == nil {
			r.logger.Warn("remove namespace TUN", zap.Error(err))
		}
	}
	defer func() {
		if !owned {
			t.cleanup()
			closeNamespaceFiles(files)
		}
	}()
	index := info.Queues
	if info.TProxy {
		t.tpListener, err = net.FileListener(files[index])
		files[index].Close()
		index++
		if err != nil {
			return nil, err
		}
	}
	if info.Queue {
		t.namespaceQueue = files[index]
		index++
	}
	if info.Monitor {
		t.namespaceMonitor = files[index]
		events := make(chan struct{}, 1)
		t.networkEvents = events
		t.monitor = func() {
			buffer := make([]byte, 65536)
			t.watchNetwork(func() error { _, err := t.namespaceMonitor.Read(buffer); return err }, events)
		}
		t.refreshEgress = func() error { t.refreshNamespaceAddresses(); return nil }
	}
	t.installNamespaceRefresh()
	owned = true
	return t, nil
}

func (t *tunTunnel) namespaceSnapshot() (*namespaceTUNInfo, error) {
	ctx, cancel := context.WithTimeout(t.runtime.ctx, time.Second)
	defer cancel()
	response, files, err := t.namespace.call(ctx, namespaceRequest{Op: "tun-snapshot", ID: t.namespaceID})
	closeNamespaceFiles(files)
	if err != nil {
		return nil, err
	}
	if response.Tun == nil {
		return nil, errors.New("missing namespace snapshot")
	}
	return response.Tun, nil
}
func (t *tunTunnel) refreshNamespaceAddresses() {
	info, err := t.namespaceSnapshot()
	if err != nil {
		return
	}
	t.hostMu.Lock()
	t.hostAddresses = info.HostAddresses
	t.hostMu.Unlock()
}
func (t *tunTunnel) namespaceNetworkKey() string {
	info, err := t.namespaceSnapshot()
	if err != nil {
		return "namespace-unavailable"
	}
	return info.NetworkKey
}
func (t *tunTunnel) installNamespaceRefresh() {
	if !t.in.AutoRoute {
		return
	}
	base := t.in
	for _, in := range t.runtime.config.Inbounds {
		if in.Tag == base.Tag {
			base = in
			break
		}
	}
	tags := append(slices.Clone(base.RouteAddressSet), base.RouteExcludeAddressSet...)
	if len(tags) == 0 {
		return
	}
	previous := make([]*ruleSnapshot, len(tags))
	for i, tag := range tags {
		previous[i] = t.runtime.ruleSets[tag].current.Load()
	}
	var retry time.Time
	t.refreshRoutes = func() error {
		if time.Now().Before(retry) {
			return nil
		}
		next := make([]*ruleSnapshot, len(tags))
		changed := false
		for i, tag := range tags {
			next[i] = t.runtime.ruleSets[tag].current.Load()
			changed = changed || previous[i] != next[i]
		}
		if !changed {
			return nil
		}
		in, err := t.runtime.tunRouteSets(base)
		if err == nil {
			var files []*os.File
			_, files, err = t.namespace.call(t.ctx, namespaceRequest{Op: "tun-update", ID: t.namespaceID, Inbound: in})
			closeNamespaceFiles(files)
		}
		if err != nil {
			retry = time.Now().Add(30 * time.Second)
			return err
		}
		previous = next
		return nil
	}
}
