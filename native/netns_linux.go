package native

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const namespaceFrameLimit = 16 << 20

type networkNamespace struct {
	control *net.UnixConn
	command *exec.Cmd
	once    sync.Once
	pidPath string
	pidInfo os.FileInfo
	pidFile *os.File
	stop    func() bool
	hostUID *uint32
	netInfo os.FileInfo
}

type namespaceRequest struct {
	Op       string
	Network  string
	Address  string
	Target   string
	Deadline int64
	Dial     DialOptions
	Listen   ListenOptions
	Route    Route
	Inbound  Inbound
	ID       string
	Source   string
	Paths    []string
}
type namespaceResponse struct {
	Error    string
	PID      int
	Tun      *namespaceTUNInfo
	Metadata Metadata
	Inode    uint32
	Networks []networkChoice
}

func (n *networkNamespace) matches(path string) bool {
	info, err := os.Stat(path)
	return err == nil && n.netInfo != nil && os.SameFile(info, n.netInfo)
}

func namespacePair(kind int) (*net.UnixConn, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, kind|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	a, b := os.NewFile(uintptr(fds[0]), "netns-parent"), os.NewFile(uintptr(fds[1]), "netns-child")
	c, err := net.FileConn(a)
	a.Close()
	if err != nil {
		b.Close()
		return nil, nil, err
	}
	return c.(*net.UnixConn), b, nil
}

func writeNamespaceFrame(c io.Writer, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(b) > namespaceFrameLimit {
		return errors.New("network namespace request exceeds16MiB")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(b)))
	if err = writeAll(c, header[:]); err != nil {
		return err
	}
	return writeAll(c, b)
}
func readNamespaceFrame(c io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > namespaceFrameLimit {
		return errors.New("invalid network namespace frame length")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	return json.Unmarshal(b, value)
}
func namespaceRights(c *net.UnixConn, files []*os.File) error {
	fds := make([]int, len(files))
	for i, f := range files {
		fds[i] = int(f.Fd())
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var sendErr error
	err = raw.Control(func(fd uintptr) {
		_, sendErr = syscall.SendmsgN(int(fd), []byte{1}, syscall.UnixRights(fds...), nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
	})
	if err != nil {
		return err
	}
	return sendErr
}
func readNamespaceRights(c *net.UnixConn) ([]*os.File, error) {
	var marker [1]byte
	oob := make([]byte, syscall.CmsgSpace(4*16))
	n, on, flags, _, err := c.ReadMsgUnix(marker[:], oob)
	if err != nil {
		return nil, err
	}
	var files []*os.File
	messages, parseErr := syscall.ParseSocketControlMessage(oob[:on])
	if parseErr == nil {
		for _, m := range messages {
			fds, e := syscall.ParseUnixRights(&m)
			if e != nil {
				parseErr = e
				continue
			}
			for _, fd := range fds {
				syscall.CloseOnExec(fd)
				files = append(files, os.NewFile(uintptr(fd), "namespace-resource"))
			}
		}
	}
	if n != 1 || marker[0] != 1 || flags&(syscall.MSG_CTRUNC|syscall.MSG_TRUNC) != 0 || parseErr != nil {
		for _, f := range files {
			f.Close()
		}
		return nil, errors.New("invalid namespace descriptor message")
	}
	return files, nil
}

func (n *networkNamespace) call(ctx context.Context, q namespaceRequest) (namespaceResponse, []*os.File, error) {
	var response namespaceResponse
	if err := ctx.Err(); err != nil {
		return response, nil, err
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, peer, err := namespacePair(syscall.SOCK_STREAM)
	if err != nil {
		return response, nil, err
	}
	defer c.Close()
	defer peer.Close()
	deadline, _ := call.Deadline()
	q.Deadline = deadline.UnixNano()
	c.SetDeadline(deadline)
	stop := context.AfterFunc(call, func() { c.Close() })
	defer stop()
	if err = namespaceRights(n.control, []*os.File{peer}); err == nil {
		err = writeNamespaceFrame(c, q)
	}
	if err != nil {
		if call.Err() != nil {
			err = call.Err()
		}
		return response, nil, err
	}
	files, err := readNamespaceRights(c)
	if err == nil {
		err = readNamespaceFrame(c, &response)
	}
	if err == nil && response.Error != "" {
		err = errors.New(response.Error)
	}
	if err != nil {
		for _, f := range files {
			f.Close()
		}
		if call.Err() != nil {
			err = call.Err()
		}
		return response, nil, err
	}
	return response, files, nil
}

func startNamespace(ctx context.Context, o NetworkNamespaceOptions, route Route) (result *networkNamespace, err error) {
	control, child, err := namespacePair(syscall.SOCK_SEQPACKET)
	if err != nil {
		return nil, err
	}
	defer child.Close()
	n := &networkNamespace{control: control}
	ok := false
	defer func() {
		if !ok {
			// An embedding executable may not dispatch the private worker role.
			if n.command != nil {
				n.command.Process.Kill()
			}
			n.close()
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	mode := "active"
	var target *os.File
	if o.Type != "unshare" {
		path, err := namespacePath(o.Path)
		if err != nil {
			return nil, err
		}
		target, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer target.Close()
		var fs syscall.Statfs_t
		if err = syscall.Fstatfs(int(target.Fd()), &fs); err != nil {
			return nil, err
		}
		kind, _, code := syscall.Syscall(syscall.SYS_IOCTL, target.Fd(), 0xb703, 0)
		if fs.Type != 0x6e736673 || code != 0 || kind != syscall.CLONE_NEWNET {
			return nil, errors.New("path is not a Linux network namespace")
		}
		n.netInfo, err = target.Stat()
		if err != nil {
			return nil, err
		}
		mode = "enter"
	}
	n.command = exec.Command(executable, "network-namespace-worker", mode)
	n.command.ExtraFiles = []*os.File{child}
	if target != nil {
		n.command.ExtraFiles = append(n.command.ExtraFiles, target)
	}
	if o.Type == "unshare" {
		n.command.Args = append(n.command.Args, "new")
		n.command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		if os.Geteuid() != 0 {
			uid := uint32(os.Getuid())
			n.hostUID = &uid
			n.command.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
			n.command.SysProcAttr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
			n.command.SysProcAttr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
		}
	}
	if err = n.command.Start(); err != nil {
		n.command = nil
		return nil, fmt.Errorf("create namespace helper: %w", err)
	}
	child.Close()
	if n.netInfo == nil {
		n.netInfo, _ = os.Stat(fmt.Sprintf("/proc/%d/ns/net", n.command.Process.Pid))
	}
	_, files, err := n.call(ctx, namespaceRequest{Op: "init", Route: Route{DefaultInterface: route.DefaultInterface, DefaultMark: route.DefaultMark, AutoDetectInterface: route.AutoDetectInterface}})
	for _, f := range files {
		f.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("namespace helper startup failed (the executable must dispatch RunNetworkNamespaceWorker): %w", err)
	}
	if o.PIDFile != "" {
		path, err := filepath.Abs(o.PIDFile)
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		n.pidPath, n.pidFile = path, f
		n.pidInfo, _ = f.Stat()
		if _, err = fmt.Fprintln(f, n.command.Process.Pid); err != nil {
			return nil, err
		}
	}
	published := make(chan struct{})
	n.stop = context.AfterFunc(ctx, func() { <-published; n.close() })
	close(published)
	ok = true
	return n, nil
}

func (n *networkNamespace) close() {
	n.once.Do(func() {
		if n.stop != nil {
			n.stop()
		}
		n.control.Close()
		if n.command != nil {
			n.command.Wait()
		}
		if n.pidInfo != nil {
			if info, err := os.Lstat(n.pidPath); err == nil && os.SameFile(info, n.pidInfo) {
				os.Remove(n.pidPath)
			}
		}
		if n.pidFile != nil {
			n.pidFile.Close()
		}
	})
}
func (n *networkNamespace) dial(ctx context.Context, o DialOptions, network, address string) (net.Conn, error) {
	o.NetNS, o.namespace = "", nil
	_, files, err := n.call(ctx, namespaceRequest{Op: "dial", Network: network, Address: address, Dial: o})
	if err != nil {
		return nil, err
	}
	defer closeNamespaceFiles(files)
	if len(files) != 1 {
		return nil, errors.New("namespace dial returned invalid descriptors")
	}
	return net.FileConn(files[0])
}
func (n *networkNamespace) listen(ctx context.Context, o ListenOptions, network, address string) (net.Listener, error) {
	o.NetNS, o.namespace = "", nil
	_, files, err := n.call(ctx, namespaceRequest{Op: "listen", Network: network, Address: address, Listen: o})
	if err != nil {
		return nil, err
	}
	defer closeNamespaceFiles(files)
	if len(files) != 1 {
		return nil, errors.New("namespace listen returned invalid descriptors")
	}
	return net.FileListener(files[0])
}
func (n *networkNamespace) packet(ctx context.Context, o DialOptions, l ListenOptions, network, address, target string, listener bool) (net.PacketConn, error) {
	o.NetNS, o.namespace = "", nil
	l.NetNS, l.namespace = "", nil
	op := "packet"
	if listener {
		op = "packet-listen"
	}
	_, files, err := n.call(ctx, namespaceRequest{Op: op, Network: network, Address: address, Target: target, Dial: o, Listen: l})
	if err != nil {
		return nil, err
	}
	defer closeNamespaceFiles(files)
	if len(files) != 1 {
		return nil, errors.New("namespace packet listen returned invalid descriptors")
	}
	return net.FilePacketConn(files[0])
}
func closeNamespaceFiles(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

func (n *networkNamespace) processIdentity(ctx context.Context, finder *processFinder, origin socketOrigin, wantPath bool) Metadata {
	call, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	deadline, _ := call.Deadline()
	response, files, err := n.call(call, namespaceRequest{Op: "process", Network: origin.network, Source: origin.source, Target: origin.destination})
	closeNamespaceFiles(files)
	if err != nil || response.Inode == 0 || response.Metadata.UserID == nil {
		return Metadata{}
	}
	uid := *response.Metadata.UserID
	if n.hostUID != nil {
		if uid != 0 {
			return Metadata{}
		}
		uid = *n.hostUID
	}
	return finder.identityForInode(call, response.Inode, uid, wantPath, deadline)
}

func (n *networkNamespace) neighborIdentity(ctx context.Context, source string, paths []string) Metadata {
	response, files, err := n.call(ctx, namespaceRequest{Op: "neighbor", Source: source, Paths: paths})
	closeNamespaceFiles(files)
	if err != nil {
		return Metadata{}
	}
	return response.Metadata
}

// RunNetworkNamespaceWorker runs the private same-executable namespace resource broker.
// Embedders dispatch this before their UI or ordinary command-line handling.
func RunNetworkNamespaceWorker(args []string) (bool, error) {
	if len(args) == 0 || args[0] != "network-namespace-worker" {
		return false, nil
	}
	if len(args) < 2 || len(args) > 3 {
		return true, errors.New("invalid namespace worker mode")
	}
	if args[1] == "enter" {
		runtime.LockOSThread()
		target := os.NewFile(4, "namespace-target")
		current, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			return true, err
		}
		a, e1 := target.Stat()
		b, e2 := current.Stat()
		current.Close()
		if e1 != nil {
			return true, e1
		}
		if e2 != nil {
			return true, e2
		}
		if !os.SameFile(a, b) {
			_, _, code := syscall.Syscall(namespaceSetns, target.Fd(), syscall.CLONE_NEWNET, 0)
			if code != 0 {
				return true, code
			}
		}
		target.Close()
		// Re-exec makes every Go runtime thread inherit the selected namespace.
		return true, syscall.Exec("/proc/self/exe", []string{os.Args[0], "network-namespace-worker", "active"}, os.Environ())
	}
	if args[1] != "active" {
		return true, errors.New("invalid namespace worker mode")
	}
	file := os.NewFile(3, "namespace-control")
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return true, err
	}
	control, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return true, errors.New("namespace control must be a Unix socket")
	}
	defer control.Close()
	if len(args) == 3 {
		if args[2] != "new" {
			return true, errors.New("invalid namespace creation mode")
		}
		lo, err := net.InterfaceByName("lo")
		if err != nil {
			return true, err
		}
		if err = configureLink(lo.Index, 65536); err != nil {
			return true, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Runtime{ctx: ctx, cancel: cancel, logger: zap.NewNop(), namespaceKernelOnly: true}
	tuns := &namespaceTUNs{all: map[string]*tunTunnel{}}
	defer tuns.close()
	initial, err := readNamespaceRights(control)
	if err != nil {
		return true, err
	}
	if len(initial) != 1 {
		closeNamespaceFiles(initial)
		return true, errors.New("invalid namespace initialization")
	}
	namespaceServeRequest(ctx, r, tuns, initial[0], true)
	var workers sync.WaitGroup
	defer workers.Wait()
	limit := make(chan struct{}, 64)
	for {
		files, err := readNamespaceRights(control)
		if err != nil {
			cancel()
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return true, nil
			}
			return true, err
		}
		if len(files) != 1 {
			closeNamespaceFiles(files)
			cancel()
			return true, errors.New("namespace request requires one reply channel")
		}
		select {
		case limit <- struct{}{}:
		default:
			closeNamespaceFiles(files)
			continue
		}
		workers.Go(func() { defer func() { <-limit }(); namespaceServeRequest(ctx, r, tuns, files[0], false) })
	}
}

func namespaceServeRequest(ctx context.Context, r *Runtime, tuns *namespaceTUNs, file *os.File, initialize bool) {
	conn, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return
	}
	defer conn.Close()
	client := conn.(*net.UnixConn)
	var q namespaceRequest
	client.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err = readNamespaceFrame(client, &q); err != nil {
		return
	}
	deadline := time.Unix(0, q.Deadline)
	if deadline.After(time.Now().Add(15 * time.Second)) {
		deadline = time.Now().Add(15 * time.Second)
	}
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	client.SetDeadline(deadline)
	go func() { var b [1]byte; client.Read(b[:]); cancel() }()
	response := namespaceResponse{PID: os.Getpid()}
	var files []*os.File
	if initialize && q.Op != "init" {
		return
	}
	if q.Op == "dial" || q.Op == "listen" || q.Op == "packet" || q.Op == "packet-listen" {
		switch q.Network {
		case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip4:tcp", "ip6:tcp", "ip4:icmp", "ip6:ipv6-icmp":
		default:
			response.Error = "namespace socket requires TCP, UDP or raw IP"
			namespaceRights(client, nil)
			writeNamespaceFrame(client, response)
			return
		}
	}
	switch q.Op {
	case "init":
		if !initialize {
			err = errors.New("namespace already initialized")
		} else {
			r.config.Route = q.Route
		}
	case "dial":
		var c net.Conn
		c, err = r.dialSocket(call, q.Dial, q.Network, q.Address)
		if err == nil {
			f, e := c.(interface{ File() (*os.File, error) }).File()
			c.Close()
			err = e
			if err == nil {
				files = []*os.File{f}
			}
		}
	case "listen":
		var l net.Listener
		l, err = q.Listen.listen(call, q.Network, q.Address)
		if err == nil {
			f, e := l.(interface{ File() (*os.File, error) }).File()
			l.Close()
			err = e
			if err == nil {
				files = []*os.File{f}
			}
		}
	case "packet", "packet-listen":
		var c net.PacketConn
		if q.Op == "packet" {
			c, err = r.listenPacketWithOptions(call, q.Dial, q.Network, q.Address, q.Target)
		} else {
			c, err = q.Listen.listenPacket(call, q.Network, q.Address)
		}
		if err == nil {
			f, e := c.(interface{ File() (*os.File, error) }).File()
			c.Close()
			err = e
			if err == nil {
				files = []*os.File{f}
			}
		}
	case "networks":
		state := r.network.snapshot(context.WithValue(call, networkSelectionKey{}, true), r)
		r.network.mu.Lock()
		for _, c := range state.networkChoices {
			if !r.network.excluded[c.Name] {
				response.Networks = append(response.Networks, c)
			}
		}
		r.network.mu.Unlock()
	case "process":
		var uid uint32
		response.Inode, uid = processSocketOwner(call, socketOrigin{network: q.Network, source: q.Source, destination: q.Target}, deadline)
		if response.Inode != 0 {
			response.Metadata.UserID = &uid
		}
	case "neighbor":
		if source, e := netip.ParseAddrPort(q.Source); e == nil {
			state := r.neighbors.snapshot(call, q.Paths)
			if entry := state.byIP[source.Addr().Unmap()]; entry.valid(time.Now()) {
				response.Metadata.SourceMACAddress, response.Metadata.SourceHostname = entry.mac, entry.hostname
			}
		}
	default:
		response.Tun, files, err = tuns.request(r, q)
	}
	defer closeNamespaceFiles(files)
	if err != nil {
		response.Error = err.Error()
	}
	if namespaceRights(client, files) == nil {
		writeNamespaceFrame(client, response)
	}
}

func (n *networkNamespace) networkChoices(ctx context.Context) ([]networkChoice, error) {
	response, files, err := n.call(ctx, namespaceRequest{Op: "networks"})
	closeNamespaceFiles(files)
	return response.Networks, err
}
