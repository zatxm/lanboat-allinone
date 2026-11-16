package native

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTailscaleSSHReference(t *testing.T) {
	if !tsSSHPlatform() {
		t.Skip("SSH server supports Linux/macOS")
	}
	t.Setenv("LANBOAT_TS_SSH", "1")
	url, decoder, input := startTSReference(t, false)
	r := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "ts", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), ForceDERP: true, Hostname: "ssh-native", SSHServer: TailscaleSSHOptions{Enabled: true}}}}, Route: Route{Final: "ts"}})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	status, e := r.TailscaleStatus(ctx, "ts")
	if e != nil {
		t.Fatal(e)
	}
	c := r.tailscaleClient("ts")
	exe := filepath.Join(t.TempDir(), "lanboat-allinone")
	build := exec.CommandContext(ctx, "go", "build", "-o", exe, "../cmd/lanboat-allinone")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatal("worker build", e, string(b))
	}
	c.ssh.worker = exe
	u, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(map[string]string{"Op": "ssh-bridge", "Address": net.JoinHostPort(status.Addresses[0].Addr().String(), "22")})
	input.Write(append(b, '\n'))
	var bridge struct{ Address string }
	if e = decoder.Decode(&bridge); e != nil {
		t.Fatal(e)
	}
	_, port, e := net.SplitHostPort(bridge.Address)
	if e != nil {
		t.Fatal(bridge, e)
	}
	args := []string{"-F", "/dev/null", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "PubkeyAuthentication=no", "-o", "PasswordAuthentication=no"}
	ssh := func(command string, pty bool) (string, string, error) {
		t.Helper()
		a := append([]string{}, args...)
		if pty {
			a = append(a, "-tt")
		}
		a = append(a, "-p", port, "-l", u.Username, "127.0.0.1", command)
		cmd := exec.CommandContext(ctx, "ssh", a...)
		cmd.Stdin = strings.NewReader("")
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		e := cmd.Run()
		return out.String(), stderr.String(), e
	}
	out, stderr, e := ssh("printf lanboat-ssh; printf lanboat-stderr >&2; exit 7", false)
	if e == nil || out != "lanboat-ssh" || stderr != "lanboat-stderr" {
		t.Fatalf("exec: %q stderr=%q err=%v", out, stderr, e)
	}
	out, stderr, e = ssh("stty size; printf pty-output", true)
	if e != nil || !strings.Contains(out, "24 80") || !strings.Contains(out, "pty-output") {
		t.Fatalf("PTY: %q stderr=%q err=%v", out, stderr, e)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	target := filepath.Join(dir, "uploaded")
	copy := filepath.Join(dir, "downloaded")
	payload := bytes.Repeat([]byte("sftp-tailnet-"), 12000)
	if e = os.WriteFile(source, payload, 0600); e != nil {
		t.Fatal(e)
	}
	sftpArgs := append([]string{}, args...)
	sftpArgs = append(sftpArgs, "-P", port, "-b", "-", u.Username+"@127.0.0.1")
	cmd := exec.CommandContext(ctx, "sftp", sftpArgs...)
	cmd.Stdin = strings.NewReader("put " + source + " " + target + "\nget " + target + " " + copy + "\nrename " + target + " " + target + ".renamed\nrm " + target + ".renamed\n")
	if b, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("SFTP %v\n%s", e, b)
	}
	got, e := os.ReadFile(copy)
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatal("SFTP payload", e)
	}
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			conn, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	localArgs := append(append([]string{}, args...), "-p", port, "-l", u.Username, "-W", echo.Addr().String(), "127.0.0.1")
	cmd = exec.CommandContext(ctx, "ssh", localArgs...)
	cmd.Stdin = strings.NewReader("forwarded-local")
	if b, e := cmd.Output(); e != nil || string(b) != "forwarded-local" {
		t.Fatal("local forwarding", e, string(b))
	}
	reserve, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	remotePort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	remoteArgs := append(append([]string{}, args...), "-o", "ExitOnForwardFailure=yes", "-p", port, "-l", u.Username, "-R", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort))+":"+echo.Addr().String(), "-N", "127.0.0.1")
	forwardCtx, stopForward := context.WithCancel(ctx)
	forward := exec.CommandContext(forwardCtx, "ssh", remoteArgs...)
	if e = forward.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { stopForward(); forward.Wait() }()
	var forwarded net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; {
		forwarded, e = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort)), 100*time.Millisecond)
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("remote forwarding unavailable", e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	forwarded.SetDeadline(time.Now().Add(3 * time.Second))
	forwarded.Write([]byte("remote-forward"))
	remoteData := make([]byte, 14)
	_, e = io.ReadFull(forwarded, remoteData)
	forwarded.Close()
	if e != nil || string(remoteData) != "remote-forward" {
		t.Fatal("remote forwarding", e, string(remoteData))
	}
	agentCtx, stopAgent := context.WithCancel(ctx)
	defer stopAgent()
	agentSocket := filepath.Join(dir, "agent.sock")
	agent := exec.CommandContext(agentCtx, "ssh-agent", "-D", "-a", agentSocket)
	if e = agent.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { stopAgent(); agent.Wait() }()
	for deadline := time.Now().Add(time.Second); ; {
		if _, e = os.Stat(agentSocket); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	agentArgs := append(append([]string{}, args...), "-A", "-p", port, "-l", u.Username, "127.0.0.1", "ssh-add -l")
	cmd = exec.CommandContext(ctx, "ssh", agentArgs...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSocket)
	if b, e := cmd.CombinedOutput(); e == nil || !strings.Contains(string(b), "no identities") {
		t.Fatal("agent forwarding", e, string(b))
	}
	unixEchoPath := filepath.Join(dir, "unix-echo.sock")
	unixEcho, e := net.Listen("unix", unixEchoPath)
	if e != nil {
		t.Fatal(e)
	}
	defer unixEcho.Close()
	go func() {
		for {
			conn, e := unixEcho.Accept()
			if e != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	temporary, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	unixTCPPort := temporary.Addr().(*net.TCPAddr).Port
	temporary.Close()
	unixCtx, stopUnix := context.WithCancel(ctx)
	localUnix := exec.CommandContext(unixCtx, "ssh", append(append([]string{}, args...), "-o", "ExitOnForwardFailure=yes", "-p", port, "-l", u.Username, "-L", net.JoinHostPort("127.0.0.1", strconv.Itoa(unixTCPPort))+":"+unixEchoPath, "-N", "127.0.0.1")...)
	if e = localUnix.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { stopUnix(); localUnix.Wait() }()
	var localUnixStream net.Conn
	for deadline := time.Now().Add(3 * time.Second); ; {
		localUnixStream, e = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(unixTCPPort)), 100*time.Millisecond)
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local Unix forwarding not ready", e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	localUnixStream.SetDeadline(time.Now().Add(4 * time.Second))
	localUnixStream.Write([]byte("local-unix"))
	unixData := make([]byte, 10)
	_, e = io.ReadFull(localUnixStream, unixData)
	localUnixStream.Close()
	if e != nil || string(unixData) != "local-unix" {
		t.Fatal("Unix direct forwarding", e, string(unixData))
	}
	remoteUnixPath := filepath.Join(dir, "remote-unix.sock")
	remoteUnixCtx, stopRemoteUnix := context.WithCancel(ctx)
	remoteUnix := exec.CommandContext(remoteUnixCtx, "ssh", append(append([]string{}, args...), "-o", "ExitOnForwardFailure=yes", "-p", port, "-l", u.Username, "-R", remoteUnixPath+":"+unixEchoPath, "-N", "127.0.0.1")...)
	var remoteUnixErrors bytes.Buffer
	remoteUnix.Stderr = &remoteUnixErrors
	if e = remoteUnix.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { stopRemoteUnix(); remoteUnix.Wait() }()
	var remoteUnixStream net.Conn
	for deadline := time.Now().Add(4 * time.Second); ; {
		remoteUnixStream, e = net.DialTimeout("unix", remoteUnixPath, 100*time.Millisecond)
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			stopRemoteUnix()
			remoteUnix.Wait()
			t.Fatal("remote Unix forwarding not ready", e, remoteUnixErrors.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if info, e := os.Stat(remoteUnixPath); e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("forwarded Unix socket permissions", info, e)
	}
	remoteUnixStream.SetDeadline(time.Now().Add(4 * time.Second))
	remoteUnixStream.Write([]byte("remote-unix"))
	unixData = make([]byte, 11)
	_, e = io.ReadFull(remoteUnixStream, unixData)
	remoteUnixStream.Close()
	if e != nil || string(unixData) != "remote-unix" {
		t.Fatal("Unix remote forwarding", e, string(unixData))
	}
	stopRemoteUnix()
	remoteUnix.Wait()
	for deadline := time.Now().Add(2 * time.Second); ; {
		_, e = os.Lstat(remoteUnixPath)
		if os.IsNotExist(e) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Unix listener pathname survived disconnect")
		}
		time.Sleep(10 * time.Millisecond)
	}
	disabled := newTestRuntime(t, Config{Endpoints: []Outbound{{Type: "tailscale", Tag: "disabled", TailscaleOptions: TailscaleOptions{AuthKey: "test-only-auth", ControlURL: url, StateDirectory: t.TempDir(), ForceDERP: true, Hostname: "ssh-disabled", SSHServer: TailscaleSSHOptions{Enabled: true, DisablePTY: true, DisableSFTP: true, DisableForwarding: true}}}}, Route: Route{Final: "disabled"}})
	disabledStatus, e := disabled.TailscaleStatus(ctx, "disabled")
	if e != nil {
		t.Fatal(e)
	}
	b, _ = json.Marshal(map[string]string{"Op": "ssh-bridge", "Address": net.JoinHostPort(disabledStatus.Addresses[0].Addr().String(), "22")})
	input.Write(append(b, '\n'))
	if e = decoder.Decode(&bridge); e != nil {
		t.Fatal(e)
	}
	originalPort := port
	_, port, e = net.SplitHostPort(bridge.Address)
	if e != nil {
		t.Fatal(e)
	}
	out, stderr, e = ssh("test -t 0", true)
	if e == nil || !strings.Contains(stderr, "PTY allocation request failed") {
		t.Fatal("disable_pty", e, out, stderr)
	}
	cmd = exec.CommandContext(ctx, "sftp", append(append([]string{}, args...), "-P", port, "-b", "-", u.Username+"@127.0.0.1")...)
	cmd.Stdin = strings.NewReader("pwd\n")
	if b, e := cmd.CombinedOutput(); e == nil {
		t.Fatal("disable_sftp ignored", string(b))
	}
	cmd = exec.CommandContext(ctx, "ssh", append(append([]string{}, args...), "-p", port, "-l", u.Username, "-W", echo.Addr().String(), "127.0.0.1")...)
	if b, e := cmd.CombinedOutput(); e == nil {
		t.Fatal("disable_forwarding ignored", string(b))
	}
	if len(disabled.tailscaleClient("disabled").ssh.processes) != 0 {
		t.Fatal("disabled subsystem launched worker")
	}
	port = originalPort
	// Existing sessions must stop when the coordinator removes SSH permission.
	long := exec.CommandContext(ctx, "ssh", append(append([]string{}, args...), "-p", port, "-l", u.Username, "127.0.0.1", "printf started; sleep 30")...)
	output, e := long.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var errors bytes.Buffer
	long.Stderr = &errors
	if e = long.Start(); e != nil {
		t.Fatal(e)
	}
	started := make([]byte, 7)
	if _, e = io.ReadFull(output, started); e != nil || string(started) != "started" {
		t.Fatal("long command", e, string(started))
	}
	io.WriteString(input, "{\"Op\":\"ssh-revoke\"}\n")
	var reply map[string]any
	if e = decoder.Decode(&reply); e != nil {
		t.Fatal(e)
	}
	wait := make(chan error, 1)
	go func() { wait <- long.Wait() }()
	select {
	case <-wait:
	case <-time.After(3 * time.Second):
		long.Process.Kill()
		t.Fatal("SSH policy revocation did not terminate session")
	}
	if _, _, e = ssh("true", false); e == nil {
		t.Fatal("revoked SSH policy permitted login")
	}
}

func TestTailscaleSSHPolicy(t *testing.T) {
	now := time.Now().Add(-time.Second)
	ip := netip.MustParseAddr("100.64.0.2")
	c := &tailscaleClient{self: tsNode{ID: 1}, nodes: map[int64]tsNode{2: {ID: 2, StableID: "n2", Key: "key", User: 12}}, addressOwners: map[netip.Addr]int64{ip: 2}, userLogins: map[int64]string{12: "u@example.com"}}
	accept := &tsSSHAction{Accept: true}
	rule := func(p *tsSSHPrincipal) *tsSSHRule {
		return &tsSSHRule{Principals: []*tsSSHPrincipal{p}, SSHUsers: map[string]string{"alice": "local"}, Action: accept}
	}
	for _, principal := range []*tsSSHPrincipal{{Any: true}, {Node: "n2"}, {NodeIP: ip.String()}, {UserLogin: "u@example.com"}} {
		c.sshPolicy = &tsSSHPolicy{Rules: []*tsSSHRule{rule(principal)}}
		if g, ok := c.sshGrantLocked(ip, "alice", true); !ok || g.local != "local" {
			t.Fatal("principal did not match", principal)
		}
	}
	for _, change := range []func(*tsSSHRule){func(r *tsSSHRule) { r.RuleExpires = &now }, func(r *tsSSHRule) { r.Action = nil }, func(r *tsSSHRule) { r.Action = &tsSSHAction{Accept: true, Reject: true} }, func(r *tsSSHRule) { r.SSHUsers = nil }, func(r *tsSSHRule) { r.Principals[0] = &tsSSHPrincipal{Node: "other"} }, func(r *tsSSHRule) { r.SSHUsers["alice"] = "../root" }} {
		rule := rule(&tsSSHPrincipal{Any: true})
		change(rule)
		c.sshPolicy = &tsSSHPolicy{Rules: []*tsSSHRule{rule}}
		if _, ok := c.sshGrantLocked(ip, "alice", true); ok {
			t.Fatal("invalid policy accepted")
		}
	}
	deny := &tsSSHRule{Principals: []*tsSSHPrincipal{{Any: true}}, Action: &tsSSHAction{Reject: true}}
	c.sshPolicy = &tsSSHPolicy{Rules: []*tsSSHRule{deny, rule(&tsSSHPrincipal{Any: true})}}
	if _, ok := c.sshGrantLocked(ip, "alice", true); ok {
		t.Fatal("first matching rejection bypassed")
	}
	identity := rule(&tsSSHPrincipal{Any: true})
	identity.SSHUsers = map[string]string{"*": "="}
	root := rule(&tsSSHPrincipal{Any: true})
	root.SSHUsers = map[string]string{"root": "root"}
	c.sshPolicy = &tsSSHPolicy{Rules: []*tsSSHRule{identity}}
	if _, ok := c.sshGrantLocked(ip, "root", false); ok {
		t.Fatal("nonroot identity mapping allowed UID0")
	}
	if _, ok := c.sshGrantLocked(ip, "toor", false); ok {
		t.Fatal("UID0 alias bypassed nonroot identity mapping")
	}
	if _, ok := c.sshGrantLocked(ip, "missing", false); ok {
		t.Fatal("identity mapping allowed missing system account")
	}
	if grant, ok := c.sshGrantLocked(ip, "alice", true); !ok || grant.local != "alice" {
		t.Fatal("nonroot identity mapping rejected")
	}
	c.sshPolicy.Rules = append(c.sshPolicy.Rules, root)
	if grant, ok := c.sshGrantLocked(ip, "root", false); !ok || grant.local != "root" {
		t.Fatal("explicit root grant after nonroot rule rejected")
	}
}
func TestTailscaleSSHOptions(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	for _, value := range []string{"true", `{"enabled":true,"disable_pty":true,"disable_sftp":true,"disable_forwarding":true}`} {
		_, e := Parse([]byte(`{"endpoints":[{"type":"tailscale","tag":"ts","ssh_server":` + value + `}],"route":{"final":"ts"}}`))
		if e != nil {
			t.Fatal(value, e)
		}
	}
	for _, value := range []string{`{"enabled":true,"unknown":true}`, `{"disable_pty":true}`, "1"} {
		_, e := Parse([]byte(`{"endpoints":[{"type":"tailscale","tag":"ts","ssh_server":` + value + `}],"route":{"final":"ts"}}`))
		if e == nil {
			t.Fatal("invalid SSH option accepted", value)
		}
	}
}
func TestTailscaleSSHExpiry(t *testing.T) {
	ip := netip.MustParseAddr("100.64.0.2")
	expires := time.Now().Add(20 * time.Millisecond)
	temporary := &tsSSHRule{RuleExpires: &expires, Principals: []*tsSSHPrincipal{{Any: true}}, SSHUsers: map[string]string{"alice": "local"}, Action: &tsSSHAction{Accept: true, AllowLocalPortForwarding: true}}
	standing := &tsSSHRule{Principals: []*tsSSHPrincipal{{Any: true}}, SSHUsers: map[string]string{"alice": "local"}, Action: &tsSSHAction{Accept: true}}
	c := &tailscaleClient{self: tsNode{ID: 1}, nodes: map[int64]tsNode{2: {ID: 2, Key: "key"}}, addressOwners: map[netip.Addr]int64{ip: 2}, sshPolicy: &tsSSHPolicy{Rules: []*tsSSHRule{temporary, standing}}}
	grant, ok := c.sshGrantLocked(ip, "alice", true)
	if !ok {
		t.Fatal("temporary permission did not match")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &tsSSHConnection{server: &tsSSHServer{c: c}, source: ip, nodeKey: "key", requested: "alice", identityAllowed: true, ctx: ctx, cancel: cancel, grant: grant}
	done := make(chan struct{})
	go func() { conn.watchPolicy(); close(done) }()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("expired forwarding permission survived fallback to a weaker accepting rule")
	}
	<-done
}
func TestTailscaleSSHAccountShell(t *testing.T) {
	for _, row := range []struct{ data, user, uid, want string }{
		{"alice:x:1000:1000::/home/alice:/bin/bash\n", "alice", "1000", "/bin/bash"},
		{"alice:x:1000:1000::/home/alice:\n", "alice", "1000", "/bin/sh"},
		{"locked:x:1001:1001::/home/locked:/sbin/nologin\n", "locked", "1001", "/sbin/nologin"},
	} {
		if got, e := tsSSHParsePasswd(row.data, &user.User{Username: row.user, Uid: row.uid, Gid: row.uid, HomeDir: "/home/" + row.user}); e != nil || got != row.want {
			t.Fatal("passwd shell", got, e)
		}
	}
	for _, account := range []*user.User{{Username: "missing", Uid: "1000", Gid: "1000"}, {Username: "alice", Uid: "0", Gid: "1000", HomeDir: "/home/alice"}, {Username: "alice", Uid: "1000", Gid: "0", HomeDir: "/home/alice"}, {Username: "alice", Uid: "1000", Gid: "1000", HomeDir: "/root"}} {
		if _, e := tsSSHParsePasswd("alice:x:1000:1000::/home/alice:/bin/bash\n", account); e == nil {
			t.Fatal("unknown account received fallback shell")
		}
	}
	for _, input := range []string{"UserShell: /bin/zsh\n", "dsAttrTypeStandard:UserShell: %2Fbin%2Fzsh\n"} {
		if shell, e := tsSSHParseDirectoryShell(input); e != nil || shell != "/bin/zsh" {
			t.Fatal("Directory Service shell", shell, e)
		}
	}
	for _, input := range []string{"", "UserShell:", "RecordName: /bin/zsh", "UserShell: /bin/zsh /bin/sh", "UserShell: relative", "UserShell: /bin/zsh%00", "UserShell: /bin/zsh%0A", "UserShell: %xx"} {
		if _, e := tsSSHParseDirectoryShell(input); e == nil {
			t.Fatal("invalid Directory Service shell accepted", input)
		}
	}
}
func TestTailscaleSSHPtyPermissions(t *testing.T) {
	if !tsSSHPlatform() {
		return
	}
	u, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	master, slave, e := tsSSHOpenPTY(u, 80, 24, []byte{0})
	if e != nil {
		t.Fatal(e)
	}
	defer master.Close()
	defer slave.Close()
	info, e := slave.Stat()
	if e != nil {
		t.Fatal(e)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("PTY exposed to other members of the login group", info.Mode())
	}
	if e = tsSSHResize(master, 100, 30); e != nil {
		t.Fatal(e)
	}
}
