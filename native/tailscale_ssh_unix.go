//go:build linux || darwin

package native

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func tsSSHPlatform() bool { return true }
func tsSSHCanSwitch(account *user.User) error {
	if os.Geteuid() != 0 && strconv.Itoa(os.Geteuid()) != account.Uid {
		return errors.New("Tailscale SSH needs root to switch local users")
	}
	return nil
}
func tsSSHProcess(ctx context.Context, u *user.User, command string, login, sftp bool, worker string, env map[string]string, term string, slave *os.File) (*exec.Cmd, error) {
	shell, e := tsSSHAccountShell(ctx, u)
	if e != nil {
		return nil, e
	}
	if !strings.HasPrefix(shell, "/") || strings.ContainsAny(shell, "\x00\r\n") || strings.HasSuffix(shell, "/nologin") || strings.HasSuffix(shell, "/false") {
		return nil, errors.New("local account has no login shell")
	}
	var cmd *exec.Cmd
	if sftp {
		cmd = exec.CommandContext(ctx, worker, "tailscale-ssh-worker")
	} else if login {
		cmd = exec.CommandContext(ctx, shell)
		cmd.Args[0] = "-" + filepath.Base(shell)
	} else {
		cmd = exec.CommandContext(ctx, shell, "-c", command)
	}
	cmd.Dir = u.HomeDir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Env = []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "SHELL=" + shell, "PATH=/usr/local/bin:/usr/bin:/bin"}
	if term != "" {
		cmd.Env = append(cmd.Env, "TERM="+term)
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	if e := tsSSHConfigureProcess(cmd, u, slave); e != nil {
		return nil, e
	}
	return cmd, nil
}
func tsSSHWorkerProcess(ctx context.Context, u *user.User, worker string, args ...string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, worker, append([]string{"tailscale-ssh-worker"}, args...)...)
	cmd.Dir = u.HomeDir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	cmd.Env = []string{"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username, "PATH=/usr/local/bin:/usr/bin:/bin"}
	if e := tsSSHConfigureProcess(cmd, u, nil); e != nil {
		return nil, e
	}
	// IPC EOF gives the worker time to unlink its listening socket before forced termination.
	cmd.Cancel = func() error { return nil }
	return cmd, nil
}
func tsSSHConfigureProcess(cmd *exec.Cmd, u *user.User, slave *os.File) error {
	if e := tsSSHCanSwitch(u); e != nil {
		return e
	}
	uid, e := strconv.ParseUint(u.Uid, 10, 32)
	if e != nil {
		return e
	}
	gid, e := strconv.ParseUint(u.Gid, 10, 32)
	if e != nil {
		return e
	}
	attr := &syscall.SysProcAttr{Setsid: true}
	if os.Geteuid() == 0 {
		groups, e := u.GroupIds()
		if e != nil {
			return e
		}
		credential := &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
		for _, group := range groups {
			id, e := strconv.ParseUint(group, 10, 32)
			if e != nil {
				return e
			}
			credential.Groups = append(credential.Groups, uint32(id))
		}
		attr.Credential = credential
	}
	if slave != nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		attr.Setctty = true
		attr.Ctty = 0
	}
	cmd.SysProcAttr = attr
	cmd.Cancel = func() error { tsSSHKill(cmd); return nil }
	cmd.WaitDelay = time.Second
	return nil
}
func tsSSHKill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
func tsSSHSignal(cmd *exec.Cmd, name string) error {
	signals := map[string]syscall.Signal{"ABRT": syscall.SIGABRT, "ALRM": syscall.SIGALRM, "FPE": syscall.SIGFPE, "HUP": syscall.SIGHUP, "ILL": syscall.SIGILL, "INT": syscall.SIGINT, "KILL": syscall.SIGKILL, "PIPE": syscall.SIGPIPE, "QUIT": syscall.SIGQUIT, "SEGV": syscall.SIGSEGV, "TERM": syscall.SIGTERM, "USR1": syscall.SIGUSR1, "USR2": syscall.SIGUSR2}
	signal, ok := signals[name]
	if !ok || cmd.Process == nil {
		return errors.New("unknown SSH signal")
	}
	return syscall.Kill(-cmd.Process.Pid, signal)
}
