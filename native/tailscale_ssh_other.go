//go:build !linux && !darwin

package native

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
)

func tsSSHPlatform() bool { return false }
func tsSSHCanSwitch(*user.User) error {
	return errors.New("Tailscale SSH server requires Linux or macOS")
}
func tsSSHProcess(context.Context, *user.User, string, bool, bool, string, map[string]string, string, *os.File) (*exec.Cmd, error) {
	return nil, tsSSHCanSwitch(nil)
}
func tsSSHWorkerProcess(context.Context, *user.User, string, ...string) (*exec.Cmd, error) {
	return nil, tsSSHCanSwitch(nil)
}
func tsSSHOpenPTY(*user.User, uint32, uint32, []byte) (*os.File, *os.File, error) {
	return nil, nil, tsSSHCanSwitch(nil)
}
func tsSSHResize(*os.File, uint32, uint32) error { return tsSSHCanSwitch(nil) }
func tsSSHSignal(*exec.Cmd, string) error        { return tsSSHCanSwitch(nil) }
func tsSSHKill(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
