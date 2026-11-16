package native

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"os/user"
	"time"
)

type tsSSHAccountOutput struct{ bytes.Buffer }

func (b *tsSSHAccountOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 16384 {
		return 0, errors.New("Directory Service response too large")
	}
	return b.Buffer.Write(p)
}
func tsSSHAccountShell(ctx context.Context, u *user.User) (string, error) {
	if !tsSSHName(u.Username) {
		return "", errors.New("invalid local account")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/dscl", "-url", "/Search", "-read", "/Users/"+u.Username, "UserShell")
	var output tsSSHAccountOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if e := cmd.Run(); e != nil {
		return "", errors.New("Directory Service shell lookup failed")
	}
	return tsSSHParseDirectoryShell(output.String())
}
