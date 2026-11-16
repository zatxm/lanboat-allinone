package native

import (
	"context"
	"os"
	"os/user"
)

func tsSSHAccountShell(_ context.Context, u *user.User) (string, error) {
	b, e := os.ReadFile("/etc/passwd")
	if e != nil {
		return "", e
	}
	return tsSSHParsePasswd(string(b), u)
}
