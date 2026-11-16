package native

import (
	"errors"
	"net/url"
	"os/user"
	"strconv"
	"strings"
)

func tsSSHParsePasswd(data string, u *user.User) (string, error) {
	uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
	if e1 != nil || e2 != nil {
		return "", errors.New("invalid local account identity")
	}
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == u.Username {
			recordUID, e1 := strconv.ParseUint(fields[2], 10, 32)
			recordGID, e2 := strconv.ParseUint(fields[3], 10, 32)
			if e1 != nil || e2 != nil || recordUID != uid || recordGID != gid || fields[5] != u.HomeDir {
				return "", errors.New("local account record differs from system identity")
			}
			if fields[6] == "" {
				return "/bin/sh", nil
			}
			return fields[6], nil
		}
	}
	return "", errors.New("local account shell could not be verified")
}
func tsSSHParseDirectoryShell(data string) (string, error) {
	line := strings.TrimSpace(data)
	line = strings.TrimPrefix(line, "dsAttrTypeStandard:")
	key, value, ok := strings.Cut(line, ":")
	values := strings.Fields(value)
	if !ok || key != "UserShell" || len(values) != 1 {
		return "", errors.New("invalid Directory Service shell response")
	}
	shell, e := url.PathUnescape(values[0])
	if e != nil || !strings.HasPrefix(shell, "/") || strings.ContainsAny(shell, "\x00\r\n") {
		return "", errors.New("invalid Directory Service shell")
	}
	return shell, nil
}
