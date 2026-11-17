//go:build !windows

package native

import "time"

func quicNow() time.Time { return time.Now() }
