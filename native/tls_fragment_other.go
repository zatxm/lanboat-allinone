//go:build !linux && !darwin && !windows

package native

import "time"

func tcpFragmentRTT(uintptr) time.Duration { return 0 }
