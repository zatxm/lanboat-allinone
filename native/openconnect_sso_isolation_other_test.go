//go:build !linux

package native

import "testing"

func isolateOpenConnectSSO(*testing.T) bool { return false }
