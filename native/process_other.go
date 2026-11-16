//go:build !linux && !windows && !darwin

package native

import "context"

func (*processFinder) lookup(context.Context, socketOrigin) (string, string) { return "", "" }
