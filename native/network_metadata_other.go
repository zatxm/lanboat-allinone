//go:build !linux && !windows && !darwin

package native

import "context"

func systemNetworkMetadata(context.Context, *Runtime) Metadata { return Metadata{} }
