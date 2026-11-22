package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/zatxm/lanboat-allinone/v26/internal/nativecmd"
	"github.com/zatxm/lanboat-allinone/v26/native"
)

func main() {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(64 << 20)
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(80)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := nativecmd.Execute(ctx, os.Args[1:], os.Stdout); err != nil {
		// Matches sing-box, which reports startup failures as one FATAL line.
		if logger, _, logErr := native.NewLogger(native.LogOptions{}); logErr == nil {
			logger.Fatal(err.Error())
		}
		os.Exit(1)
	}
}
