package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/zatxm/lanboat-allinone/internal/nativecmd"
	"go.uber.org/zap"
)

func main() {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(64 << 20)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := nativecmd.Execute(ctx, os.Args[1:], os.Stdout); err != nil {
		logger, logErr := zap.NewProduction()
		if logErr == nil {
			logger.Error("command failed", zap.Error(err))
			_ = logger.Sync()
		}
		os.Exit(1)
	}
}
