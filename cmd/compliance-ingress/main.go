package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pug-sh/pug/internal/app/complianceingress"
	"github.com/pug-sh/pug/internal/slogx"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := complianceingress.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.ErrorContext(ctx, "compliance ingress error", slogx.Error(err))
		os.Exit(1)
	}
}
