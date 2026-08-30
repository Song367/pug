package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	"github.com/pug-sh/pug/internal/app/bootstrap"
	"github.com/pug-sh/pug/internal/slogx"
)

func main() {
	confirmEnvironment := flag.String("confirm-environment", "", "must exactly match PUG_ENVIRONMENT")
	confirmEmpty := flag.Bool("confirm-empty-database", false, "confirm this one-time job may initialize an empty Pug database")
	credentialsOut := flag.String("credentials-out", "", "absolute path to a new 0600 JSON credentials file")
	flag.Parse()

	ctx, done := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer done()
	if err := godotenv.Load(); err != nil {
		slog.DebugContext(ctx, "No .env file found, relying on environment variables")
	}

	if err := bootstrap.Run(ctx, bootstrap.Options{
		ConfirmEnvironment: *confirmEnvironment,
		ConfirmEmpty:       *confirmEmpty,
		CredentialsOut:     *credentialsOut,
	}); err != nil {
		slog.ErrorContext(ctx, "operator bootstrap failed", slogx.Error(err))
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "operator bootstrap completed; credentials were written once to the protected output file")
}
