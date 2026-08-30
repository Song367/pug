package sessiongateway

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/pug-sh/pug/internal/deps/redis"
	"github.com/pug-sh/pug/internal/deps/telemetry"
	"github.com/pug-sh/pug/internal/gen/proto/public/auth/v1/authv1connect"
	"github.com/pug-sh/pug/internal/slogx"
	"github.com/sethvargo/go-envconfig"
)

func Run(ctx context.Context) error {
	var raw config
	if err := envconfig.Process(ctx, &raw); err != nil {
		return fmt.Errorf("session gateway configuration: %w", err)
	}
	cfg, err := raw.validate()
	if err != nil {
		return err
	}

	shutdownTelemetry, err := telemetry.SetupSDK(ctx)
	if err != nil {
		return err
	}
	defer telemetry.ShutdownOnExit(ctx, shutdownTelemetry)

	redisClient, err := redis.NewFromConfig(ctx, &redis.Config{URL: cfg.RedisURL})
	if err != nil {
		return fmt.Errorf("initialize session store: %w", err)
	}
	defer redisClient.Close(ctx)

	store, err := newRedisSessionStore(redisClient.Unwrap(), cfg.encryptionKey)
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 65 * time.Second,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{Transport: transport, Timeout: upstreamAuthTimeout}
	authClient := authv1connect.NewAuthServiceClient(httpClient, cfg.apiUpstream.String())
	sessions := newSessionManager(store, authClient)
	handler := newGateway(cfg, sessions, authClient, transport, transport)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.ErrorContext(shutdownCtx, "session gateway shutdown error", slogx.Error(err)) // puglint:exempt — no span at shutdown
		}
	}()

	slog.InfoContext(ctx, "starting dashboard session gateway",
		slog.String("addr", cfg.Addr),
		slog.String("public_origin", cfg.publicOrigin.String()))
	if err := server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve dashboard session gateway: %w", err)
	}
	return nil
}
