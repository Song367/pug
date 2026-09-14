package server

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/otelconnect"
	"github.com/jackc/pgx/v5/pgxpool"
	pogrpc "github.com/pug-sh/pug/internal/app/server/rpc"
	"github.com/pug-sh/pug/internal/core/authz"
	chdb "github.com/pug-sh/pug/internal/deps/clickhouse"
	"github.com/pug-sh/pug/internal/deps/nats"
	"github.com/pug-sh/pug/internal/deps/postgres"
	"github.com/pug-sh/pug/internal/deps/redis"
	"github.com/pug-sh/pug/internal/deps/telemetry"
	"github.com/pug-sh/pug/internal/security/jwtkeyring"
	"github.com/pug-sh/pug/internal/slogx"
	"github.com/sethvargo/go-envconfig"
)

type deps struct {
	authz             *authz.Authorizer
	ch                *chdb.Conn
	closeOtel         func(context.Context) error
	corsOrigins       []string
	jwtKeys           *jwtkeyring.Keyring
	nats              *nats.NATSClient
	otelInterceptor   *otelconnect.Interceptor
	pgRo              *pgxpool.Pool
	pgW               *pgxpool.Pool
	redis             *redis.Client
	ingestGuard       *pogrpc.IngestGuard
	port              string
	demoEnabled       bool
	trustProxyHeaders bool

	// readyFailures counts consecutive failed readiness probes. It distinguishes
	// a transient blip (logged at WARN) from a sustained outage (escalated to
	// error telemetry); see (*deps).recordReadiness in health.go.
	readyFailures atomic.Int64
}

// close shuts down all deps. OTel must shut down last — it owns the slog backend,
// so earlier components' shutdown logs are still captured. Cancellation is
// stripped from ctx so cleanup isn't aborted by a cancelled signal context.
func (d *deps) close(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	d.pgRo.Close()
	d.pgW.Close()
	if d.nats != nil {
		d.nats.Close()
	}
	if d.redis != nil {
		d.redis.Close(ctx)
	}
	if d.ch != nil {
		if err := d.ch.Close(); err != nil {
			slog.ErrorContext(ctx, "failed to close clickhouse", slogx.Error(err)) // puglint:exempt — no span at shutdown
		}
	}
	if d.closeOtel != nil {
		if err := d.closeOtel(ctx); err != nil {
			slog.ErrorContext(ctx, "failed to shutdown telemetry", slogx.Error(err)) // puglint:exempt — nothing left to record it on
		}
	}
}

func newDeps(ctx context.Context) (*deps, error) {
	var closers []func()
	success := false
	defer func() {
		if !success {
			for _, closer := range slices.Backward(closers) {
				closer()
			}
		}
	}()

	var serverCfg config
	if err := envconfig.Process(ctx, &serverCfg); err != nil {
		return nil, err
	}
	if err := serverCfg.validate(); err != nil {
		return nil, fmt.Errorf("validate server security configuration: %w", err)
	}
	var jwtKeys *jwtkeyring.Keyring
	if serverCfg.JWTKeyringFile != "" {
		loadedJWTKeys, loadErr := jwtkeyring.Load(serverCfg.JWTKeyringFile, time.Now())
		if loadErr != nil {
			return nil, fmt.Errorf("load JWT keyring: %w", loadErr)
		}
		jwtKeys = loadedJWTKeys
	} else {
		jwtKeys = jwtkeyring.Single([]byte(serverCfg.JWTKey))
	}
	ingestGuard, err := pogrpc.NewIngestGuard(pogrpc.IngestGuardConfig{
		ProjectRate:        serverCfg.IngestProjectRate,
		ProjectBurst:       serverCfg.IngestProjectBurst,
		IPRate:             serverCfg.IngestIPRate,
		IPBurst:            serverCfg.IngestIPBurst,
		ProjectConcurrency: serverCfg.IngestProjectConcurrency,
		IPConcurrency:      serverCfg.IngestIPConcurrency,
		IdleTTL:            10 * time.Minute,
		MaxTrackedKeys:     20_000,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize ingest guard: %w", err)
	}

	otelInterceptor, closeOtel, err := telemetry.NewOtelInterceptor(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "failed to initialize telemetry", slogx.Error(err)) // puglint:exempt — nothing to record it on yet
		return nil, err
	}
	closers = append(closers, func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := closeOtel(rollbackCtx); err != nil {
			slog.ErrorContext(rollbackCtx, "failed to close otel during rollback", slogx.Error(err)) // puglint:exempt — nothing left to record it on
		}
	})

	var pgCfg postgres.Config
	if err := envconfig.Process(ctx, &pgCfg); err != nil {
		return nil, err
	}

	pgRo, err := postgres.NewReaderPool(ctx, &pgCfg)
	if err != nil {
		return nil, err
	}
	closers = append(closers, pgRo.Close)

	pgW, err := postgres.NewWriterPool(ctx, &pgCfg)
	if err != nil {
		return nil, err
	}
	closers = append(closers, pgW.Close)

	natsClient, err := nats.New(ctx)
	if err != nil {
		return nil, err
	}
	closers = append(closers, natsClient.Close)

	var redisCfg redis.Config
	if err := envconfig.Process(ctx, &redisCfg); err != nil {
		return nil, err
	}

	redisClient, err := redis.NewFromConfig(ctx, &redisCfg)
	if err != nil {
		return nil, err
	}
	closers = append(closers, func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		redisClient.Close(rollbackCtx)
	})

	var chCfg chdb.Config
	if err := envconfig.Process(ctx, &chCfg); err != nil {
		return nil, err
	}

	chConn, err := chdb.NewReaderPool(ctx, &chCfg)
	if err != nil {
		return nil, err
	}
	closers = append(closers, func() {
		if err := chConn.Close(); err != nil {
			slog.ErrorContext(ctx, "failed to close clickhouse during rollback", slogx.Error(err)) // puglint:exempt — no span at startup
		}
	})

	// Authorization policy is built from static in-code rules; it has no I/O or
	// lifecycle, so it is constructed here and injected like any other dep. A
	// malformed policy fails startup via this error (no panic, no global).
	authorizer, err := authz.NewAuthorizer()
	if err != nil {
		return nil, err
	}

	success = true
	return &deps{
		authz:             authorizer,
		ch:                chConn,
		closeOtel:         closeOtel,
		corsOrigins:       strings.Split(serverCfg.CORSOrigins, ","),
		jwtKeys:           jwtKeys,
		nats:              natsClient,
		otelInterceptor:   otelInterceptor,
		pgRo:              pgRo,
		pgW:               pgW,
		redis:             redisClient,
		ingestGuard:       ingestGuard,
		port:              serverCfg.Port,
		demoEnabled:       serverCfg.DemoEnabled,
		trustProxyHeaders: serverCfg.TrustProxyHeaders,
	}, nil
}
