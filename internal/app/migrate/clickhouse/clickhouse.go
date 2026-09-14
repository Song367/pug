package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/pressly/goose/v3"
	clickhousedeps "github.com/pug-sh/pug/internal/deps/clickhouse"
	"github.com/pug-sh/pug/internal/deps/rawretention"
	"github.com/sethvargo/go-envconfig"
)

func Up(ctx context.Context, num int) error {
	db, dir, err := setup(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if num == 0 {
		if err := goose.UpContext(ctx, db, dir); err != nil {
			return err
		}
		if err := reconcileRawEventsRetention(ctx, db); err != nil {
			return err
		}
		slog.InfoContext(ctx, "applied all clickhouse migrations")
		return nil
	}

	current, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return err
	}

	if err := goose.UpToContext(ctx, db, dir, current+int64(num)); err != nil {
		return err
	}
	if err := reconcileRawEventsRetention(ctx, db); err != nil {
		return err
	}

	slog.InfoContext(ctx, "applied clickhouse migrations", slog.Int("applied_migrations", num))
	return nil
}

func reconcileRawEventsRetention(ctx context.Context, db *sql.DB) error {
	var cfg clickhousedeps.Config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return err
	}
	query, days, managed, err := rawEventsRetentionDDL(cfg.Environment, cfg.RawEventsRetention)
	if err != nil {
		return err
	}
	if !managed {
		return nil
	}

	if err := applyRawEventsRetention(ctx, sqlRetentionCatalog{db: db}, query); err != nil {
		return err
	}
	slog.InfoContext(ctx, "reconciled raw events retention", slog.Int64("retention_days", days))
	return nil
}

type retentionCatalog interface {
	ShowCreate(context.Context) (string, error)
	Exec(context.Context, string) error
}

type sqlRetentionCatalog struct{ db *sql.DB }

var retentionDaysPattern = regexp.MustCompile(`(?i)(?:INTERVAL\s+([0-9]+)\s+DAY|toIntervalDay\(([0-9]+)\))`)

func (c sqlRetentionCatalog) ShowCreate(ctx context.Context) (string, error) {
	var createTable string
	if err := c.db.QueryRowContext(ctx, "SHOW CREATE TABLE events").Scan(&createTable); err != nil {
		return "", err
	}
	return createTable, nil
}

func (c sqlRetentionCatalog) Exec(ctx context.Context, query string) error {
	_, err := c.db.ExecContext(ctx, query)
	return err
}

func applyRawEventsRetention(ctx context.Context, catalog retentionCatalog, query string) error {
	before, err := catalog.ShowCreate(ctx)
	if err != nil {
		return fmt.Errorf("snapshot raw events table definition: %w", err)
	}
	rollback := rawEventsRetentionRollbackDDL(before)
	if err = catalog.Exec(ctx, query); err != nil {
		if rollbackErr := catalog.Exec(context.WithoutCancel(ctx), rollback); rollbackErr != nil {
			return fmt.Errorf("apply raw events retention: %w (automatic rollback failed: %w)", err, rollbackErr)
		}
		return fmt.Errorf("apply raw events retention: %w (previous TTL restored)", err)
	}
	after, verifyErr := catalog.ShowCreate(ctx)
	if verifyErr == nil {
		verifyErr = verifyRawEventsRetention(query, after)
	}
	if verifyErr == nil {
		return nil
	}
	if rollbackErr := catalog.Exec(context.WithoutCancel(ctx), rollback); rollbackErr != nil {
		return fmt.Errorf("verify raw events retention: %w (automatic rollback failed: %w)", verifyErr, rollbackErr)
	}
	return fmt.Errorf("verify raw events retention: %w (previous TTL restored)", verifyErr)
}

func rawEventsRetentionRollbackDDL(createTable string) string {
	if ttl := extractEventsTTL(createTable); ttl != "" {
		return "ALTER TABLE events MODIFY TTL " + ttl
	}
	return "ALTER TABLE events REMOVE TTL"
}

func verifyRawEventsRetention(query, createTable string) error {
	wanted := strings.TrimSpace(strings.TrimPrefix(query, "ALTER TABLE events MODIFY TTL"))
	got := extractEventsTTL(createTable)
	if query == "ALTER TABLE events REMOVE TTL" {
		if got != "" {
			return fmt.Errorf("events TTL still present: %q", got)
		}
		return nil
	}
	wantedDays, wantedOK := retentionExpressionDays(wanted)
	gotDays, gotOK := retentionExpressionDays(got)
	if !wantedOK || !gotOK || wantedDays != gotDays {
		return fmt.Errorf("events TTL = %q, want %q", got, wanted)
	}
	return nil
}

func extractEventsTTL(createTable string) string {
	for line := range strings.SplitSeq(strings.ReplaceAll(createTable, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 4 && strings.EqualFold(trimmed[:4], "TTL ") {
			return strings.TrimSpace(trimmed[4:])
		}
	}
	return ""
}

func normalizeRetentionExpression(value string) string {
	return strings.Join(strings.Fields(strings.ToLower(strings.TrimSpace(value))), " ")
}

func retentionExpressionDays(value string) (int64, bool) {
	match := retentionDaysPattern.FindStringSubmatch(normalizeRetentionExpression(value))
	if len(match) != 3 {
		return 0, false
	}
	raw := match[1]
	if raw == "" {
		raw = match[2]
	}
	days, err := strconv.ParseInt(raw, 10, 64)
	return days, err == nil && days >= 1 && days <= 14
}

func rawEventsRetentionDDL(environment, raw string) (string, int64, bool, error) {
	// An empty value in Test is an explicit rollback request. Leaving it as a
	// no-op would keep a previously installed TTL active even though the
	// deployment configuration says retention is unmanaged. Production keeps
	// the upstream no-op behavior and cannot use this Test-only control.
	if strings.EqualFold(strings.TrimSpace(environment), "test") && strings.TrimSpace(raw) == "" {
		return "ALTER TABLE events REMOVE TTL", 0, true, nil
	}
	retention, managed, err := rawretention.Resolve(environment, raw)
	if err != nil || !managed {
		return "", 0, managed, err
	}
	days := int64(retention / (24 * time.Hour))
	return fmt.Sprintf("ALTER TABLE events MODIFY TTL occur_time + INTERVAL %d DAY DELETE", days), days, true, nil
}

func Down(ctx context.Context, num int) error {
	db, dir, err := setup(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if num == 0 {
		if err := pruneOrphanedVersions(ctx, db, dir); err != nil {
			return err
		}
		for {
			current, err := goose.GetDBVersionContext(ctx, db)
			if err != nil {
				return err
			}
			if current == 0 {
				break
			}
			if err := goose.DownContext(ctx, db, dir); err != nil {
				return err
			}
		}
		slog.InfoContext(ctx, "rolled back all clickhouse migrations")
		return nil
	}

	for range num {
		if err := goose.DownContext(ctx, db, dir); err != nil {
			return err
		}
	}

	slog.InfoContext(ctx, "rolled back clickhouse migrations", slog.Int("rolled_back_migrations", num))
	return nil
}

// pruneOrphanedVersions removes applied version entries from goose_db_version
// that have no corresponding migration file in dir. This handles the case where
// migration files were deleted or are on a different branch, allowing Down to
// proceed normally from the highest available version.
func pruneOrphanedVersions(ctx context.Context, db *sql.DB, dir string) error {
	migrations, err := goose.CollectMigrations(dir, 0, goose.MaxVersion)
	if err != nil {
		return err
	}

	available := make(map[int64]struct{}, len(migrations))
	var maxAvailable int64
	for _, m := range migrations {
		available[m.Version] = struct{}{}
		if m.Version > maxAvailable {
			maxAvailable = m.Version
		}
	}

	current, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return err
	}

	if current <= maxAvailable {
		return nil
	}

	slog.InfoContext(ctx, "pruning orphaned migration versions",
		slog.Int64("db_version", current),
		slog.Int64("max_available", maxAvailable),
	)
	_, err = db.ExecContext(ctx,
		"DELETE FROM goose_db_version WHERE version_id > ?", maxAvailable)
	return err
}

func setup(ctx context.Context) (*sql.DB, string, error) {
	var cfg clickhousedeps.Config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return nil, "", err
	}

	db, err := sql.Open("clickhouse", cfg.URL)
	if err != nil {
		return nil, "", err
	}

	wd, err := os.Getwd()
	if err != nil {
		_ = db.Close()
		return nil, "", err
	}

	if err := goose.SetDialect("clickhouse"); err != nil {
		_ = db.Close()
		return nil, "", err
	}

	return db, filepath.Join(wd, "schema", "clickhouse", "migrations"), nil
}
