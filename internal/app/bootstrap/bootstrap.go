package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	coreauth "github.com/pug-sh/pug/internal/core/auth"
	coreorgs "github.com/pug-sh/pug/internal/core/orgs"
	"github.com/pug-sh/pug/internal/core/projects"
	"github.com/pug-sh/pug/internal/deps/postgres"
	"github.com/pug-sh/pug/internal/gen/repo/dbread"
	"github.com/pug-sh/pug/internal/gen/repo/dbwrite"
	"github.com/rs/xid"
	"github.com/sethvargo/go-envconfig"
	"golang.org/x/crypto/bcrypt"
)

const bootstrapAdvisoryLockID int64 = 0x505547424f4f54 // "PUGBOOT"

type Options struct {
	ConfirmEnvironment string
	ConfirmEmpty       bool
	CredentialsOut     string
}

type config struct {
	Environment       string `env:"PUG_ENVIRONMENT,required"`
	DemoEnabled       bool   `env:"PUG_DEMO_ENABLED,default=false"`
	Email             string `env:"PUG_BOOTSTRAP_EMAIL,required"`
	DisplayName       string `env:"PUG_BOOTSTRAP_DISPLAY_NAME,default=Pug Operator"`
	OrgName           string `env:"PUG_BOOTSTRAP_ORG_NAME,required"`
	ProjectName       string `env:"PUG_BOOTSTRAP_PROJECT_NAME,required"`
	ReportingTimezone string `env:"PUG_BOOTSTRAP_REPORTING_TIMEZONE"`
}

type Credentials struct {
	Environment string `json:"environment"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	OrgID       string `json:"org_id"`
	ProjectID   string `json:"project_id"`
	PublicKey   string `json:"public_api_key"`
	PrivateKey  string `json:"private_api_key"`
}

func Run(ctx context.Context, opts Options) error {
	var cfg config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return fmt.Errorf("bootstrap configuration: %w", err)
	}
	if err := cfg.validate(opts); err != nil {
		return err
	}

	var pgCfg postgres.Config
	if err := envconfig.Process(ctx, &pgCfg); err != nil {
		return fmt.Errorf("postgres configuration: %w", err)
	}
	pool, err := postgres.NewWriterPool(ctx, &pgCfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	return run(ctx, pool, cfg, opts.CredentialsOut)
}

func (c *config) validate(opts Options) error {
	c.Environment = strings.ToLower(strings.TrimSpace(c.Environment))
	switch c.Environment {
	case "development", "test", "production":
	default:
		return fmt.Errorf("PUG_ENVIRONMENT must be development, test, or production, got %q", c.Environment)
	}
	if c.DemoEnabled {
		return errors.New("operator bootstrap refuses to run while PUG_DEMO_ENABLED=true")
	}
	if strings.TrimSpace(opts.ConfirmEnvironment) != c.Environment {
		return fmt.Errorf("--confirm-environment must exactly match PUG_ENVIRONMENT=%s", c.Environment)
	}
	if !opts.ConfirmEmpty {
		return errors.New("--confirm-empty-database is required")
	}
	if !filepath.IsAbs(opts.CredentialsOut) {
		return errors.New("--credentials-out must be an absolute path to a new file")
	}

	c.Email = strings.TrimSpace(c.Email)
	address, err := mail.ParseAddress(c.Email)
	if err != nil || address.Address != c.Email || len(c.Email) > 255 {
		return errors.New("PUG_BOOTSTRAP_EMAIL must be one valid bare email address of at most 255 characters")
	}
	for name, value := range map[string]string{
		"PUG_BOOTSTRAP_DISPLAY_NAME": c.DisplayName,
		"PUG_BOOTSTRAP_ORG_NAME":     c.OrgName,
		"PUG_BOOTSTRAP_PROJECT_NAME": c.ProjectName,
	} {
		if err := validateDisplayValue(name, value); err != nil {
			return err
		}
	}
	return nil
}

func validateDisplayValue(name, value string) error {
	if value != strings.TrimSpace(value) || value == "" || len([]rune(value)) > 150 {
		return fmt.Errorf("%s must be non-empty, trimmed, and at most 150 characters", name)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s must not contain control characters", name)
	}
	return nil
}

func run(ctx context.Context, pool *pgxpool.Pool, cfg config, credentialsOut string) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return fmt.Errorf("begin bootstrap transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1)", bootstrapAdvisoryLockID); err != nil {
		return fmt.Errorf("acquire bootstrap lock: %w", err)
	}
	var populated bool
	if err := tx.QueryRow(ctx, `
		select exists(select 1 from customers)
		    or exists(select 1 from orgs)
		    or exists(select 1 from projects)
		    or exists(select 1 from api_keys)
	`).Scan(&populated); err != nil {
		return fmt.Errorf("check bootstrap state: %w", err)
	}
	if populated {
		return errors.New("refusing one-time bootstrap: business tables are not empty")
	}

	password, err := generatePassword()
	if err != nil {
		return err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash operator password: %w", err)
	}

	w := dbwrite.New(tx)
	customer, err := w.CreateCustomer(ctx, dbwrite.CreateCustomerParams{
		ID:           xid.New().String(),
		Email:        cfg.Email,
		DisplayName:  cfg.DisplayName,
		PasswordHash: string(passwordHash),
		PictureUri:   "",
	})
	if err != nil {
		return fmt.Errorf("create operator customer: %w", err)
	}
	if err := coreauth.FinalizeVerifiedCustomer(ctx, w, customer.ID); err != nil {
		return fmt.Errorf("verify operator email: %w", err)
	}

	org, project, err := coreorgs.CreateOrgWithProjectInTx(
		ctx, w, customer.ID, cfg.OrgName, cfg.ProjectName, cfg.ReportingTimezone,
	)
	if err != nil {
		return fmt.Errorf("create operator org and project: %w", err)
	}
	keys, err := dbread.New(tx).GetApiKeysByProjectID(ctx, project.ID)
	if err != nil {
		return fmt.Errorf("read starter project key: %w", err)
	}
	if len(keys) != 1 || projects.Kind(keys[0].Kind) != projects.KindPublic {
		return fmt.Errorf("expected exactly one starter public key, got %d keys", len(keys))
	}
	privateKey, err := projects.CreateApiKeyInTx(ctx, w, project.ID, projects.KindPrivate, "operator-bootstrap")
	if err != nil {
		return fmt.Errorf("create private project key: %w", err)
	}

	creds := Credentials{
		Environment: cfg.Environment,
		Email:       customer.Email,
		Password:    password,
		OrgID:       org.ID,
		ProjectID:   project.ID,
		PublicKey:   keys[0].Token,
		PrivateKey:  privateKey.RawKey,
	}
	if err := writeCredentialsExclusive(credentialsOut, creds); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		if cleanupErr := os.Remove(credentialsOut); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			return errors.Join(fmt.Errorf("commit bootstrap transaction: %w", err), fmt.Errorf("remove uncommitted credentials file %s: %w", credentialsOut, cleanupErr))
		}
		return fmt.Errorf("commit bootstrap transaction: %w", err)
	}
	return nil
}

func generatePassword() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate operator password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func writeCredentialsExclusive(path string, creds Credentials) (err error) {
	// #nosec G304 -- the operator supplies this absolute CLI output path; O_EXCL prevents
	// overwriting an existing file or following an existing final-component symlink.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create credentials output: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()

	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	// #nosec G117 -- this one-shot command intentionally writes generated credentials to
	// the new 0600 file above; it never serializes them to stdout or application logs.
	if err := encoder.Encode(creds); err != nil {
		return fmt.Errorf("write credentials output: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync credentials output: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close credentials output: %w", err)
	}
	success = true
	return nil
}
