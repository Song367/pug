package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pug-sh/pug/internal/core/orgs"
	"github.com/pug-sh/pug/internal/gen/repo/dbread"
	"github.com/pug-sh/pug/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

func TestBootstrapCreatesOnlyOperatorOrgProjectAndInitialKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := testutil.SetupPostgres(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	cfg := validConfig()

	if err := run(ctx, db.PgW, cfg, path); err != nil {
		t.Fatalf("run: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var creds Credentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		t.Fatal(err)
	}
	if creds.Environment != "test" || creds.Email != cfg.Email {
		t.Fatalf("credential identity = (%q, %q)", creds.Environment, creds.Email)
	}

	r := dbread.New(db.PgW)
	customer, err := r.GetCustomerByEmail(ctx, cfg.Email)
	if err != nil {
		t.Fatal(err)
	}
	if !customer.EmailVerifiedAt.Valid {
		t.Fatal("operator email was not marked verified")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(customer.PasswordHash), []byte(creds.Password)); err != nil {
		t.Fatalf("generated password does not match stored hash: %v", err)
	}
	role, err := r.GetOrgMemberRole(ctx, dbread.GetOrgMemberRoleParams{OrgID: creds.OrgID, CustomerID: customer.ID})
	if err != nil {
		t.Fatal(err)
	}
	if role != orgs.RoleAdmin.String() {
		t.Fatalf("operator role = %q, want admin", role)
	}
	project, err := r.GetProjectByID(ctx, creds.ProjectID)
	if err != nil {
		t.Fatal(err)
	}
	if project.OrgID != creds.OrgID || project.DisplayName != cfg.ProjectName {
		t.Fatalf("project = %#v", project)
	}
	keys, err := r.GetApiKeysByProjectID(ctx, project.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want public + private", len(keys))
	}
	privateDigest := sha256.Sum256([]byte(creds.PrivateKey))
	wantPrivateToken := hex.EncodeToString(privateDigest[:])
	foundPublic, foundPrivate := false, false
	for _, key := range keys {
		switch key.Kind {
		case "public":
			foundPublic = key.Token == creds.PublicKey
		case "private":
			foundPrivate = key.Token == wantPrivateToken && key.Token != creds.PrivateKey
		}
	}
	if !foundPublic || !foundPrivate {
		t.Fatalf("initial key storage mismatch: public=%v private=%v", foundPublic, foundPrivate)
	}

	secondPath := filepath.Join(t.TempDir(), "second.json")
	if err := run(ctx, db.PgW, cfg, secondPath); err == nil {
		t.Fatal("second bootstrap unexpectedly succeeded")
	}
	if _, err := os.Stat(secondPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second bootstrap output exists or stat failed: %v", err)
	}
	if _, err := r.GetCustomerByEmail(ctx, "woof@pug.sh"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("demo customer exists or query failed: %v", err)
	}
}
