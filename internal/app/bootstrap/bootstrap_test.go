package bootstrap

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfig() config {
	return config{
		Environment: "test",
		Email:       "operator@example.test",
		DisplayName: "Pug Operator",
		OrgName:     "Example Org",
		ProjectName: "Example Project",
	}
}

func validOptions(t *testing.T) Options {
	t.Helper()
	return Options{
		ConfirmEnvironment: "test",
		ConfirmEmpty:       true,
		CredentialsOut:     filepath.Join(t.TempDir(), "credentials.json"),
	}
}

func TestConfigValidateRequiresExplicitSafeBootstrap(t *testing.T) {
	cfg := validConfig()
	if err := cfg.validate(validOptions(t)); err != nil {
		t.Fatalf("validate: %v", err)
	}

	for name, mutate := range map[string]func(*config, *Options){
		"demo": func(c *config, _ *Options) { c.DemoEnabled = true },
		"environment mismatch": func(_ *config, o *Options) {
			o.ConfirmEnvironment = "production"
		},
		"missing empty confirmation": func(_ *config, o *Options) { o.ConfirmEmpty = false },
		"relative output":            func(_ *config, o *Options) { o.CredentialsOut = "credentials.json" },
		"invalid email":              func(c *config, _ *Options) { c.Email = "Operator <operator@example.test>" },
		"untrimmed project":          func(c *config, _ *Options) { c.ProjectName = " project " },
		"control character":          func(c *config, _ *Options) { c.OrgName = "org\nname" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validConfig()
			opts := validOptions(t)
			mutate(&candidate, &opts)
			if err := candidate.validate(opts); err == nil {
				t.Fatal("validate unexpectedly succeeded")
			}
		})
	}
}

func TestGeneratePasswordUsesThirtyTwoRandomBytes(t *testing.T) {
	first, err := generatePassword()
	if err != nil {
		t.Fatal(err)
	}
	second, err := generatePassword()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		t.Fatalf("decode password: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("password entropy bytes = %d, want 32", len(decoded))
	}
	if first == second {
		t.Fatal("two generated passwords were identical")
	}
}

func TestWriteCredentialsExclusiveCreatesProtectedOneTimeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	want := Credentials{
		Environment: "test",
		Email:       "operator@example.test",
		Password:    "secret-password",
		OrgID:       "org-id",
		ProjectID:   "project-id",
		PublicKey:   "pub_example",
		PrivateKey:  "prv_example",
	}
	if err := writeCredentialsExclusive(path, want); err != nil {
		t.Fatalf("writeCredentialsExclusive: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %#o, want 0600", got)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Credentials
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode credentials: %v", err)
	}
	if got != want {
		t.Fatalf("credentials = %#v, want %#v", got, want)
	}

	if err := writeCredentialsExclusive(path, Credentials{Password: "replacement"}); err == nil {
		t.Fatal("second write unexpectedly replaced the credentials file")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), "secret-password") || strings.Contains(string(after), "replacement") {
		t.Fatal("exclusive write modified existing credentials")
	}
}
