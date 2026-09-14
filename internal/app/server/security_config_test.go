package server

import (
	"strings"
	"testing"
)

func secureTestConfig() config {
	return config{
		Environment:              "test",
		JWTKeyringFile:           "/run/secrets/pug-jwt-keyring.json",
		CORSOrigins:              "https://analytics.example.test",
		IngestProjectRate:        200,
		IngestProjectBurst:       400,
		IngestIPRate:             50,
		IngestIPBurst:            100,
		IngestProjectConcurrency: 32,
		IngestIPConcurrency:      8,
	}
}

func TestConfigValidateAcceptsStrongExplicitConfiguration(t *testing.T) {
	cfg := secureTestConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestConfigValidateRejectsWeakJWTKeys(t *testing.T) {
	for _, key := range []string{
		"short",
		"your_jwt_secret_key_here",
		strings.Repeat("a", minimumJWTKeyBytes),
	} {
		t.Run(key, func(t *testing.T) {
			cfg := secureTestConfig()
			cfg.Environment = "development"
			cfg.JWTKeyringFile = ""
			cfg.JWTKey = key
			if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "PUG_JWT_SECRET_KEY") {
				t.Fatalf("validate error = %v, want JWT rejection", err)
			}
		})
	}
}

func TestConfigValidateRejectsUnsafeNonDevelopmentSettings(t *testing.T) {
	t.Run("wildcard CORS", func(t *testing.T) {
		cfg := secureTestConfig()
		cfg.CORSOrigins = "*"
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "allowlist") {
			t.Fatalf("validate error = %v, want explicit allowlist rejection", err)
		}
	})

	t.Run("demo enabled", func(t *testing.T) {
		cfg := secureTestConfig()
		cfg.DemoEnabled = true
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "PUG_DEMO_ENABLED") {
			t.Fatalf("validate error = %v, want demo rejection", err)
		}
	})
}

func TestConfigValidateAllowsDevelopmentWildcardAndDemo(t *testing.T) {
	cfg := secureTestConfig()
	cfg.Environment = "development"
	cfg.CORSOrigins = "*"
	cfg.DemoEnabled = true
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestConfigValidateRequiresKeyringOutsideDevelopment(t *testing.T) {
	cfg := secureTestConfig()
	cfg.JWTKeyringFile = ""
	cfg.JWTKey = "e8deabf4e0c241d9bb723c871cb3ad6fe4487867a2b313edb3ae47f89b51d09c"
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "PUG_JWT_KEYRING_FILE") {
		t.Fatalf("validate error = %v, want keyring requirement", err)
	}
}

func TestConfigValidateRejectsBothJWTConfigurationModes(t *testing.T) {
	cfg := secureTestConfig()
	cfg.JWTKey = "e8deabf4e0c241d9bb723c871cb3ad6fe4487867a2b313edb3ae47f89b51d09c"
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("validate error = %v, want mutually exclusive rejection", err)
	}
}

func TestConfigValidateNormalizesCORSOrigins(t *testing.T) {
	cfg := secureTestConfig()
	cfg.CORSOrigins = " https://one.example ,https://two.example,https://one.example "
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got, want := cfg.CORSOrigins, "https://one.example,https://two.example"; got != want {
		t.Fatalf("CORSOrigins = %q, want %q", got, want)
	}
}

func TestConfigValidateRejectsMalformedOriginsAndEnvironment(t *testing.T) {
	for _, origins := range []string{
		"https://example.com/path",
		"https://user@example.com",
		"* , https://example.com",
		"https://example.com,",
		"ftp://example.com",
	} {
		t.Run(origins, func(t *testing.T) {
			cfg := secureTestConfig()
			cfg.CORSOrigins = origins
			if err := cfg.validate(); err == nil {
				t.Fatal("validate unexpectedly succeeded")
			}
		})
	}

	cfg := secureTestConfig()
	cfg.Environment = "staging"
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "PUG_ENVIRONMENT") {
		t.Fatalf("validate error = %v, want environment rejection", err)
	}
}

func TestConfigValidateRejectsNonPositiveIngestLimits(t *testing.T) {
	cfg := secureTestConfig()
	cfg.IngestIPConcurrency = 0
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "PUG_INGEST_IP_CONCURRENCY") {
		t.Fatalf("validate error = %v, want ingest limit rejection", err)
	}
}
