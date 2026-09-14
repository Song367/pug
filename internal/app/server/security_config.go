package server

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

const minimumJWTKeyBytes = 32

var rejectedJWTKeys = map[string]struct{}{
	"change_me":                    {},
	"changeme":                     {},
	"jwt_secret":                   {},
	"secret":                       {},
	"your_jwt_secret_key_here":     {},
	"your-jwt-secret-key-here":     {},
	"replace_with_a_secure_secret": {},
}

func (c *config) validate() error {
	c.Environment = strings.ToLower(strings.TrimSpace(c.Environment))
	switch c.Environment {
	case "development", "test", "production":
	default:
		return fmt.Errorf("PUG_ENVIRONMENT must be development, test, or production, got %q", c.Environment)
	}

	c.JWTKeyringFile = strings.TrimSpace(c.JWTKeyringFile)
	if strings.TrimSpace(c.JWTKey) != "" && c.JWTKeyringFile != "" {
		return errors.New("PUG_JWT_SECRET_KEY and PUG_JWT_KEYRING_FILE are mutually exclusive")
	}
	if c.JWTKeyringFile != "" {
		if !filepath.IsAbs(c.JWTKeyringFile) {
			return errors.New("PUG_JWT_KEYRING_FILE must be an absolute path")
		}
	} else {
		if c.Environment != "development" {
			return errors.New("PUG_JWT_KEYRING_FILE is required outside development")
		}
		if err := validateJWTKey(c.JWTKey); err != nil {
			return err
		}
	}

	origins, err := parseCORSOrigins(c.CORSOrigins)
	if err != nil {
		return err
	}
	c.CORSOrigins = strings.Join(origins, ",")

	if c.Environment != "development" {
		if c.DemoEnabled {
			return errors.New("PUG_DEMO_ENABLED must be false outside development")
		}
		if len(origins) == 1 && origins[0] == "*" {
			return errors.New("PUG_CORS_ORIGINS must be an explicit allowlist outside development")
		}
	}

	positiveLimits := map[string]int{
		"PUG_INGEST_PROJECT_RATE":        c.IngestProjectRate,
		"PUG_INGEST_PROJECT_BURST":       c.IngestProjectBurst,
		"PUG_INGEST_IP_RATE":             c.IngestIPRate,
		"PUG_INGEST_IP_BURST":            c.IngestIPBurst,
		"PUG_INGEST_PROJECT_CONCURRENCY": c.IngestProjectConcurrency,
		"PUG_INGEST_IP_CONCURRENCY":      c.IngestIPConcurrency,
	}
	for name, value := range positiveLimits {
		if value <= 0 {
			return fmt.Errorf("%s must be positive", name)
		}
	}

	return nil
}

func validateJWTKey(key string) error {
	if len([]byte(key)) < minimumJWTKeyBytes {
		return fmt.Errorf("PUG_JWT_SECRET_KEY must contain at least %d bytes", minimumJWTKeyBytes)
	}

	normalized := strings.ToLower(strings.TrimSpace(key))
	if _, rejected := rejectedJWTKeys[normalized]; rejected {
		return errors.New("PUG_JWT_SECRET_KEY uses a forbidden placeholder or common weak value")
	}
	if normalized != "" && strings.Trim(normalized, string(normalized[0])) == "" {
		return errors.New("PUG_JWT_SECRET_KEY must not be a repeated-character value")
	}
	return nil
}

func parseCORSOrigins(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	origins := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		origin := strings.TrimSpace(part)
		if origin == "" {
			return nil, errors.New("PUG_CORS_ORIGINS must not contain an empty origin")
		}
		if origin != "*" {
			u, err := url.Parse(origin)
			if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				return nil, fmt.Errorf("PUG_CORS_ORIGINS entry %q must be an absolute origin without path, credentials, query, or fragment", origin)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return nil, fmt.Errorf("PUG_CORS_ORIGINS entry %q must use http or https", origin)
			}
			origin = u.String()
		}
		if _, duplicate := seen[origin]; duplicate {
			continue
		}
		seen[origin] = struct{}{}
		origins = append(origins, origin)
	}
	if len(origins) == 0 {
		return nil, errors.New("PUG_CORS_ORIGINS must contain at least one origin")
	}
	if len(origins) > 1 {
		if _, wildcard := seen["*"]; wildcard {
			return nil, errors.New("PUG_CORS_ORIGINS wildcard cannot be combined with explicit origins")
		}
	}
	return origins, nil
}
