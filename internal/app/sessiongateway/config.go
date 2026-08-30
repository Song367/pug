package sessiongateway

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const encryptionKeyBytes = 32

type config struct {
	Environment            string `env:"PUG_ENVIRONMENT,required"`
	Addr                   string `env:"PUG_SESSION_GATEWAY_ADDR,default=:8443"`
	PublicOrigin           string `env:"PUG_SESSION_GATEWAY_PUBLIC_ORIGIN,required"`
	APIUpstreamURL         string `env:"PUG_SESSION_GATEWAY_API_UPSTREAM_URL,required"`
	StaticUpstreamURL      string `env:"PUG_SESSION_GATEWAY_STATIC_UPSTREAM_URL,required"`
	SourceCodeURL          string `env:"PUG_SOURCE_CODE_URL,required"`
	DashboardSourceCodeURL string `env:"PUG_DASHBOARD_SOURCE_CODE_URL,required"`
	TLSCertFile            string `env:"PUG_SESSION_GATEWAY_TLS_CERT_FILE,required"`
	TLSKeyFile             string `env:"PUG_SESSION_GATEWAY_TLS_KEY_FILE,required"`
	RedisURL               string `env:"REDIS_URL,required"`
	EncryptionKeyHex       string `env:"PUG_SESSION_ENCRYPTION_KEY,required"`
}

type resolvedConfig struct {
	config
	publicOrigin        *url.URL
	apiUpstream         *url.URL
	staticUpstream      *url.URL
	sourceCode          *url.URL
	dashboardSourceCode *url.URL
	encryptionKey       []byte
}

func (c config) validate() (resolvedConfig, error) {
	c.Environment = strings.ToLower(strings.TrimSpace(c.Environment))
	switch c.Environment {
	case "development", "test", "production":
	default:
		return resolvedConfig{}, fmt.Errorf("PUG_ENVIRONMENT must be development, test, or production, got %q", c.Environment)
	}
	if strings.TrimSpace(c.Addr) == "" {
		return resolvedConfig{}, errors.New("PUG_SESSION_GATEWAY_ADDR must be non-empty")
	}
	if strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "" {
		return resolvedConfig{}, errors.New("PUG_SESSION_GATEWAY_TLS_CERT_FILE and PUG_SESSION_GATEWAY_TLS_KEY_FILE are required")
	}
	if strings.TrimSpace(c.RedisURL) == "" {
		return resolvedConfig{}, errors.New("REDIS_URL is required")
	}

	publicOrigin, err := parseOrigin(c.PublicOrigin, true)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("PUG_SESSION_GATEWAY_PUBLIC_ORIGIN: %w", err)
	}
	apiUpstream, err := parseOrigin(c.APIUpstreamURL, false)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("PUG_SESSION_GATEWAY_API_UPSTREAM_URL: %w", err)
	}
	staticUpstream, err := parseOrigin(c.StaticUpstreamURL, false)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("PUG_SESSION_GATEWAY_STATIC_UPSTREAM_URL: %w", err)
	}
	sourceCode, err := parseSourceCodeURL(c.SourceCodeURL)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("PUG_SOURCE_CODE_URL: %w", err)
	}
	dashboardSourceCode, err := parseSourceCodeURL(c.DashboardSourceCodeURL)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("PUG_DASHBOARD_SOURCE_CODE_URL: %w", err)
	}

	key, err := hex.DecodeString(strings.TrimSpace(c.EncryptionKeyHex))
	if err != nil || len(key) != encryptionKeyBytes {
		return resolvedConfig{}, fmt.Errorf("PUG_SESSION_ENCRYPTION_KEY must be exactly %d random bytes encoded as %d hexadecimal characters", encryptionKeyBytes, encryptionKeyBytes*2)
	}
	if subtle.ConstantTimeCompare(key, make([]byte, encryptionKeyBytes)) == 1 || allBytesEqual(key) {
		return resolvedConfig{}, errors.New("PUG_SESSION_ENCRYPTION_KEY must not be zero or a repeated-byte value")
	}

	return resolvedConfig{
		config:              c,
		publicOrigin:        publicOrigin,
		apiUpstream:         apiUpstream,
		staticUpstream:      staticUpstream,
		sourceCode:          sourceCode,
		dashboardSourceCode: dashboardSourceCode,
		encryptionKey:       key,
	}, nil
}

func parseSourceCodeURL(raw string) (*url.URL, error) {
	value, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || value.Scheme != "https" || value.Host == "" || value.User != nil ||
		value.RawQuery != "" || value.Fragment != "" {
		return nil, errors.New("must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return value, nil
}

func parseOrigin(raw string, requireHTTPS bool) (*url.URL, error) {
	value, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || value.Scheme == "" || value.Host == "" || value.User != nil ||
		(value.Path != "" && value.Path != "/") || value.RawQuery != "" || value.Fragment != "" {
		return nil, errors.New("must be an absolute HTTP(S) origin without credentials, path, query, or fragment")
	}
	if requireHTTPS && value.Scheme != "https" {
		return nil, errors.New("must use HTTPS")
	}
	if value.Scheme != "http" && value.Scheme != "https" {
		return nil, errors.New("must use HTTP or HTTPS")
	}
	value.Path = ""
	return value, nil
}

func allBytesEqual(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	for _, b := range value[1:] {
		if b != value[0] {
			return false
		}
	}
	return true
}
