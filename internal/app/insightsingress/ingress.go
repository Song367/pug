package insightsingress

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/pug-sh/pug/internal/deps/telemetry"
	"github.com/pug-sh/pug/internal/gen/proto/shared/insights/v1/insightsv1connect"
	"github.com/pug-sh/pug/internal/security/apikeyfile"
	"github.com/sethvargo/go-envconfig"
)

const maxBodyBytes = 256 << 10

type config struct {
	Environment   string `env:"PUG_ENVIRONMENT,required"`
	HTTPSAddr     string `env:"PUG_INSIGHTS_INGRESS_HTTPS_ADDR,default=:8443"`
	PublicHost    string `env:"PUG_INSIGHTS_INGRESS_PUBLIC_HOST,required"`
	UpstreamURL   string `env:"PUG_INSIGHTS_INGRESS_UPSTREAM_URL,required"`
	TLSCertFile   string `env:"PUG_INSIGHTS_INGRESS_TLS_CERT_FILE,required"`
	TLSKeyFile    string `env:"PUG_INSIGHTS_INGRESS_TLS_KEY_FILE,required"`
	APIKeyFile    string `env:"PUG_INSIGHTS_INGRESS_API_KEY_FILE,required"`
	SourceCodeURL string `env:"PUG_SOURCE_CODE_URL,required"`
}

func (c *config) validate() (*url.URL, error) {
	c.Environment = strings.ToLower(strings.TrimSpace(c.Environment))
	switch c.Environment {
	case "development", "test", "production":
	default:
		return nil, fmt.Errorf("PUG_ENVIRONMENT must be development, test, or production, got %q", c.Environment)
	}
	if strings.TrimSpace(c.HTTPSAddr) == "" {
		return nil, errors.New("PUG_INSIGHTS_INGRESS_HTTPS_ADDR must be non-empty")
	}
	if strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "" {
		return nil, errors.New("PUG_INSIGHTS_INGRESS_TLS_CERT_FILE and PUG_INSIGHTS_INGRESS_TLS_KEY_FILE are required")
	}
	if !filepath.IsAbs(strings.TrimSpace(c.APIKeyFile)) {
		return nil, errors.New("PUG_INSIGHTS_INGRESS_API_KEY_FILE must be an absolute path")
	}
	publicURL, err := url.Parse("https://" + c.PublicHost)
	if err != nil || publicURL.Host != c.PublicHost || publicURL.User != nil || publicURL.Path != "" || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return nil, errors.New("PUG_INSIGHTS_INGRESS_PUBLIC_HOST must be a host[:port] without scheme, credentials, path, query, or fragment")
	}
	upstream, err := url.Parse(c.UpstreamURL)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" || upstream.User != nil || (upstream.Path != "" && upstream.Path != "/") || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("PUG_INSIGHTS_INGRESS_UPSTREAM_URL must be an http(s) origin without credentials, path, query, or fragment")
	}
	if _, err := parseSourceCodeURL(c.SourceCodeURL); err != nil {
		return nil, fmt.Errorf("PUG_SOURCE_CODE_URL: %w", err)
	}
	return upstream, nil
}

func Run(ctx context.Context) error {
	var cfg config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return fmt.Errorf("insights ingress configuration: %w", err)
	}
	upstream, err := cfg.validate()
	if err != nil {
		return err
	}
	shutdownTelemetry, err := telemetry.SetupSDK(ctx)
	if err != nil {
		return err
	}
	defer telemetry.ShutdownOnExit(ctx, shutdownTelemetry)

	apiKey, err := apikeyfile.Load(cfg.APIKeyFile)
	if err != nil {
		return fmt.Errorf("load Insights ingress role key: %w", err)
	}
	handler, err := newHandler(cfg, upstream, nil, apiKey)
	if err != nil {
		return err
	}
	server := secureServer(cfg.HTTPSAddr, handler)
	errCh := make(chan error, 1)
	go func() {
		slog.InfoContext(ctx, "starting private insights TLS ingress", slog.String("addr", cfg.HTTPSAddr))
		errCh <- server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return errors.Join(server.Shutdown(shutdownCtx), ctx.Err())
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve private insights TLS ingress: %w", err)
	}
}

func secureServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

type handler struct {
	proxy         *httputil.ReverseProxy
	sourceCodeURL string
	apiKey        []byte
}

func newHandler(cfg config, upstream *url.URL, transport http.RoundTripper, apiKey []byte) (*handler, error) {
	sourceCodeURL, err := parseSourceCodeURL(cfg.SourceCodeURL)
	if err != nil {
		return nil, fmt.Errorf("PUG_SOURCE_CODE_URL: %w", err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(upstream)
			req.Out.Header = forwardedHeaders(req.In.Header)
			req.Out.Host = upstream.Host
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Access-Control-Allow-Credentials")
			resp.Header.Del("Access-Control-Allow-Origin")
			resp.Header.Del("Server")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeGatewayError(w, http.StatusBadGateway, "insights upstream unavailable")
		},
		Transport: transport,
	}
	if len(apiKey) == 0 {
		return nil, errors.New("Insights ingress role key is required")
	}
	return &handler{proxy: proxy, sourceCodeURL: sourceCodeURL.String(), apiKey: append([]byte(nil), apiKey...)}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setResponseSecurityHeaders(w.Header(), h.sourceCodeURL)
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	if r.URL.Path != insightsv1connect.InsightsServiceQueryProcedure {
		writeGatewayError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeGatewayError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("Origin") != "" {
		writeGatewayError(w, http.StatusForbidden, "browser origin denied")
		return
	}
	if !apikeyfile.Matches(h.apiKey, r.Header.Get("X-Api-Key")) {
		writeGatewayError(w, http.StatusUnauthorized, "private API key required")
		return
	}
	if r.ContentLength > maxBodyBytes {
		writeGatewayError(w, http.StatusRequestEntityTooLarge, "request body exceeds 256 KiB")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeGatewayError(w, http.StatusRequestEntityTooLarge, "request body exceeds 256 KiB")
		} else {
			writeGatewayError(w, http.StatusBadRequest, "invalid request body")
		}
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	h.proxy.ServeHTTP(w, r)
}

func forwardedHeaders(source http.Header) http.Header {
	forwarded := make(http.Header)
	for _, name := range []string{
		"Accept",
		"Accept-Encoding",
		"Connect-Protocol-Version",
		"Connect-Timeout-Ms",
		"Content-Encoding",
		"Content-Type",
		"Grpc-Timeout",
		"Traceparent",
		"Tracestate",
		"User-Agent",
		"X-Api-Key",
	} {
		for _, value := range source.Values(name) {
			forwarded.Add(name, value)
		}
	}
	return forwarded
}

func writeGatewayError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}

func setResponseSecurityHeaders(h http.Header, sourceCodeURL string) {
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	h.Set("Link", "<"+sourceCodeURL+">; rel=\"source\"")
}

func parseSourceCodeURL(raw string) (*url.URL, error) {
	value, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || value.Scheme != "https" || value.Host == "" || value.User != nil || value.RawQuery != "" || value.Fragment != "" {
		return nil, errors.New("must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return value, nil
}
