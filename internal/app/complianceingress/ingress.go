package complianceingress

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
	"regexp"
	"strings"
	"time"

	"github.com/pug-sh/pug/internal/deps/telemetry"
	"github.com/pug-sh/pug/internal/gen/proto/shared/profiles/v1/profilesv1connect"
	"github.com/sethvargo/go-envconfig"
)

const maxBodyBytes = 64 << 10

var privateAPIKeyPattern = regexp.MustCompile(`^prv_[0-9a-f]{32}$`)

type config struct {
	Environment   string `env:"PUG_ENVIRONMENT,required"`
	HTTPSAddr     string `env:"PUG_COMPLIANCE_INGRESS_HTTPS_ADDR,default=:8443"`
	PublicHost    string `env:"PUG_COMPLIANCE_INGRESS_PUBLIC_HOST,required"`
	UpstreamURL   string `env:"PUG_COMPLIANCE_INGRESS_UPSTREAM_URL,required"`
	TLSCertFile   string `env:"PUG_COMPLIANCE_INGRESS_TLS_CERT_FILE,required"`
	TLSKeyFile    string `env:"PUG_COMPLIANCE_INGRESS_TLS_KEY_FILE,required"`
	SourceCodeURL string `env:"PUG_SOURCE_CODE_URL,required"`
}

func (c *config) validate() (*url.URL, error) {
	c.Environment = strings.ToLower(strings.TrimSpace(c.Environment))
	if c.Environment != "test" && c.Environment != "production" {
		return nil, fmt.Errorf("PUG_ENVIRONMENT must be test or production, got %q", c.Environment)
	}
	if strings.TrimSpace(c.HTTPSAddr) == "" {
		return nil, errors.New("PUG_COMPLIANCE_INGRESS_HTTPS_ADDR must be non-empty")
	}
	if strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "" {
		return nil, errors.New("PUG_COMPLIANCE_INGRESS_TLS_CERT_FILE and PUG_COMPLIANCE_INGRESS_TLS_KEY_FILE are required")
	}
	publicURL, err := url.Parse("https://" + c.PublicHost)
	if err != nil || publicURL.Host != c.PublicHost || publicURL.User != nil || publicURL.Path != "" || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return nil, errors.New("PUG_COMPLIANCE_INGRESS_PUBLIC_HOST must be a host[:port] without scheme, credentials, path, query, or fragment")
	}
	upstream, err := url.Parse(c.UpstreamURL)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" || upstream.User != nil || (upstream.Path != "" && upstream.Path != "/") || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("PUG_COMPLIANCE_INGRESS_UPSTREAM_URL must be an http(s) origin without credentials, path, query, or fragment")
	}
	if _, err := parseSourceCodeURL(c.SourceCodeURL); err != nil {
		return nil, fmt.Errorf("PUG_SOURCE_CODE_URL: %w", err)
	}
	return upstream, nil
}

func Run(ctx context.Context) error {
	var cfg config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return fmt.Errorf("compliance ingress configuration: %w", err)
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
	handler, err := newHandler(cfg, upstream, nil)
	if err != nil {
		return err
	}
	server := secureServer(cfg.HTTPSAddr, handler)
	errCh := make(chan error, 1)
	go func() {
		slog.InfoContext(ctx, "starting private compliance TLS ingress", slog.String("addr", cfg.HTTPSAddr))
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
		return fmt.Errorf("serve private compliance TLS ingress: %w", err)
	}
}

func secureServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}

type handler struct {
	proxy         *httputil.ReverseProxy
	sourceCodeURL string
}

func newHandler(cfg config, upstream *url.URL, transport http.RoundTripper) (*handler, error) {
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
			for _, name := range []string{"Access-Control-Allow-Credentials", "Access-Control-Allow-Origin", "Server"} {
				resp.Header.Del(name)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeGatewayError(w, http.StatusBadGateway, "compliance upstream unavailable")
		},
		Transport: transport,
	}
	return &handler{proxy: proxy, sourceCodeURL: sourceCodeURL.String()}, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setResponseSecurityHeaders(w.Header(), h.sourceCodeURL)
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	if r.URL.Path != profilesv1connect.ProfilesServiceDeleteDataSubjectProcedure && r.URL.Path != profilesv1connect.ProfilesServiceGetDeletionRequestProcedure {
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
	if !privateAPIKeyPattern.MatchString(r.Header.Get("X-Api-Key")) {
		writeGatewayError(w, http.StatusUnauthorized, "private API key required")
		return
	}
	if r.ContentLength > maxBodyBytes {
		writeGatewayError(w, http.StatusRequestEntityTooLarge, "request body exceeds 64 KiB")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeGatewayError(w, http.StatusRequestEntityTooLarge, "request body exceeds 64 KiB")
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
	for _, name := range []string{"Accept", "Accept-Encoding", "Connect-Protocol-Version", "Connect-Timeout-Ms", "Content-Encoding", "Content-Type", "Grpc-Timeout", "Traceparent", "Tracestate", "User-Agent", "X-Api-Key"} {
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
