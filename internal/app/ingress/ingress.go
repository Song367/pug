package ingress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/errgroup"

	pogrpc "github.com/pug-sh/pug/internal/app/server/rpc"
	"github.com/pug-sh/pug/internal/deps/telemetry"
	"github.com/pug-sh/pug/internal/gen/proto/sdk/events/v1/eventsv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/sdk/profiles/v1/sdkprofilesv1connect"
	"github.com/pug-sh/pug/internal/geo"
	"github.com/sethvargo/go-envconfig"
)

const (
	maxBodyBytes        = 1 << 20
	sourceCodePath      = "/source"
	wellKnownSourcePath = "/.well-known/source-code"
)

var ingressRejectedCounter metric.Int64Counter

func init() {
	ingressRejectedCounter, _ = otel.Meter("github.com/pug-sh/pug/internal/app/ingress").Int64Counter(
		"ingress.rejected_total",
		metric.WithDescription("Collector gateway requests rejected before reaching Pug. reason is path, method, payload, rate_limit, concurrency_limit, client_ip, or upstream."),
	)
}

type config struct {
	Environment      string `env:"PUG_ENVIRONMENT,required"`
	HTTPAddr         string `env:"PUG_INGRESS_HTTP_ADDR,default=:8080"`
	HTTPSAddr        string `env:"PUG_INGRESS_HTTPS_ADDR,default=:8443"`
	PublicHost       string `env:"PUG_INGRESS_PUBLIC_HOST,required"`
	UpstreamURL      string `env:"PUG_INGRESS_UPSTREAM_URL,required"`
	TLSCertFile      string `env:"PUG_INGRESS_TLS_CERT_FILE,required"`
	TLSKeyFile       string `env:"PUG_INGRESS_TLS_KEY_FILE,required"`
	SourceCodeURL    string `env:"PUG_SOURCE_CODE_URL,required"`
	TrustEdgeHeaders bool   `env:"PUG_INGRESS_TRUST_EDGE_HEADERS,default=false"`
	KeyRate          int    `env:"PUG_INGRESS_KEY_RATE,default=200"`
	KeyBurst         int    `env:"PUG_INGRESS_KEY_BURST,default=400"`
	IPRate           int    `env:"PUG_INGRESS_IP_RATE,default=50"`
	IPBurst          int    `env:"PUG_INGRESS_IP_BURST,default=100"`
	KeyConcurrency   int    `env:"PUG_INGRESS_KEY_CONCURRENCY,default=32"`
	IPConcurrency    int    `env:"PUG_INGRESS_IP_CONCURRENCY,default=8"`
}

func (c *config) validate() (*url.URL, error) {
	c.Environment = strings.ToLower(strings.TrimSpace(c.Environment))
	switch c.Environment {
	case "development", "test", "production":
	default:
		return nil, fmt.Errorf("PUG_ENVIRONMENT must be development, test, or production, got %q", c.Environment)
	}
	if c.HTTPAddr == c.HTTPSAddr {
		return nil, errors.New("PUG_INGRESS_HTTP_ADDR and PUG_INGRESS_HTTPS_ADDR must differ")
	}
	if strings.TrimSpace(c.HTTPAddr) == "" || strings.TrimSpace(c.HTTPSAddr) == "" {
		return nil, errors.New("PUG_INGRESS_HTTP_ADDR and PUG_INGRESS_HTTPS_ADDR must be non-empty")
	}
	if strings.TrimSpace(c.TLSCertFile) == "" || strings.TrimSpace(c.TLSKeyFile) == "" {
		return nil, errors.New("PUG_INGRESS_TLS_CERT_FILE and PUG_INGRESS_TLS_KEY_FILE are required")
	}
	publicURL, err := url.Parse("https://" + c.PublicHost)
	if err != nil || publicURL.Host != c.PublicHost || publicURL.User != nil || publicURL.Path != "" || publicURL.RawQuery != "" || publicURL.Fragment != "" {
		return nil, errors.New("PUG_INGRESS_PUBLIC_HOST must be a host[:port] without scheme, credentials, path, query, or fragment")
	}
	upstream, err := url.Parse(c.UpstreamURL)
	if err != nil || (upstream.Scheme != "http" && upstream.Scheme != "https") || upstream.Host == "" || upstream.User != nil || (upstream.Path != "" && upstream.Path != "/") || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("PUG_INGRESS_UPSTREAM_URL must be an http(s) origin without credentials, path, query, or fragment")
	}
	if _, err := parseSourceCodeURL(c.SourceCodeURL); err != nil {
		return nil, fmt.Errorf("PUG_SOURCE_CODE_URL: %w", err)
	}
	for name, value := range map[string]int{
		"PUG_INGRESS_KEY_RATE":        c.KeyRate,
		"PUG_INGRESS_KEY_BURST":       c.KeyBurst,
		"PUG_INGRESS_IP_RATE":         c.IPRate,
		"PUG_INGRESS_IP_BURST":        c.IPBurst,
		"PUG_INGRESS_KEY_CONCURRENCY": c.KeyConcurrency,
		"PUG_INGRESS_IP_CONCURRENCY":  c.IPConcurrency,
	} {
		if value <= 0 {
			return nil, fmt.Errorf("%s must be positive", name)
		}
	}
	return upstream, nil
}

func Run(ctx context.Context) error {
	var cfg config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return fmt.Errorf("ingress configuration: %w", err)
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
	httpsServer := secureServer(cfg.HTTPSAddr, handler)
	httpServer := secureServer(cfg.HTTPAddr, redirectHandler(url.URL{Scheme: "https", Host: cfg.PublicHost}))

	g, runCtx := errgroup.WithContext(ctx)
	g.Go(func() error {
		slog.InfoContext(runCtx, "starting collector TLS ingress", slog.String("addr", cfg.HTTPSAddr))
		if err := httpsServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve collector TLS ingress: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		slog.InfoContext(runCtx, "starting collector HTTP redirect", slog.String("addr", cfg.HTTPAddr))
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve collector HTTP redirect: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		<-runCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(runCtx), 10*time.Second)
		defer cancel()
		return errors.Join(httpsServer.Shutdown(shutdownCtx), httpServer.Shutdown(shutdownCtx))
	})
	return g.Wait()
}

func secureServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
	}
}

func redirectHandler(publicURL url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := publicURL
		target.Path = r.URL.Path
		target.RawPath = r.URL.RawPath
		target.RawQuery = r.URL.RawQuery
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Location", target.String())
		w.WriteHeader(http.StatusPermanentRedirect)
	})
}

type handler struct {
	proxy            *httputil.ReverseProxy
	guard            *pogrpc.IngestGuard
	sourceCodeURL    string
	trustEdgeHeaders bool
}

func newHandler(cfg config, upstream *url.URL, transport http.RoundTripper) (*handler, error) {
	sourceCodeURL, err := parseSourceCodeURL(cfg.SourceCodeURL)
	if err != nil {
		return nil, fmt.Errorf("PUG_SOURCE_CODE_URL: %w", err)
	}
	guard, err := pogrpc.NewIngestGuard(pogrpc.IngestGuardConfig{
		ProjectRate:        cfg.KeyRate,
		ProjectBurst:       cfg.KeyBurst,
		IPRate:             cfg.IPRate,
		IPBurst:            cfg.IPBurst,
		ProjectConcurrency: cfg.KeyConcurrency,
		IPConcurrency:      cfg.IPConcurrency,
		IdleTTL:            10 * time.Minute,
		MaxTrackedKeys:     20_000,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize ingress guard: %w", err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			clientIP, _ := req.In.Context().Value(clientIPContextKey{}).(string)
			req.SetURL(upstream)
			req.Out.Header = forwardedHeaders(req.In.Header, cfg.TrustEdgeHeaders)
			req.Out.Header.Set(geo.HeaderXForwardedFor, clientIP)
			req.Out.Host = upstream.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			ingressRejectedCounter.Add(r.Context(), 1, metric.WithAttributes(attribute.String("reason", "upstream")))
			writeGatewayError(w, http.StatusBadGateway, "collector upstream unavailable")
		},
		Transport: transport,
	}
	return &handler{
		proxy:            proxy,
		guard:            guard,
		sourceCodeURL:    sourceCodeURL.String(),
		trustEdgeHeaders: cfg.TrustEdgeHeaders,
	}, nil
}

type clientIPContextKey struct{}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setResponseSecurityHeaders(w.Header(), h.sourceCodeURL)
	if r.URL.Path == sourceCodePath || r.URL.Path == wellKnownSourcePath {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.reject(w, r, http.StatusMethodNotAllowed, "method", "method not allowed")
			return
		}
		http.Redirect(w, r, h.sourceCodeURL, http.StatusPermanentRedirect)
		return
	}
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
		return
	}
	isEvents := r.URL.Path == eventsv1connect.EventsServiceBatchCreateProcedure
	isIdentify := r.URL.Path == sdkprofilesv1connect.ProfilesSDKServiceIdentifyProcedure
	if !isEvents && !isIdentify {
		h.reject(w, r, http.StatusNotFound, "path", "not found")
		return
	}
	if r.Method != http.MethodPost && !(isEvents && r.Method == http.MethodOptions) {
		h.reject(w, r, http.StatusMethodNotAllowed, "method", "method not allowed")
		return
	}

	clientIP, ok := resolveClientIP(r, h.trustEdgeHeaders)
	if !ok {
		h.reject(w, r, http.StatusBadRequest, "client_ip", "invalid client address")
		return
	}
	release, reason := h.guard.Acquire(bucketHash(r.Header.Get("X-Api-Key")), bucketHash(clientIP))
	if reason != pogrpc.IngestLimitNone {
		w.Header().Set("Retry-After", "1")
		if reason == pogrpc.IngestLimitConcurrency {
			h.reject(w, r, http.StatusTooManyRequests, "concurrency_limit", "collector concurrency limit exceeded")
		} else {
			h.reject(w, r, http.StatusTooManyRequests, "rate_limit", "collector rate limit exceeded")
		}
		return
	}
	defer release()

	if r.ContentLength > maxBodyBytes {
		h.reject(w, r, http.StatusRequestEntityTooLarge, "payload", "request body exceeds 1 MiB")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			h.reject(w, r, http.StatusRequestEntityTooLarge, "payload", "request body exceeds 1 MiB")
		} else {
			h.reject(w, r, http.StatusBadRequest, "payload", "invalid request body")
		}
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r = r.WithContext(context.WithValue(r.Context(), clientIPContextKey{}, clientIP))
	h.proxy.ServeHTTP(w, r)
}

func (h *handler) reject(w http.ResponseWriter, r *http.Request, status int, reason, message string) {
	ingressRejectedCounter.Add(r.Context(), 1, metric.WithAttributes(attribute.String("reason", reason)))
	writeGatewayError(w, status, message)
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
	if err != nil || value.Scheme != "https" || value.Host == "" || value.User != nil ||
		value.RawQuery != "" || value.Fragment != "" {
		return nil, errors.New("must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return value, nil
}

func resolveClientIP(r *http.Request, trustEdgeHeaders bool) (string, bool) {
	if trustEdgeHeaders {
		for _, name := range []string{geo.HeaderCFConnectingIP, geo.HeaderTrueClientIP, geo.HeaderXForwardedFor} {
			values := r.Header.Values(name)
			if len(values) == 0 {
				continue
			}
			if len(values) != 1 {
				return "", false
			}
			raw := values[0]
			if name == geo.HeaderXForwardedFor {
				raw, _, _ = strings.Cut(raw, ",")
			}
			if _, ok := geo.ParseClientIP(raw); !ok {
				return "", false
			}
		}
		if ip, _ := geo.ClientIPWithSource(r.Header); ip != "" {
			return ip, true
		}
		return "", false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", false
	}
	return geo.ParseClientIP(host)
}

func bucketHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return string(sum[:])
}

var forwardedHeaderNames = []string{
	"Accept",
	"Accept-Encoding",
	"Access-Control-Request-Headers",
	"Access-Control-Request-Method",
	"Connect-Protocol-Version",
	"Connect-Timeout-Ms",
	"Content-Encoding",
	"Content-Type",
	"Grpc-Timeout",
	"Origin",
	"Traceparent",
	"Tracestate",
	"User-Agent",
	"X-Api-Key",
}

var trustedEdgeEnrichmentHeaders = []string{
	"CF-IPContinent",
	"CF-IPCountry",
	"CF-Region",
	"CF-IPCity",
	"CF-Postal-Code",
	"CF-Metro-Code",
	"CF-IPLatitude",
	"CF-IPLongitude",
	"CF-Timezone",
	"CF-Bot-Score",
	"CF-Verified-Bot",
}

func forwardedHeaders(in http.Header, trustEdgeHeaders bool) http.Header {
	out := make(http.Header, len(forwardedHeaderNames))
	copyValues := func(name string) {
		if values := in.Values(name); len(values) > 0 {
			out[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	for _, name := range forwardedHeaderNames {
		copyValues(name)
	}
	if trustEdgeHeaders {
		for _, name := range trustedEdgeEnrichmentHeaders {
			copyValues(name)
		}
	}
	return out
}
