package ingress

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/pug-sh/pug/internal/gen/proto/sdk/events/v1/eventsv1connect"
)

type captureTransport struct {
	mu    sync.Mutex
	req   *http.Request
	body  string
	calls int
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.req = req.Clone(context.Background())
	t.req.Header = req.Header.Clone()
	t.body = string(body)
	t.calls++
	t.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Header:     make(http.Header),
		Body:       http.NoBody,
	}, nil
}

func (t *captureTransport) snapshot() (*http.Request, string, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.req, t.body, t.calls
}

func testConfig() config {
	return config{
		Environment: "test",
		HTTPAddr:    ":8080",
		HTTPSAddr:   ":8443",
		PublicHost:  "collector.example.test",
		UpstreamURL: "http://pug-server:3000",
		TLSCertFile: "/run/tls/tls.crt",
		TLSKeyFile:  "/run/tls/tls.key",
		KeyRate:     10, KeyBurst: 10,
		IPRate: 10, IPBurst: 10,
		KeyConcurrency: 2, IPConcurrency: 2,
	}
}

func makeHandler(t *testing.T, cfg config, transport http.RoundTripper) *handler {
	t.Helper()
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(cfg, upstream, transport)
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	return h
}

func ingestRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, eventsv1connect.EventsServiceBatchCreateProcedure, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:4321"
	req.Header.Set("Content-Type", "application/proto")
	req.Header.Set("X-Api-Key", "pub_test")
	return req
}

func TestIngressForwardsOnlyAllowlistedHeadersAndKernelPeer(t *testing.T) {
	capture := &captureTransport{}
	h := makeHandler(t, testConfig(), capture)
	req := ingestRequest("event-batch")
	req.Header.Set("Authorization", "Bearer must-not-pass")
	req.Header.Set("Cookie", "session=must-not-pass")
	req.Header.Set("Baggage", "ip=must-not-pass")
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	req.Header.Set("CF-IPCountry", "US")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	forwarded, body, calls := capture.snapshot()
	if calls != 1 || body != "event-batch" {
		t.Fatalf("upstream calls/body = %d/%q", calls, body)
	}
	if got := forwarded.Header.Get("X-Forwarded-For"); got != "192.0.2.10" {
		t.Fatalf("X-Forwarded-For = %q, want kernel peer", got)
	}
	if forwarded.Header.Get("Authorization") != "" || forwarded.Header.Get("Cookie") != "" || forwarded.Header.Get("Baggage") != "" {
		t.Fatal("non-allowlisted credential/tracing header reached upstream")
	}
	if forwarded.Header.Get("CF-Connecting-IP") != "" || forwarded.Header.Get("CF-IPCountry") != "" {
		t.Fatal("untrusted edge header reached upstream")
	}
	if forwarded.Header.Get("X-Api-Key") != "pub_test" || forwarded.Header.Get("Content-Type") != "application/proto" {
		t.Fatal("required Connect headers were not forwarded")
	}
}

func TestIngressTrustedEdgeUsesCanonicalVisitorIPAndSelectedEnrichment(t *testing.T) {
	cfg := testConfig()
	cfg.TrustEdgeHeaders = true
	capture := &captureTransport{}
	h := makeHandler(t, cfg, capture)
	req := ingestRequest("batch")
	req.Header.Set("CF-Connecting-IP", "::ffff:203.0.113.7")
	req.Header.Set("CF-IPCountry", "US")
	req.Header.Set("CF-Verified-Bot", "true")
	req.Header.Set("CF-Ray", "not-consumed-by-pug")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	forwarded, _, _ := capture.snapshot()
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if got := forwarded.Header.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Fatalf("visitor IP = %q", got)
	}
	if forwarded.Header.Get("CF-IPCountry") != "US" || forwarded.Header.Get("CF-Verified-Bot") != "true" {
		t.Fatal("trusted enrichment headers were not forwarded")
	}
	if forwarded.Header.Get("CF-Ray") != "" || forwarded.Header.Get("CF-Connecting-IP") != "" {
		t.Fatal("unused/raw incoming edge header reached upstream")
	}
}

func TestIngressRejectsMalformedTrustedEdgeIP(t *testing.T) {
	cfg := testConfig()
	cfg.TrustEdgeHeaders = true
	capture := &captureTransport{}
	h := makeHandler(t, cfg, capture)
	req := ingestRequest("batch")
	req.Header.Set("CF-Connecting-IP", "not-an-ip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if _, _, calls := capture.snapshot(); calls != 0 {
		t.Fatal("malformed trusted header reached upstream")
	}
}

func TestIngressRejectsNonCollectorRoutesMethodsAndLargePayloads(t *testing.T) {
	for name, tc := range map[string]struct {
		req  *http.Request
		want int
	}{
		"path": {
			req:  httptest.NewRequest(http.MethodPost, "/dashboard.projects.v1.ProjectsService/List", nil),
			want: http.StatusNotFound,
		},
		"method": {
			req:  httptest.NewRequest(http.MethodGet, eventsv1connect.EventsServiceBatchCreateProcedure, nil),
			want: http.StatusMethodNotAllowed,
		},
		"payload": {
			req:  ingestRequest(strings.Repeat("x", maxBodyBytes+1)),
			want: http.StatusRequestEntityTooLarge,
		},
	} {
		t.Run(name, func(t *testing.T) {
			capture := &captureTransport{}
			h := makeHandler(t, testConfig(), capture)
			tc.req.RemoteAddr = "192.0.2.10:4321"
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, tc.req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if _, _, calls := capture.snapshot(); calls != 0 {
				t.Fatal("rejected request reached upstream")
			}
		})
	}
}

func TestIngressReturns429WithRetryAfterWhenRateLimited(t *testing.T) {
	cfg := testConfig()
	cfg.KeyRate, cfg.KeyBurst = 1, 1
	cfg.IPRate, cfg.IPBurst = 1, 1
	capture := &captureTransport{}
	h := makeHandler(t, cfg, capture)

	first := httptest.NewRecorder()
	h.ServeHTTP(first, ingestRequest("one"))
	second := httptest.NewRecorder()
	h.ServeHTTP(second, ingestRequest("two"))
	if first.Code != http.StatusNoContent || second.Code != http.StatusTooManyRequests {
		t.Fatalf("statuses = %d, %d", first.Code, second.Code)
	}
	if second.Header().Get("Retry-After") != "1" {
		t.Fatal("rate rejection omitted Retry-After")
	}
	if _, _, calls := capture.snapshot(); calls != 1 {
		t.Fatalf("upstream calls = %d, want 1", calls)
	}
}

type blockingTransport struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (t *blockingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.once.Do(func() { close(t.started) })
	<-t.release
	return &http.Response{StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}, nil
}

func TestIngressConcurrencyLimitReleasesAfterRequest(t *testing.T) {
	cfg := testConfig()
	cfg.KeyConcurrency, cfg.IPConcurrency = 1, 1
	transport := &blockingTransport{started: make(chan struct{}), release: make(chan struct{})}
	h := makeHandler(t, cfg, transport)
	done := make(chan int, 1)
	go func() {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, ingestRequest("one"))
		done <- rec.Code
	}()
	<-transport.started

	second := httptest.NewRecorder()
	h.ServeHTTP(second, ingestRequest("two"))
	if second.Code != http.StatusTooManyRequests || !strings.Contains(second.Body.String(), "concurrency") {
		t.Fatalf("second response = %d %q", second.Code, second.Body.String())
	}
	close(transport.release)
	if got := <-done; got != http.StatusNoContent {
		t.Fatalf("first status = %d", got)
	}
}

func TestRedirectUsesConfiguredHostNotRequestHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://attacker.invalid/path?q=1", nil)
	rec := httptest.NewRecorder()
	redirectHandler(url.URL{Scheme: "https", Host: "collector.example.test:8443"}).ServeHTTP(rec, req)
	if got, want := rec.Header().Get("Location"), "https://collector.example.test:8443/path?q=1"; got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
}

func TestIngressConfigAndTLSFailClosed(t *testing.T) {
	cfg := testConfig()
	if _, err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	server := secureServer(":0", http.NotFoundHandler())
	if server.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS minimum = %#x, want TLS 1.2", server.TLSConfig.MinVersion)
	}

	for name, mutate := range map[string]func(*config){
		"environment":          func(c *config) { c.Environment = "staging" },
		"same listener":        func(c *config) { c.HTTPAddr = c.HTTPSAddr },
		"host injection":       func(c *config) { c.PublicHost = "example.test/path" },
		"upstream credentials": func(c *config) { c.UpstreamURL = "http://user:pass@pug:3000" },
		"zero rate":            func(c *config) { c.IPRate = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testConfig()
			mutate(&candidate)
			if _, err := candidate.validate(); err == nil {
				t.Fatal("validate unexpectedly succeeded")
			}
		})
	}
}
