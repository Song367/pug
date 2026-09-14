package insightsingress

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

	"github.com/pug-sh/pug/internal/gen/proto/shared/insights/v1/insightsv1connect"
)

const testPrivateKey = "prv_0123456789abcdef0123456789abcdef"

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
		StatusCode: http.StatusBadRequest,
		Header: http.Header{
			"Access-Control-Allow-Origin":      []string{"https://must-not-pass.example"},
			"Access-Control-Allow-Credentials": []string{"true"},
			"Server":                           []string{"must-not-pass"},
		},
		Body: http.NoBody,
	}, nil
}

func (t *captureTransport) snapshot() (*http.Request, string, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.req, t.body, t.calls
}

func testConfig() config {
	return config{
		Environment:   "test",
		HTTPSAddr:     ":8443",
		PublicHost:    "insights-test.example",
		UpstreamURL:   "http://pug-server:3000",
		TLSCertFile:   "/run/tls/tls.crt",
		TLSKeyFile:    "/run/tls/tls.key",
		APIKeyFile:    "/run/secrets/insights.key",
		SourceCodeURL: "https://github.com/Song367/pug/tree/test-insights-sidecar",
	}
}

func makeHandler(t *testing.T, transport http.RoundTripper) (*handler, *captureTransport) {
	t.Helper()
	capture, ok := transport.(*captureTransport)
	if !ok {
		t.Fatal("test transport must capture requests")
	}
	cfg := testConfig()
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(cfg, upstream, transport, []byte(testPrivateKey))
	if err != nil {
		t.Fatalf("newHandler: %v", err)
	}
	return h, capture
}

func queryRequest(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, insightsv1connect.InsightsServiceQueryProcedure, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", testPrivateKey)
	return req
}

func TestInsightsIngressForwardsOnlyQueryAndAllowlistedHeaders(t *testing.T) {
	h, capture := makeHandler(t, &captureTransport{})
	req := queryRequest(`{"projectId":"test"}`)
	req.Header.Set("Authorization", "Bearer must-not-pass")
	req.Header.Set("Cookie", "session=must-not-pass")
	req.Header.Set("Forwarded", "for=must-not-pass")
	req.Header.Set("X-Forwarded-For", "must-not-pass")
	req.Header.Set("CF-Connecting-IP", "must-not-pass")
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	forwarded, body, calls := capture.snapshot()
	if calls != 1 || body != `{"projectId":"test"}` {
		t.Fatalf("upstream calls/body = %d/%q", calls, body)
	}
	for _, name := range []string{"Authorization", "Cookie", "Forwarded", "X-Forwarded-For", "CF-Connecting-IP"} {
		if forwarded.Header.Get(name) != "" {
			t.Fatalf("%s reached upstream", name)
		}
	}
	if forwarded.Header.Get("X-Api-Key") != testPrivateKey || forwarded.Header.Get("Content-Type") != "application/json" {
		t.Fatal("required Connect headers were not forwarded")
	}
	for _, name := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Server"} {
		if rec.Header().Get(name) != "" {
			t.Fatalf("%s reached downstream", name)
		}
	}
}

func TestInsightsIngressRejectsEverythingExceptPrivateQuery(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*http.Request)
		want   int
	}{
		"unknown path": {
			mutate: func(r *http.Request) { r.URL.Path = "/shared.insights.v1.InsightsService/GetFilterSchema" },
			want:   http.StatusNotFound,
		},
		"wrong method": {
			mutate: func(r *http.Request) { r.Method = http.MethodGet },
			want:   http.StatusMethodNotAllowed,
		},
		"browser origin": {
			mutate: func(r *http.Request) { r.Header.Set("Origin", "https://testonlyf.velvetplot.com") },
			want:   http.StatusForbidden,
		},
		"missing key": {
			mutate: func(r *http.Request) { r.Header.Del("X-Api-Key") },
			want:   http.StatusUnauthorized,
		},
		"public key": {
			mutate: func(r *http.Request) { r.Header.Set("X-Api-Key", "pub_0123456789abcdef0123456789abcdef") },
			want:   http.StatusUnauthorized,
		},
		"other role private key": {
			mutate: func(r *http.Request) { r.Header.Set("X-Api-Key", "prv_abcdef0123456789abcdef0123456789") },
			want:   http.StatusUnauthorized,
		},
	} {
		t.Run(name, func(t *testing.T) {
			h, capture := makeHandler(t, &captureTransport{})
			req := queryRequest("{}")
			tc.mutate(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if _, _, calls := capture.snapshot(); calls != 0 {
				t.Fatal("rejected request reached upstream")
			}
		})
	}
}

func TestInsightsIngressRejectsOversizedBody(t *testing.T) {
	h, capture := makeHandler(t, &captureTransport{})
	req := queryRequest(strings.Repeat("x", maxBodyBytes+1))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if _, _, calls := capture.snapshot(); calls != 0 {
		t.Fatal("oversized body reached upstream")
	}
}

func TestInsightsIngressHealthAndTLSBoundary(t *testing.T) {
	h, capture := makeHandler(t, &captureTransport{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("health response = %d %q", rec.Code, rec.Body.String())
	}
	if _, _, calls := capture.snapshot(); calls != 0 {
		t.Fatal("health request reached upstream")
	}
	if server := secureServer(":0", http.NotFoundHandler()); server.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("TLS minimum is not 1.2")
	}
}

func TestInsightsIngressConfigFailsClosed(t *testing.T) {
	cfg := testConfig()
	if _, err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	for name, mutate := range map[string]func(*config){
		"environment":          func(c *config) { c.Environment = "staging" },
		"empty listener":       func(c *config) { c.HTTPSAddr = "" },
		"relative role key":    func(c *config) { c.APIKeyFile = "insights.key" },
		"host injection":       func(c *config) { c.PublicHost = "example.test/path" },
		"upstream credentials": func(c *config) { c.UpstreamURL = "http://user:pass@pug:3000" },
		"insecure source URL":  func(c *config) { c.SourceCodeURL = "http://github.com/Song367/pug" },
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
