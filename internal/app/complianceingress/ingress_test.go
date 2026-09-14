package complianceingress

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

	"github.com/pug-sh/pug/internal/gen/proto/shared/profiles/v1/profilesv1connect"
	"github.com/pug-sh/pug/internal/security/apikeyfile"
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
	return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Access-Control-Allow-Origin": []string{"https://must-not-pass.example"}, "Server": []string{"must-not-pass"}}, Body: http.NoBody}, nil
}

func (t *captureTransport) snapshot() (*http.Request, string, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.req, t.body, t.calls
}

func testConfig() config {
	return config{Environment: "test", HTTPSAddr: ":8443", PublicHost: "insights-test.example", UpstreamURL: "http://pug-server:3000", TLSCertFile: "/run/tls/tls.crt", TLSKeyFile: "/run/tls/tls.key", APIKeyFile: "/run/secrets/compliance.key", SourceCodeURL: "https://github.com/Song367/pug/tree/t7"}
}

func makeHandler(t *testing.T, transport *captureTransport) *handler {
	t.Helper()
	cfg := testConfig()
	upstream, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandler(cfg, upstream, transport, apikeyfile.Keyring{[]byte(testPrivateKey)})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func complianceRequest(path string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"externalId":"opaque"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", testPrivateKey)
	return req
}

func TestComplianceIngressForwardsOnlyTwoProceduresAndAllowlistedHeaders(t *testing.T) {
	for _, path := range []string{profilesv1connect.ProfilesServiceDeleteDataSubjectProcedure, profilesv1connect.ProfilesServiceGetDeletionRequestProcedure} {
		t.Run(path, func(t *testing.T) {
			capture := &captureTransport{}
			h := makeHandler(t, capture)
			req := complianceRequest(path)
			req.Header.Set("Authorization", "Bearer must-not-pass")
			req.Header.Set("Cookie", "must-not-pass")
			req.Header.Set("X-Forwarded-For", "must-not-pass")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", rec.Code)
			}
			forwarded, _, calls := capture.snapshot()
			if calls != 1 {
				t.Fatalf("calls = %d", calls)
			}
			for _, name := range []string{"Authorization", "Cookie", "X-Forwarded-For"} {
				if forwarded.Header.Get(name) != "" {
					t.Fatalf("%s reached upstream", name)
				}
			}
			if forwarded.Header.Get("X-Api-Key") != testPrivateKey {
				t.Fatal("private key did not reach upstream")
			}
		})
	}
}

func TestComplianceIngressRejectsOtherTraffic(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*http.Request)
		want   int
	}{
		"unknown procedure": {func(r *http.Request) { r.URL.Path = "/shared.profiles.v1.ProfilesService/List" }, http.StatusNotFound},
		"wrong method":      {func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
		"browser":           {func(r *http.Request) { r.Header.Set("Origin", "https://testonlyf.velvetplot.com") }, http.StatusForbidden},
		"missing key":       {func(r *http.Request) { r.Header.Del("X-Api-Key") }, http.StatusUnauthorized},
		"public key":        {func(r *http.Request) { r.Header.Set("X-Api-Key", "pub_0123456789abcdef0123456789abcdef") }, http.StatusUnauthorized},
		"other private key": {func(r *http.Request) { r.Header.Set("X-Api-Key", "prv_abcdef0123456789abcdef0123456789") }, http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			capture := &captureTransport{}
			h := makeHandler(t, capture)
			req := complianceRequest(profilesv1connect.ProfilesServiceDeleteDataSubjectProcedure)
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

func TestComplianceIngressBodyHealthTLSAndConfig(t *testing.T) {
	capture := &captureTransport{}
	h := makeHandler(t, capture)
	req := complianceRequest(profilesv1connect.ProfilesServiceDeleteDataSubjectProcedure)
	req.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", maxBodyBytes+1)))
	req.ContentLength = maxBodyBytes + 1
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
	health := httptest.NewRecorder()
	h.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || health.Body.String() != "ok\n" {
		t.Fatalf("health = %d %q", health.Code, health.Body.String())
	}
	if secureServer(":0", http.NotFoundHandler()).TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("TLS minimum is not 1.2")
	}
	for name, mutate := range map[string]func(*config){
		"development":    func(c *config) { c.Environment = "development" },
		"host injection": func(c *config) { c.PublicHost = "example.test/path" },
		"credentials":    func(c *config) { c.UpstreamURL = "http://user:pass@pug:3000" },
		"relative key":   func(c *config) { c.APIKeyFile = "compliance.key" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := testConfig()
			mutate(&candidate)
			if _, err := candidate.validate(); err == nil {
				t.Fatal("configuration unexpectedly accepted")
			}
		})
	}
}
