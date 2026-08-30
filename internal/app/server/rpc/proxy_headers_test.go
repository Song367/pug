package rpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func captureProxyHeaders(t *testing.T, trust bool, h http.Header) (http.Header, int) {
	t.Helper()
	var captured http.Header
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
	})
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header = h.Clone()
	rec := httptest.NewRecorder()
	WithProxyHeaderPolicy(trust, next).ServeHTTP(rec, req)
	return captured, rec.Code
}

func TestProxyHeaderPolicyStripsAllProxyValuesWhenUntrusted(t *testing.T) {
	h := http.Header{
		"CF-Connecting-IP": {"203.0.113.7"},
		"CF-IPCountry":     {"US"},
		"CF-Bot-Score":     {"99"},
		"CF-Unused":        {"spoofed"},
		"True-Client-IP":   {"203.0.113.8"},
		"X-Forwarded-For":  {"203.0.113.9"},
		"X-Real-IP":        {"203.0.113.10"},
		"Forwarded":        {"for=203.0.113.11"},
		"User-Agent":       {"test-agent"},
	}
	got, status := captureProxyHeaders(t, false, h)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Get("User-Agent") != "test-agent" {
		t.Fatal("ordinary header was removed")
	}
	for name := range h {
		if isProxyControlledHeader(strings.ToLower(name)) && got.Get(name) != "" {
			t.Errorf("proxy-controlled header %s survived: %q", name, got.Get(name))
		}
	}
}

func TestProxyHeaderPolicyAllowsOnlyKnownTrustedValuesAndNormalizesIPs(t *testing.T) {
	h := http.Header{
		"CF-Connecting-IP": {"::ffff:203.0.113.7"},
		"X-Forwarded-For":  {"2001:0DB8::1, 192.0.2.1"},
		"CF-IPCountry":     {"US"},
		"CF-Verified-Bot":  {"true"},
		"CF-Ray":           {"must-not-reach-pug"},
		"Forwarded":        {"for=203.0.113.9"},
	}
	got, status := captureProxyHeaders(t, true, h)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if got.Get("CF-Connecting-IP") != "203.0.113.7" {
		t.Errorf("CF-Connecting-IP = %q", got.Get("CF-Connecting-IP"))
	}
	if got.Get("X-Forwarded-For") != "2001:db8::1" {
		t.Errorf("X-Forwarded-For = %q", got.Get("X-Forwarded-For"))
	}
	if got.Get("CF-IPCountry") != "US" || got.Get("CF-Verified-Bot") != "true" {
		t.Error("approved enrichment header was removed")
	}
	if got.Get("CF-Ray") != "" || got.Get("Forwarded") != "" {
		t.Error("unused proxy-controlled header survived")
	}
}

func TestProxyHeaderPolicyRejectsMalformedOrAmbiguousTrustedIP(t *testing.T) {
	for name, h := range map[string]http.Header{
		"malformed": {"CF-Connecting-IP": {"not-an-ip"}},
		"duplicate": {"True-Client-IP": {"203.0.113.7", "203.0.113.8"}},
	} {
		t.Run(name, func(t *testing.T) {
			got, status := captureProxyHeaders(t, true, h)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", status)
			}
			if got != nil {
				t.Fatal("downstream handler ran")
			}
		})
	}
}

func TestProxyHeaderPolicyMatchesNonCanonicalHeaderNames(t *testing.T) {
	h := http.Header{"cf-connecting-ip": {"203.0.113.7"}}
	got, _ := captureProxyHeaders(t, false, h)
	for name := range got {
		if strings.EqualFold(name, "cf-connecting-ip") {
			t.Fatal("lower-case spoofed header survived")
		}
	}
}
