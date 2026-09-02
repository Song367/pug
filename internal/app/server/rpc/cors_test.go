package rpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWithSDKCORSAllowsBrowserConnectHeaders(t *testing.T) {
	handler := WithSDKCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodOptions, "http://pug.test/sdk/events", nil)
	req.Header.Set("Origin", "https://customer.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	// Browsers lowercase and sort Access-Control-Request-Headers as required by Fetch.
	req.Header.Set("Access-Control-Request-Headers", "connect-protocol-version,content-type,x-api-key")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want %d", recorder.Code, http.StatusNoContent)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want wildcard", got)
	}
	assertHeaderToken(t, recorder.Header().Get("Access-Control-Allow-Methods"), http.MethodPost)
	assertHeaderToken(t, recorder.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
	assertHeaderToken(t, recorder.Header().Get("Access-Control-Allow-Headers"), "Connect-Protocol-Version")
	assertHeaderToken(t, recorder.Header().Get("Access-Control-Allow-Headers"), HeaderAPIKey)
}

func TestWithSDKCORSRejectsUnknownBrowserHeader(t *testing.T) {
	handler := WithSDKCORS(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodOptions, "http://pug.test/sdk/events", nil)
	req.Header.Set("Origin", "https://customer.example")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "content-type,x-api-key,x-unapproved-secret")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unknown request header received Access-Control-Allow-Origin %q", got)
	}
}

func assertHeaderToken(t *testing.T, raw, want string) {
	t.Helper()
	for _, value := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(value), want) {
			return
		}
	}
	t.Fatalf("header %q does not include %q", raw, want)
}
