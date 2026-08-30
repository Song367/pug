package sessiongateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/pug-sh/pug/internal/gen/proto/dashboard/customers/v1/customersv1connect"
	authv1 "github.com/pug-sh/pug/internal/gen/proto/public/auth/v1"
	"github.com/pug-sh/pug/internal/gen/proto/public/auth/v1/authv1connect"
)

func TestAuthServerKeepsIssuedTokensOutOfBrowser(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	access := testAccessToken(t, "cust-1", now.Add(time.Hour))
	auth := &fakeAuthClient{signInResponse: &authv1.SignInWithEmailResponse{
		Token:        ptr(access),
		RefreshToken: ptr("refresh-secret"),
	}}
	store := newMemorySessionStore()
	manager := newSessionManager(store, auth)
	manager.now = func() time.Time { return now }
	server := &authServer{upstream: auth, sessions: manager, publicOrigin: "https://dashboard.example.test"}

	req := connect.NewRequest(&authv1.SignInWithEmailRequest{Email: ptr("operator@example.test"), Password: ptr("password")})
	resp, err := server.SignInWithEmail(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Msg.GetToken() != "" || resp.Msg.GetRefreshToken() != "" {
		t.Fatal("gateway returned raw Pug tokens to the browser")
	}
	setCookie := resp.Header().Get("Set-Cookie")
	for _, required := range []string{sessionCookieName + "=", "Path=/", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(setCookie, required) {
			t.Fatalf("Set-Cookie %q missing %q", setCookie, required)
		}
	}
	if strings.Contains(setCookie, access) || strings.Contains(setCookie, "refresh-secret") {
		t.Fatal("raw Pug token leaked into the cookie")
	}

	cookies := (&http.Response{Header: resp.Header()}).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d, want 1", len(cookies))
	}
	record, err := store.Get(context.Background(), cookies[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if record.AccessToken != access || record.RefreshToken != "refresh-secret" || record.CustomerID != "cust-1" {
		t.Fatal("server-side session record is incomplete")
	}
}

func TestAuthServerRejectsBrowserRefreshAndUsesStoredTokenForSignOut(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	auth := &fakeAuthClient{}
	store := newMemorySessionStore()
	manager := newSessionManager(store, auth)
	manager.now = func() time.Time { return now }
	sessionID, record, err := manager.create(
		context.Background(),
		testAccessToken(t, "cust-1", now.Add(time.Hour)),
		"stored-refresh",
		false,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	server := &authServer{upstream: auth, sessions: manager, publicOrigin: "https://dashboard.example.test"}

	if _, err := server.RefreshSession(context.Background(), connect.NewRequest(&authv1.RefreshSessionRequest{
		RefreshToken: ptr("browser-supplied"),
	})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("RefreshSession code = %v", connect.CodeOf(err))
	}

	req := connect.NewRequest(&authv1.SignOutRequest{RefreshToken: ptr("browser-supplied")})
	req.Header().Set("Cookie", (&http.Cookie{Name: sessionCookieName, Value: sessionID}).String())
	req.Header().Set(csrfHeaderName, record.CSRFToken)
	resp, err := server.SignOut(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if auth.signedOutToken != "stored-refresh" {
		t.Fatalf("revoked token = %q, want stored token", auth.signedOutToken)
	}
	if !strings.Contains(resp.Header().Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("sign-out cookie was not expired: %q", resp.Header().Get("Set-Cookie"))
	}
}

func TestAuthServerFailsSignOutClosedWhenSessionDeletionFails(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	baseStore := newMemorySessionStore()
	store := &deleteFailSessionStore{memorySessionStore: baseStore}
	auth := &fakeAuthClient{}
	manager := newSessionManager(store, auth)
	manager.now = func() time.Time { return now }
	sessionID, record, err := manager.create(
		context.Background(),
		testAccessToken(t, "cust-1", now.Add(time.Hour)),
		"stored-refresh",
		false,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	server := &authServer{upstream: auth, sessions: manager, publicOrigin: "https://dashboard.example.test"}
	req := connect.NewRequest(&authv1.SignOutRequest{})
	req.Header().Set("Cookie", (&http.Cookie{Name: sessionCookieName, Value: sessionID}).String())
	req.Header().Set(csrfHeaderName, record.CSRFToken)

	resp, err := server.SignOut(context.Background(), req)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("SignOut code = %v, want unavailable", connect.CodeOf(err))
	}
	if resp != nil {
		t.Fatal("failed sign-out returned a cookie-clearing response")
	}
	if _, err := baseStore.Get(context.Background(), sessionID); err != nil {
		t.Fatalf("failed deletion unexpectedly removed session: %v", err)
	}
}

type deleteFailSessionStore struct {
	*memorySessionStore
}

func (*deleteFailSessionStore) Delete(context.Context, string) error {
	return errors.New("delete unavailable")
}

func TestGatewayRequiresOriginAndCSRFAndStripsBrowserCredentials(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	store := newMemorySessionStore()
	auth := &fakeAuthClient{}
	manager := newSessionManager(store, auth)
	manager.now = func() time.Time { return now }
	access := testAccessToken(t, "cust-1", now.Add(time.Hour))
	sessionID, record, err := manager.create(context.Background(), access, "refresh", false, "")
	if err != nil {
		t.Fatal(err)
	}
	apiCapture := &captureTransport{response: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/proto"}},
		Body:       http.NoBody,
	}}
	staticCapture := &captureTransport{response: &http.Response{StatusCode: http.StatusOK, Header: http.Header{
		"Server":                    []string{"nginx"},
		"Strict-Transport-Security": []string{"upstream-value"},
	}, Body: http.NoBody}}
	handler := testGateway(t, manager, auth, apiCapture, staticCapture)

	makeRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, customersv1connect.CustomersServiceGetMeProcedure, strings.NewReader("request"))
		req.Host = "dashboard.example.test"
		req.Header.Set("Origin", "https://dashboard.example.test")
		req.Header.Set("Cookie", (&http.Cookie{Name: sessionCookieName, Value: sessionID}).String())
		req.Header.Set(csrfHeaderName, record.CSRFToken)
		req.Header.Set("Authorization", "Bearer attacker")
		req.Header.Set("X-Project-Id", "project-1")
		return req
	}

	missingOrigin := makeRequest()
	missingOrigin.Header.Del("Origin")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, missingOrigin)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("missing origin status = %d", recorder.Code)
	}

	missingCSRF := makeRequest()
	missingCSRF.Header.Del(csrfHeaderName)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, missingCSRF)
	if recorder.Code != http.StatusForbidden || recorder.Header().Get("Set-Cookie") != "" {
		t.Fatalf("missing CSRF status/cookie = %d/%q", recorder.Code, recorder.Header().Get("Set-Cookie"))
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, makeRequest())
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated proxy status = %d: %s", recorder.Code, recorder.Body.String())
	}
	forwarded := apiCapture.snapshot()
	if forwarded == nil {
		t.Fatal("authenticated request did not reach upstream")
	}
	if got := forwarded.Header.Get("Authorization"); got != "Bearer "+access {
		t.Fatalf("upstream authorization = %q", got)
	}
	if forwarded.Header.Get("Cookie") != "" || forwarded.Header.Get(csrfHeaderName) != "" {
		t.Fatal("browser cookie or CSRF token reached Pug upstream")
	}
	if forwarded.Header.Get("X-Project-Id") != "project-1" {
		t.Fatal("project scope header was not forwarded")
	}
}

func TestGatewaySessionStatusAndStaticBoundaryExposeNoCredentials(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	store := newMemorySessionStore()
	auth := &fakeAuthClient{}
	manager := newSessionManager(store, auth)
	manager.now = func() time.Time { return now }
	sessionID, record, err := manager.create(
		context.Background(),
		testAccessToken(t, "cust-1", now.Add(time.Hour)),
		"refresh-secret",
		false,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	apiCapture := &captureTransport{}
	staticCapture := &captureTransport{response: &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}}
	handler := testGateway(t, manager, auth, apiCapture, staticCapture)

	statusReq := httptest.NewRequest(http.MethodGet, sessionStatusPath, nil)
	statusReq.Host = "dashboard.example.test"
	statusReq.Header.Set("Cookie", (&http.Cookie{Name: sessionCookieName, Value: sessionID}).String())
	statusRecorder := httptest.NewRecorder()
	handler.ServeHTTP(statusRecorder, statusReq)
	if statusRecorder.Code != http.StatusOK {
		t.Fatalf("status = %d", statusRecorder.Code)
	}
	var status sessionStatusResponse
	if err := json.Unmarshal(statusRecorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Authenticated || status.CustomerID != "cust-1" || status.CSRFToken != record.CSRFToken {
		t.Fatalf("session status = %#v", status)
	}
	if !strings.Contains(statusRecorder.Body.String(), `"demo":false`) {
		t.Fatal("non-demo session status omitted its explicit demo flag")
	}
	if strings.Contains(statusRecorder.Body.String(), "refresh-secret") || strings.Contains(statusRecorder.Body.String(), record.AccessToken) {
		t.Fatal("session status exposed an upstream token")
	}

	staticReq := httptest.NewRequest(http.MethodGet, "/assets/app.js", nil)
	staticReq.Host = "dashboard.example.test"
	staticReq.Header.Set("Cookie", "private=must-not-pass")
	staticReq.Header.Set("Authorization", "Bearer must-not-pass")
	staticRecorder := httptest.NewRecorder()
	handler.ServeHTTP(staticRecorder, staticReq)
	if staticRecorder.Code != http.StatusOK {
		t.Fatalf("static status = %d", staticRecorder.Code)
	}
	if values := staticRecorder.Header().Values("Strict-Transport-Security"); len(values) != 1 {
		t.Fatalf("gateway security header count = %d, want 1", len(values))
	}
	if staticRecorder.Header().Get("Server") != "" {
		t.Fatal("static upstream server header reached the browser")
	}
	forwarded := staticCapture.snapshot()
	if forwarded.Header.Get("Cookie") != "" || forwarded.Header.Get("Authorization") != "" {
		t.Fatal("browser credentials reached the static server")
	}

	for _, path := range []string{"/favicon.ico", "/favicon.svg", "/logo.svg", "/theme-init.js"} {
		assetReq := httptest.NewRequest(http.MethodGet, path, nil)
		assetReq.Host = "dashboard.example.test"
		assetRecorder := httptest.NewRecorder()
		handler.ServeHTTP(assetRecorder, assetReq)
		if assetRecorder.Code != http.StatusOK {
			t.Fatalf("root asset %s status = %d, want 200", path, assetRecorder.Code)
		}
	}

	forbiddenReq := httptest.NewRequest(http.MethodGet, "/sdk.events.v1.EventsService/BatchCreate", nil)
	forbiddenReq.Host = "dashboard.example.test"
	forbiddenRecorder := httptest.NewRecorder()
	handler.ServeHTTP(forbiddenRecorder, forbiddenReq)
	if forbiddenRecorder.Code != http.StatusNotFound {
		t.Fatalf("SDK path status = %d, want 404", forbiddenRecorder.Code)
	}
}

func testGateway(
	t *testing.T,
	manager *sessionManager,
	auth *fakeAuthClient,
	apiTransport http.RoundTripper,
	staticTransport http.RoundTripper,
) http.Handler {
	t.Helper()
	publicOrigin, _ := url.Parse("https://dashboard.example.test")
	apiUpstream, _ := url.Parse("http://pug-server:3000")
	staticUpstream, _ := url.Parse("http://dashboard:8080")
	return newGateway(resolvedConfig{
		publicOrigin: publicOrigin, apiUpstream: apiUpstream, staticUpstream: staticUpstream,
	}, manager, auth, apiTransport, staticTransport)
}

var _ authv1connect.AuthServiceClient = (*fakeAuthClient)(nil)
