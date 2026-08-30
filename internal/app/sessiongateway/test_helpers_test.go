package sessiongateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	coreauth "github.com/pug-sh/pug/internal/core/auth"
	authv1 "github.com/pug-sh/pug/internal/gen/proto/public/auth/v1"
)

type memorySessionStore struct {
	mu      sync.Mutex
	records map[string]sessionRecord
	locks   map[string]string
	pingErr error
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{records: make(map[string]sessionRecord), locks: make(map[string]string)}
}

func (s *memorySessionStore) Create(_ context.Context, id string, record sessionRecord, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.records[id]; exists {
		return errSessionCollision
	}
	s.records[id] = record
	return nil
}

func (s *memorySessionStore) Get(_ context.Context, id string) (sessionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[id]
	if !ok {
		return sessionRecord{}, errSessionNotFound
	}
	return record, nil
}

func (s *memorySessionStore) Put(_ context.Context, id string, record sessionRecord, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[id] = record
	return nil
}

func (s *memorySessionStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return nil
}

func (s *memorySessionStore) TryRefreshLock(_ context.Context, id, owner string, _ time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.locks[id]; exists {
		return false, nil
	}
	s.locks[id] = owner
	return true, nil
}

func (s *memorySessionStore) ReleaseRefreshLock(_ context.Context, id, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks[id] == owner {
		delete(s.locks, id)
	}
	return nil
}

func (s *memorySessionStore) Ping(context.Context) error {
	return s.pingErr
}

type fakeAuthClient struct {
	signInResponse  *authv1.SignInWithEmailResponse
	refreshResponse *authv1.RefreshSessionResponse
	refreshErr      error
	refreshCalls    int
	signOutCalls    int
	signedOutToken  string
}

func (f *fakeAuthClient) GetAuthConfig(
	context.Context,
	*connect.Request[authv1.GetAuthConfigRequest],
) (*connect.Response[authv1.GetAuthConfigResponse], error) {
	return connect.NewResponse(&authv1.GetAuthConfigResponse{}), nil
}

func (f *fakeAuthClient) SignInWithEmail(
	context.Context,
	*connect.Request[authv1.SignInWithEmailRequest],
) (*connect.Response[authv1.SignInWithEmailResponse], error) {
	if f.signInResponse == nil {
		return nil, errors.New("sign-in response not configured")
	}
	return connect.NewResponse(f.signInResponse), nil
}

func (f *fakeAuthClient) RequestMagicLink(
	context.Context,
	*connect.Request[authv1.RequestMagicLinkRequest],
) (*connect.Response[authv1.RequestMagicLinkResponse], error) {
	return connect.NewResponse(&authv1.RequestMagicLinkResponse{}), nil
}

func (f *fakeAuthClient) CompleteMagicLink(
	context.Context,
	*connect.Request[authv1.CompleteMagicLinkRequest],
) (*connect.Response[authv1.CompleteMagicLinkResponse], error) {
	return nil, errors.New("complete magic link response not configured")
}

func (f *fakeAuthClient) CompleteOIDCSignIn(
	context.Context,
	*connect.Request[authv1.CompleteOIDCSignInRequest],
) (*connect.Response[authv1.CompleteOIDCSignInResponse], error) {
	return nil, errors.New("complete OIDC response not configured")
}

func (f *fakeAuthClient) RefreshSession(
	context.Context,
	*connect.Request[authv1.RefreshSessionRequest],
) (*connect.Response[authv1.RefreshSessionResponse], error) {
	f.refreshCalls++
	if f.refreshErr != nil {
		return nil, f.refreshErr
	}
	if f.refreshResponse == nil {
		return nil, errors.New("refresh response not configured")
	}
	return connect.NewResponse(f.refreshResponse), nil
}

func (f *fakeAuthClient) SignOut(
	_ context.Context,
	req *connect.Request[authv1.SignOutRequest],
) (*connect.Response[authv1.SignOutResponse], error) {
	f.signOutCalls++
	f.signedOutToken = req.Msg.GetRefreshToken()
	return connect.NewResponse(&authv1.SignOutResponse{}), nil
}

func (f *fakeAuthClient) DemoSignIn(
	context.Context,
	*connect.Request[authv1.DemoSignInRequest],
) (*connect.Response[authv1.DemoSignInResponse], error) {
	return nil, errors.New("demo response not configured")
}

func testAccessToken(t *testing.T, customerID string, expiresAt time.Time) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{coreauth.Audience},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(expiresAt.Add(-time.Hour)),
		Issuer:    coreauth.Issuer,
		Subject:   customerID,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-only-signing-key"))
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type captureTransport struct {
	mu       sync.Mutex
	request  *http.Request
	response *http.Response
}

func (t *captureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.request = req.Clone(context.Background())
	t.request.Header = req.Header.Clone()
	resp := t.response
	t.mu.Unlock()
	if resp == nil {
		resp = &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}
	}
	if resp.Body == nil {
		resp.Body = io.NopCloser(http.NoBody)
	}
	return resp, nil
}

func (t *captureTransport) snapshot() *http.Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.request
}
