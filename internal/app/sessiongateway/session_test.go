package sessiongateway

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/pug-sh/pug/internal/gen/proto/public/auth/v1"
)

func TestSessionManagerCreatesOpaqueStateAndRefreshesServerSide(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	store := newMemorySessionStore()
	auth := &fakeAuthClient{}
	manager := newSessionManager(store, auth)
	manager.now = func() time.Time { return now }

	sessionID, created, err := manager.create(
		context.Background(),
		testAccessToken(t, "cust-1", now.Add(10*time.Second)),
		"refresh-one",
		false,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !validOpaqueToken(sessionID, sessionTokenBytes) || !validOpaqueToken(created.CSRFToken, sessionTokenBytes) {
		t.Fatal("session or CSRF token does not carry 256 bits")
	}

	auth.refreshResponse = &authv1.RefreshSessionResponse{
		Token:        ptr(testAccessToken(t, "cust-1", now.Add(24*time.Hour))),
		RefreshToken: ptr("refresh-two"),
	}
	refreshed, err := manager.valid(context.Background(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if auth.refreshCalls != 1 || refreshed.RefreshToken != "refresh-two" || refreshed.CustomerID != "cust-1" {
		t.Fatalf("refresh result/calls = %#v/%d", refreshed, auth.refreshCalls)
	}
	if refreshed.CSRFToken != created.CSRFToken {
		t.Fatal("refresh rotated CSRF independently of the browser")
	}
}

func TestSessionManagerDeletesRejectedOrIdentityChangingRefresh(t *testing.T) {
	for name, configure := range map[string]func(*testing.T, *fakeAuthClient, time.Time){
		"upstream rejection": func(_ *testing.T, auth *fakeAuthClient, _ time.Time) {
			auth.refreshErr = connect.NewError(connect.CodeUnauthenticated, errors.New("expired"))
		},
		"identity change": func(t *testing.T, auth *fakeAuthClient, now time.Time) {
			auth.refreshResponse = &authv1.RefreshSessionResponse{
				Token:        ptr(testAccessToken(t, "cust-2", now.Add(time.Hour))),
				RefreshToken: ptr("attacker-refresh"),
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
			store := newMemorySessionStore()
			auth := &fakeAuthClient{}
			configure(t, auth, now)
			manager := newSessionManager(store, auth)
			manager.now = func() time.Time { return now }
			sessionID, _, err := manager.create(
				context.Background(),
				testAccessToken(t, "cust-1", now.Add(time.Second)),
				"refresh-one",
				false,
				"",
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := manager.valid(context.Background(), sessionID); !errors.Is(err, errSessionUnauthenticated) {
				t.Fatalf("valid err = %v, want unauthenticated", err)
			}
			if _, err := store.Get(context.Background(), sessionID); !errors.Is(err, errSessionNotFound) {
				t.Fatal("rejected session remained in the store")
			}
		})
	}
}

func TestSessionManagerSignOutCannotRaceRefreshIntoResurrectingSession(t *testing.T) {
	now := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	auth := &blockingSessionAuth{
		refreshResponse: &authv1.RefreshSessionResponse{
			Token:        ptr(testAccessToken(t, "cust-1", now.Add(time.Hour))),
			RefreshToken: ptr("refresh-two"),
		},
		refreshStarted: make(chan struct{}),
		releaseRefresh: make(chan struct{}),
		signedOut:      make(chan string, 1),
	}
	store := newMemorySessionStore()
	manager := newSessionManager(store, auth)
	manager.now = func() time.Time { return now }
	sessionID, _, err := manager.create(
		context.Background(),
		testAccessToken(t, "cust-1", now.Add(time.Second)),
		"refresh-one",
		false,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}

	refreshDone := make(chan error, 1)
	go func() {
		_, refreshErr := manager.valid(context.Background(), sessionID)
		refreshDone <- refreshErr
	}()
	<-auth.refreshStarted

	signOutDone := make(chan error, 1)
	go func() { signOutDone <- manager.signOut(context.Background(), sessionID) }()
	select {
	case err := <-signOutDone:
		t.Fatalf("sign-out bypassed the in-flight refresh lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(auth.releaseRefresh)
	if err := <-refreshDone; err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := <-signOutDone; err != nil {
		t.Fatalf("sign-out: %v", err)
	}
	if _, err := store.Get(context.Background(), sessionID); !errors.Is(err, errSessionNotFound) {
		t.Fatalf("session survived sign-out after refresh: %v", err)
	}
	if token := <-auth.signedOut; token != "refresh-two" {
		t.Fatalf("revoked token = %q, want the rotated refresh token", token)
	}
}

type blockingSessionAuth struct {
	refreshResponse *authv1.RefreshSessionResponse
	refreshStarted  chan struct{}
	releaseRefresh  chan struct{}
	signedOut       chan string
}

func (a *blockingSessionAuth) RefreshSession(
	ctx context.Context,
	_ *connect.Request[authv1.RefreshSessionRequest],
) (*connect.Response[authv1.RefreshSessionResponse], error) {
	close(a.refreshStarted)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-a.releaseRefresh:
		return connect.NewResponse(a.refreshResponse), nil
	}
}

func (a *blockingSessionAuth) SignOut(
	_ context.Context,
	req *connect.Request[authv1.SignOutRequest],
) (*connect.Response[authv1.SignOutResponse], error) {
	a.signedOut <- req.Msg.GetRefreshToken()
	return connect.NewResponse(&authv1.SignOutResponse{}), nil
}

func ptr[T any](value T) *T {
	return &value
}
