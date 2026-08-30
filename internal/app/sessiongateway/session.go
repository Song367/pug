package sessiongateway

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/golang-jwt/jwt/v5"
	coreauth "github.com/pug-sh/pug/internal/core/auth"
	authv1 "github.com/pug-sh/pug/internal/gen/proto/public/auth/v1"
	"github.com/pug-sh/pug/internal/slogx"
)

const (
	sessionTTL          = 90 * 24 * time.Hour
	refreshLeeway       = 30 * time.Second
	refreshLockTTL      = 75 * time.Second
	refreshWaitTimeout  = 5 * time.Second
	refreshPollInterval = 50 * time.Millisecond
	storeOperationTTL   = 5 * time.Second
	upstreamAuthTimeout = 70 * time.Second
	sessionTokenBytes   = 32
	refreshOwnerBytes   = 16
)

var (
	errSessionUnauthenticated = errors.New("session is not authenticated")
	errSessionUnavailable     = errors.New("session service is unavailable")
	errCSRFInvalid            = errors.New("CSRF token is invalid")
)

type authSessionClient interface {
	RefreshSession(context.Context, *connect.Request[authv1.RefreshSessionRequest]) (*connect.Response[authv1.RefreshSessionResponse], error)
	SignOut(context.Context, *connect.Request[authv1.SignOutRequest]) (*connect.Response[authv1.SignOutResponse], error)
}

type sessionManager struct {
	store  sessionStore
	auth   authSessionClient
	now    func() time.Time
	random io.Reader
}

func newSessionManager(store sessionStore, auth authSessionClient) *sessionManager {
	return &sessionManager{store: store, auth: auth, now: time.Now, random: rand.Reader}
}

func (m *sessionManager) create(
	ctx context.Context,
	accessToken string,
	refreshToken string,
	demo bool,
	oldSessionID string,
) (string, sessionRecord, error) {
	now := m.now()
	customerID, accessExpiresAt, err := parseTrustedAccessToken(accessToken, now)
	if err != nil || refreshToken == "" {
		return "", sessionRecord{}, errors.New("upstream returned an invalid session")
	}
	csrfToken, err := randomToken(m.random, sessionTokenBytes)
	if err != nil {
		return "", sessionRecord{}, fmt.Errorf("generate CSRF token: %w", err)
	}
	record := sessionRecord{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		CustomerID:       customerID,
		CSRFToken:        csrfToken,
		AccessExpiresAt:  accessExpiresAt.Unix(),
		SessionExpiresAt: now.Add(sessionTTL).Unix(),
		Demo:             demo,
	}

	var sessionID string
	for range 3 {
		sessionID, err = randomToken(m.random, sessionTokenBytes)
		if err != nil {
			return "", sessionRecord{}, fmt.Errorf("generate session identifier: %w", err)
		}
		err = m.store.Create(ctx, sessionID, record, sessionTTL)
		if !errors.Is(err, errSessionCollision) {
			break
		}
	}
	if err != nil {
		return "", sessionRecord{}, fmt.Errorf("persist session: %w", err)
	}

	if oldSessionID != "" && oldSessionID != sessionID {
		if err := m.signOut(ctx, oldSessionID); err != nil {
			_ = m.store.Delete(context.WithoutCancel(ctx), sessionID)
			_, _ = m.auth.SignOut(context.WithoutCancel(ctx), connect.NewRequest(&authv1.SignOutRequest{
				RefreshToken: &record.RefreshToken,
			}))
			return "", sessionRecord{}, fmt.Errorf("invalidate replaced dashboard session: %w", err)
		}
	}
	return sessionID, record, nil
}

func (m *sessionManager) valid(ctx context.Context, sessionID string) (sessionRecord, error) {
	record, err := m.load(ctx, sessionID)
	if err != nil {
		return sessionRecord{}, err
	}
	if time.Unix(record.AccessExpiresAt, 0).After(m.now().Add(refreshLeeway)) {
		return record, nil
	}
	return m.refresh(ctx, sessionID, record)
}

func (m *sessionManager) load(ctx context.Context, sessionID string) (sessionRecord, error) {
	if !validOpaqueToken(sessionID, sessionTokenBytes) {
		return sessionRecord{}, errSessionUnauthenticated
	}
	record, err := m.store.Get(ctx, sessionID)
	if errors.Is(err, errSessionNotFound) {
		return sessionRecord{}, errSessionUnauthenticated
	}
	if errors.Is(err, errSessionCorrupt) {
		_ = m.store.Delete(ctx, sessionID)
		return sessionRecord{}, errSessionUnauthenticated
	}
	if err != nil {
		return sessionRecord{}, errors.Join(errSessionUnavailable, err)
	}
	if record.CustomerID == "" || !validOpaqueToken(record.CSRFToken, sessionTokenBytes) ||
		record.RefreshToken == "" || record.AccessToken == "" || record.SessionExpiresAt <= m.now().Unix() {
		_ = m.store.Delete(ctx, sessionID)
		return sessionRecord{}, errSessionUnauthenticated
	}
	return record, nil
}

func (m *sessionManager) authenticate(ctx context.Context, sessionID, csrfToken string) (sessionRecord, error) {
	record, err := m.valid(ctx, sessionID)
	if err != nil {
		return sessionRecord{}, err
	}
	if subtle.ConstantTimeCompare([]byte(record.CSRFToken), []byte(csrfToken)) != 1 {
		return sessionRecord{}, errCSRFInvalid
	}
	return record, nil
}

func (m *sessionManager) signOut(ctx context.Context, sessionID string) error {
	owner, err := m.acquireRefreshLock(ctx, sessionID)
	if errors.Is(err, errSessionUnauthenticated) {
		return nil
	}
	if err != nil {
		return err
	}
	defer m.releaseRefreshLock(ctx, sessionID, owner)

	record, err := m.load(ctx, sessionID)
	if errors.Is(err, errSessionUnauthenticated) {
		return nil
	}
	if err != nil {
		return err
	}
	deleteCtx, cancelDelete := context.WithTimeout(context.WithoutCancel(ctx), storeOperationTTL)
	deleteErr := m.store.Delete(deleteCtx, sessionID)
	cancelDelete()
	if deleteErr != nil {
		return errors.Join(errSessionUnavailable, deleteErr)
	}

	revokeCtx, cancelRevoke := context.WithTimeout(context.WithoutCancel(ctx), upstreamAuthTimeout)
	_, revokeErr := m.auth.SignOut(revokeCtx, connect.NewRequest(&authv1.SignOutRequest{RefreshToken: &record.RefreshToken}))
	cancelRevoke()
	if revokeErr != nil {
		slog.WarnContext(ctx, "dashboard session deleted but upstream refresh family revocation failed", slogx.Error(revokeErr))
	}
	return nil
}

func (m *sessionManager) refresh(
	ctx context.Context,
	sessionID string,
	initial sessionRecord,
) (sessionRecord, error) {
	if time.Unix(initial.AccessExpiresAt, 0).After(m.now().Add(refreshLeeway)) {
		return initial, nil
	}
	owner, err := m.acquireRefreshLock(ctx, sessionID)
	if err != nil {
		return sessionRecord{}, err
	}
	return m.refreshWhileLocked(ctx, sessionID, owner)
}

func (m *sessionManager) refreshWhileLocked(ctx context.Context, sessionID, owner string) (sessionRecord, error) {
	defer m.releaseRefreshLock(ctx, sessionID, owner)

	record, err := m.load(ctx, sessionID)
	if err != nil {
		return sessionRecord{}, err
	}
	if time.Unix(record.AccessExpiresAt, 0).After(m.now().Add(refreshLeeway)) {
		return record, nil
	}
	resp, err := m.auth.RefreshSession(ctx, connect.NewRequest(&authv1.RefreshSessionRequest{RefreshToken: &record.RefreshToken}))
	if err != nil {
		if connectErr, ok := errors.AsType[*connect.Error](err); ok && connectErr.Code() == connect.CodeUnauthenticated {
			_ = m.store.Delete(context.WithoutCancel(ctx), sessionID)
			return sessionRecord{}, errSessionUnauthenticated
		}
		return sessionRecord{}, errors.Join(errSessionUnavailable, err)
	}

	customerID, expiresAt, parseErr := parseTrustedAccessToken(resp.Msg.GetToken(), m.now())
	if parseErr != nil || customerID != record.CustomerID || resp.Msg.GetRefreshToken() == "" {
		_ = m.store.Delete(context.WithoutCancel(ctx), sessionID)
		if resp.Msg.GetRefreshToken() != "" {
			_, _ = m.auth.SignOut(context.WithoutCancel(ctx), connect.NewRequest(&authv1.SignOutRequest{
				RefreshToken: resp.Msg.RefreshToken,
			}))
		}
		return sessionRecord{}, errSessionUnauthenticated
	}

	record.AccessToken = resp.Msg.GetToken()
	record.RefreshToken = resp.Msg.GetRefreshToken()
	record.AccessExpiresAt = expiresAt.Unix()
	remaining := time.Unix(record.SessionExpiresAt, 0).Sub(m.now())
	if remaining <= 0 {
		_ = m.store.Delete(context.WithoutCancel(ctx), sessionID)
		return sessionRecord{}, errSessionUnauthenticated
	}
	persistCtx, cancelPersist := context.WithTimeout(context.WithoutCancel(ctx), storeOperationTTL)
	err = m.store.Put(persistCtx, sessionID, record, remaining)
	cancelPersist()
	if err != nil {
		return sessionRecord{}, errors.Join(errSessionUnavailable, err)
	}
	return record, nil
}

func (m *sessionManager) acquireRefreshLock(ctx context.Context, sessionID string) (string, error) {
	if !validOpaqueToken(sessionID, sessionTokenBytes) {
		return "", errSessionUnauthenticated
	}
	owner, err := randomToken(m.random, refreshOwnerBytes)
	if err != nil {
		return "", errors.Join(errSessionUnavailable, err)
	}
	timeout := time.NewTimer(refreshWaitTimeout)
	defer timeout.Stop()
	ticker := time.NewTicker(refreshPollInterval)
	defer ticker.Stop()
	for {
		locked, lockErr := m.store.TryRefreshLock(ctx, sessionID, owner, refreshLockTTL)
		if lockErr != nil {
			return "", errors.Join(errSessionUnavailable, lockErr)
		}
		if locked {
			return owner, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-timeout.C:
			return "", errors.Join(errSessionUnavailable, errors.New("timed out waiting for session operation lock"))
		case <-ticker.C:
		}
	}
}

func (m *sessionManager) releaseRefreshLock(ctx context.Context, sessionID, owner string) {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeOperationTTL)
	defer cancel()
	if err := m.store.ReleaseRefreshLock(releaseCtx, sessionID, owner); err != nil {
		slog.WarnContext(ctx, "unable to release dashboard session operation lock", slogx.Error(err))
	}
}

func parseTrustedAccessToken(raw string, now time.Time) (string, time.Time, error) {
	claims := &jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return "", time.Time{}, err
	}
	if claims.Subject == "" || claims.Issuer != coreauth.Issuer || !slices.Contains(claims.Audience, coreauth.Audience) || claims.ExpiresAt == nil {
		return "", time.Time{}, errors.New("access token claims are invalid")
	}
	if !claims.ExpiresAt.After(now) {
		return "", time.Time{}, errors.New("access token is expired")
	}
	return claims.Subject, claims.ExpiresAt.Time, nil
}

func randomToken(source io.Reader, size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(source, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validOpaqueToken(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == size
}
