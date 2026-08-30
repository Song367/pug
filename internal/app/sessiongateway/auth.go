package sessiongateway

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect"
	authv1 "github.com/pug-sh/pug/internal/gen/proto/public/auth/v1"
	"github.com/pug-sh/pug/internal/gen/proto/public/auth/v1/authv1connect"
	"github.com/pug-sh/pug/internal/slogx"
)

const (
	sessionCookieName = "__Host-pug_session"
	csrfHeaderName    = "X-Pug-CSRF-Token"
)

type authClient interface {
	authv1connect.AuthServiceClient
}

type authServer struct {
	upstream     authClient
	sessions     *sessionManager
	publicOrigin string
}

func (s *authServer) GetAuthConfig(
	ctx context.Context,
	req *connect.Request[authv1.GetAuthConfigRequest],
) (*connect.Response[authv1.GetAuthConfigResponse], error) {
	return s.upstream.GetAuthConfig(ctx, upstreamAuthRequest(req.Msg, s.publicOrigin, req.Header()))
}

func (s *authServer) SignInWithEmail(
	ctx context.Context,
	req *connect.Request[authv1.SignInWithEmailRequest],
) (*connect.Response[authv1.SignInWithEmailResponse], error) {
	upstream, err := s.upstream.SignInWithEmail(ctx, upstreamAuthRequest(req.Msg, s.publicOrigin, req.Header()))
	if err != nil {
		return nil, err
	}
	sessionID, record, err := s.sessions.create(
		ctx,
		upstream.Msg.GetToken(),
		upstream.Msg.GetRefreshToken(),
		false,
		sessionIDFromHeader(req.Header()),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not establish session"))
	}
	resp := connect.NewResponse(&authv1.SignInWithEmailResponse{})
	setSessionCookie(resp.Header(), sessionID, record, s.sessions.now())
	return resp, nil
}

func (s *authServer) RequestMagicLink(
	ctx context.Context,
	req *connect.Request[authv1.RequestMagicLinkRequest],
) (*connect.Response[authv1.RequestMagicLinkResponse], error) {
	return s.upstream.RequestMagicLink(ctx, upstreamAuthRequest(req.Msg, s.publicOrigin, req.Header()))
}

func (s *authServer) CompleteMagicLink(
	ctx context.Context,
	req *connect.Request[authv1.CompleteMagicLinkRequest],
) (*connect.Response[authv1.CompleteMagicLinkResponse], error) {
	upstream, err := s.upstream.CompleteMagicLink(ctx, upstreamAuthRequest(req.Msg, s.publicOrigin, req.Header()))
	if err != nil {
		return nil, err
	}
	sessionID, record, err := s.sessions.create(
		ctx,
		upstream.Msg.GetToken(),
		upstream.Msg.GetRefreshToken(),
		false,
		sessionIDFromHeader(req.Header()),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not establish session"))
	}
	resp := connect.NewResponse(&authv1.CompleteMagicLinkResponse{})
	setSessionCookie(resp.Header(), sessionID, record, s.sessions.now())
	return resp, nil
}

func (s *authServer) CompleteOIDCSignIn(
	ctx context.Context,
	req *connect.Request[authv1.CompleteOIDCSignInRequest],
) (*connect.Response[authv1.CompleteOIDCSignInResponse], error) {
	upstream, err := s.upstream.CompleteOIDCSignIn(ctx, upstreamAuthRequest(req.Msg, s.publicOrigin, req.Header()))
	if err != nil {
		return nil, err
	}
	sessionID, record, err := s.sessions.create(
		ctx,
		upstream.Msg.GetToken(),
		upstream.Msg.GetRefreshToken(),
		false,
		sessionIDFromHeader(req.Header()),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not establish session"))
	}
	resp := connect.NewResponse(&authv1.CompleteOIDCSignInResponse{})
	setSessionCookie(resp.Header(), sessionID, record, s.sessions.now())
	return resp, nil
}

func (s *authServer) RefreshSession(
	context.Context,
	*connect.Request[authv1.RefreshSessionRequest],
) (*connect.Response[authv1.RefreshSessionResponse], error) {
	return nil, connect.NewError(connect.CodePermissionDenied, errors.New("browser token refresh is disabled"))
}

func (s *authServer) SignOut(
	ctx context.Context,
	req *connect.Request[authv1.SignOutRequest],
) (*connect.Response[authv1.SignOutResponse], error) {
	resp := connect.NewResponse(&authv1.SignOutResponse{})
	sessionID := sessionIDFromHeader(req.Header())
	if sessionID == "" {
		clearSessionCookie(resp.Header())
		return resp, nil
	}
	record, err := s.sessions.load(ctx, sessionID)
	if errors.Is(err, errSessionUnauthenticated) {
		clearSessionCookie(resp.Header())
		return resp, nil
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("session service unavailable"))
	}
	if subtle.ConstantTimeCompare([]byte(record.CSRFToken), []byte(req.Header().Get(csrfHeaderName))) != 1 {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("CSRF validation failed"))
	}
	if err := s.sessions.signOut(ctx, sessionID); err != nil {
		slog.WarnContext(ctx, "dashboard sign-out could not delete the server-side session", slogx.Error(err))
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("session service unavailable"))
	}
	clearSessionCookie(resp.Header())
	return resp, nil
}

func (s *authServer) DemoSignIn(
	ctx context.Context,
	req *connect.Request[authv1.DemoSignInRequest],
) (*connect.Response[authv1.DemoSignInResponse], error) {
	upstream, err := s.upstream.DemoSignIn(ctx, upstreamAuthRequest(req.Msg, s.publicOrigin, req.Header()))
	if err != nil {
		return nil, err
	}
	sessionID, record, err := s.sessions.create(
		ctx,
		upstream.Msg.GetToken(),
		upstream.Msg.GetRefreshToken(),
		true,
		sessionIDFromHeader(req.Header()),
	)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("could not establish session"))
	}
	resp := connect.NewResponse(&authv1.DemoSignInResponse{ProjectId: upstream.Msg.ProjectId})
	setSessionCookie(resp.Header(), sessionID, record, s.sessions.now())
	return resp, nil
}

func upstreamAuthRequest[T any](message *T, publicOrigin string, incoming http.Header) *connect.Request[T] {
	req := connect.NewRequest(message)
	req.Header().Set("Origin", publicOrigin)
	for _, name := range []string{"Connect-Timeout-Ms", "Traceparent", "Tracestate", "User-Agent"} {
		if value := incoming.Get(name); value != "" {
			req.Header().Set(name, value)
		}
	}
	return req
}

func sessionIDFromHeader(header http.Header) string {
	req := &http.Request{Header: header}
	cookie, err := req.Cookie(sessionCookieName)
	if err != nil || !validOpaqueToken(cookie.Value, sessionTokenBytes) {
		return ""
	}
	return cookie.Value
}

func setSessionCookie(header http.Header, sessionID string, record sessionRecord, now time.Time) {
	expires := time.Unix(record.SessionExpiresAt, 0)
	remaining := max(time.Duration(0), expires.Sub(now))
	header.Add("Set-Cookie", (&http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(remaining.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}).String())
}

func clearSessionCookie(header http.Header) {
	header.Add("Set-Cookie", (&http.Cookie{
		Name:     sessionCookieName,
		Path:     "/",
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}).String())
}
