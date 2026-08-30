package sessiongateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/pug-sh/pug/internal/app/server/rpc"
	"github.com/pug-sh/pug/internal/gen/proto/dashboard/customers/v1/customersv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/dashboard/dashboards/v1/dashboardsv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/dashboard/orgemailproviders/v1/orgemailprovidersv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/dashboard/orgs/v1/orgsv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/dashboard/projects/v1/projectsv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/dashboard/usage/v1/usagev1connect"
	"github.com/pug-sh/pug/internal/gen/proto/public/auth/v1/authv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/public/dashboards/v1/publicdashboardsv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/shared/activity/v1/activityv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/shared/insights/v1/insightsv1connect"
	"github.com/pug-sh/pug/internal/gen/proto/shared/profiles/v1/profilesv1connect"
)

const sessionStatusPath = "/_pug/session"

type sessionContextKey struct{}

type gateway struct {
	publicOrigin *url.URL
	sessions     *sessionManager
	authHandler  http.Handler
	apiProxy     *httputil.ReverseProxy
	publicProxy  *httputil.ReverseProxy
	staticProxy  *httputil.ReverseProxy
}

func newGateway(
	cfg resolvedConfig,
	sessions *sessionManager,
	upstreamAuth authClient,
	apiTransport http.RoundTripper,
	staticTransport http.RoundTripper,
) http.Handler {
	authPath, authHandler := authv1connect.NewAuthServiceHandler(
		&authServer{upstream: upstreamAuth, sessions: sessions, publicOrigin: cfg.publicOrigin.String()},
		connect.WithReadMaxBytes(64<<10),
	)
	g := &gateway{
		publicOrigin: cfg.publicOrigin,
		sessions:     sessions,
		authHandler:  authHandler,
		apiProxy:     newAPIProxy(cfg.apiUpstream, apiTransport, true),
		publicProxy:  newAPIProxy(cfg.apiUpstream, apiTransport, false),
		staticProxy:  newStaticProxy(cfg.staticUpstream, staticTransport),
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(g.liveness))
	mux.Handle("/readyz", http.HandlerFunc(g.readiness))
	mux.Handle(sessionStatusPath, http.HandlerFunc(g.sessionStatus))
	mux.Handle(authPath, g.requireSameOrigin(g.authHandler))
	mux.Handle(servicePath(publicdashboardsv1connect.SharedDashboardsServiceName), g.requireSameOrigin(g.publicProxy))

	for _, service := range []string{
		customersv1connect.CustomersServiceName,
		dashboardsv1connect.DashboardsServiceName,
		orgemailprovidersv1connect.OrgEmailProvidersServiceName,
		orgsv1connect.OrgsServiceName,
		projectsv1connect.ProjectsServiceName,
		usagev1connect.UsageServiceName,
		activityv1connect.ActivityServiceName,
		insightsv1connect.InsightsServiceName,
		profilesv1connect.ProfilesServiceName,
	} {
		mux.Handle(servicePath(service), g.authenticatedAPI())
	}
	mux.Handle("/", http.HandlerFunc(g.static))

	return securityHeaders(g.requirePublicHost(rpc.WithRequestLimits(mux)))
}

func (g *gateway) liveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePlainError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func (g *gateway) readiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writePlainError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := g.sessions.store.Ping(ctx); err != nil {
		writePlainError(w, http.StatusServiceUnavailable, "session store unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ready\n")
}

type sessionStatusResponse struct {
	Authenticated bool   `json:"authenticated"`
	CustomerID    string `json:"customerId,omitempty"`
	CSRFToken     string `json:"csrfToken,omitempty"`
	Demo          bool   `json:"demo"`
}

func (g *gateway) sessionStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	sessionID := sessionIDFromHeader(r.Header)
	if sessionID == "" {
		_ = json.NewEncoder(w).Encode(sessionStatusResponse{})
		return
	}
	record, err := g.sessions.valid(r.Context(), sessionID)
	if errors.Is(err, errSessionUnauthenticated) {
		clearSessionCookie(w.Header())
		_ = json.NewEncoder(w).Encode(sessionStatusResponse{})
		return
	}
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "session service unavailable")
		return
	}
	setSessionCookie(w.Header(), sessionID, record, g.sessions.now())
	_ = json.NewEncoder(w).Encode(sessionStatusResponse{
		Authenticated: true,
		CustomerID:    record.CustomerID,
		CSRFToken:     record.CSRFToken,
		Demo:          record.Demo,
	})
}

func (g *gateway) authenticatedAPI() http.Handler {
	return g.requireSameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeConnectError(w, http.StatusMethodNotAllowed, "unimplemented", "method not allowed")
			return
		}
		sessionID := sessionIDFromHeader(r.Header)
		record, err := g.sessions.authenticate(r.Context(), sessionID, r.Header.Get(csrfHeaderName))
		if errors.Is(err, errCSRFInvalid) {
			writeConnectError(w, http.StatusForbidden, "permission_denied", "CSRF validation failed")
			return
		}
		if errors.Is(err, errSessionUnauthenticated) {
			clearSessionCookie(w.Header())
			writeConnectError(w, http.StatusUnauthorized, "unauthenticated", "not authenticated")
			return
		}
		if err != nil {
			writeConnectError(w, http.StatusServiceUnavailable, "unavailable", "session service unavailable")
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionContextKey{}, record))
		g.apiProxy.ServeHTTP(w, r)
	}))
}

func (g *gateway) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !sameOriginRequest(r, g.publicOrigin) {
			writeConnectError(w, http.StatusForbidden, "permission_denied", "same-origin request required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *gateway) requirePublicHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && !strings.EqualFold(r.Host, g.publicOrigin.Host) {
			writePlainError(w, http.StatusMisdirectedRequest, "unexpected host")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *gateway) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writePlainError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if isForbiddenGatewayPath(r.URL.Path) {
		writePlainError(w, http.StatusNotFound, "not found")
		return
	}
	g.staticProxy.ServeHTTP(w, r)
}

func newAPIProxy(upstream *url.URL, transport http.RoundTripper, authenticated bool) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(upstream)
			req.Out.Host = upstream.Host
			req.Out.Header = forwardedAPIHeaders(req.In.Header)
			if authenticated {
				record, _ := req.In.Context().Value(sessionContextKey{}).(sessionRecord)
				req.Out.Header.Set("Authorization", "Bearer "+record.AccessToken)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			stripUpstreamResponseHeaders(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeConnectError(w, http.StatusBadGateway, "unavailable", "Pug API unavailable")
		},
		Transport: transport,
	}
	return proxy
}

func newStaticProxy(upstream *url.URL, transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(upstream)
			req.Out.Host = upstream.Host
			req.Out.Header = forwardedStaticHeaders(req.In.Header)
		},
		ModifyResponse: func(resp *http.Response) error {
			stripUpstreamResponseHeaders(resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writePlainError(w, http.StatusBadGateway, "Dashboard unavailable")
		},
		Transport: transport,
	}
}

func stripUpstreamResponseHeaders(header http.Header) {
	for _, name := range []string{
		"Cross-Origin-Opener-Policy",
		"Cross-Origin-Resource-Policy",
		"Permissions-Policy",
		"Referrer-Policy",
		"Server",
		"Set-Cookie",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-Frame-Options",
	} {
		header.Del(name)
	}
	for name := range header {
		if strings.HasPrefix(strings.ToLower(name), "access-control-") {
			header.Del(name)
		}
	}
}

func forwardedAPIHeaders(in http.Header) http.Header {
	out := make(http.Header)
	for _, name := range []string{
		"Accept",
		"Accept-Encoding",
		"Connect-Protocol-Version",
		"Connect-Timeout-Ms",
		"Content-Encoding",
		"Content-Type",
		"Grpc-Timeout",
		"Traceparent",
		"Tracestate",
		"User-Agent",
		"X-Project-Id",
	} {
		if values := in.Values(name); len(values) > 0 {
			out[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	return out
}

func forwardedStaticHeaders(in http.Header) http.Header {
	out := make(http.Header)
	for _, name := range []string{"Accept", "Accept-Encoding", "If-Modified-Since", "If-None-Match", "Range", "User-Agent"} {
		if values := in.Values(name); len(values) > 0 {
			out[http.CanonicalHeaderKey(name)] = append([]string(nil), values...)
		}
	}
	return out
}

func sameOriginRequest(r *http.Request, publicOrigin *url.URL) bool {
	origin, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	if !strings.EqualFold(origin.Scheme, publicOrigin.Scheme) || !strings.EqualFold(origin.Host, publicOrigin.Host) {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	return true
}

func servicePath(service string) string {
	return "/" + service + "/"
}

func isForbiddenGatewayPath(path string) bool {
	if path == "/mcp" || strings.HasPrefix(path, "/mcp/") {
		return true
	}
	segment := strings.TrimPrefix(path, "/")
	segment, _, _ = strings.Cut(segment, "/")
	if !strings.Contains(segment, ".") {
		return false
	}

	// Connect service names contain dots, so an unknown dotted top-level path
	// must never fall through to the SPA and accidentally expose a backend RPC.
	// Vite also emits a small, fixed set of root-level static files; allow only
	// those exact public assets and keep every other dotted path closed.
	switch path {
	case "/apple-touch-icon.png", "/favicon.ico", "/favicon.svg", "/google.svg", "/index.html", "/logo.svg", "/theme-init.js":
		return false
	default:
		return true
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()")
		next.ServeHTTP(w, r)
	})
}

func writeConnectError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func writePlainError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}
