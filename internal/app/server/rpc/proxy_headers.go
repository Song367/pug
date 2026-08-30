package rpc

import (
	"net/http"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/pug-sh/pug/internal/geo"
)

var trustedProxyHeaderRejectedCounter metric.Int64Counter

func init() {
	trustedProxyHeaderRejectedCounter, _ = otel.Meter("github.com/pug-sh/pug/internal/app/server/rpc").Int64Counter(
		"http.trusted_proxy_header_rejected_total",
		metric.WithDescription("A request from the configured private-gateway boundary was rejected because an approved visitor-IP header was ambiguous or malformed."),
	)
}

// Header names are lower-case because HTTP canonicalization does not preserve
// Cloudflare's capitalization. The allowlist contains only values Pug consumes.
var trustedProxyHeaderAllowlist = map[string]struct{}{
	"cf-connecting-ip": {},
	"true-client-ip":   {},
	"x-forwarded-for":  {},
	"cf-ipcontinent":   {},
	"cf-ipcountry":     {},
	"cf-region":        {},
	"cf-ipcity":        {},
	"cf-postal-code":   {},
	"cf-metro-code":    {},
	"cf-iplatitude":    {},
	"cf-iplongitude":   {},
	"cf-timezone":      {},
	"cf-bot-score":     {},
	"cf-verified-bot":  {},
}

var trustedIPHeaders = []string{
	geo.HeaderCFConnectingIP,
	geo.HeaderTrueClientIP,
	geo.HeaderXForwardedFor,
}

// WithProxyHeaderPolicy is the application-side backstop for the edge trust
// boundary. When no private gateway is trusted, all proxy-derived identity,
// geo, and bot headers are removed before handlers can read them. When one is
// trusted, only headers Pug consumes survive and visitor IPs are reduced to one
// canonical address. The gateway must still replace client values and keep the
// origin unreachable from the public network.
func WithProxyHeaderPolicy(trustProxyHeaders bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripUntrustedProxyHeaders(r.Header, trustProxyHeaders)
		if trustProxyHeaders {
			if invalidHeader := normalizeTrustedIPHeaders(r.Header); invalidHeader != "" {
				trustedProxyHeaderRejectedCounter.Add(r.Context(), 1, metric.WithAttributes(
					attribute.String("header", strings.ToLower(invalidHeader)),
				))
				http.Error(w, "invalid trusted proxy header", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func stripUntrustedProxyHeaders(h http.Header, trustProxyHeaders bool) {
	for name := range h {
		lower := strings.ToLower(name)
		_, allowed := trustedProxyHeaderAllowlist[lower]
		if !isProxyControlledHeader(lower) {
			continue
		}
		if !trustProxyHeaders || !allowed {
			delete(h, name)
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		if canonical != name {
			values := h[name]
			delete(h, name)
			h[canonical] = append(h[canonical], values...)
		}
	}
}

func isProxyControlledHeader(lowerName string) bool {
	return strings.HasPrefix(lowerName, "cf-") ||
		lowerName == "true-client-ip" ||
		lowerName == "x-forwarded-for" ||
		lowerName == "x-real-ip" ||
		lowerName == "forwarded"
}

func normalizeTrustedIPHeaders(h http.Header) string {
	for _, name := range trustedIPHeaders {
		values := h.Values(name)
		if len(values) == 0 {
			continue
		}
		if len(values) != 1 {
			return name
		}
		raw := values[0]
		if name == geo.HeaderXForwardedFor {
			raw, _, _ = strings.Cut(raw, ",")
		}
		ip, ok := geo.ParseClientIP(raw)
		if !ok {
			return name
		}
		h.Set(name, ip)
	}
	return ""
}
