package rpc

import (
	"crypto/sha256"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pug-sh/pug/internal/geo"
)

type IngestLimitReason string

const (
	IngestLimitNone        IngestLimitReason = ""
	IngestLimitRate        IngestLimitReason = "rate"
	IngestLimitConcurrency IngestLimitReason = "concurrency"
)

type IngestGuardConfig struct {
	ProjectRate        int
	ProjectBurst       int
	IPRate             int
	IPBurst            int
	ProjectConcurrency int
	IPConcurrency      int
	IdleTTL            time.Duration
	MaxTrackedKeys     int
}

type ingestLimitState struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
	active   int
}

// IngestGuard provides a bounded, in-process second layer behind the edge/WAF.
// It intentionally stores only a SHA-256 digest of the transient client IP.
type IngestGuard struct {
	mu     sync.Mutex
	cfg    IngestGuardConfig
	now    func() time.Time
	states map[string]*ingestLimitState
}

func NewIngestGuard(cfg IngestGuardConfig) (*IngestGuard, error) {
	if cfg.ProjectRate <= 0 || cfg.ProjectBurst <= 0 || cfg.IPRate <= 0 || cfg.IPBurst <= 0 {
		return nil, errors.New("ingest rates and bursts must be positive")
	}
	if cfg.ProjectConcurrency <= 0 || cfg.IPConcurrency <= 0 {
		return nil, errors.New("ingest concurrency limits must be positive")
	}
	if cfg.IdleTTL <= 0 || cfg.MaxTrackedKeys <= 1 {
		return nil, errors.New("ingest guard bounds must be positive")
	}
	return &IngestGuard{cfg: cfg, now: time.Now, states: make(map[string]*ingestLimitState)}, nil
}

// Acquire reserves one request against both project and client limits. A
// successful call returns an idempotent release function.
func (g *IngestGuard) Acquire(projectID, clientKey string) (func(), IngestLimitReason) {
	return g.AcquireN(projectID, clientKey, 1)
}

// AcquireN reserves eventCount tokens against both project and client limits.
// This makes configured rates event quotas rather than request quotas, so a
// client cannot bypass the project ceiling by filling 100-event batches.
func (g *IngestGuard) AcquireN(projectID, clientKey string, eventCount int) (func(), IngestLimitReason) {
	if eventCount < 1 {
		eventCount = 1
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()

	project, client := g.statesLocked("project:"+projectID, "client:"+clientKey, now)
	if project == nil {
		return nil, IngestLimitRate
	}

	refill(project, g.cfg.ProjectRate, g.cfg.ProjectBurst, now)
	refill(client, g.cfg.IPRate, g.cfg.IPBurst, now)
	if project.active >= g.cfg.ProjectConcurrency || client.active >= g.cfg.IPConcurrency {
		return nil, IngestLimitConcurrency
	}
	cost := float64(eventCount)
	if project.tokens < cost || client.tokens < cost {
		return nil, IngestLimitRate
	}

	project.tokens -= cost
	client.tokens -= cost
	project.active++
	client.active++

	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			project.active--
			client.active--
			g.mu.Unlock()
		})
	}, IngestLimitNone
}

func (g *IngestGuard) statesLocked(projectKey, clientKey string, now time.Time) (*ingestLimitState, *ingestLimitState) {
	missingCount := func() int {
		missing := 0
		if g.states[projectKey] == nil {
			missing++
		}
		if g.states[clientKey] == nil {
			missing++
		}
		return missing
	}
	missing := missingCount()
	if len(g.states)+missing > g.cfg.MaxTrackedKeys {
		g.pruneLocked(now)
		missing = missingCount()
	}
	if len(g.states)+missing > g.cfg.MaxTrackedKeys {
		return nil, nil
	}
	project := g.states[projectKey]
	if project == nil {
		project = &ingestLimitState{tokens: float64(g.cfg.ProjectBurst), last: now, lastSeen: now}
		g.states[projectKey] = project
	}
	client := g.states[clientKey]
	if client == nil {
		client = &ingestLimitState{tokens: float64(g.cfg.IPBurst), last: now, lastSeen: now}
		g.states[clientKey] = client
	}
	project.lastSeen = now
	client.lastSeen = now
	return project, client
}

func (g *IngestGuard) pruneLocked(now time.Time) {
	cutoff := now.Add(-g.cfg.IdleTTL)
	for key, state := range g.states {
		if state.active == 0 && state.lastSeen.Before(cutoff) {
			delete(g.states, key)
		}
	}
}

func refill(state *ingestLimitState, ratePerSecond, burst int, now time.Time) {
	elapsed := now.Sub(state.last).Seconds()
	if elapsed > 0 {
		state.tokens = min(float64(burst), state.tokens+elapsed*float64(ratePerSecond))
		state.last = now
	}
	state.lastSeen = now
}

// IngestClientKey derives the transient client bucket key without retaining a
// raw IP. Proxy headers are read only when the deployment explicitly trusts its
// private gateway; otherwise the kernel-derived connection peer is used.
func IngestClientKey(h http.Header, peerAddr string, trustProxyHeaders bool) string {
	var ip string
	if trustProxyHeaders {
		ip, _ = geo.ClientIPWithSource(h)
	}
	if ip == "" {
		ip = peerAddressIP(peerAddr)
	}
	if ip == "" {
		ip = "unknown"
	}
	digest := sha256.Sum256([]byte(ip))
	return string(digest[:])
}

func peerAddressIP(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		ip, _ := geo.ParseClientIP(host)
		return ip
	}
	ip, _ := geo.ParseClientIP(addr)
	return ip
}
