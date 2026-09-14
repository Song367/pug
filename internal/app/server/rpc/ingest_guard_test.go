package rpc

import (
	"net/http"
	"testing"
	"time"
)

func newTestIngestGuard(t *testing.T, cfg IngestGuardConfig) *IngestGuard {
	t.Helper()
	g, err := NewIngestGuard(cfg)
	if err != nil {
		t.Fatalf("NewIngestGuard: %v", err)
	}
	return g
}

func TestIngestGuardRateAndRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	g := newTestIngestGuard(t, IngestGuardConfig{
		ProjectRate: 2, ProjectBurst: 2, IPRate: 2, IPBurst: 2,
		ProjectConcurrency: 2, IPConcurrency: 2, IdleTTL: time.Minute, MaxTrackedKeys: 10,
	})
	g.now = func() time.Time { return now }

	for range 2 {
		release, reason := g.Acquire("project-a", "client-a")
		if reason != IngestLimitNone {
			t.Fatalf("Acquire reason = %q", reason)
		}
		release()
	}
	if _, reason := g.Acquire("project-a", "client-a"); reason != IngestLimitRate {
		t.Fatalf("third Acquire reason = %q, want rate", reason)
	}

	now = now.Add(time.Second)
	if release, reason := g.Acquire("project-a", "client-a"); reason != IngestLimitNone {
		t.Fatalf("Acquire after refill reason = %q", reason)
	} else {
		release()
	}
}

func TestIngestGuardChargesEveryEventInBatch(t *testing.T) {
	g := newTestIngestGuard(t, IngestGuardConfig{
		ProjectRate: 10, ProjectBurst: 10, IPRate: 10, IPBurst: 10,
		ProjectConcurrency: 2, IPConcurrency: 2, IdleTTL: time.Minute, MaxTrackedKeys: 10,
	})
	if release, reason := g.AcquireN("project-a", "client-a", 8); reason != IngestLimitNone {
		t.Fatalf("first batch reason = %q", reason)
	} else {
		release()
	}
	if _, reason := g.AcquireN("project-a", "client-a", 3); reason != IngestLimitRate {
		t.Fatalf("batch above remaining event quota reason = %q, want rate", reason)
	}
	if release, reason := g.AcquireN("project-a", "client-a", 2); reason != IngestLimitNone {
		t.Fatalf("rejected batch consumed tokens, reason = %q", reason)
	} else {
		release()
	}
}

func TestIngestGuardConcurrencyAndIdempotentRelease(t *testing.T) {
	g := newTestIngestGuard(t, IngestGuardConfig{
		ProjectRate: 10, ProjectBurst: 10, IPRate: 10, IPBurst: 10,
		ProjectConcurrency: 1, IPConcurrency: 1, IdleTTL: time.Minute, MaxTrackedKeys: 10,
	})
	release, reason := g.Acquire("project-a", "client-a")
	if reason != IngestLimitNone {
		t.Fatalf("Acquire reason = %q", reason)
	}
	if _, reason := g.Acquire("project-a", "client-a"); reason != IngestLimitConcurrency {
		t.Fatalf("concurrent Acquire reason = %q, want concurrency", reason)
	}
	release()
	release()
	if release2, reason := g.Acquire("project-a", "client-a"); reason != IngestLimitNone {
		t.Fatalf("Acquire after release reason = %q", reason)
	} else {
		release2()
	}
}

func TestIngestClientKeyTrustBoundary(t *testing.T) {
	header := http.Header{"X-Forwarded-For": {"203.0.113.7"}}
	peer := "192.0.2.10:4321"

	trusted := IngestClientKey(header, peer, true)
	direct := IngestClientKey(header, peer, false)
	if trusted == direct {
		t.Fatal("trusted proxy address and direct peer produced the same key")
	}
	if direct != IngestClientKey(http.Header{}, peer, false) {
		t.Fatal("untrusted proxy header affected client key")
	}
}

func TestIngestGuardCapacityFailureDoesNotLeavePartialState(t *testing.T) {
	g := newTestIngestGuard(t, IngestGuardConfig{
		ProjectRate: 10, ProjectBurst: 10, IPRate: 10, IPBurst: 10,
		ProjectConcurrency: 2, IPConcurrency: 2, IdleTTL: time.Hour, MaxTrackedKeys: 3,
	})
	if release, reason := g.Acquire("project-a", "client-a"); reason != IngestLimitNone {
		t.Fatalf("first Acquire reason = %q", reason)
	} else {
		release()
	}
	if _, reason := g.Acquire("project-b", "client-b"); reason != IngestLimitRate {
		t.Fatalf("capacity Acquire reason = %q, want rate", reason)
	}
	if len(g.states) != 2 || g.states["project:project-b"] != nil {
		t.Fatalf("capacity failure left partial state: %#v", g.states)
	}
}
