package clickhouse

import (
	"strings"
	"testing"
)

func TestRawEventsRetentionDDL(t *testing.T) {
	query, days, managed, err := rawEventsRetentionDDL("test", "336h")
	if err != nil {
		t.Fatal(err)
	}
	if !managed || days != 14 || query != "ALTER TABLE events MODIFY TTL occur_time + INTERVAL 14 DAY DELETE" {
		t.Fatalf("rawEventsRetentionDDL() = (%q, %d, %t)", query, days, managed)
	}
}

func TestRawEventsRetentionDDLDefaultsToUnmanaged(t *testing.T) {
	query, days, managed, err := rawEventsRetentionDDL("production", "")
	if err != nil || managed || days != 0 || query != "" {
		t.Fatalf("rawEventsRetentionDDL() = (%q, %d, %t, %v)", query, days, managed, err)
	}
}

func TestRawEventsRetentionDDLRejectsProduction(t *testing.T) {
	_, _, _, err := rawEventsRetentionDDL("production", "336h")
	if err == nil || !strings.Contains(err.Error(), "only") {
		t.Fatalf("rawEventsRetentionDDL() error = %v, want test-only rejection", err)
	}
}
