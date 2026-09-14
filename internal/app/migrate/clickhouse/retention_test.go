package clickhouse

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type retentionCatalogStub struct {
	show  []string
	execs []string
	errAt int
}

func (s *retentionCatalogStub) ShowCreate(context.Context) (string, error) {
	if len(s.show) == 0 {
		return "", errors.New("unexpected ShowCreate")
	}
	value := s.show[0]
	s.show = s.show[1:]
	return value, nil
}

func (s *retentionCatalogStub) Exec(_ context.Context, query string) error {
	s.execs = append(s.execs, query)
	if s.errAt > 0 && len(s.execs) == s.errAt {
		return errors.New("injected failure")
	}
	return nil
}

func TestRawEventsRetentionDDL(t *testing.T) {
	query, days, managed, err := rawEventsRetentionDDL("test", "336h")
	if err != nil {
		t.Fatal(err)
	}
	if !managed || days != 14 || query != "ALTER TABLE events MODIFY TTL occur_time + INTERVAL 14 DAY DELETE" {
		t.Fatalf("rawEventsRetentionDDL() = (%q, %d, %t)", query, days, managed)
	}
}

func TestRawEventsRetentionDDLProductionDefaultsToUnmanaged(t *testing.T) {
	query, days, managed, err := rawEventsRetentionDDL("production", "")
	if err != nil || managed || days != 0 || query != "" {
		t.Fatalf("rawEventsRetentionDDL() = (%q, %d, %t, %v)", query, days, managed, err)
	}
}

func TestRawEventsRetentionDDLTestEmptyRemovesManagedTTL(t *testing.T) {
	query, days, managed, err := rawEventsRetentionDDL(" test ", " ")
	if err != nil || !managed || days != 0 || query != "ALTER TABLE events REMOVE TTL" {
		t.Fatalf("rawEventsRetentionDDL() = (%q, %d, %t, %v)", query, days, managed, err)
	}
}

func TestRawEventsRetentionDDLRejectsProduction(t *testing.T) {
	_, _, _, err := rawEventsRetentionDDL("production", "336h")
	if err == nil || !strings.Contains(err.Error(), "only") {
		t.Fatalf("rawEventsRetentionDDL() error = %v, want test-only rejection", err)
	}
}

func TestApplyRawEventsRetentionAppliesAndVerifies(t *testing.T) {
	catalog := &retentionCatalogStub{show: []string{
		"CREATE TABLE events\nTTL occur_time + INTERVAL 7 DAY DELETE\nSETTINGS index_granularity=8192",
		"CREATE TABLE events\nTTL occur_time + INTERVAL 14 DAY DELETE\nSETTINGS index_granularity=8192",
	}}
	query := "ALTER TABLE events MODIFY TTL occur_time + INTERVAL 14 DAY DELETE"
	if err := applyRawEventsRetention(context.Background(), catalog, query); err != nil {
		t.Fatal(err)
	}
	if len(catalog.execs) != 1 || catalog.execs[0] != query {
		t.Fatalf("execs=%v", catalog.execs)
	}
}

func TestVerifyRawEventsRetentionAcceptsClickHouseNormalization(t *testing.T) {
	query := "ALTER TABLE events MODIFY TTL occur_time + INTERVAL 14 DAY DELETE"
	createTable := "CREATE TABLE events\nTTL occur_time + toIntervalDay(14)\nSETTINGS index_granularity=8192"
	if err := verifyRawEventsRetention(query, createTable); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRawEventsRetentionDisablesTTL(t *testing.T) {
	catalog := &retentionCatalogStub{show: []string{
		"CREATE TABLE events\nTTL occur_time + INTERVAL 14 DAY DELETE\nSETTINGS index_granularity=8192",
		"CREATE TABLE events\nSETTINGS index_granularity=8192",
	}}
	if err := applyRawEventsRetention(context.Background(), catalog, "ALTER TABLE events REMOVE TTL"); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRawEventsRetentionRestoresSnapshotOnVerificationFailure(t *testing.T) {
	catalog := &retentionCatalogStub{show: []string{
		"CREATE TABLE events\nTTL occur_time + INTERVAL 7 DAY DELETE\nSETTINGS index_granularity=8192",
		"CREATE TABLE events\nTTL occur_time + INTERVAL 30 DAY DELETE\nSETTINGS index_granularity=8192",
	}}
	err := applyRawEventsRetention(context.Background(), catalog, "ALTER TABLE events MODIFY TTL occur_time + INTERVAL 14 DAY DELETE")
	if err == nil || !strings.Contains(err.Error(), "previous TTL restored") {
		t.Fatalf("error=%v", err)
	}
	wantRollback := "ALTER TABLE events MODIFY TTL occur_time + INTERVAL 7 DAY DELETE"
	if len(catalog.execs) != 2 || catalog.execs[1] != wantRollback {
		t.Fatalf("execs=%v", catalog.execs)
	}
}

func TestApplyRawEventsRetentionRestoresNoTTLOnApplyFailure(t *testing.T) {
	catalog := &retentionCatalogStub{
		show:  []string{"CREATE TABLE events\nSETTINGS index_granularity=8192"},
		errAt: 1,
	}
	err := applyRawEventsRetention(context.Background(), catalog, "ALTER TABLE events MODIFY TTL occur_time + INTERVAL 14 DAY DELETE")
	if err == nil || len(catalog.execs) != 2 || catalog.execs[1] != "ALTER TABLE events REMOVE TTL" {
		t.Fatalf("execs=%v err=%v", catalog.execs, err)
	}
}
