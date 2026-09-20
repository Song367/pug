package profiles_test

import (
	"os"
	"strings"
	"testing"
)

const migration012Path = "../../../schema/clickhouse/migrations/012_profile_web_context.sql"

func TestMigration012UsesConditionalWebContextStates(t *testing.T) {
	raw, err := os.ReadFile(migration012Path)
	if err != nil {
		t.Fatalf("read migration 012: %v", err)
	}
	up, _, _ := strings.Cut(string(raw), "-- +goose Down")
	for _, field := range []string{"browser", "browser_version", "os", "os_version", "device", "country", "region", "city"} {
		want := "argMaxIfState(" + field + ", occur_time, url != '' AND " + field + " != '')"
		if got := strings.Count(up, want); got != 2 {
			t.Errorf("012 Up must use %q in MV and backfill, got %d", want, got)
		}
	}
	if !strings.Contains(up, "sumState(toUInt64(kind = 'page_view'))") {
		t.Error("012 must keep native page_view counting")
	}
	if strings.Contains(up, "kind = 'page.view'") {
		t.Error("012 must not fabricate legacy page.view pageviews")
	}
	if !strings.Contains(up, "WHERE NOT startsWith(distinct_id, 'cookieless-')") {
		t.Error("012 must retain cookieless profile exclusion")
	}
}
