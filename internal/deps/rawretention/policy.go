package rawretention

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const maxRetention = 30 * 24 * time.Hour

// Resolve returns an explicitly managed raw-event retention window. An empty
// value leaves upstream Pug defaults unchanged. Retention is deliberately
// restricted to test deployments so a Test privacy policy cannot silently
// become a Production data-deletion policy.
func Resolve(environment, raw string) (time.Duration, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, nil
	}
	if strings.ToLower(strings.TrimSpace(environment)) != "test" {
		return 0, false, errors.New("PUG_RAW_EVENTS_RETENTION is supported only when PUG_ENVIRONMENT=test")
	}

	retention, err := time.ParseDuration(raw)
	if err != nil {
		return 0, false, fmt.Errorf("parse PUG_RAW_EVENTS_RETENTION: %w", err)
	}
	if retention < 24*time.Hour || retention > maxRetention || retention%(24*time.Hour) != 0 {
		return 0, false, errors.New("PUG_RAW_EVENTS_RETENTION must be a whole number of days between 1d and 30d")
	}
	return retention, true, nil
}
