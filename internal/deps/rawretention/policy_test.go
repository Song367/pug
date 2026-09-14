package rawretention

import (
	"strings"
	"testing"
	"time"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name        string
		environment string
		raw         string
		want        time.Duration
		managed     bool
		wantErr     string
	}{
		{name: "unset preserves upstream defaults", environment: "production"},
		{name: "test fourteen days", environment: "test", raw: "336h", want: 14 * 24 * time.Hour, managed: true},
		{name: "environment normalized", environment: " TEST ", raw: "24h", want: 24 * time.Hour, managed: true},
		{name: "production fails closed", environment: "production", raw: "336h", wantErr: "only"},
		{name: "development fails closed", environment: "development", raw: "336h", wantErr: "only"},
		{name: "fractional day rejected", environment: "test", raw: "25h", wantErr: "whole number"},
		{name: "too short rejected", environment: "test", raw: "23h", wantErr: "whole number"},
		{name: "too long rejected", environment: "test", raw: "744h", wantErr: "whole number"},
		{name: "invalid rejected", environment: "test", raw: "fourteen-days", wantErr: "parse"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, managed, err := Resolve(tt.environment, tt.raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Resolve() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want || managed != tt.managed {
				t.Fatalf("Resolve() = (%v, %t), want (%v, %t)", got, managed, tt.want, tt.managed)
			}
		})
	}
}
