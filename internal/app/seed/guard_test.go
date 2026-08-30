package seed

import (
	"strings"
	"testing"
)

func TestValidateGuard(t *testing.T) {
	tests := []struct {
		name      string
		cfg       guardConfig
		confirmed bool
		wantErr   string
	}{
		{
			name:      "disposable development with confirmation",
			cfg:       guardConfig{Environment: " development ", Disposable: true},
			confirmed: true,
		},
		{
			name:      "production is always rejected",
			cfg:       guardConfig{Environment: "production", Disposable: true},
			confirmed: true,
			wantErr:   "only development is allowed",
		},
		{
			name:      "test is rejected",
			cfg:       guardConfig{Environment: "test", Disposable: true},
			confirmed: true,
			wantErr:   "only development is allowed",
		},
		{
			name:      "disposable marker required",
			cfg:       guardConfig{Environment: "development"},
			confirmed: true,
			wantErr:   "PUG_DISPOSABLE_ENVIRONMENT=true",
		},
		{
			name:    "explicit flag required",
			cfg:     guardConfig{Environment: "development", Disposable: true},
			wantErr: "--confirm-disposable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGuard(tt.cfg, tt.confirmed)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateGuard() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateGuard() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
