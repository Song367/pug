package jwtkeyring

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestParseAndSelectKeys(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	oldKey := []byte("0123456789abcdef0123456789abcdef")
	newKey := []byte("abcdef0123456789abcdef0123456789")
	raw := []byte(fmt.Sprintf(`{"version":1,"active_kid":"v2","keys":{"v1":%q,"v2":%q},"legacy_no_kid_key_id":"v1","legacy_no_kid_until":%q}`,
		base64.RawURLEncoding.EncodeToString(oldKey), base64.RawURLEncoding.EncodeToString(newKey), now.Add(15*time.Minute).Format(time.RFC3339)))
	ring, err := Parse(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	id, active, err := ring.Active()
	if err != nil || id != "v2" || string(active) != string(newKey) {
		t.Fatalf("Active() = %q %q %v", id, active, err)
	}

	withKeyID := jwt.New(jwt.SigningMethodHS256)
	withKeyID.Header["kid"] = "v1"
	got, err := ring.VerificationKey(withKeyID)
	if err != nil || string(got.([]byte)) != string(oldKey) {
		t.Fatalf("VerificationKey(v1) = %v %v", got, err)
	}
	legacy := jwt.New(jwt.SigningMethodHS256)
	ring.now = func() time.Time { return now.Add(14 * time.Minute) }
	if _, err := ring.VerificationKey(legacy); err != nil {
		t.Fatalf("legacy token inside compatibility window: %v", err)
	}
	ring.now = func() time.Time { return now.Add(15 * time.Minute) }
	if _, err := ring.VerificationKey(legacy); err == nil {
		t.Fatal("legacy token at compatibility deadline must be rejected")
	}
}

func TestParseRejectsUnsafeConfigurations(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	key := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	tests := []string{
		fmt.Sprintf(`{"version":2,"active_kid":"v1","keys":{"v1":%q}}`, key),
		fmt.Sprintf(`{"version":1,"active_kid":"missing","keys":{"v1":%q}}`, key),
		fmt.Sprintf(`{"version":1,"active_kid":"v1","keys":{"v1":%q},"legacy_no_kid_key_id":"v1","legacy_no_kid_until":%q}`, key, now.Add(16*time.Minute).Format(time.RFC3339)),
		`{"version":1,"active_kid":"v1","keys":{"v1":"short"}}`,
		fmt.Sprintf(`{"version":1,"active_kid":"v1","keys":{"v1":%q},"unknown":true}`, key),
	}
	for _, raw := range tests {
		if _, err := Parse([]byte(raw), now); err == nil {
			t.Fatalf("Parse(%s) unexpectedly succeeded", raw)
		}
	}
}
