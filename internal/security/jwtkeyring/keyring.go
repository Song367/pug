package jwtkeyring

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	Version             = 1
	MinimumKeyBytes     = 32
	MaximumFileBytes    = 64 << 10
	MaximumLegacyWindow = 15 * time.Minute
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type fileConfig struct {
	Version            int               `json:"version"`
	ActiveKeyID        string            `json:"active_kid"`
	Keys               map[string]string `json:"keys"`
	LegacyNoKeyID      string            `json:"legacy_no_kid_key_id,omitempty"`
	LegacyNoKeyIDUntil string            `json:"legacy_no_kid_until,omitempty"`
}

type Keyring struct {
	activeKeyID string
	keys        map[string][]byte
	legacyKeyID string
	legacyUntil time.Time
	now         func() time.Time
}

func Load(path string, now time.Time) (*Keyring, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("PUG_JWT_KEYRING_FILE must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read PUG_JWT_KEYRING_FILE metadata: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("PUG_JWT_KEYRING_FILE must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("PUG_JWT_KEYRING_FILE must not be accessible by group or other users")
	}
	if info.Size() <= 0 || info.Size() > MaximumFileBytes {
		return nil, errors.New("PUG_JWT_KEYRING_FILE has an invalid size")
	}
	// #nosec G304 -- the operator-supplied absolute path is validated above and
	// the opened inode is compared with the lstat result before any data is read.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read PUG_JWT_KEYRING_FILE: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) {
		return nil, errors.New("PUG_JWT_KEYRING_FILE changed while it was being opened")
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaximumFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read PUG_JWT_KEYRING_FILE: %w", err)
	}
	if int64(len(raw)) != openedInfo.Size() {
		return nil, errors.New("PUG_JWT_KEYRING_FILE changed while it was being read")
	}
	return Parse(raw, now)
}

func Parse(raw []byte, now time.Time) (*Keyring, error) {
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(raw), MaximumFileBytes+1))
	decoder.DisallowUnknownFields()
	var cfg fileConfig
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode PUG_JWT_KEYRING_FILE: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("PUG_JWT_KEYRING_FILE must contain exactly one JSON object")
	}
	if cfg.Version != Version {
		return nil, fmt.Errorf("PUG_JWT_KEYRING_FILE version must be %d", Version)
	}
	if !keyIDPattern.MatchString(cfg.ActiveKeyID) {
		return nil, errors.New("PUG_JWT_KEYRING_FILE active_kid is invalid")
	}
	if len(cfg.Keys) == 0 || len(cfg.Keys) > 8 {
		return nil, errors.New("PUG_JWT_KEYRING_FILE must contain between one and eight keys")
	}
	keys := make(map[string][]byte, len(cfg.Keys))
	for id, encoded := range cfg.Keys {
		if !keyIDPattern.MatchString(id) {
			return nil, errors.New("PUG_JWT_KEYRING_FILE contains an invalid key id")
		}
		key, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(key) < MinimumKeyBytes {
			return nil, fmt.Errorf("PUG_JWT_KEYRING_FILE key %q must be base64url without padding and contain at least %d bytes", id, MinimumKeyBytes)
		}
		keys[id] = key
	}
	if _, ok := keys[cfg.ActiveKeyID]; !ok {
		return nil, errors.New("PUG_JWT_KEYRING_FILE active_kid does not name a configured key")
	}

	var legacyUntil time.Time
	if (cfg.LegacyNoKeyID == "" && cfg.LegacyNoKeyIDUntil != "") ||
		(cfg.LegacyNoKeyID != "" && cfg.LegacyNoKeyIDUntil == "") {
		return nil, errors.New("PUG_JWT_KEYRING_FILE legacy no-kid fields must be configured together")
	}
	if cfg.LegacyNoKeyID != "" {
		if _, ok := keys[cfg.LegacyNoKeyID]; !ok {
			return nil, errors.New("PUG_JWT_KEYRING_FILE legacy_no_kid_key_id does not name a configured key")
		}
		var err error
		legacyUntil, err = time.Parse(time.RFC3339, cfg.LegacyNoKeyIDUntil)
		if err != nil {
			return nil, errors.New("PUG_JWT_KEYRING_FILE legacy_no_kid_until must use RFC3339")
		}
		if legacyUntil.After(now.Add(MaximumLegacyWindow)) {
			return nil, errors.New("PUG_JWT_KEYRING_FILE legacy no-kid window must not exceed 15 minutes")
		}
	}

	return &Keyring{
		activeKeyID: cfg.ActiveKeyID,
		keys:        keys,
		legacyKeyID: cfg.LegacyNoKeyID,
		legacyUntil: legacyUntil,
		now:         time.Now,
	}, nil
}

func Single(key []byte) *Keyring {
	cloned := append([]byte(nil), key...)
	return &Keyring{
		activeKeyID: "legacy",
		keys:        map[string][]byte{"legacy": cloned},
		legacyKeyID: "legacy",
		legacyUntil: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		now:         time.Now,
	}
}

func (k *Keyring) Active() (string, []byte, error) {
	if k == nil {
		return "", nil, errors.New("JWT keyring is nil")
	}
	key, ok := k.keys[k.activeKeyID]
	if !ok || len(key) == 0 {
		return "", nil, errors.New("JWT active key is unavailable")
	}
	return k.activeKeyID, append([]byte(nil), key...), nil
}

func (k *Keyring) VerificationKey(token *jwt.Token) (any, error) {
	if k == nil || token == nil || token.Method.Alg() != jwt.SigningMethodHS256.Alg() {
		return nil, errors.New("unexpected JWT signing method")
	}
	rawKeyID, hasKeyID := token.Header["kid"]
	if hasKeyID {
		keyID, ok := rawKeyID.(string)
		if !ok || !keyIDPattern.MatchString(keyID) {
			return nil, errors.New("invalid JWT key id")
		}
		key, ok := k.keys[keyID]
		if !ok {
			return nil, errors.New("unknown JWT key id")
		}
		return key, nil
	}
	if k.legacyKeyID == "" || !k.now().Before(k.legacyUntil) {
		return nil, errors.New("JWT key id is required")
	}
	return k.keys[k.legacyKeyID], nil
}
