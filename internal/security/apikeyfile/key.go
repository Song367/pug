package apikeyfile

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	maximumFileBytes = 256
	maximumKeys      = 2
)

var privateKeyPattern = regexp.MustCompile(`^prv_[0-9a-f]{32}$`)

// Keyring contains the active role-specific private API key and, during a
// bounded rotation overlap, its replacement. It never contains keys for a
// different ingress role.
type Keyring [][]byte

// Load reads one or two role-specific private API keys from a protected file.
func Load(path string) (Keyring, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("API key file must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read API key file metadata: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("API key file must be a protected regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > maximumFileBytes {
		return nil, errors.New("API key file has an invalid size")
	}
	// #nosec G304 -- the absolute operator path and opened inode are validated.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open API key file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("API key file changed while it was being opened")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumFileBytes+1))
	if err != nil || int64(len(raw)) != opened.Size() {
		return nil, errors.New("API key file changed while it was being read")
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 || len(lines) > maximumKeys {
		return nil, errors.New("API key file must contain one or two private keys")
	}
	keyring := make(Keyring, 0, len(lines))
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		key := strings.TrimSpace(line)
		if !privateKeyPattern.MatchString(key) {
			return nil, errors.New("API key file contains an invalid private key")
		}
		if _, exists := seen[key]; exists {
			return nil, errors.New("API key file contains duplicate private keys")
		}
		seen[key] = struct{}{}
		keyring = append(keyring, []byte(key))
	}
	return keyring, nil
}

// Matches compares against every key so the matching position is not exposed.
func Matches(expected Keyring, candidate string) bool {
	matched := 0
	for _, key := range expected {
		matched |= subtle.ConstantTimeCompare(key, []byte(candidate))
	}
	return matched == 1
}
