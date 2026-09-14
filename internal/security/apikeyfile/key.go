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

const maximumFileBytes = 128

var privateKeyPattern = regexp.MustCompile(`^prv_[0-9a-f]{32}$`)

// Load reads one role-specific private API key from a protected regular file.
func Load(path string) ([]byte, error) {
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
	key := strings.TrimSpace(string(raw))
	if !privateKeyPattern.MatchString(key) {
		return nil, errors.New("API key file must contain exactly one private key")
	}
	return []byte(key), nil
}

// Matches performs an exact constant-time comparison with this ingress role's key.
func Matches(expected []byte, candidate string) bool {
	return subtle.ConstantTimeCompare(expected, []byte(candidate)) == 1
}
