package apikeyfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndMatchProtectedPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "role.key")
	const key = "prv_0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !Matches(loaded, key) || Matches(loaded, "prv_abcdef0123456789abcdef0123456789") {
		t.Fatal("role key comparison did not remain exact")
	}
}

func TestLoadRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	worldReadable := filepath.Join(dir, "world.key")
	if err := os.WriteFile(worldReadable, []byte("prv_0123456789abcdef0123456789abcdef\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(worldReadable); err == nil {
		t.Fatal("world-readable API key file was accepted")
	}
	link := filepath.Join(dir, "link.key")
	if err := os.Symlink(worldReadable, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Fatal("symlink API key file was accepted")
	}
}
