package credstore

import (
	"os"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestResolvePrecedence(t *testing.T) {
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	const host = "https://vault.example"

	if _, _, err := Resolve(host); err != ErrNotFound {
		t.Fatalf("empty: want ErrNotFound, got %v", err)
	}

	if store, err := Store(host, "dwv_keyring"); err != nil || store != "keyring" {
		t.Fatalf("Store: store=%v err=%v", store, err)
	}
	if k, src, err := Resolve(host); err != nil || k != "dwv_keyring" || src != SourceKeyring {
		t.Fatalf("Resolve keyring: k=%q src=%q err=%v", k, src, err)
	}

	// env wins over a stored key, and is never persisted
	t.Setenv("VAULT_API_KEY", "dwv_env")
	if k, src, err := Resolve(host); err != nil || k != "dwv_env" || src != SourceEnv {
		t.Fatalf("Resolve env: k=%q src=%q err=%v", k, src, err)
	}
	t.Setenv("VAULT_API_KEY", "")

	if err := Delete(host); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := Resolve(host); err != ErrNotFound {
		t.Fatalf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestFileFallback(t *testing.T) {
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	const host = "https://vault.example"

	if err := fileSet(host, "dwv_file"); err != nil {
		t.Fatalf("fileSet: %v", err)
	}
	p, _ := filePath()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %#o, want 0600", perm)
	}
	if k, src, err := Resolve(host); err != nil || k != "dwv_file" || src != SourceFile {
		t.Fatalf("Resolve file: k=%q src=%q err=%v", k, src, err)
	}

	// loosened perms ⇒ refuse to read
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, _, err := Resolve(host); err == nil {
		t.Fatal("expected insecure-perms error, got nil")
	}
}
