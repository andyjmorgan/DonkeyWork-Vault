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

func TestResolveCredential_LegacyRawApiKey(t *testing.T) {
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	const host = "https://vault.example"

	if err := keyring.Set(service, host, "dwv_legacy"); err != nil {
		t.Fatalf("keyring set: %v", err)
	}
	c, src, err := ResolveCredential(host)
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}
	if src != SourceKeyring || c.Type != TypeAPIKey || c.Secret != "dwv_legacy" {
		t.Fatalf("got src=%s credential=%+v", src, c)
	}
}

func TestStoreResolveCredential_OAuthBlob(t *testing.T) {
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	const host = "https://vault.example"

	want := &Credential{
		Type:         TypeOAuth,
		Issuer:       "https://auth.example/realms/vault",
		ClientID:     "donkeywork-vault-cli",
		Scopes:       "openid profile email offline_access",
		AccessToken:  "access",
		RefreshToken: "refresh",
		ExpiresAt:    "2026-06-11T12:00:00Z",
		Account:      "user@example.com",
	}
	if store, err := StoreCredential(host, want); err != nil || store != "keyring" {
		t.Fatalf("StoreCredential: store=%v err=%v", store, err)
	}
	got, src, err := ResolveCredential(host)
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}
	if src != SourceKeyring || got.Type != TypeOAuth || got.RefreshToken != want.RefreshToken || got.ClientID != want.ClientID {
		t.Fatalf("got src=%s credential=%+v", src, got)
	}
	if _, _, err := Resolve(host); err == nil {
		t.Fatal("Resolve should reject an OAuth credential when an API key was requested")
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
