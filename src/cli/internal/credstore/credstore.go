// Package credstore resolves and persists the dwvault credential for a host.
//
// Resolution precedence (highest first):
//  1. VAULT_API_KEY environment variable — ephemeral, NEVER persisted.
//  2. OS keyring — macOS Keychain, Linux Secret Service, Windows Credential Manager.
//  3. A 0600 fallback credentials file (used only when no keyring is available).
//
// `auth login` writes the OAuth/API-key credential blob to the keyring (or the file
// fallback); the env variable is read-only and is never written to either store.
package credstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/zalando/go-keyring"

	"donkeywork.dev/vault-cli/internal/config"
)

const (
	service  = "dwvault"
	envVar   = "VAULT_API_KEY"
	credFile = "credentials.json"
)

// Source identifies where a resolved key came from.
type Source string

const (
	SourceEnv     Source = "env"
	SourceKeyring Source = "keyring"
	SourceFile    Source = "file"
)

// ErrNotFound is returned when no credential exists for the host.
var ErrNotFound = errors.New("no stored credential for host")

type CredentialType string

const (
	TypeAPIKey CredentialType = "api_key"
	TypeOAuth  CredentialType = "oauth"
)

type Credential struct {
	Type             CredentialType `json:"type"`
	Secret           string         `json:"secret,omitempty"`
	Issuer           string         `json:"issuer,omitempty"`
	ClientID         string         `json:"clientId,omitempty"`
	Scopes           string         `json:"scopes,omitempty"`
	AccessToken      string         `json:"accessToken,omitempty"`
	RefreshToken     string         `json:"refreshToken,omitempty"`
	ExpiresAt        string         `json:"expiresAt,omitempty"`
	RefreshExpiresAt string         `json:"refreshExpiresAt,omitempty"`
	Account          string         `json:"account,omitempty"`
}

// Resolve returns the API key for host and where it came from, honouring precedence.
func Resolve(host string) (key string, src Source, err error) {
	c, src, err := ResolveCredential(host)
	if err != nil {
		return "", "", err
	}
	if c.Type != TypeAPIKey {
		return "", "", fmt.Errorf("stored credential for %s is %s, not api_key", host, c.Type)
	}
	return c.Secret, src, nil
}

func ResolveCredential(host string) (*Credential, Source, error) {
	if v := os.Getenv(envVar); v != "" {
		return &Credential{Type: TypeAPIKey, Secret: v}, SourceEnv, nil
	}
	if v, kerr := keyring.Get(service, host); kerr == nil && v != "" {
		c, err := parseCredential(v)
		return c, SourceKeyring, err
	}
	v, ok, ferr := fileGet(host)
	if ferr != nil {
		return nil, "", ferr
	}
	if ok {
		c, err := parseCredential(v)
		return c, SourceFile, err
	}
	return nil, "", ErrNotFound
}

// Store persists key for host. It prefers the OS keyring; if that's unavailable it
// falls back to a 0600 file. The chosen store is returned so callers can record it.
func Store(host, key string) (config.StoreKind, error) {
	return StoreCredential(host, &Credential{Type: TypeAPIKey, Secret: key})
}

func StoreCredential(host string, c *Credential) (config.StoreKind, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return storeRaw(host, string(b))
}

func storeRaw(host, key string) (config.StoreKind, error) {
	if err := keyring.Set(service, host, key); err == nil {
		_ = fileDelete(host) // drop any stale file copy once the keyring holds it
		return config.StoreKeyring, nil
	} else {
		// Surface the fallback rather than silently writing the secret to disk.
		fmt.Fprintf(os.Stderr, "dwvault: OS keyring unavailable (%v); storing secret in 0600 file fallback\n", err)
	}
	if err := fileSet(host, key); err != nil {
		return "", fmt.Errorf("no OS keyring available and file fallback failed: %w", err)
	}
	return config.StoreFile, nil
}

func parseCredential(raw string) (*Credential, error) {
	if raw == "" {
		return nil, ErrNotFound
	}
	if raw[0] != '{' {
		return &Credential{Type: TypeAPIKey, Secret: raw}, nil
	}
	var c Credential
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, err
	}
	if c.Type == "" {
		return nil, fmt.Errorf("credential missing type")
	}
	return &c, nil
}

// Delete removes any stored credential for host from both stores.
func Delete(host string) error {
	_ = keyring.Delete(service, host)
	return fileDelete(host)
}

// --- 0600 file fallback ---

func filePath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "dwvault", credFile), nil
}

func fileLoad() (map[string]string, string, error) {
	p, err := filePath()
	if err != nil {
		return nil, "", err
	}
	// Refuse a group/other-readable secrets file before reading, writing, or deleting.
	if err := checkPerms(p); err != nil {
		return nil, p, err
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return map[string]string{}, p, nil
	}
	if err != nil {
		return nil, p, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, p, fmt.Errorf("parse %s: %w", p, err)
	}
	return m, p, nil
}

func fileGet(host string) (string, bool, error) {
	m, _, err := fileLoad() // fileLoad already enforces file permissions
	if err != nil {
		return "", false, err
	}
	v, ok := m[host]
	return v, ok, nil
}

func fileSet(host, key string) error {
	m, p, err := fileLoad()
	if err != nil {
		return err
	}
	m[host] = key
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return writeFileAtomic(p, b)
}

// writeFileAtomic writes b to a unique 0600 temp file in p's directory, then renames it
// over p. The unique temp name avoids a fixed-suffix race between concurrent invocations.
func writeFileAtomic(p string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), ".tmp-*") // CreateTemp makes the file 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename succeeds
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func fileDelete(host string) error {
	m, p, err := fileLoad()
	if err != nil {
		return err
	}
	if _, ok := m[host]; !ok {
		return nil
	}
	delete(m, host)
	if len(m) == 0 {
		if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
			return rerr
		}
		return nil
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(p, b, 0o600)
}

// checkPerms refuses to read a secrets file that group/other can access.
func checkPerms(p string) error {
	if runtime.GOOS == "windows" {
		return nil // POSIX perm bits aren't meaningful on Windows
	}
	fi, err := os.Stat(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("insecure permissions %#o on %s (want 0600); refusing to read", fi.Mode().Perm(), p)
	}
	return nil
}
