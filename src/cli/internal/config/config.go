// Package config manages the dwvault CLI's host-keyed configuration file.
//
// The file holds only NON-SECRET metadata: which hosts you've logged into, the
// account a host's key belongs to, and where that host's secret is stored. The
// secret itself lives in the OS keyring or a separate 0600 credentials file — see
// package credstore. The file is $XDG_CONFIG_HOME/dwvault/hosts.json (0600).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// StoreKind records where a host's secret is kept.
type StoreKind string
type AuthType string

const (
	StoreKeyring StoreKind = "keyring"
	StoreFile    StoreKind = "file"

	AuthAPIKey AuthType = "api_key"
	AuthOAuth  AuthType = "oauth"
)

// Host is the non-secret record for one vault host.
type Host struct {
	Account string    `json:"account,omitempty"` // identity the key belongs to (email/name/sub)
	Store   StoreKind `json:"store,omitempty"`   // where the secret is kept
	Auth    AuthType  `json:"auth,omitempty"`    // api_key or oauth
}

// Config is the whole file.
type Config struct {
	Hosts map[string]Host `json:"hosts"`
}

const (
	dirName  = "dwvault"
	fileName = "hosts.json"
)

// createTemp is os.CreateTemp, indirected only so tests can exercise Save's atomic-write
// failure path (e.g. by handing back an already-closed file). Production never reassigns it.
var createTemp = os.CreateTemp

// Dir returns the dwvault config directory ($XDG_CONFIG_HOME/dwvault), the home for
// hosts.json and other non-secret state files (e.g. the update-check cache).
func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, dirName), nil
}

// Path returns the config file path ($XDG_CONFIG_HOME/dwvault/hosts.json).
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, fileName), nil
}

// Load reads the config, returning an empty (non-nil) Config if the file is absent.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return &Config{Hosts: map[string]Host{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if c.Hosts == nil {
		c.Hosts = map[string]Host{}
	}
	return &c, nil
}

// Save writes the config atomically with 0600 perms (0700 dir).
func Save(c *Config) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err //coverage:ignore Config always marshals
	}
	// Unique temp file (0600) in the same dir, renamed over the target — avoids a
	// fixed-suffix race between concurrent invocations.
	f, err := createTemp(filepath.Dir(p), ".tmp-*")
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
		return err //coverage:ignore Close error after a successful write not reproducible
	}
	return os.Rename(tmp, p)
}
