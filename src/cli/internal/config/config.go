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

const (
	StoreKeyring StoreKind = "keyring"
	StoreFile    StoreKind = "file"
)

// Host is the non-secret record for one vault host.
type Host struct {
	Account string    `json:"account,omitempty"` // identity the key belongs to (email/name/sub)
	Store   StoreKind `json:"store,omitempty"`   // where the secret is kept
}

// Config is the whole file.
type Config struct {
	Hosts map[string]Host `json:"hosts"`
}

const (
	dirName  = "dwvault"
	fileName = "hosts.json"
)

// Path returns the config file path ($XDG_CONFIG_HOME/dwvault/hosts.json).
func Path() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, dirName, fileName), nil
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
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
