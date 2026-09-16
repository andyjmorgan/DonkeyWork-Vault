package main

import (
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"donkeywork.dev/vault-cli/internal/config"
	"donkeywork.dev/vault-cli/internal/credstore"
)

func TestAuthLoginCredentialGuard(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		metadata, credential, corrupt, force bool
		want                                 string
	}{
		{name: "stale metadata", metadata: true, want: "mutually exclusive"},
		{name: "no stored login", want: "mutually exclusive"},
		{name: "credential without metadata", credential: true, want: "already logged in"},
		{name: "stored login", metadata: true, credential: true, want: "already logged in"},
		{name: "forced replacement", credential: true, force: true, want: "mutually exclusive"},
		{name: "corrupt credential", corrupt: true, want: "read credential"},
		{name: "forced corrupt replacement", corrupt: true, force: true, want: "mutually exclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetClientGlobals(t)
			addr = "https://vault.example"
			if tc.metadata {
				if err := config.Save(&config.Config{Hosts: map[string]config.Host{addr: {Store: config.StoreKeyring}}}); err != nil {
					t.Fatal(err)
				}
			}
			if tc.credential {
				if _, err := credstore.Store(addr, "dwv_test"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.corrupt {
				if err := keyring.Set("dwvault", addr, "{invalid"); err != nil {
					t.Fatal(err)
				}
			}
			cmd := cmdAuthLogin()
			// Conflicting flags stop before interactive/network work once the guard passes.
			args := []string{"--oauth", "--api-key"}
			if tc.force {
				args = append(args, "--force")
			}
			if err := cmd.ParseFlags(args); err != nil {
				t.Fatal(err)
			}
			err := cmd.RunE(cmd, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAuthStatusCredentialErrors(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		name, want := "missing", "not logged in"
		if corrupt {
			name, want = "corrupt", "read credential"
		}
		t.Run(name, func(t *testing.T) {
			resetClientGlobals(t)
			addr = "https://vault.example"
			if corrupt {
				if err := keyring.Set("dwvault", addr, "{invalid"); err != nil {
					t.Fatal(err)
				}
			}
			cmd := cmdAuthStatus()
			err := cmd.RunE(cmd, nil)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %q", err, want)
			}
		})
	}
}
