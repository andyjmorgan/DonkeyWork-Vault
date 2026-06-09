package config

import (
	"os"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	c, err := Load()
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if len(c.Hosts) != 0 {
		t.Fatalf("want empty, got %v", c.Hosts)
	}

	c.Hosts["https://vault.example"] = Host{Account: "a@b.c", Store: StoreKeyring}
	if err := Save(c); err != nil {
		t.Fatalf("Save: %v", err)
	}

	p, _ := Path()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("perm = %#o, want 0600", perm)
	}

	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	h, ok := got.Hosts["https://vault.example"]
	if !ok || h.Account != "a@b.c" || h.Store != StoreKeyring {
		t.Fatalf("round trip mismatch: %+v", got.Hosts)
	}
}
