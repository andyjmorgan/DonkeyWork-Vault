package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDirAndPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-config-test")

	dir, err := Dir()
	if err != nil {
		t.Fatalf("Dir: %v", err)
	}
	if dir != filepath.Join("/tmp/xdg-config-test", dirName) {
		t.Fatalf("Dir = %q", dir)
	}

	p, err := Path()
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if p != filepath.Join(dir, fileName) {
		t.Fatalf("Path = %q", p)
	}
}

// With neither XDG_CONFIG_HOME nor HOME set, os.UserConfigDir fails, so Dir/Path —
// and Load/Save which call them — return that error.
func TestNoConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := Dir(); err == nil {
		t.Fatal("Dir: expected error with no config home")
	}
	if _, err := Path(); err == nil {
		t.Fatal("Path: expected error with no config home")
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load: expected error with no config home")
	}
	if err := Save(&Config{Hosts: map[string]Host{}}); err == nil {
		t.Fatal("Save: expected error with no config home")
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	c, err := Load()
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if c.Hosts == nil || len(c.Hosts) != 0 {
		t.Fatalf("want empty non-nil hosts, got %v", c.Hosts)
	}
}

func TestLoadMalformedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p, _ := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected parse error for malformed file")
	}
}

// A valid JSON file with a null "hosts" should normalize to an empty map.
func TestLoadNullHosts(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p, _ := Path()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"hosts":null}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Hosts == nil {
		t.Fatal("Hosts should be normalized to non-nil")
	}
}

// Save fails to MkdirAll when XDG_CONFIG_HOME is actually a regular file.
func TestSaveMkdirAllError(t *testing.T) {
	dir := t.TempDir()
	asFile := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(asFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", asFile) // dwvault dir would be under a file ⇒ MkdirAll errors
	if err := Save(&Config{Hosts: map[string]Host{}}); err == nil {
		t.Fatal("expected MkdirAll error")
	}
}

// Save fails to create the temp file when the target dir is read-only.
func TestSaveCreateTempError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only dir CreateTemp behavior differs on Windows")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	dwdir := filepath.Join(dir, dirName)
	if err := os.MkdirAll(dwdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dwdir, 0o500); err != nil { // read-only ⇒ CreateTemp fails
		t.Fatal(err)
	}
	defer os.Chmod(dwdir, 0o700)
	if err := Save(&Config{Hosts: map[string]Host{}}); err == nil {
		t.Fatal("expected CreateTemp error in read-only dir")
	}
}

// Load surfaces a read error that isn't "not exist" (e.g. path is a directory).
func TestLoadReadError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p, _ := Path()
	// Create hosts.json as a directory so os.ReadFile returns a non-IsNotExist error.
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected read error when hosts.json is a directory")
	}
}

// Save surfaces a write failure: an already-closed staging file makes f.Write fail.
func TestSaveWriteError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	old := createTemp
	createTemp = func(dir, pattern string) (*os.File, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		f.Close() // name persists for the defer Remove; Write now fails
		return f, nil
	}
	defer func() { createTemp = old }()
	if err := Save(&Config{Hosts: map[string]Host{}}); err == nil {
		t.Fatal("expected write error on a closed staging file")
	}
}

// Save must create the directory tree when it doesn't exist yet.
func TestSaveCreatesDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "nested", "deeper"))
	c := &Config{Hosts: map[string]Host{"h": {Account: "a", Store: StoreFile, Auth: AuthAPIKey}}}
	if err := Save(c); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.Hosts["h"].Account != "a" {
		t.Fatalf("round trip mismatch: %+v", got.Hosts)
	}
}
