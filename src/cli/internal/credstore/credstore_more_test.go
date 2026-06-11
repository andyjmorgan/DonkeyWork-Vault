package credstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/zalando/go-keyring"
)

// storeRaw falls back to the 0600 file when the keyring is unavailable, and
// StoreCredential reports config.StoreFile for that path.
func TestStoreCredential_FileFallback(t *testing.T) {
	keyring.MockInitWithError(errors.New("no keyring here"))
	defer keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	const host = "https://vault.example"

	store, err := StoreCredential(host, &Credential{Type: TypeAPIKey, Secret: "s"})
	if err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}
	if store != "file" {
		t.Fatalf("store = %q, want file", store)
	}
	// Now resolvable from the file.
	c, src, err := ResolveCredential(host)
	if err != nil || src != SourceFile || c.Secret != "s" {
		t.Fatalf("Resolve file: c=%+v src=%q err=%v", c, src, err)
	}
}

// When the keyring is down AND the file can't be written, storeRaw surfaces the failure.
func TestStoreCredential_FileFallbackFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based unwritable dir not meaningful on Windows")
	}
	keyring.MockInitWithError(errors.New("no keyring"))
	defer keyring.MockInit()
	t.Setenv("VAULT_API_KEY", "")

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	// Pre-create the dwvault dir and make it unwritable so MkdirAll succeeds (it
	// exists) but CreateTemp inside it fails.
	dwdir := filepath.Join(dir, "dwvault")
	if err := os.MkdirAll(dwdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dwdir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dwdir, 0o700)

	_, err := StoreCredential("https://vault.example", &Credential{Type: TypeAPIKey, Secret: "s"})
	if err == nil {
		t.Fatal("expected fallback write failure")
	}
}

func TestParseCredential(t *testing.T) {
	// empty → ErrNotFound
	if _, err := parseCredential(""); err != ErrNotFound {
		t.Fatalf("empty: want ErrNotFound, got %v", err)
	}
	// non-brace → legacy raw api key
	c, err := parseCredential("dwv_raw")
	if err != nil || c.Type != TypeAPIKey || c.Secret != "dwv_raw" {
		t.Fatalf("legacy: c=%+v err=%v", c, err)
	}
	// valid JSON blob
	c, err = parseCredential(`{"type":"oauth","refreshToken":"r"}`)
	if err != nil || c.Type != TypeOAuth || c.RefreshToken != "r" {
		t.Fatalf("blob: c=%+v err=%v", c, err)
	}
	// malformed JSON
	if _, err := parseCredential(`{bad`); err == nil {
		t.Fatal("malformed: expected json error")
	}
	// JSON missing type
	if _, err := parseCredential(`{"secret":"x"}`); err == nil {
		t.Fatal("missing type: expected error")
	}
}

// With no config home, filePath fails and the file-fallback callers propagate it.
func TestNoConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := filePath(); err == nil {
		t.Fatal("filePath: expected error with no config home")
	}
	if _, _, err := fileLoad(); err == nil {
		t.Fatal("fileLoad: expected error with no config home")
	}
	if _, _, err := fileGet("h"); err == nil {
		t.Fatal("fileGet: expected error with no config home")
	}
	if err := fileSet("h", "v"); err == nil {
		t.Fatal("fileSet: expected error with no config home")
	}
	if err := fileDelete("h"); err == nil {
		t.Fatal("fileDelete: expected error with no config home")
	}
}

func TestFilePath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg-cred-test")
	p, err := filePath()
	if err != nil {
		t.Fatalf("filePath: %v", err)
	}
	want := filepath.Join("/tmp/xdg-cred-test", "dwvault", credFile)
	if p != want {
		t.Fatalf("filePath = %q, want %q", p, want)
	}
}

func TestFileLoad_MissingIsEmpty(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	m, _, err := fileLoad()
	if err != nil {
		t.Fatalf("fileLoad missing: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("want empty map, got %v", m)
	}
}

func TestFileLoad_Malformed(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := filePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fileLoad(); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestFileLoad_InsecurePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm bits not meaningful on Windows")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := filePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := fileLoad()
	if err == nil {
		t.Fatal("expected insecure-perms refusal")
	}
}

func TestFileSet_PreservesExisting(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := fileSet("h1", "a"); err != nil {
		t.Fatalf("fileSet h1: %v", err)
	}
	if err := fileSet("h2", "b"); err != nil {
		t.Fatalf("fileSet h2: %v", err)
	}
	m, _, err := fileLoad()
	if err != nil {
		t.Fatalf("fileLoad: %v", err)
	}
	if m["h1"] != "a" || m["h2"] != "b" {
		t.Fatalf("got %v", m)
	}
}

// fileDelete on a nonexistent host is a no-op.
func TestFileDelete_Nonexistent(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := fileDelete("nope"); err != nil {
		t.Fatalf("fileDelete missing host: %v", err)
	}
	// also fine when the file doesn't exist at all
	if err := fileDelete("still-nope"); err != nil {
		t.Fatalf("fileDelete missing file: %v", err)
	}
}

// Deleting the last entry removes the whole file.
func TestFileDelete_LastEntryRemovesFile(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := fileSet("only", "x"); err != nil {
		t.Fatal(err)
	}
	if err := fileDelete("only"); err != nil {
		t.Fatalf("fileDelete: %v", err)
	}
	p, _ := filePath()
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("file should be removed, stat err = %v", err)
	}
}

// Deleting one of several rewrites the file with the rest intact.
func TestFileDelete_KeepsOthers(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := fileSet("h1", "a"); err != nil {
		t.Fatal(err)
	}
	if err := fileSet("h2", "b"); err != nil {
		t.Fatal(err)
	}
	if err := fileDelete("h1"); err != nil {
		t.Fatalf("fileDelete: %v", err)
	}
	m, _, err := fileLoad()
	if err != nil {
		t.Fatalf("fileLoad: %v", err)
	}
	if _, ok := m["h1"]; ok {
		t.Fatal("h1 should be gone")
	}
	if m["h2"] != "b" {
		t.Fatalf("h2 lost: %v", m)
	}
}

// fileDelete surfaces an os.Remove failure when deleting the last entry from a file in
// a read-only directory (the dir is readable so fileLoad succeeds, but unlink is denied).
func TestFileDelete_RemoveError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dir-perm unlink semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := fileSet("only", "x"); err != nil {
		t.Fatal(err)
	}
	p, _ := filePath()
	d := filepath.Dir(p)
	if err := os.Chmod(d, 0o500); err != nil { // read+exec but not write ⇒ unlink denied
		t.Fatal(err)
	}
	defer os.Chmod(d, 0o700)
	if err := fileDelete("only"); err == nil {
		t.Fatal("expected os.Remove error in read-only dir")
	}
}

// Delete() clears both stores (keyring + file).
func TestDelete_BothStores(t *testing.T) {
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	const host = "https://vault.example"

	if err := keyring.Set(service, host, "k"); err != nil {
		t.Fatal(err)
	}
	if err := fileSet(host, "f"); err != nil {
		t.Fatal(err)
	}
	if err := Delete(host); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := keyring.Get(service, host); err == nil {
		t.Fatal("keyring entry should be gone")
	}
	m, _, _ := fileLoad()
	if _, ok := m[host]; ok {
		t.Fatal("file entry should be gone")
	}
}

func TestWriteFileAtomic_BadDir(t *testing.T) {
	// Parent dir doesn't exist → CreateTemp fails.
	p := filepath.Join(t.TempDir(), "no-such-subdir", "f.json")
	if err := writeFileAtomic(p, []byte("x")); err == nil {
		t.Fatal("expected error writing into nonexistent dir")
	}
}

func TestCheckPerms_Missing(t *testing.T) {
	// Nonexistent path is allowed (nothing to refuse yet).
	if err := checkPerms(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatalf("checkPerms missing: %v", err)
	}
}

func TestCheckPerms_Secure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm bits not meaningful on Windows")
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkPerms(p); err != nil {
		t.Fatalf("checkPerms 0600: %v", err)
	}
}

func TestCheckPerms_Insecure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm bits not meaningful on Windows")
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkPerms(p); err == nil {
		t.Fatal("expected insecure-perms refusal")
	}
}

// fileLoad surfaces a non-IsNotExist read error (path is a directory).
func TestFileLoad_ReadError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := filePath()
	if err := os.MkdirAll(p, 0o700); err != nil { // credentials.json is a dir
		t.Fatal(err)
	}
	if _, _, err := fileLoad(); err == nil {
		t.Fatal("expected read error when credentials.json is a directory")
	}
}

// fileSet fails at MkdirAll when the config home sits under a read-only parent: the
// (absent) credentials file loads as empty, but creating the dwvault dir is denied.
func TestFileSet_MkdirAllError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("dir-perm semantics differ on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permission")
	}
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.MkdirAll(ro, 0o500); err != nil { // read+exec, not writable
		t.Fatal(err)
	}
	defer os.Chmod(ro, 0o700)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(ro, "sub")) // can't create "sub" under ro
	if err := fileSet("h", "v"); err == nil {
		t.Fatal("expected MkdirAll error")
	}
}

// fileDelete propagates a fileLoad error (insecure perms) rather than masking it.
func TestFileDelete_LoadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm bits not meaningful on Windows")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := filePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{"h":"v"}`), 0o644); err != nil { // insecure
		t.Fatal(err)
	}
	if err := fileDelete("h"); err == nil {
		t.Fatal("expected load error from insecure file")
	}
}

// checkPerms surfaces a Stat error that isn't IsNotExist (parent is unreadable).
func TestCheckPerms_StatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm bits not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission checks")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(sub, "f")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sub, 0o000); err != nil { // no access ⇒ Stat fails with EACCES
		t.Fatal(err)
	}
	defer os.Chmod(sub, 0o700)
	err := checkPerms(target)
	if err == nil {
		t.Fatal("expected stat error on inaccessible parent")
	}
}

// StoreCredential marshalling path with the keyring available returns StoreKeyring.
func TestStoreCredential_Keyring(t *testing.T) {
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	store, err := StoreCredential("https://vault.example", &Credential{Type: TypeAPIKey, Secret: "s"})
	if err != nil || store != "keyring" {
		t.Fatalf("store=%q err=%v", store, err)
	}
}

// fileGet surfaces a load error (e.g. insecure perms) rather than masking it.
func TestFileGet_Error(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm bits not meaningful on Windows")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := filePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fileGet("h"); err == nil {
		t.Fatal("expected error from insecure file")
	}
}
