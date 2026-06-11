package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRepo(t *testing.T) {
	t.Setenv("DWVAULT_REPO", "")
	if Repo() != defaultRepo {
		t.Fatalf("default Repo = %q", Repo())
	}
	t.Setenv("DWVAULT_REPO", "me/fork")
	if Repo() != "me/fork" {
		t.Fatalf("override Repo = %q", Repo())
	}
}

func TestLatest_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/repos/me/fork/releases/latest") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("accept = %q", r.Header.Get("Accept"))
		}
		_ = json.NewEncoder(w).Encode(Release{TagName: "v1.2.3"})
	}))
	defer srv.Close()
	t.Setenv("DWVAULT_REPO", "me/fork")
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()

	rel, err := Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if rel.TagName != "v1.2.3" {
		t.Fatalf("got %+v", rel)
	}
}

func TestLatest_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()
	if _, err := Latest(context.Background()); err == nil {
		t.Fatal("expected non-200 error")
	}
}

func TestLatest_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()
	if _, err := Latest(context.Background()); err == nil {
		t.Fatal("expected json error")
	}
}

func TestLatest_EmptyTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Release{})
	}))
	defer srv.Close()
	old := githubAPIBase
	githubAPIBase = srv.URL
	defer func() { githubAPIBase = old }()
	_, err := Latest(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty tag") {
		t.Fatalf("want empty tag error, got %v", err)
	}
}

func TestLatest_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close()
	old := githubAPIBase
	githubAPIBase = addr
	defer func() { githubAPIBase = old }()
	if _, err := Latest(context.Background()); err == nil {
		t.Fatal("expected network error")
	}
}

func TestLatest_BadRequest(t *testing.T) {
	old := githubAPIBase
	githubAPIBase = "http://%zz"
	defer func() { githubAPIBase = old }()
	if _, err := Latest(context.Background()); err == nil {
		t.Fatal("expected request-build error")
	}
}

func TestAssetURL(t *testing.T) {
	rel := &Release{}
	rel.Assets = append(rel.Assets, struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}{Name: "a", BrowserDownloadURL: "https://x/a"})

	if got := assetURL(rel, "a"); got != "https://x/a" {
		t.Fatalf("assetURL = %q", got)
	}
	if got := assetURL(rel, "missing"); got != "" {
		t.Fatalf("assetURL missing = %q, want empty", got)
	}
}

// asset builder helper
func relWith(t *testing.T, base string, names ...string) *Release {
	t.Helper()
	rel := &Release{TagName: "v9.9.9"}
	for _, n := range names {
		rel.Assets = append(rel.Assets, struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}{Name: n, BrowserDownloadURL: base + "/" + n})
	}
	return rel
}

func TestDownload_Success(t *testing.T) {
	bin := []byte("the-binary-bytes")
	sum := sha256.Sum256(bin)
	manifest := hex.EncodeToString(sum[:]) + "  " + AssetName() + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, AssetName()):
			_, _ = w.Write(bin)
		case strings.HasSuffix(r.URL.Path, sha256SumsAsset):
			_, _ = w.Write([]byte(manifest))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	rel := relWith(t, srv.URL, AssetName(), sha256SumsAsset)
	got, err := Download(context.Background(), rel)
	if err != nil {
		t.Fatalf("Download: %v", err)
	}
	if string(got) != string(bin) {
		t.Fatalf("got %q", got)
	}
}

func TestDownload_ChecksumMismatch(t *testing.T) {
	bin := []byte("real")
	wrong := sha256.Sum256([]byte("different"))
	manifest := hex.EncodeToString(wrong[:]) + "  " + AssetName() + "\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, AssetName()):
			_, _ = w.Write(bin)
		case strings.HasSuffix(r.URL.Path, sha256SumsAsset):
			_, _ = w.Write([]byte(manifest))
		}
	}))
	defer srv.Close()

	rel := relWith(t, srv.URL, AssetName(), sha256SumsAsset)
	_, err := Download(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
}

func TestDownload_MissingBinaryAsset(t *testing.T) {
	rel := relWith(t, "https://x", sha256SumsAsset) // no platform binary
	_, err := Download(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "no asset") {
		t.Fatalf("want no-asset error, got %v", err)
	}
}

func TestDownload_MissingManifest(t *testing.T) {
	rel := relWith(t, "https://x", AssetName()) // no SHA256SUMS
	_, err := Download(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("want manifest error, got %v", err)
	}
}

func TestDownload_ManifestFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError) // both assets fail
	}))
	defer srv.Close()
	rel := relWith(t, srv.URL, AssetName(), sha256SumsAsset)
	_, err := Download(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "fetch SHA256SUMS") {
		t.Fatalf("want manifest fetch error, got %v", err)
	}
}

func TestDownload_AssetNotInManifest(t *testing.T) {
	// manifest lists some other file, not our platform asset
	manifest := strings.Repeat("a", 64) + "  some-other-file\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, sha256SumsAsset) {
			_, _ = w.Write([]byte(manifest))
			return
		}
		_, _ = w.Write([]byte("bin"))
	}))
	defer srv.Close()
	rel := relWith(t, srv.URL, AssetName(), sha256SumsAsset)
	_, err := Download(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "not listed") {
		t.Fatalf("want not-listed error, got %v", err)
	}
}

func TestDownload_BinaryFetchError(t *testing.T) {
	bin := []byte("bin")
	sum := sha256.Sum256(bin)
	manifest := hex.EncodeToString(sum[:]) + "  " + AssetName() + "\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, sha256SumsAsset) {
			_, _ = w.Write([]byte(manifest))
			return
		}
		w.WriteHeader(http.StatusNotFound) // binary asset 404s
	}))
	defer srv.Close()
	rel := relWith(t, srv.URL, AssetName(), sha256SumsAsset)
	_, err := Download(context.Background(), rel)
	if err == nil || !strings.Contains(err.Error(), "fetch "+AssetName()) {
		t.Fatalf("want binary fetch error, got %v", err)
	}
}

func TestFetch_BadURL(t *testing.T) {
	if _, err := fetch(context.Background(), "http://%zz"); err == nil {
		t.Fatal("expected request-build error")
	}
}

func TestFetch_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	addr := srv.URL
	srv.Close() // nothing listening ⇒ Do() errors
	if _, err := fetch(context.Background(), addr); err == nil {
		t.Fatal("expected network error")
	}
}

// parse rejects a negative component (the `n < 0` branch).
func TestParse_NegativeComponent(t *testing.T) {
	// Routed through Compare: a negative-component version is unparseable, so it sorts
	// below a valid one.
	if got := Compare("v-1.0.0", "v0.0.0"); got != -1 {
		t.Fatalf("Compare(v-1.0.0, v0.0.0) = %d, want -1", got)
	}
}

// sumFor surfaces a scanner error: a single line longer than bufio's max token size
// (64KB) with no newline makes Scan() fail with bufio.ErrTooLong.
func TestSumFor_ScannerError(t *testing.T) {
	huge := make([]byte, 70*1024) // > bufio.MaxScanTokenSize, no '\n'
	for i := range huge {
		huge[i] = 'a'
	}
	if _, err := sumFor(huge, "dwvault-linux-amd64"); err == nil {
		t.Fatal("expected scanner error for oversized line")
	}
}

// sumFor skips malformed (non-2-field) lines before finding the match.
func TestSumFor_SkipsMalformedLines(t *testing.T) {
	good := sum256("x")
	manifest := []byte(
		"# a comment line with many fields here\n" +
			"\n" + // blank line
			good + "  dwvault-linux-amd64\n",
	)
	got, err := sumFor(manifest, "dwvault-linux-amd64")
	if err != nil {
		t.Fatalf("sumFor: %v", err)
	}
	if got != good {
		t.Fatalf("got %q", got)
	}
}

func TestApply_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dwvault")
	if err := os.WriteFile(target, []byte("OLD"), 0o755); err != nil { //nolint:gosec // G306: test fixture binary must be executable (0o755)
		t.Fatal(err)
	}
	old := executable
	executable = func() (string, error) { return target, nil }
	defer func() { executable = old }()

	path, err := Apply([]byte("NEWBINARY"))
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if path != target {
		t.Fatalf("path = %q, want %q", path, target)
	}
	got, _ := os.ReadFile(target) //nolint:gosec // G304: path is a test-controlled temp file, not attacker-supplied
	if string(got) != "NEWBINARY" {
		t.Fatalf("contents = %q", got)
	}
	fi, _ := os.Stat(target)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("perm = %#o", fi.Mode().Perm())
	}
}

func TestApply_ExecutableError(t *testing.T) {
	old := executable
	executable = func() (string, error) { return "", os.ErrPermission }
	defer func() { executable = old }()
	if _, err := Apply([]byte("x")); err == nil {
		t.Fatal("expected executable() error")
	}
}

func TestApply_EvalSymlinksError(t *testing.T) {
	old := executable
	// Point at a nonexistent path so EvalSymlinks fails.
	executable = func() (string, error) { return filepath.Join(t.TempDir(), "does-not-exist"), nil }
	defer func() { executable = old }()
	if _, err := Apply([]byte("x")); err == nil {
		t.Fatal("expected EvalSymlinks error")
	}
}

func TestApply_StageError(t *testing.T) {
	// Resolve to a path inside a directory that doesn't exist → CreateTemp fails.
	dir := t.TempDir()
	realFile := filepath.Join(dir, "exe")
	if err := os.WriteFile(realFile, []byte("x"), 0o755); err != nil { //nolint:gosec // G306: test fixture binary must be executable (0o755)
		t.Fatal(err)
	}
	old := executable
	executable = func() (string, error) { return realFile, nil }
	defer func() { executable = old }()
	// Make the dir unwritable so CreateTemp in it fails.
	if err := os.Chmod(dir, 0o500); err != nil { //nolint:gosec // G302: test deliberately makes the dir read-only
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }() //nolint:gosec // G302: restoring dir perms in test cleanup; directories need the exec bit
	if _, err := Apply([]byte("x")); err == nil {
		t.Fatal("expected stage error in unwritable dir")
	}
}

// With no config home, statePath fails and Load/SaveState propagate it.
func TestNoConfigHome(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := statePath(); err == nil {
		t.Fatal("statePath: expected error with no config home")
	}
	if _, err := LoadState(); err == nil {
		t.Fatal("LoadState: expected error with no config home")
	}
	if err := SaveState(State{}); err == nil {
		t.Fatal("SaveState: expected error with no config home")
	}
}

// Apply's rename fails when the resolved "executable" is actually a (non-empty)
// directory: staging in its parent succeeds, but renaming a file over a populated dir
// is rejected by the OS.
func TestApply_RenameError(t *testing.T) {
	dir := t.TempDir()
	exeDir := filepath.Join(dir, "exe-as-dir")
	if err := os.MkdirAll(exeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	// Populate it so the rename can't succeed as an empty-dir replacement.
	if err := os.WriteFile(filepath.Join(exeDir, "child"), []byte("x"), 0o644); err != nil { //nolint:gosec // G306: test fixture file, perms are not security-sensitive
		t.Fatal(err)
	}
	old := executable
	executable = func() (string, error) { return exeDir, nil }
	defer func() { executable = old }()
	if _, err := Apply([]byte("new")); err == nil {
		t.Fatal("expected rename error replacing a populated directory")
	}
}

// closedTempFile returns a real (named) temp file that's already closed, so the caller's
// next Write fails with os.ErrClosed — exercising the atomic-write failure branch.
func closedTempFile(dir, pattern string) (*os.File, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	_ = f.Close() // name still exists (defer Remove works); Write/Sync now fail
	return f, nil
}

func TestApply_WriteError(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "exe")
	if err := os.WriteFile(target, []byte("OLD"), 0o755); err != nil { //nolint:gosec // G306: test fixture binary must be executable (0o755)
		t.Fatal(err)
	}
	oldExe, oldCT := executable, createTemp
	executable = func() (string, error) { return target, nil }
	createTemp = closedTempFile
	defer func() { executable, createTemp = oldExe, oldCT }()

	if _, err := Apply([]byte("new")); err == nil {
		t.Fatal("expected write error on a closed staging file")
	}
	// Original must be untouched.
	if got, _ := os.ReadFile(target); string(got) != "OLD" { //nolint:gosec // G304: path is a test-controlled temp file, not attacker-supplied
		t.Fatalf("target mutated: %q", got)
	}
}

func TestSaveState_WriteError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	oldCT := createTemp
	createTemp = closedTempFile
	defer func() { createTemp = oldCT }()
	if err := SaveState(State{LatestVersion: "v1"}); err == nil {
		t.Fatal("expected write error on a closed temp file")
	}
}

func TestStatePathAndState(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)

	// Absent file → zero State, no error.
	s, err := LoadState()
	if err != nil {
		t.Fatalf("LoadState empty: %v", err)
	}
	if !s.CheckedAt.IsZero() || s.LatestVersion != "" {
		t.Fatalf("want zero state, got %+v", s)
	}

	want := State{CheckedAt: time.Now().UTC().Truncate(time.Second), LatestVersion: "v1.2.3"}
	if err := SaveState(want); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	p, err := statePath()
	if err != nil {
		t.Fatalf("statePath: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("perm = %#o, want 0600", fi.Mode().Perm())
	}

	got, err := LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if got.LatestVersion != "v1.2.3" || !got.CheckedAt.Equal(want.CheckedAt) {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, want)
	}
}

func TestLoadState_CorruptIsEmpty(t *testing.T) {
	cfg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfg)
	p, _ := statePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Corrupt cache is disposable: treated as empty, no error.
	s, err := LoadState()
	if err != nil {
		t.Fatalf("LoadState corrupt: %v", err)
	}
	if s != (State{}) {
		t.Fatalf("want empty state, got %+v", s)
	}
}

// LoadState surfaces a non-IsNotExist read error (the cache path is a directory).
func TestLoadState_ReadError(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	p, _ := statePath()
	if err := os.MkdirAll(p, 0o700); err != nil { // update.json is a dir
		t.Fatal(err)
	}
	if _, err := LoadState(); err == nil {
		t.Fatal("expected read error when update.json is a directory")
	}
}

// SaveState fails to MkdirAll when the config home is a regular file.
func TestSaveState_MkdirAllError(t *testing.T) {
	dir := t.TempDir()
	asFile := filepath.Join(dir, "f")
	if err := os.WriteFile(asFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", asFile)
	if err := SaveState(State{LatestVersion: "v1"}); err == nil {
		t.Fatal("expected MkdirAll error")
	}
}

// SaveState fails to create the temp file when the dir is read-only.
func TestSaveState_CreateTempError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("read-only dir CreateTemp behavior differs on Windows")
	}
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p, _ := statePath()
	d := filepath.Dir(p)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o500); err != nil { //nolint:gosec // G302: test deliberately makes the dir read-only
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(d, 0o700) }() //nolint:gosec // G302: restoring dir perms in test cleanup; directories need the exec bit
	if err := SaveState(State{LatestVersion: "v1"}); err == nil {
		t.Fatal("expected CreateTemp error in read-only dir")
	}
}

func TestSaveStateCreatesDir(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "nested")
	t.Setenv("XDG_CONFIG_HOME", cfg)
	if err := SaveState(State{LatestVersion: "v0.0.1"}); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	got, _ := LoadState()
	if got.LatestVersion != "v0.0.1" {
		t.Fatalf("got %+v", got)
	}
}
