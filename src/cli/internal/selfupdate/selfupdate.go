// Package selfupdate upgrades the running dwvault binary in place from the project's
// GitHub releases, and maintains a small cache of the latest-seen version for the CLI's
// passive update notice.
//
// Releases publish one binary per platform named "dwvault-<goos>-<goarch>" plus a
// "SHA256SUMS" manifest (see .github/workflows/cli-autorelease.yml). An upgrade fetches
// the asset for the current runtime, verifies its sha256 against the manifest, and
// atomically renames it over the live executable — it never touches PATH or shell
// profiles (first-install placement is install.sh's job).
package selfupdate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"donkeywork.dev/vault-cli/internal/config"
)

// defaultRepo is the GitHub "owner/name" that hosts the dwvault releases. Kept here as the
// single source of truth so the self-updater and install.sh stay in lockstep.
const defaultRepo = "andyjmorgan/DonkeyWork-Vault"

const sha256SumsAsset = "SHA256SUMS"

// githubAPIBase is the GitHub REST API root. It's a var (not a const) only so tests can
// point Latest at an httptest server; production never changes it.
var githubAPIBase = "https://api.github.com"

// createTemp is os.CreateTemp, indirected only so tests can exercise the atomic-write
// failure paths in Apply and SaveState (e.g. by handing back an already-closed file so
// the subsequent Write fails). Production never reassigns it.
var createTemp = os.CreateTemp

// maxDownload caps a single asset read so a misconfigured or hostile DWVAULT_REPO can't
// exhaust memory. The dwvault binary is ~10 MB; 256 MB is comfortable headroom. A truncated
// binary fails the sha256 check; a truncated manifest fails the "not listed" lookup.
const maxDownload = 256 << 20

// Repo returns the release repo, honoring the DWVAULT_REPO override for parity with
// install.sh (so `dwvault update` follows the same source the binary was installed from).
func Repo() string {
	if r := os.Getenv("DWVAULT_REPO"); r != "" {
		return r
	}
	return defaultRepo
}

// Release is the subset of the GitHub release payload we need.
type Release struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// AssetName is the release asset name for the current platform, e.g. dwvault-linux-amd64.
func AssetName() string {
	return fmt.Sprintf("dwvault-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// Latest returns the newest published (non-draft, non-prerelease) release. The caller
// controls the timeout via ctx.
func Latest(ctx context.Context) (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", githubAPIBase, Repo())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github releases: %s", resp.Status)
	}
	var rel Release
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("github releases: empty tag in response")
	}
	return &rel, nil
}

// Compare orders two strict vMAJOR.MINOR.PATCH versions: -1 if a<b, 0 if equal, +1 if a>b.
// A version that doesn't parse (e.g. "dev") is treated as the lowest possible, so it never
// looks newer than a real release.
func Compare(a, b string) int {
	am, aok := parse(a)
	bm, bok := parse(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	for i := 0; i < 3; i++ {
		if am[i] != bm[i] {
			if am[i] < bm[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// parse splits a strict "vMAJOR.MINOR.PATCH" tag into its three numeric components.
func parse(v string) ([3]int, bool) {
	var out [3]int
	s := strings.TrimPrefix(v, "v")
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Download fetches this platform's binary from the release and verifies its sha256 against
// the release's SHA256SUMS manifest. It returns the verified binary bytes.
func Download(ctx context.Context, rel *Release) ([]byte, error) {
	name := AssetName()
	binURL := assetURL(rel, name)
	if binURL == "" {
		return nil, fmt.Errorf("release %s has no asset %q", rel.TagName, name)
	}
	sumsURL := assetURL(rel, sha256SumsAsset)
	if sumsURL == "" {
		return nil, fmt.Errorf("release %s has no %s manifest", rel.TagName, sha256SumsAsset)
	}

	sums, err := fetch(ctx, sumsURL)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", sha256SumsAsset, err)
	}
	want, err := sumFor(sums, name)
	if err != nil {
		return nil, err
	}

	bin, err := fetch(ctx, binURL)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", name, err)
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return nil, fmt.Errorf("checksum mismatch for %s (release may be corrupt)", name)
	}
	return bin, nil
}

// assetURL returns the download URL of the named asset, or "" if absent.
func assetURL(rel *Release, name string) string {
	for _, a := range rel.Assets {
		if a.Name == name {
			return a.BrowserDownloadURL
		}
	}
	return ""
}

// sumFor extracts the hex sha256 for name from a "sha256  filename" manifest (the format
// produced by `sha256sum`).
func sumFor(manifest []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		// `sha256sum` prefixes the binary-mode filename with '*'.
		if strings.TrimPrefix(fields[1], "*") == name {
			sum := strings.ToLower(fields[0])
			if len(sum) != sha256.Size*2 {
				return "", fmt.Errorf("malformed checksum for %s in %s", name, sha256SumsAsset)
			}
			return sum, nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s not listed in %s", name, sha256SumsAsset)
}

// fetch GETs a URL and returns the full body.
func fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

// executable resolves the running binary's real path. It's a var (not a direct
// os.Executable call) only so tests can point Apply at a temp file instead of the live
// test binary; production always uses os.Executable.
var executable = os.Executable

// Apply atomically replaces the running executable with bin. It resolves the executable
// through symlinks, writes a temp file alongside the real target (same dir ⇒ rename is
// atomic, not a cross-device copy), makes it executable, and renames it into place.
// Returns the resolved path that was replaced.
func Apply(bin []byte) (string, error) {
	exe, err := executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	f, err := createTemp(dir, ".dwvault-update-*")
	if err != nil {
		return "", fmt.Errorf("cannot stage update in %s: %w", dir, err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once the rename succeeds
	if _, err := f.Write(bin); err != nil {
		_ = f.Close()
		return "", err
	}
	// Flush to disk before the rename so a crash can't leave a truncated binary in place.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err //coverage:ignore Sync syscall failure not reproducible on a normal temp file
	}
	if err := f.Close(); err != nil {
		return "", err //coverage:ignore Close error after a successful write/sync not reproducible
	}
	if err := os.Chmod(tmp, 0o755); err != nil { //nolint:gosec // G302: staged binary must be executable (0o755); the file is program-controlled
		return "", err //coverage:ignore Chmod syscall failure not reproducible on a normal temp file
	}
	if err := os.Rename(tmp, exe); err != nil {
		return "", fmt.Errorf("cannot replace %s: %w", exe, err)
	}
	return exe, nil
}

// State is the cached result of the last passive update check.
type State struct {
	CheckedAt     time.Time `json:"checked_at"`
	LatestVersion string    `json:"latest_version"`
}

const stateFile = "update.json"

func statePath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, stateFile), nil
}

// LoadState reads the update-check cache, returning a zero State if it's absent.
func LoadState() (State, error) {
	var s State
	p, err := statePath()
	if err != nil {
		return s, err
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: path is the program-controlled update-check cache, not attacker-supplied
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		// The cache is disposable: treat a corrupt file as empty so the next check
		// simply rewrites it, rather than erroring on the CLI's hot path.
		return State{}, nil
	}
	return s, nil
}

// SaveState writes the update-check cache atomically (0600 file, 0700 dir).
func SaveState(s State) error {
	p, err := statePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err //coverage:ignore State always marshals
	}
	f, err := createTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err //coverage:ignore Close error after a successful write not reproducible
	}
	return os.Rename(tmp, p)
}
