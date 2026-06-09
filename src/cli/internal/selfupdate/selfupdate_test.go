package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"runtime"
	"testing"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.4", "v1.2.3", 1},
		{"v1.3.0", "v1.2.9", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v0.2.10", "v0.2.9", 1}, // numeric, not lexical
		{"1.0.0", "v1.0.0", 0},   // missing leading v still parses
		{"dev", "v0.1.0", -1},    // unparseable is never newer
		{"v0.1.0", "dev", 1},
		{"dev", "dev", 0},
		{"v1.2", "v1.2.0", -1}, // malformed (2 parts) sorts below valid
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestAssetName(t *testing.T) {
	want := fmt.Sprintf("dwvault-%s-%s", runtime.GOOS, runtime.GOARCH)
	if got := AssetName(); got != want {
		t.Errorf("AssetName() = %q, want %q", got, want)
	}
}

func sum256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func TestSumFor(t *testing.T) {
	hexsum := sum256("payload")
	manifest := []byte(
		sum256("linux") + "  dwvault-linux-amd64\n" +
			hexsum + "  dwvault-darwin-arm64\n" +
			sum256("win") + " *dwvault-windows-amd64\n", // sha256sum binary-mode '*' prefix
	)

	got, err := sumFor(manifest, "dwvault-darwin-arm64")
	if err != nil {
		t.Fatalf("sumFor: %v", err)
	}
	if got != hexsum {
		t.Errorf("sumFor = %q, want %q", got, hexsum)
	}

	if _, err := sumFor(manifest, "dwvault-linux-arm64"); err == nil {
		t.Error("sumFor: expected error for asset not in manifest")
	}

	// Binary-mode '*' prefix on the filename is stripped before matching.
	if _, err := sumFor(manifest, "dwvault-windows-amd64"); err != nil {
		t.Errorf("sumFor: '*'-prefixed filename should match: %v", err)
	}

	// A digest that isn't 64 hex chars is rejected rather than silently used.
	bad := []byte("deadbeef  dwvault-linux-amd64\n")
	if _, err := sumFor(bad, "dwvault-linux-amd64"); err == nil {
		t.Error("sumFor: expected error for malformed (non-64-hex) checksum")
	}
}
