package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifierAndChallenge(t *testing.T) {
	v := GenerateVerifier()
	if len(v) != 43 { // 32 bytes base64url unpadded
		t.Fatalf("verifier length %d", len(v))
	}
	if strings.ContainsAny(v, "+/=") {
		t.Fatal("verifier must be base64url without padding")
	}
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := Challenge(v); got != want {
		t.Fatalf("challenge mismatch")
	}
}

func TestRandomStateUnique(t *testing.T) {
	if RandomState() == RandomState() {
		t.Fatal("states should differ")
	}
}
