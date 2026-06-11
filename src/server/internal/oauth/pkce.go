// Package oauth holds small, dependency-free OAuth helpers shared by the flow service.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

// randReader is the CSPRNG source for verifier/state generation. It is a package var so tests can
// inject a failing reader to exercise the error path; production code reads from crypto/rand.
var randReader = rand.Reader

// GenerateVerifier returns a PKCE code verifier (43-char base64url of 32 random bytes).
func GenerateVerifier() (string, error) { return randomBase64url(32) }

// Challenge returns the S256 PKCE code challenge for a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64url(sum[:])
}

// RandomState returns an opaque anti-forgery state value.
func RandomState() (string, error) { return randomBase64url(32) }

// randomBase64url returns n CSPRNG bytes as base64url. A rand.Read failure is surfaced rather than
// silently producing a guessable (zero-padded) value, which would weaken PKCE/state CSRF defence.
func randomBase64url(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(randReader, b); err != nil {
		return "", err
	}
	return base64url(b), nil
}

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
