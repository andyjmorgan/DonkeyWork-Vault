// Package oauth holds small, dependency-free OAuth helpers shared by the flow service.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GenerateVerifier returns a PKCE code verifier (43-char base64url of 32 random bytes).
func GenerateVerifier() string { return base64url(randomBytes(32)) }

// Challenge returns the S256 PKCE code challenge for a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64url(sum[:])
}

// RandomState returns an opaque anti-forgery state value.
func RandomState() string { return base64url(randomBytes(32)) }

func randomBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
