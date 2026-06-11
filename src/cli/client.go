package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"donkeywork.dev/vault-cli/internal/credstore"
	"donkeywork.dev/vault-cli/internal/oauthdevice"
	"donkeywork.dev/vault-cli/internal/vaultapi"
)

// newClient builds a vaultapi client for the resolved base URL, injecting the
// caller's API key as the X-Api-Key header on every request.
//
// The base URL and transport (plaintext vs TLS) come from httpBaseURL(), where the
// --addr scheme is the sole signal (https:// ⇒ TLS; a bare host defaults to http://).
// The key is resolved via credstore: --api-key / VAULT_API_KEY, then the OS keyring,
// then the 0600 file written by `dwvault auth login`.
func newClient() (*vaultapi.ClientWithResponses, error) {
	base := httpBaseURL()

	authHeader, err := requestAuth(base)
	if err != nil {
		return nil, err
	}

	editor := func(_ context.Context, req *http.Request) error {
		for k, v := range authHeader {
			req.Header.Set(k, v)
		}
		req.Header.Set("Accept", "application/json")
		return nil
	}
	return vaultapi.NewClientWithResponses(base, vaultapi.WithRequestEditorFn(editor))
}

func requestAuth(base string) (map[string]string, error) {
	if apiKey != "" {
		return map[string]string{"X-Api-Key": apiKey}, nil
	}
	c, src, err := credstore.ResolveCredential(base)
	if err != nil {
		return nil, fmt.Errorf("no credentials for %s; run `dwvault auth login` or set VAULT_API_KEY", base)
	}
	switch c.Type {
	case credstore.TypeAPIKey:
		return map[string]string{"X-Api-Key": c.Secret}, nil
	case credstore.TypeOAuth:
		token, err := oauthAccessToken(base, c, src)
		if err != nil {
			return nil, err
		}
		return map[string]string{"Authorization": "Bearer " + token}, nil
	default:
		return nil, fmt.Errorf("unsupported credential type %q", c.Type)
	}
}

func oauthAccessToken(base string, c *credstore.Credential, src credstore.Source) (string, error) {
	if c.AccessToken != "" && !expiresSoon(c.ExpiresAt) {
		return c.AccessToken, nil
	}
	if c.RefreshToken == "" {
		return "", fmt.Errorf("OAuth credential for %s has no refresh token; run `dwvault auth login --oauth --force`", base)
	}
	d, err := oauthdevice.Discover(c.Issuer)
	if err != nil {
		return "", err
	}
	tok, err := oauthdevice.Refresh(d.TokenEndpoint, c.ClientID, c.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("refresh OAuth credential: %w", err)
	}
	updateOAuthCredential(c, tok)
	if src != credstore.SourceEnv {
		if _, err := credstore.StoreCredential(base, c); err != nil {
			return "", err
		}
	}
	return c.AccessToken, nil
}

func expiresSoon(s string) bool {
	if s == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return true
	}
	return time.Until(t) < 60*time.Second
}

func updateOAuthCredential(c *credstore.Credential, tok *oauthdevice.TokenResponse) {
	c.AccessToken = tok.AccessToken
	c.RefreshToken = tok.RefreshToken
	if tok.Scope != "" {
		c.Scopes = tok.Scope
	}
	if tok.ExpiresIn > 0 {
		c.ExpiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	}
	if tok.RefreshExpiresIn > 0 {
		c.RefreshExpiresAt = time.Now().Add(time.Duration(tok.RefreshExpiresIn) * time.Second).UTC().Format(time.RFC3339)
	} else if c.RefreshExpiresAt == "" {
		c.RefreshExpiresAt = "offline"
	}
}

// deref returns the pointed-to string, or "" when the pointer is nil.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
