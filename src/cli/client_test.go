package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"donkeywork.dev/vault-cli/internal/credstore"
	"donkeywork.dev/vault-cli/internal/oauthdevice"
)

// resetClientGlobals isolates the package-level flags client.go reads (addr/apiKey)
// and gives credstore a clean mock keyring + temp config dir, so storage is
// deterministic and never touches the developer's real keyring or files.
func resetClientGlobals(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("VAULT_API_KEY", "")
	oldAddr, oldKey := addr, apiKey
	addr, apiKey = "", ""
	t.Cleanup(func() { addr, apiKey = oldAddr, oldKey })
}

func TestDeref(t *testing.T) {
	if got := deref(nil); got != "" {
		t.Fatalf("deref(nil) = %q, want empty", got)
	}
	s := "hello"
	if got := deref(&s); got != "hello" {
		t.Fatalf("deref(&s) = %q, want %q", got, s)
	}
}

func TestExpiresSoon(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"empty", "", true},
		{"unparseable", "not-a-time", true},
		{"already expired", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), true},
		{"within window", time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339), true},
		{"comfortably valid", time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := expiresSoon(tc.in); got != tc.want {
				t.Fatalf("expiresSoon(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRequestAuth_FlagAPIKey(t *testing.T) {
	resetClientGlobals(t)
	apiKey = "dwv_flag"
	t.Cleanup(func() { apiKey = "" })

	h, err := requestAuth("http://vault.example")
	if err != nil {
		t.Fatalf("requestAuth: %v", err)
	}
	if h["X-Api-Key"] != "dwv_flag" {
		t.Fatalf("got %v, want X-Api-Key=dwv_flag", h)
	}
}

func TestRequestAuth_StoredAPIKey(t *testing.T) {
	resetClientGlobals(t)
	const host = "http://vault.example"
	if _, err := credstore.StoreCredential(host, &credstore.Credential{
		Type:   credstore.TypeAPIKey,
		Secret: "dwv_stored",
	}); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	h, err := requestAuth(host)
	if err != nil {
		t.Fatalf("requestAuth: %v", err)
	}
	if h["X-Api-Key"] != "dwv_stored" {
		t.Fatalf("got %v, want X-Api-Key=dwv_stored", h)
	}
}

func TestRequestAuth_NoCredential(t *testing.T) {
	resetClientGlobals(t)
	if _, err := requestAuth("http://vault.example"); err == nil {
		t.Fatal("requestAuth: want error for missing credential, got nil")
	}
}

func TestRequestAuth_UnsupportedType(t *testing.T) {
	resetClientGlobals(t)
	const host = "http://vault.example"
	if _, err := credstore.StoreCredential(host, &credstore.Credential{
		Type: credstore.CredentialType("weird"),
	}); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}
	if _, err := requestAuth(host); err == nil {
		t.Fatal("requestAuth: want error for unsupported type, got nil")
	}
}

func TestRequestAuth_OAuthValidToken(t *testing.T) {
	resetClientGlobals(t)
	const host = "http://vault.example"
	if _, err := credstore.StoreCredential(host, &credstore.Credential{
		Type:        credstore.TypeOAuth,
		AccessToken: "still-good",
		ExpiresAt:   time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	h, err := requestAuth(host)
	if err != nil {
		t.Fatalf("requestAuth: %v", err)
	}
	if h["Authorization"] != "Bearer still-good" {
		t.Fatalf("got %v, want Authorization=Bearer still-good", h)
	}
}

// oauthServer stands in for the Keycloak issuer: it serves the OIDC discovery
// document (pointing token_endpoint back at itself) and the token refresh endpoint.
func oauthServer(t *testing.T, tok oauthdevice.TokenResponse, tokenStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                        srv.URL,
			"device_authorization_endpoint": srv.URL + "/device",
			"token_endpoint":                srv.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tokenStatus)
		_ = json.NewEncoder(w).Encode(tok)
	})
	return srv
}

func TestOAuthAccessToken_RefreshAndPersist(t *testing.T) {
	resetClientGlobals(t)
	const host = "http://vault.example"
	srv := oauthServer(t, oauthdevice.TokenResponse{
		AccessToken:      "fresh-access",
		RefreshToken:     "fresh-refresh",
		Scope:            "openid offline_access",
		ExpiresIn:        3600,
		RefreshExpiresIn: 7200,
	}, http.StatusOK)

	c := &credstore.Credential{
		Type:         credstore.TypeOAuth,
		Issuer:       srv.URL,
		ClientID:     "cli",
		AccessToken:  "stale",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), // expired ⇒ refresh
	}
	if _, err := credstore.StoreCredential(host, c); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	tok, err := oauthAccessToken(host, c, credstore.SourceKeyring)
	if err != nil {
		t.Fatalf("oauthAccessToken: %v", err)
	}
	if tok != "fresh-access" {
		t.Fatalf("returned token = %q, want fresh-access", tok)
	}
	// The refreshed credential must have been persisted back to the store.
	got, _, err := credstore.ResolveCredential(host)
	if err != nil {
		t.Fatalf("ResolveCredential: %v", err)
	}
	if got.AccessToken != "fresh-access" || got.RefreshToken != "fresh-refresh" {
		t.Fatalf("persisted credential = %+v, want fresh tokens", got)
	}
}

// requestAuth must surface an oauthAccessToken error rather than swallow it.
func TestRequestAuth_OAuthRefreshError(t *testing.T) {
	resetClientGlobals(t)
	const host = "http://vault.example"
	srv := oauthServer(t, oauthdevice.TokenResponse{Error: "invalid_grant"}, http.StatusBadRequest)
	if _, err := credstore.StoreCredential(host, &credstore.Credential{
		Type:         credstore.TypeOAuth,
		Issuer:       srv.URL,
		ClientID:     "cli",
		RefreshToken: "old",
		ExpiresAt:    "", // forces a refresh attempt
	}); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}
	if _, err := requestAuth(host); err == nil {
		t.Fatal("requestAuth: want propagated refresh error, got nil")
	}
}

// When persisting a refreshed credential fails (no keyring, unwritable file
// fallback), oauthAccessToken must return the store error.
func TestOAuthAccessToken_PersistError(t *testing.T) {
	keyring.MockInitWithError(errors.New("keyring unavailable"))
	t.Cleanup(keyring.MockInit) // restore the plain mock for later tests
	// Point the config dir at a path that cannot be created (a child under a
	// regular file), so the 0600 file fallback also fails.
	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "notadir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", blocker)
	t.Setenv("VAULT_API_KEY", "")

	srv := oauthServer(t, oauthdevice.TokenResponse{
		AccessToken:  "fresh",
		RefreshToken: "fresh-r",
		ExpiresIn:    3600,
	}, http.StatusOK)
	c := &credstore.Credential{
		Type:         credstore.TypeOAuth,
		Issuer:       srv.URL,
		ClientID:     "cli",
		RefreshToken: "r",
		ExpiresAt:    "",
	}
	if _, err := oauthAccessToken("http://vault.example", c, credstore.SourceKeyring); err == nil {
		t.Fatal("want persistence error, got nil")
	}
}

func TestOAuthAccessToken_NoRefreshToken(t *testing.T) {
	resetClientGlobals(t)
	c := &credstore.Credential{
		Type:      credstore.TypeOAuth,
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}
	if _, err := oauthAccessToken("http://vault.example", c, credstore.SourceKeyring); err == nil {
		t.Fatal("want error when refresh token is missing, got nil")
	}
}

func TestOAuthAccessToken_DiscoverFailure(t *testing.T) {
	resetClientGlobals(t)
	c := &credstore.Credential{
		Type:         credstore.TypeOAuth,
		Issuer:       "http://127.0.0.1:1", // nothing listening ⇒ discovery network error
		RefreshToken: "r",
		ExpiresAt:    "",
	}
	if _, err := oauthAccessToken("http://vault.example", c, credstore.SourceKeyring); err == nil {
		t.Fatal("want discovery error, got nil")
	}
}

func TestOAuthAccessToken_RefreshRejected(t *testing.T) {
	resetClientGlobals(t)
	srv := oauthServer(t, oauthdevice.TokenResponse{
		Error:            "invalid_grant",
		ErrorDescription: "token expired",
	}, http.StatusBadRequest)
	c := &credstore.Credential{
		Type:         credstore.TypeOAuth,
		Issuer:       srv.URL,
		ClientID:     "cli",
		RefreshToken: "old",
		ExpiresAt:    "",
	}
	if _, err := oauthAccessToken("http://vault.example", c, credstore.SourceKeyring); err == nil {
		t.Fatal("want refresh error, got nil")
	}
}

// SourceEnv credentials are ephemeral and must NOT be written back to the store
// when refreshed; only the in-memory credential is updated.
func TestOAuthAccessToken_EnvSourceNotPersisted(t *testing.T) {
	resetClientGlobals(t)
	const host = "http://vault.example"
	srv := oauthServer(t, oauthdevice.TokenResponse{
		AccessToken:  "env-fresh",
		RefreshToken: "env-refresh",
		ExpiresIn:    3600,
	}, http.StatusOK)

	c := &credstore.Credential{
		Type:         credstore.TypeOAuth,
		Issuer:       srv.URL,
		ClientID:     "cli",
		RefreshToken: "r",
		ExpiresAt:    "",
	}
	tok, err := oauthAccessToken(host, c, credstore.SourceEnv)
	if err != nil {
		t.Fatalf("oauthAccessToken: %v", err)
	}
	if tok != "env-fresh" {
		t.Fatalf("token = %q, want env-fresh", tok)
	}
	if _, _, err := credstore.ResolveCredential(host); err != credstore.ErrNotFound {
		t.Fatalf("env-source refresh must not persist; ResolveCredential err = %v, want ErrNotFound", err)
	}
}

func TestUpdateOAuthCredential(t *testing.T) {
	t.Run("full token with expiries", func(t *testing.T) {
		c := &credstore.Credential{AccessToken: "old", RefreshToken: "oldr", Scopes: "old-scope"}
		updateOAuthCredential(c, &oauthdevice.TokenResponse{
			AccessToken:      "new",
			RefreshToken:     "newr",
			Scope:            "new-scope",
			ExpiresIn:        3600,
			RefreshExpiresIn: 7200,
		})
		if c.AccessToken != "new" || c.RefreshToken != "newr" || c.Scopes != "new-scope" {
			t.Fatalf("token fields not updated: %+v", c)
		}
		if c.ExpiresAt == "" || c.RefreshExpiresAt == "" || c.RefreshExpiresAt == "offline" {
			t.Fatalf("expiry fields not set from ExpiresIn/RefreshExpiresIn: %+v", c)
		}
	})

	t.Run("no scope keeps existing, no refresh-expiry defaults to offline", func(t *testing.T) {
		c := &credstore.Credential{Scopes: "keep-me"}
		updateOAuthCredential(c, &oauthdevice.TokenResponse{
			AccessToken:  "a",
			RefreshToken: "r",
			// Scope, ExpiresIn, RefreshExpiresIn all zero/empty.
		})
		if c.Scopes != "keep-me" {
			t.Fatalf("Scopes overwritten: %q", c.Scopes)
		}
		if c.ExpiresAt != "" {
			t.Fatalf("ExpiresAt set despite zero ExpiresIn: %q", c.ExpiresAt)
		}
		if c.RefreshExpiresAt != "offline" {
			t.Fatalf("RefreshExpiresAt = %q, want offline", c.RefreshExpiresAt)
		}
	})
}

// TestNewClient exercises the full newClient path: it resolves a stored API key,
// builds the generated client, and confirms the request editor attaches the
// X-Api-Key header on an actual request to the vault server.
func TestNewClient_AttachesAuthHeader(t *testing.T) {
	resetClientGlobals(t)

	gotKey := make(chan string, 1)
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey <- r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"authEnabled": false})
	}))
	t.Cleanup(vault.Close)

	addr = vault.URL // httpBaseURL passes http:// URLs through verbatim
	if _, err := credstore.StoreCredential(vault.URL, &credstore.Credential{
		Type:   credstore.TypeAPIKey,
		Secret: "dwv_newclient",
	}); err != nil {
		t.Fatalf("StoreCredential: %v", err)
	}

	cl, err := newClient()
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if _, err := cl.GetApiConfigWithResponse(context.Background()); err != nil {
		t.Fatalf("GetApiConfigWithResponse: %v", err)
	}
	if k := <-gotKey; k != "dwv_newclient" {
		t.Fatalf("server saw X-Api-Key=%q, want dwv_newclient", k)
	}
}

func TestNewClient_AuthError(t *testing.T) {
	resetClientGlobals(t)
	addr = "vault.example" // bare host ⇒ http://vault.example, no stored credential
	if _, err := newClient(); err == nil {
		t.Fatal("newClient: want error when no credential resolves, got nil")
	}
}
