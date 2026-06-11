package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

// oidcDiscoveryServer stands up an httptest server that serves a minimal but valid OIDC discovery
// document (and an empty JWKS) whose issuer equals the server's own URL, so oidc.NewProvider
// succeeds.
func oidcDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func oidcDeps(t *testing.T, oidc OIDCConfig) Deps {
	t.Helper()
	kek, err := crypto.NewLocalKekProvider("local:v1", map[string]string{"local:v1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	if err != nil {
		t.Fatal(err)
	}
	cipher := crypto.NewEnvelopeCipher(kek)
	ms := memstore.New()
	loader, err := manifests.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	resolver := manifests.NewResolver(ms, loader)
	auditLog := audit.NewLog(100, nil, nil)
	return Deps{
		APIKeys:      service.NewAPIKeyService(ms, cipher, auditLog),
		AccessKeys:   service.NewAccessKeyService(ms, auditLog),
		OAuthConfigs: service.NewOAuthConfigService(ms, cipher, auditLog, resolver),
		OAuthTokens:  service.NewOAuthTokenService(ms, cipher, auditLog, resolver, http.DefaultClient),
		OAuthFlow:    service.NewOAuthFlowService(ms, cipher, resolver, auditLog, http.DefaultClient, nil),
		Resolver:     resolver, Discovery: manifests.NewDiscovery(http.DefaultClient),
		AuditLog: auditLog, AuditQuery: audit.NewQueryService(ms, auditLog),
		IPResolver: audit.NewForwardedIPResolver(nil), PublicBaseURL: "https://v",
		OIDC: oidc,
	}
}

// TestNewServerDiscoverySuccess covers initVerifier's happy path: discovery succeeds and a verifier
// is installed.
func TestNewServerDiscoverySuccess(t *testing.T) {
	idp := oidcDiscoveryServer(t)
	srv, err := NewServer(context.Background(), oidcDeps(t, OIDCConfig{Authority: idp.URL}))
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv.jwtVerifier() == nil {
		t.Fatal("expected verifier installed after successful discovery")
	}
	if !srv.authOn {
		t.Fatal("authOn should be true when an authority is configured")
	}
}

// TestNewServerInternalAuthority covers initVerifier's branch that uses a distinct InternalAuthority
// (in-cluster metadata URL) while validating against the public issuer via InsecureIssuerURLContext.
func TestNewServerInternalAuthority(t *testing.T) {
	idp := oidcDiscoveryServer(t)
	// InternalAuthority differs from Authority, so the metadata is fetched from InternalAuthority and
	// the issuer is validated against Authority. The discovery doc's issuer is idp.URL, so set
	// Authority = idp.URL and InternalAuthority to the same reachable server with a trailing slash to
	// force the "InternalAuthority != Authority" path; oidc validates the issuer claim (idp.URL)
	// against Authority (idp.URL), which matches.
	deps := oidcDeps(t, OIDCConfig{Authority: idp.URL, InternalAuthority: idp.URL + "/"})
	srv, err := NewServer(context.Background(), deps)
	if err != nil {
		t.Fatalf("NewServer internal authority: %v", err)
	}
	if srv.jwtVerifier() == nil {
		t.Fatal("expected verifier with internal authority")
	}
}

// TestNewServerRequireHTTPSRejected covers the RequireHTTPS guard in NewServer (non-https Authority
// fails fast).
func TestNewServerRequireHTTPSRejected(t *testing.T) {
	_, err := NewServer(context.Background(), oidcDeps(t, OIDCConfig{
		Authority: "http://insecure.example", RequireHTTPS: true,
	}))
	if err == nil {
		t.Fatal("expected error for non-https authority with RequireHTTPS")
	}
}

// TestNewServerRequireHTTPSInternalRejected covers the guard loop's second iteration
// (InternalAuthority non-https).
func TestNewServerRequireHTTPSInternalRejected(t *testing.T) {
	idp := oidcDiscoveryServer(t)
	_, err := NewServer(context.Background(), oidcDeps(t, OIDCConfig{
		Authority: idp.URL, InternalAuthority: "http://insecure.internal", RequireHTTPS: true,
	}))
	if err == nil {
		t.Fatal("expected error for non-https internal authority with RequireHTTPS")
	}
}

// TestNewServerDiscoveryFailureSpawnsRetry covers NewServer's discovery-failure branch (logs and
// spawns retryVerifier) and retryVerifier's ctx.Done() exit. The authority points at a dead address
// so initVerifier fails; cancelling the context makes the spawned retryVerifier exit via ctx.Done.
func TestNewServerDiscoveryFailureSpawnsRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv, err := NewServer(ctx, oidcDeps(t, OIDCConfig{Authority: "https://127.0.0.1:1"}))
	if err != nil {
		t.Fatalf("NewServer should not fail on discovery error: %v", err)
	}
	if srv.jwtVerifier() != nil {
		t.Fatal("verifier should be nil after discovery failure")
	}
	cancel()
	time.Sleep(20 * time.Millisecond) // let the background goroutine observe cancellation
}

// TestRetryVerifierCtxDone covers retryVerifier's immediate ctx.Done exit (already-cancelled ctx).
func TestRetryVerifierCtxDone(t *testing.T) {
	srv, err := NewServer(context.Background(), oidcDeps(t, OIDCConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { srv.retryVerifier(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("retryVerifier did not exit on cancelled context")
	}
}

// TestRetryVerifierSucceeds covers retryVerifier's retry-then-success path against a live IdP. The
// first backoff is 5s, so this test is bounded but slow; it asserts the verifier becomes installed.
func TestRetryVerifierSucceeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skips the 5s retry backoff in -short mode")
	}
	idp := oidcDiscoveryServer(t)
	srv, err := NewServer(context.Background(), oidcDeps(t, OIDCConfig{Authority: idp.URL}))
	if err != nil {
		t.Fatal(err)
	}
	srv.verifier.Store(nil) // simulate startup discovery not yet done

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { srv.retryVerifier(ctx); close(done) }()
	<-done
	if srv.jwtVerifier() == nil {
		t.Fatal("retryVerifier should have installed the verifier")
	}
}

// TestInitVerifierError covers initVerifier's error return (unreachable IdP).
func TestInitVerifierError(t *testing.T) {
	srv, err := NewServer(context.Background(), oidcDeps(t, OIDCConfig{}))
	if err != nil {
		t.Fatal(err)
	}
	srv.deps.OIDC.Authority = "https://127.0.0.1:1"
	if err := srv.initVerifier(context.Background()); err == nil {
		t.Fatal("expected initVerifier error for unreachable IdP")
	}
}
