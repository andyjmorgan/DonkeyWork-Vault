package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
)

const testIssuer = "https://idp.test"

// fakeKeySet implements oidc.KeySet by returning the token payload without real signature checks, so
// the test can exercise our JWT handling (issuer/expiry/claims/scope mapping) deterministically.
type fakeKeySet struct{}

func (fakeKeySet) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
	parts := splitJWT(jwt)
	return base64.RawURLEncoding.DecodeString(parts[1])
}

func splitJWT(s string) [3]string {
	var out [3]string
	parts := strings.SplitN(s, ".", 3)
	copy(out[:], parts)
	return out
}

func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))
	pb, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(pb)
	return hdr + "." + payload + ".sig"
}

func newJWTHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	// Rebuild the server with an injected verifier + auth on.
	kek, _ := crypto.NewLocalKekProvider("local:v1", map[string]string{"local:v1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	cipher := crypto.NewEnvelopeCipher(kek)
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(h.ms, loader)
	auditLog := audit.NewLog(100, nil, nil)
	deps := Deps{
		APIKeys:      service.NewAPIKeyService(h.ms, cipher, auditLog),
		AccessKeys:   service.NewAccessKeyService(h.ms, auditLog),
		OAuthConfigs: service.NewOAuthConfigService(h.ms, cipher, auditLog, resolver),
		OAuthTokens:  service.NewOAuthTokenService(h.ms, cipher, auditLog, resolver, http.DefaultClient),
		OAuthFlow:    service.NewOAuthFlowService(h.ms, cipher, resolver, auditLog, http.DefaultClient, nil),
		Resolver:     resolver, Discovery: manifests.NewDiscovery(http.DefaultClient),
		AuditLog: auditLog, AuditQuery: audit.NewQueryService(h.ms, auditLog),
		IPResolver: audit.NewForwardedIPResolver(nil), PublicBaseURL: "https://v",
	}
	srv, _ := NewServer(context.Background(), deps)
	srv.verifier.Store(oidc.NewVerifier(testIssuer, fakeKeySet{}, &oidc.Config{SkipClientIDCheck: true}))
	srv.authOn = true
	srv.webClientID = "web"
	srv.cliClientID = "cli"
	h.h = srv.Handler()
	return h
}

func bearer(h *harness, t *testing.T, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func TestJWTWebUserFullScopes(t *testing.T) {
	h := newJWTHarness(t)
	tok := makeJWT(t, map[string]any{
		"iss": testIssuer, "sub": uuid.NewString(), "aud": []string{"web"}, "azp": "web",
		"email": "u@e.com", "name": "U", "exp": time.Now().Add(time.Hour).Unix(),
	})
	if rec := bearer(h, t, "/api/v1/me", tok); rec.Code != 200 {
		t.Fatalf("me %d body=%s", rec.Code, rec.Body)
	}
	// web user has vault:audit
	if rec := bearer(h, t, "/api/v1/audit", tok); rec.Code != 200 {
		t.Fatalf("audit %d", rec.Code)
	}
}

func TestJWTCliUserLimitedScopes(t *testing.T) {
	h := newJWTHarness(t)
	tok := makeJWT(t, map[string]any{
		"iss": testIssuer, "sub": uuid.NewString(), "aud": []string{"web"}, "azp": "cli",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// CLI can read
	if rec := bearer(h, t, "/api/v1/api-keys", tok); rec.Code != 200 {
		t.Fatalf("cli read %d", rec.Code)
	}
	// CLI lacks vault:audit
	if rec := bearer(h, t, "/api/v1/audit", tok); rec.Code != http.StatusForbidden {
		t.Fatalf("cli audit should be 403, got %d", rec.Code)
	}
}

func TestJWTNonGUIDSubjectRejected(t *testing.T) {
	h := newJWTHarness(t)
	tok := makeJWT(t, map[string]any{"iss": testIssuer, "sub": "not-a-guid", "aud": []string{"web"}, "exp": time.Now().Add(time.Hour).Unix()})
	if rec := bearer(h, t, "/api/v1/me", tok); rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-guid sub should be 401, got %d", rec.Code)
	}
}

func TestJWTBadIssuerRejected(t *testing.T) {
	h := newJWTHarness(t)
	tok := makeJWT(t, map[string]any{"iss": "https://evil", "sub": uuid.NewString(), "aud": []string{"web"}, "exp": time.Now().Add(time.Hour).Unix()})
	if rec := bearer(h, t, "/api/v1/me", tok); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad issuer should be 401, got %d", rec.Code)
	}
}

// Ensure the access-key path still wins when both could apply.
func TestAccessKeyStillWorksWithVerifier(t *testing.T) {
	h := newJWTHarness(t)
	hash := sha256.Sum256([]byte(h.secret))
	_ = hash
	if rec := h.do(t, "GET", "/api/v1/api-keys", nil, true); rec.Code != 200 {
		t.Fatalf("access key %d", rec.Code)
	}
}
