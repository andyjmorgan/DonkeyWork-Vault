package httpapi

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

// keyWithScopes seeds an access key with the given scopes and returns its secret.
func (h *harness) keyWithScopes(t *testing.T, scopes ...string) string {
	t.Helper()
	secret := "dwv_" + uuid.NewString()
	hash := sha256.Sum256([]byte(secret))
	if err := h.ms.InsertAccessKey(context.Background(), &store.AccessKey{
		UserID: h.userID, Name: "scoped-" + uuid.NewString()[:8], KeyHash: hash[:], KeyPrefix: secret[:9],
		Scopes: scopes, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	return secret
}

func (h *harness) doKey(t *testing.T, method, path, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func TestScopeGateDenies(t *testing.T) {
	h := newHarness(t)
	readOnly := h.keyWithScopes(t, "vault:read")

	// read is allowed
	if rec := h.doKey(t, "GET", "/api/v1/api-keys", readOnly); rec.Code != 200 {
		t.Fatalf("read allowed: %d", rec.Code)
	}
	// write denied (needs vault:readwrite)
	if rec := h.doKey(t, "DELETE", "/api/v1/api-keys/"+uuid.New().String(), readOnly); rec.Code != http.StatusForbidden {
		t.Fatalf("write should be 403, got %d", rec.Code)
	}
	// audit denied (needs vault:audit)
	if rec := h.doKey(t, "GET", "/api/v1/audit", readOnly); rec.Code != http.StatusForbidden {
		t.Fatalf("audit should be 403, got %d", rec.Code)
	}
}

func TestReadWriteImpliesRead(t *testing.T) {
	h := newHarness(t)
	rw := h.keyWithScopes(t, "vault:readwrite")
	if rec := h.doKey(t, "GET", "/api/v1/api-keys", rw); rec.Code != 200 {
		t.Fatalf("readwrite implies read: %d", rec.Code)
	}
}

func TestDiscover(t *testing.T) {
	h := newHarness(t)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/auth","token_endpoint":"https://idp.example/token","userinfo_endpoint":"https://idp.example/me","scopes_supported":["openid","email","custom"]}`))
	}))
	defer idp.Close()

	rec := h.do(t, "POST", "/api/v1/manifests/oauth/discover", discoverOidcRequest{URL: &idp.URL}, true)
	if rec.Code != 200 {
		t.Fatalf("discover %d body=%s", rec.Code, rec.Body)
	}
	m := decode[oauthManifestDTO](t, rec)
	if m.TokenEndpoint != "https://idp.example/token" {
		t.Fatalf("discover mapping: %+v", m)
	}

	// bad URL -> 400
	bad := "http://127.0.0.1:1/nope"
	if rec := h.do(t, "POST", "/api/v1/manifests/oauth/discover", discoverOidcRequest{URL: &bad}, true); rec.Code != 400 {
		t.Fatalf("discover bad %d", rec.Code)
	}
}

func TestDeleteManifestMissing(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, "DELETE", "/api/v1/manifests/oauth/ghost", nil, true); rec.Code != 404 {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestGetTokenSuccessAndAuditItems(t *testing.T) {
	h := newHarness(t)
	pid := uuid.New()
	// Seed a provider manifest row (key -> provider id) and a fresh token under it.
	if err := h.ms.InsertManifest(context.Background(), &store.ProviderManifest{
		UserID: h.userID, Kind: "oauth", Key: "acme", ProviderID: pid, DocumentJSON: `{"key":"acme"}`,
	}); err != nil {
		t.Fatal(err)
	}
	live, _ := h.cipher.EncryptString("live-token")
	future := timeFuture()
	if err := h.ms.InsertOAuthToken(context.Background(), &store.OAuthToken{
		UserID: h.userID, ProviderID: pid, ProviderKey: "acme", Account: "a@b.com",
		AccessTokenCipher: live, RefreshTokenCipher: []byte{1}, ScopesJSON: ptr(`["openid"]`), ExpiresAt: &future,
	}); err != nil {
		t.Fatal(err)
	}

	// token list (toTokenDTO)
	if l := decode[[]oauthTokenDTO](t, h.do(t, "GET", "/api/v1/oauth/tokens", nil, true)); len(l) != 1 || l[0].Provider != "acme" {
		t.Fatalf("token list: %+v", l)
	}
	// live token (handleGetToken success path)
	tok := decode[oauthAccessTokenResponse](t, h.do(t, "GET", "/api/v1/oauth/acme/token", nil, true))
	if tok.AccessToken != "live-token" {
		t.Fatalf("get token: %+v", tok)
	}

	// Seed audit rows for this user so the query maps them (toAuditDTO).
	ip := "1.2.3.4"
	if err := h.ms.InsertAuditBatch(context.Background(), []store.AuditEntry{{
		EventType: 1, Outcome: 0, UserID: h.userID, SourceIP: &ip, Transport: "http",
		TargetKind: ptr("oauth_token"), CreatedAt: timeFuture().Add(-time.Hour), Headers: map[string]string{},
	}}); err != nil {
		t.Fatal(err)
	}
	page := decode[auditPageResponse](t, h.do(t, "GET", "/api/v1/audit?type=TokenAccessed&outcome=Success", nil, true))
	if len(page.Items) != 1 || page.Items[0].Type != "TokenAccessed" {
		t.Fatalf("audit items: %+v", page)
	}
}

func timeFuture() time.Time { return time.Now().Add(time.Hour) }
