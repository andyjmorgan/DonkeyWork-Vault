package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

type harness struct {
	h      http.Handler
	ms     *memstore.Mem
	cipher crypto.Cipher
	userID uuid.UUID
	secret string // access-key secret with read+write+audit scopes
}

func newHarness(t *testing.T) *harness {
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
	auditLog := audit.NewLog(1000, nil, nil)

	u := uuid.New()
	secret := "dwv_testsecretvalue"
	hash := sha256.Sum256([]byte(secret))
	_ = ms.InsertAccessKey(context.Background(), &store.AccessKey{
		UserID: u, Name: "test", KeyHash: hash[:], KeyPrefix: secret[:9],
		Scopes: []string{"vault:read", "vault:readwrite", "vault:audit"}, Enabled: true,
	})

	deps := Deps{
		APIKeys:       service.NewAPIKeyService(ms, cipher, auditLog),
		AccessKeys:    service.NewAccessKeyService(ms, auditLog),
		OAuthConfigs:  service.NewOAuthConfigService(ms, cipher, auditLog, resolver),
		OAuthTokens:   service.NewOAuthTokenService(ms, cipher, auditLog, resolver, http.DefaultClient),
		OAuthFlow:     service.NewOAuthFlowService(ms, cipher, resolver, auditLog, http.DefaultClient, nil),
		Resolver:      resolver,
		Discovery:     manifests.NewDiscovery(http.DefaultClient),
		AuditLog:      auditLog,
		AuditQuery:    audit.NewQueryService(ms, auditLog),
		IPResolver:    audit.NewForwardedIPResolver([]string{"127.0.0.1/32"}),
		PublicBaseURL: "https://vault.example",
	}
	srv, err := NewServer(context.Background(), deps)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{h: srv.Handler(), ms: ms, cipher: cipher, userID: u, secret: secret}
}

func (h *harness) do(t *testing.T, method, path string, body any, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if auth {
		req.Header.Set("X-Api-Key", h.secret)
	}
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %T: %v body=%s", v, err, rec.Body.String())
	}
	return v
}

func TestHealthAndConfig(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, "GET", "/healthz", nil, false); rec.Code != 200 {
		t.Fatalf("healthz %d", rec.Code)
	}
	rec := h.do(t, "GET", "/api/config", nil, false)
	cfg := decode[appConfigResponse](t, rec)
	if cfg.AuthEnabled {
		t.Fatal("auth should be disabled without OIDC")
	}
}

func TestUnauthenticated401(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, "GET", "/api/v1/api-keys", nil, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestBadAccessKey401(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest("GET", "/api/v1/api-keys", nil)
	req.Header.Set("X-Api-Key", "dwv_wrong")
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestMe(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "GET", "/api/v1/me", nil, true)
	me := decode[meResponse](t, rec)
	if me.UserID == nil || *me.UserID != h.userID.String() {
		t.Fatalf("me userId mismatch: %+v", me)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	h := newHarness(t)
	// create
	rec := h.do(t, "POST", "/api/v1/api-keys", createAPIKeyRequest{Name: "grafana", Secret: ptr("s3cr3t"), Header: ptr("Authorization"), Prefix: ptr("Bearer "), Kind: "header_api_key"}, true)
	if rec.Code != 200 {
		t.Fatalf("create %d body=%s", rec.Code, rec.Body)
	}
	created := decode[createdAPIKeyResponse](t, rec)

	// list
	list := decode[[]apiKeyDTO](t, h.do(t, "GET", "/api/v1/api-keys", nil, true))
	if len(list) != 1 || list[0].Name != "grafana" {
		t.Fatalf("list %+v", list)
	}

	// reveal
	rev := decode[revealAPIKeyResponse](t, h.do(t, "GET", "/api/v1/api-keys/grafana/reveal", nil, true))
	if rev.Secret != "s3cr3t" || rev.HeaderValue != "Bearer s3cr3t" {
		t.Fatalf("reveal %+v", rev)
	}

	// credential shape (no secret)
	shape := decode[credentialShapeResponse](t, h.do(t, "GET", "/api/v1/credentials/grafana", nil, true))
	if shape.Scheme != "header" {
		t.Fatalf("shape %+v", shape)
	}

	// reveal missing -> 404
	if rec := h.do(t, "GET", "/api/v1/api-keys/nope/reveal", nil, true); rec.Code != 404 {
		t.Fatalf("reveal missing %d", rec.Code)
	}

	// delete
	if rec := h.do(t, "DELETE", "/api/v1/api-keys/"+created.ID.String(), nil, true); rec.Code != 204 {
		t.Fatalf("delete %d", rec.Code)
	}
	if rec := h.do(t, "DELETE", "/api/v1/api-keys/"+created.ID.String(), nil, true); rec.Code != 404 {
		t.Fatalf("delete again %d", rec.Code)
	}
}

func TestAPIKeyValidation(t *testing.T) {
	h := newHarness(t)
	// missing name
	if rec := h.do(t, "POST", "/api/v1/api-keys", createAPIKeyRequest{Secret: ptr("x")}, true); rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	// basic auth username with colon
	if rec := h.do(t, "POST", "/api/v1/api-keys", createAPIKeyRequest{Name: "x", Secret: ptr("p"), Username: ptr("a:b")}, true); rec.Code != 400 {
		t.Fatalf("expected 400 colon, got %d", rec.Code)
	}
	// malformed body
	req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader([]byte("{bad")))
	req.Header.Set("X-Api-Key", h.secret)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("malformed body %d", rec.Code)
	}
}

func TestAccessKeyLifecycle(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/api/v1/access-keys", createAccessKeyRequest{Name: "ci", Scopes: []string{"vault:read"}}, true)
	if rec.Code != 200 {
		t.Fatalf("create %d body=%s", rec.Code, rec.Body)
	}
	created := decode[createdAccessKeyResponse](t, rec)
	if created.Secret == "" {
		t.Fatal("expected secret")
	}
	// invalid scope
	if rec := h.do(t, "POST", "/api/v1/access-keys", createAccessKeyRequest{Name: "bad", Scopes: []string{"vault:root"}}, true); rec.Code != 400 {
		t.Fatalf("invalid scope %d", rec.Code)
	}
	// patch enable
	rec = h.do(t, "PATCH", "/api/v1/access-keys/"+created.ID.String(), setEnabledRequest{Enabled: false}, true)
	if rec.Code != 200 || decode[accessKeyEnabledResponse](t, rec).Enabled {
		t.Fatalf("patch %d", rec.Code)
	}
	// patch missing
	if rec := h.do(t, "PATCH", "/api/v1/access-keys/"+uuid.New().String(), setEnabledRequest{Enabled: true}, true); rec.Code != 404 {
		t.Fatalf("patch missing %d", rec.Code)
	}
	// list + delete
	if l := decode[[]accessKeyDTO](t, h.do(t, "GET", "/api/v1/access-keys", nil, true)); len(l) != 2 {
		t.Fatalf("list %d", len(l))
	}
	if rec := h.do(t, "DELETE", "/api/v1/access-keys/"+created.ID.String(), nil, true); rec.Code != 204 {
		t.Fatalf("delete %d", rec.Code)
	}
}

func TestManifestAndConfigCRUD(t *testing.T) {
	h := newHarness(t)
	// templates (embedded library)
	tmpls := decode[[]oauthManifestDTO](t, h.do(t, "GET", "/api/v1/manifests/templates", nil, true))
	if len(tmpls) == 0 {
		t.Fatal("expected embedded templates")
	}
	// add a provider
	rec := h.do(t, "POST", "/api/v1/manifests/oauth", upsertOAuthManifestRequest{
		Key: "acme", TokenEndpoint: ptr("https://acme/token"), AuthorizationEndpoint: ptr("https://acme/auth"),
		DefaultScopes: []string{"openid"},
	}, true)
	if rec.Code != 200 {
		t.Fatalf("upsert manifest %d body=%s", rec.Code, rec.Body)
	}
	// invalid slug
	if rec := h.do(t, "POST", "/api/v1/manifests/oauth", upsertOAuthManifestRequest{Key: "bad slug!"}, true); rec.Code != 400 {
		t.Fatalf("invalid slug %d", rec.Code)
	}
	// list providers
	if l := decode[[]oauthManifestDTO](t, h.do(t, "GET", "/api/v1/manifests", nil, true)); len(l) != 1 {
		t.Fatalf("manifests %d", len(l))
	}
	// add config
	rec = h.do(t, "POST", "/api/v1/oauth/configs", upsertOAuthConfigRequest{Provider: "acme", ClientID: "cid", ClientSecret: ptr("csec"), Scopes: []string{"openid"}}, true)
	if rec.Code != 200 {
		t.Fatalf("upsert config %d body=%s", rec.Code, rec.Body)
	}
	cfg := decode[oauthConfigCreatedResponse](t, rec)
	// list configs (masked)
	if l := decode[[]oauthConfigDTO](t, h.do(t, "GET", "/api/v1/oauth/configs", nil, true)); len(l) != 1 {
		t.Fatalf("configs %d", len(l))
	}
	// connect builds an authorize URL
	conn := decode[connectResponse](t, h.do(t, "GET", "/api/v1/oauth/acme/connect?scopes=openid", nil, true))
	if conn.AuthorizeURL == "" {
		t.Fatal("expected authorize url")
	}
	// config for unknown provider -> 400
	if rec := h.do(t, "POST", "/api/v1/oauth/configs", upsertOAuthConfigRequest{Provider: "ghost", ClientID: "x", ClientSecret: ptr("y")}, true); rec.Code != 400 {
		t.Fatalf("unknown provider %d", rec.Code)
	}
	// delete config + manifest
	if rec := h.do(t, "DELETE", "/api/v1/oauth/configs/"+cfg.ID.String(), nil, true); rec.Code != 204 {
		t.Fatalf("delete config %d", rec.Code)
	}
	if rec := h.do(t, "DELETE", "/api/v1/manifests/oauth/acme", nil, true); rec.Code != 204 {
		t.Fatalf("delete manifest %d", rec.Code)
	}
}

func TestTokensAndAudit(t *testing.T) {
	h := newHarness(t)
	// no tokens yet
	if l := decode[[]oauthTokenDTO](t, h.do(t, "GET", "/api/v1/oauth/tokens", nil, true)); len(l) != 0 {
		t.Fatalf("tokens %d", len(l))
	}
	// token for unknown provider -> 404
	if rec := h.do(t, "GET", "/api/v1/oauth/ghost/token", nil, true); rec.Code != 404 {
		t.Fatalf("unknown token %d", rec.Code)
	}
	// audit endpoint (vault:audit scope present)
	rec := h.do(t, "GET", "/api/v1/audit?limit=10", nil, true)
	if rec.Code != 200 {
		t.Fatalf("audit %d body=%s", rec.Code, rec.Body)
	}
	page := decode[auditPageResponse](t, rec)
	if page.Limit != 10 {
		t.Fatalf("audit limit %d", page.Limit)
	}
}

func TestOAuthCallbackErrors(t *testing.T) {
	h := newHarness(t)
	// provider error param
	rec := h.do(t, "GET", "/api/oauth/callback?error=access_denied", nil, false)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback error redirect %d", rec.Code)
	}
	// missing code
	rec = h.do(t, "GET", "/api/oauth/callback", nil, false)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback missing code %d", rec.Code)
	}
	// invalid state
	rec = h.do(t, "GET", "/api/oauth/callback?code=x&state=nope", nil, false)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback bad state %d", rec.Code)
	}
}

func ptr(s string) *string { return &s }
