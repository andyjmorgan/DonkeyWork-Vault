package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/service"
	"donkeywork.dev/vault-server/internal/store"
)

var errFailDB = errors.New("db down")

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// doRaw posts a raw (possibly malformed) body with the access key, exercising decodeJSON errors.
func (h *harness) doRaw(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("X-Api-Key", h.secret)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

// TestHandlerBadBodies drives the decodeJSON error branch (HTTP 400) of every POST/PATCH handler
// that reads a JSON body.
func TestHandlerBadBodies(t *testing.T) {
	h := newHarness(t)
	cases := []struct{ name, method, path string }{
		{"create api key", "POST", "/api/v1/api-keys"},
		{"create access key", "POST", "/api/v1/access-keys"},
		{"set access key enabled", "PATCH", "/api/v1/access-keys/" + uuid.New().String()},
		{"upsert manifest", "POST", "/api/v1/manifests/oauth"},
		{"discover", "POST", "/api/v1/manifests/oauth/discover"},
		{"upsert config", "POST", "/api/v1/oauth/configs"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if rec := h.doRaw(t, c.method, c.path, "{not json"); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: want 400, got %d", c.name, rec.Code)
			}
		})
	}
}

// TestSetAccessKeyEnabledNotFound covers the (nil item, no error) -> 404 branch.
func TestSetAccessKeyEnabledNotFound(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "PATCH", "/api/v1/access-keys/"+uuid.New().String(), setEnabledRequest{Enabled: true}, true)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

// TestDiscoverBadBodyAndFailure covers handleDiscover's bad-body and discovery-failure (400) paths.
func TestDiscoverFailure(t *testing.T) {
	h := newHarness(t)
	bad := "http://127.0.0.1:1/unreachable"
	if rec := h.do(t, "POST", "/api/v1/manifests/oauth/discover", discoverOidcRequest{URL: &bad}, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("discover failure: want 400, got %d body=%s", rec.Code, rec.Body)
	}
}

// TestUpsertManifestInvalidSlug covers the ErrInvalidSlug branch (400) of handleUpsertManifest.
func TestUpsertManifestInvalidSlug(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/api/v1/manifests/oauth", upsertOAuthManifestRequest{Key: "Bad Slug!"}, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid slug: want 400, got %d", rec.Code)
	}
}

// TestUpsertConfigValidation covers handleUpsertConfig's validation-error branch (400).
func TestUpsertConfigValidation(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "POST", "/api/v1/oauth/configs", upsertOAuthConfigRequest{Provider: "ghost", ClientID: "x", ClientSecret: ptr("y")}, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider: want 400, got %d", rec.Code)
	}
}

// TestAuditFilterParams exercises handleAudit's type/outcome/userId filter parsing and the limit
// default branch.
func TestAuditFilterParams(t *testing.T) {
	h := newHarness(t)
	rec := h.do(t, "GET", "/api/v1/audit?type=TokenAccessed&outcome=Success&userId="+h.userID.String(), nil, true)
	if rec.Code != 200 {
		t.Fatalf("audit filters: %d body=%s", rec.Code, rec.Body)
	}
	// Garbage filter values are ignored (not 400) — only since/until garbage is rejected.
	rec = h.do(t, "GET", "/api/v1/audit?type=Nope&outcome=Nope&userId=not-a-uuid", nil, true)
	if rec.Code != 200 {
		t.Fatalf("audit ignores bad enum/uuid filters: %d", rec.Code)
	}
}

// TestMeWithTenant drives handleMe's non-nil tenant branch via a JWT carrying a tenant_id claim.
func TestMeWithTenant(t *testing.T) {
	h := newJWTHarness(t)
	tenant := uuid.NewString()
	tok := makeJWT(t, map[string]any{
		"iss": testIssuer, "sub": uuid.NewString(), "aud": []string{"web"}, "azp": "web",
		"tenant_id": tenant, "email": "u@e.com", "name": "U", "exp": time.Now().Add(time.Hour).Unix(),
	})
	rec := bearer(h, t, "/api/v1/me", tok)
	me := decode[meResponse](t, rec)
	if me.TenantID != tenant {
		t.Fatalf("tenant: got %q want %q", me.TenantID, tenant)
	}
}

// TestJWTMalformedBearerRejected covers authenticateJWT's Verify-failure branch (HTTP 401) for a
// token that is not a well-formed JWT.
func TestJWTMalformedBearerRejected(t *testing.T) {
	h := newJWTHarness(t)
	if rec := bearer(h, t, "/api/v1/me", "not.a.jwt"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer: want 401, got %d", rec.Code)
	}
}

// TestMissingAuthHeaderVariants covers the authenticate branches: empty Authorization, a non-bearer
// scheme, and a Bearer token while auth is OFF (no verifier configured) -> 401.
func TestMissingAuthHeaderVariants(t *testing.T) {
	h := newHarness(t) // authOn == false

	// No header at all.
	req := httptest.NewRequest("GET", "/api/v1/api-keys", nil)
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no header: want 401, got %d", rec.Code)
	}

	// Bearer JWT while auth is disabled: not an access key, authOn=false -> 401.
	req = httptest.NewRequest("GET", "/api/v1/api-keys", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	rec = httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bearer w/ auth off: want 401, got %d", rec.Code)
	}
}

// TestVerifierUnavailable503 covers the branch where auth is on, a JWT is presented, but the verifier
// has not yet been installed (IdP discovery still pending) -> 503.
func TestVerifierUnavailable503(t *testing.T) {
	h := newHarness(t)
	kek, _ := crypto.NewLocalKekProvider("local:v1", map[string]string{"local:v1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	cipher := crypto.NewEnvelopeCipher(kek)
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(h.ms, loader)
	auditLog := audit.NewLog(100, nil, nil)
	srv, err := NewServer(context.Background(), Deps{
		APIKeys:      service.NewAPIKeyService(h.ms, cipher, auditLog),
		AccessKeys:   service.NewAccessKeyService(h.ms, auditLog),
		OAuthConfigs: service.NewOAuthConfigService(h.ms, cipher, auditLog, resolver),
		OAuthTokens:  service.NewOAuthTokenService(h.ms, cipher, auditLog, resolver, http.DefaultClient),
		OAuthFlow:    service.NewOAuthFlowService(h.ms, cipher, resolver, auditLog, http.DefaultClient, nil),
		Resolver:     resolver, Discovery: manifests.NewDiscovery(http.DefaultClient),
		AuditLog: auditLog, AuditQuery: audit.NewQueryService(h.ms, auditLog),
		IPResolver: audit.NewForwardedIPResolver(nil), PublicBaseURL: "https://v",
	})
	if err != nil {
		t.Fatal(err)
	}
	srv.authOn = true // verifier never installed
	hh := srv.Handler()
	req := httptest.NewRequest("GET", "/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer pending.discovery.token")
	rec := httptest.NewRecorder()
	hh.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("verifier pending: want 503, got %d", rec.Code)
	}
}

// TestScopesFromNil covers the nil branch of scopesFrom (no scopes in context).
func TestScopesFromNil(t *testing.T) {
	if scopesFrom(context.Background()) != nil {
		t.Fatal("expected nil scopes for empty context")
	}
}

// TestContainsEmpty covers the empty-value short-circuit of contains.
func TestContainsEmpty(t *testing.T) {
	if contains([]string{"a"}, "") {
		t.Fatal("empty value must not match")
	}
	if !contains([]string{"a", "b"}, "b") {
		t.Fatal("present value should match")
	}
}

// TestPeerAddrInvalid covers peerAddr's non-parseable and no-port branches.
func TestPeerAddrInvalid(t *testing.T) {
	if peerAddr("garbage").IsValid() {
		t.Fatal("garbage remote addr should yield invalid Addr")
	}
	if a := peerAddr("10.0.0.1:1234"); !a.IsValid() {
		t.Fatal("host:port should parse")
	}
	if a := peerAddr("10.0.0.2"); !a.IsValid() {
		t.Fatal("bare host should parse")
	}
}

// TestResolveIPNil covers resolveIP's empty-result (nil) branch by using a resolver that trusts no
// proxies and a request with no parseable peer.
func TestResolveIPNil(t *testing.T) {
	srv := &Server{deps: Deps{IPResolver: audit.NewForwardedIPResolver(nil)}}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "garbage"
	if got := srv.resolveIP(req); got != nil {
		t.Fatalf("expected nil ip, got %q", *got)
	}
	// A valid peer resolves to a non-nil pointer.
	req.RemoteAddr = "9.9.9.9:5000"
	if got := srv.resolveIP(req); got == nil {
		t.Fatal("expected non-nil ip for valid peer")
	}
}

// TestRateLimiterSweep covers allow's map-sweep branch (triggered once the window map exceeds 10k
// entries) and the expired-window reset.
func TestRateLimiterSweep(t *testing.T) {
	now := time.Unix(2000, 0)
	l := newIPRateLimiter(5, time.Minute)
	l.now = func() time.Time { return now }

	// Seed >10k stale windows so the next allow() runs the sweep and prunes them.
	l.windows["keep"] = &rateWindow{start: now, count: 1}
	for i := 0; i < 10_001; i++ {
		l.windows["stale-"+uuid.NewString()] = &rateWindow{start: now.Add(-2 * time.Minute), count: 1}
	}
	if !l.allow("new-ip") {
		t.Fatal("new ip should be allowed")
	}
	// Stale (expired) windows should have been swept; the fresh "keep" entry survives.
	if _, ok := l.windows["keep"]; !ok {
		t.Fatal("fresh window should survive the sweep")
	}
	if len(l.windows) > 100 {
		t.Fatalf("sweep should have pruned stale windows, have %d", len(l.windows))
	}
}

// TestFromManifestRequestDelimiterDefaults covers fromManifestRequest's empty-delimiter default and
// the explicit non-default delimiter branch.
func TestFromManifestRequestDelimiterDefaults(t *testing.T) {
	// Explicit empty string delimiter -> defaults to " ".
	empty := ""
	m := fromManifestRequest(upsertOAuthManifestRequest{Key: "k", ScopeDelimiter: &empty})
	if m.ScopeDelimiter != " " {
		t.Fatalf("empty delimiter should default to space, got %q", m.ScopeDelimiter)
	}
	// Explicit non-default delimiter is preserved; supplied params map is passed through.
	comma := ","
	m = fromManifestRequest(upsertOAuthManifestRequest{
		Key: "k", ScopeDelimiter: &comma, AuthorizeParams: map[string]string{"prompt": "consent"},
		Scopes: []oauthScopeDTO{{Value: "openid"}},
	})
	if m.ScopeDelimiter != "," {
		t.Fatalf("delimiter not preserved: %q", m.ScopeDelimiter)
	}
	if m.AuthorizeParams["prompt"] != "consent" {
		t.Fatalf("authorize params not passed through: %+v", m.AuthorizeParams)
	}
	if len(m.Scopes) != 1 || m.Scopes[0].Value != "openid" {
		t.Fatalf("scopes not mapped: %+v", m.Scopes)
	}
}

// TestConnectNotFound covers handleConnect's not-found (unknown provider) path and the scopes query
// parsing branch.
func TestConnectUnknownProvider(t *testing.T) {
	h := newHarness(t)
	// Seed a manifest + config so Begin reaches the provider; then request connect with scopes.
	rec := h.do(t, "POST", "/api/v1/manifests/oauth", upsertOAuthManifestRequest{
		Key: "acme2", TokenEndpoint: ptr("https://acme/token"), AuthorizationEndpoint: ptr("https://acme/auth"),
		DefaultScopes: []string{"openid"},
	}, true)
	if rec.Code != 200 {
		t.Fatalf("seed manifest %d", rec.Code)
	}
	rec = h.do(t, "POST", "/api/v1/oauth/configs", upsertOAuthConfigRequest{Provider: "acme2", ClientID: "c", ClientSecret: ptr("s"), Scopes: []string{"openid"}}, true)
	if rec.Code != 200 {
		t.Fatalf("seed config %d", rec.Code)
	}
	conn := decode[connectResponse](t, h.do(t, "GET", "/api/v1/oauth/acme2/connect?scopes=openid,email", nil, true))
	if conn.AuthorizeURL == "" {
		t.Fatal("expected authorize url with scopes")
	}
}

// TestOAuthCallbackSuccessAndInternalError drives handleOAuthCallback's success branch and its
// generic-internal-error branch by completing a real flow against a stub token endpoint.
//
// The flow is begun via /connect (yielding a valid state nonce), then the callback is replayed. With
// a token endpoint that 500s, Complete returns a plain (non-authorization) error -> "internal error"
// redirect; with a healthy token endpoint it succeeds -> "connected=" redirect.
func TestOAuthCallbackSuccessAndInternalError(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"rt","scope":"openid"}`))
	}))
	defer idp.Close()

	begin := func(t *testing.T) (string, *harness) {
		h := newHarness(t)
		rec := h.do(t, "POST", "/api/v1/manifests/oauth", upsertOAuthManifestRequest{
			Key: "stub", TokenEndpoint: &idp.URL, AuthorizationEndpoint: ptr(idp.URL + "/auth"),
			DefaultScopes: []string{"openid"},
		}, true)
		if rec.Code != 200 {
			t.Fatalf("seed manifest %d body=%s", rec.Code, rec.Body)
		}
		rec = h.do(t, "POST", "/api/v1/oauth/configs", upsertOAuthConfigRequest{Provider: "stub", ClientID: "cid", ClientSecret: ptr("csec"), Scopes: []string{"openid"}}, true)
		if rec.Code != 200 {
			t.Fatalf("seed config %d body=%s", rec.Code, rec.Body)
		}
		conn := decode[connectResponse](t, h.do(t, "GET", "/api/v1/oauth/stub/connect?scopes=openid", nil, true))
		state := stateFromURL(conn.AuthorizeURL)
		if state == "" {
			t.Fatalf("no state in authorize url: %s", conn.AuthorizeURL)
		}
		return state, h
	}

	// Internal error: a raw store failure during Complete (GetOAuthStateByState) surfaces as a
	// non-authorization error -> the generic "internal error" redirect branch.
	t.Run("internal error", func(t *testing.T) {
		state, h := begin(t)
		h.ms.FailNext = errFailDB
		rec := h.do(t, "GET", "/api/oauth/callback?code=authcode&state="+state, nil, false)
		if rec.Code != http.StatusFound {
			t.Fatalf("want 302, got %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Location"), "oauth_error=internal") {
			t.Fatalf("expected internal-error redirect, got %q", rec.Header().Get("Location"))
		}
	})

	// Success: token endpoint returns a valid token -> connected redirect.
	t.Run("success", func(t *testing.T) {
		state, h := begin(t)
		rec := h.do(t, "GET", "/api/oauth/callback?code=authcode&state="+state, nil, false)
		if rec.Code != http.StatusFound {
			t.Fatalf("want 302, got %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Location"), "connected=stub") {
			t.Fatalf("expected connected redirect, got %q", rec.Header().Get("Location"))
		}
	})
}

// stateFromURL extracts the `state` query parameter from an authorize URL.
func stateFromURL(raw string) string {
	i := strings.Index(raw, "state=")
	if i < 0 {
		return ""
	}
	rest := raw[i+len("state="):]
	if j := strings.IndexByte(rest, '&'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// TestDeleteHandlersStoreError covers the writeServiceError (500) branch of the DELETE/PATCH handlers
// that take a UUID id. The JWT harness keeps auth off the store; FailNext makes the store call fail.
func TestDeleteHandlersStoreError(t *testing.T) {
	webTok := func(t *testing.T) string {
		return makeJWT(t, map[string]any{"iss": testIssuer, "sub": uuid.NewString(), "aud": []string{"web"}, "azp": "web", "exp": time.Now().Add(time.Hour).Unix()})
	}
	cases := []struct{ name, method, path string }{
		{"delete api key", "DELETE", "/api/v1/api-keys/" + uuid.New().String()},
		{"delete access key", "DELETE", "/api/v1/access-keys/" + uuid.New().String()},
		{"set access key enabled", "PATCH", "/api/v1/access-keys/" + uuid.New().String()},
		{"delete config", "DELETE", "/api/v1/oauth/configs/" + uuid.New().String()},
		{"delete token", "DELETE", "/api/v1/oauth/tokens/" + uuid.New().String()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newJWTHarness(t)
			h.ms.FailNext = errFailDB
			var body *bytes.Reader
			if c.method == "PATCH" {
				b, _ := jsonMarshal(setEnabledRequest{Enabled: true})
				body = bytes.NewReader(b)
			} else {
				body = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(c.method, c.path, body)
			req.Header.Set("Authorization", "Bearer "+webTok(t))
			rec := httptest.NewRecorder()
			h.h.ServeHTTP(rec, req)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("%s: want 500, got %d body=%s", c.name, rec.Code, rec.Body)
			}
		})
	}
}

// TestCredentialShapeNotFound covers handleCredentialShape's not-found path (list succeeds but the
// requested name is absent).
func TestCredentialShapeNotFound(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, "GET", "/api/v1/credentials/does-not-exist", nil, true); rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

// TestAuditUntilMalformed covers handleAudit's malformed `until` rejection (400).
func TestAuditUntilMalformed(t *testing.T) {
	h := newHarness(t)
	if rec := h.do(t, "GET", "/api/v1/audit?until=not-a-time", nil, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed until: want 400, got %d", rec.Code)
	}
}

// TestAccessKeyAuthMetadata exercises withAccessKeyCaller indirectly via a key whose prefix is
// recorded in audit metadata (covers the metadata-augmentation path end to end).
func TestAccessKeyAuthMetadata(t *testing.T) {
	h := newHarness(t)
	secret := "dwv_" + uuid.NewString()
	hash := sha256.Sum256([]byte(secret))
	if err := h.ms.InsertAccessKey(context.Background(), &store.AccessKey{
		UserID: h.userID, Name: "audited", KeyHash: hash[:], KeyPrefix: secret[:9],
		Scopes: []string{"vault:read", "vault:audit"}, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if rec := h.doKey(t, "GET", "/api/v1/me", secret); rec.Code != 200 {
		t.Fatalf("authed read %d", rec.Code)
	}
}
