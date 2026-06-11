package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

// errFailNext is the canonical store error used by these tests.
var errFailNext = errors.New("store boom")

// touchFailStore embeds the in-memory store and overrides the best-effort "touch last used"
// methods so a test can let the preceding lookup succeed and then fail only the touch. The
// memstore's FailNext fails the *next* call, which would trip the lookup, so this targeted
// override is the only way to reach the touch-error branches.
type touchFailStore struct {
	*memstore.Mem
	failAccessTouch bool
	failAPITouch    bool
}

func (s *touchFailStore) TouchAccessKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	if s.failAccessTouch {
		return errFailNext
	}
	return s.Mem.TouchAccessKeyLastUsed(ctx, id)
}

func (s *touchFailStore) TouchAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	if s.failAPITouch {
		return errFailNext
	}
	return s.Mem.TouchAPIKeyLastUsed(ctx, id)
}

// ---- accesskey.go ----

func TestAccessKeyCreateInvalidScope(t *testing.T) {
	ms := memstore.New()
	svc := NewAccessKeyService(ms, audit.NewLog(10, nil, nil))
	ctx := callerCtx()

	// A scope not in ValidScopes is rejected.
	if _, _, err := svc.Create(ctx, "k", nil, []string{"vault:read", "vault:bogus"}); err == nil {
		t.Fatal("expected invalid scope error")
	}
	// Whitespace-only scopes are normalised away, leaving none -> scope required.
	if _, _, err := svc.Create(ctx, "k", nil, []string{"  ", ""}); err == nil {
		t.Fatal("expected scope required after normalisation")
	}
}

func TestAccessKeyCreateInsertError(t *testing.T) {
	ms := memstore.New()
	svc := NewAccessKeyService(ms, audit.NewLog(10, nil, nil))
	ctx := callerCtx()
	ms.FailNext = errFailNext // InsertAccessKey is the first store call
	if _, _, err := svc.Create(ctx, "k", nil, []string{"vault:read"}); err == nil {
		t.Fatal("expected insert error")
	}
}

func TestAccessKeyList(t *testing.T) {
	ms := memstore.New()
	svc := NewAccessKeyService(ms, audit.NewLog(10, nil, nil))
	ctx := callerCtx()
	if _, _, err := svc.Create(ctx, "a", nil, []string{"vault:read"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Create(ctx, "b", nil, []string{"vault:readwrite"}); err != nil {
		t.Fatal(err)
	}
	list, err := svc.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %+v %v", list, err)
	}
	// store error path
	ms.FailNext = errFailNext
	if _, err := svc.List(ctx); err == nil {
		t.Fatal("expected list error")
	}
}

func TestAccessKeyAuthenticateStoreError(t *testing.T) {
	ms := memstore.New()
	svc := NewAccessKeyService(ms, audit.NewLog(10, nil, nil))
	ctx := callerCtx()
	ms.FailNext = errFailNext // GetAccessKeyByHash fails
	if _, err := svc.Authenticate(ctx, "dwv_whatever"); err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestAccessKeyAuthenticateTouchFailureStillSucceeds(t *testing.T) {
	ms := &touchFailStore{Mem: memstore.New(), failAccessTouch: true}
	svc := NewAccessKeyService(ms, audit.NewLog(10, nil, nil))
	ctx := callerCtx()
	_, secret, err := svc.Create(ctx, "ci", nil, []string{"vault:read"})
	if err != nil {
		t.Fatal(err)
	}
	// A failing touch is logged but must NOT reject a valid key.
	p, err := svc.Authenticate(ctx, secret)
	if err != nil || p == nil || p.Name != "ci" {
		t.Fatalf("auth despite touch failure: %+v %v", p, err)
	}
}

// ---- apikey.go ----

func TestAPIKeyCreateValidation(t *testing.T) {
	ms := memstore.New()
	svc := NewAPIKeyService(ms, testCipher(t), audit.NewLog(10, nil, nil))
	ctx := callerCtx()

	// blank name
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "  "}); err == nil {
		t.Fatal("expected name required")
	}
	// username containing ':' is rejected
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "k", Secret: strPtr("s"), Username: strPtr("a:b")}); err == nil {
		t.Fatal("expected username-with-colon error")
	}
	// create without secret -> error
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "k"}); err == nil {
		t.Fatal("expected secret required")
	}
}

func TestAPIKeyCreateStoreErrors(t *testing.T) {
	ms := memstore.New()
	svc := NewAPIKeyService(ms, testCipher(t), audit.NewLog(10, nil, nil))
	ctx := callerCtx()

	// GetAPIKeyByName fails (first store call in Create)
	ms.FailNext = errFailNext
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "k", Secret: strPtr("s")}); err == nil {
		t.Fatal("expected lookup error")
	}

	// InsertAPIKey fails: name lookup returns nil, then the insert errors.
	svc2 := NewAPIKeyService(failInsertStore{memstore.New()}, testCipher(t), audit.NewLog(10, nil, nil))
	if _, err := svc2.Create(ctx, CreateAPIKeyParams{Name: "n", Secret: strPtr("s")}); err == nil {
		t.Fatal("expected insert error")
	}

	// UpdateAPIKey fails on edit (existing row present, update fails).
	ms.FailNext = nil
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "edit", Secret: strPtr("s")}); err != nil {
		t.Fatal(err)
	}
	upd := NewAPIKeyService(updateFailStore{ms}, testCipher(t), audit.NewLog(10, nil, nil))
	if _, err := upd.Create(ctx, CreateAPIKeyParams{Name: "edit", Description: strPtr("x")}); err == nil {
		t.Fatal("expected update error")
	}
}

func TestAPIKeyListAndGetByNameStoreErrors(t *testing.T) {
	ms := memstore.New()
	svc := NewAPIKeyService(ms, testCipher(t), audit.NewLog(10, nil, nil))
	ctx := callerCtx()

	ms.FailNext = errFailNext
	if _, err := svc.List(ctx); err == nil {
		t.Fatal("expected list error")
	}

	ms.FailNext = errFailNext
	if _, err := svc.GetByName(ctx, "x"); err == nil {
		t.Fatal("expected getbyname lookup error")
	}
}

func TestAPIKeyGetByNameTouchError(t *testing.T) {
	ms := &touchFailStore{Mem: memstore.New(), failAPITouch: true}
	svc := NewAPIKeyService(ms, testCipher(t), audit.NewLog(10, nil, nil))
	ctx := callerCtx()
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "k", Secret: strPtr("s")}); err != nil {
		t.Fatal(err)
	}
	// TouchAPIKeyLastUsed error propagates from GetByName.
	if _, err := svc.GetByName(ctx, "k"); err == nil {
		t.Fatal("expected touch error to propagate")
	}
}

// failInsertStore makes InsertAPIKey fail while delegating everything else.
type failInsertStore struct{ *memstore.Mem }

func (s failInsertStore) InsertAPIKey(context.Context, *store.APIKey) error { return errFailNext }

// updateFailStore makes UpdateAPIKey fail while delegating everything else.
type updateFailStore struct{ *memstore.Mem }

func (s updateFailStore) UpdateAPIKey(context.Context, *store.APIKey) error { return errFailNext }

// ---- oauthconfig.go ----

func TestOAuthConfigListStoreError(t *testing.T) {
	ms := memstore.New()
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(ms, loader)
	svc := NewOAuthConfigService(ms, testCipher(t), audit.NewLog(10, nil, nil), resolver)
	ctx := callerCtx()
	ms.FailNext = errFailNext
	if _, err := svc.List(ctx); err == nil {
		t.Fatal("expected list error")
	}
}

func TestOAuthConfigUpsertErrors(t *testing.T) {
	ms := memstore.New()
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(ms, loader)
	svc := NewOAuthConfigService(ms, testCipher(t), audit.NewLog(10, nil, nil), resolver)
	ctx := callerCtx()

	// unknown provider -> ValidationError (ResolveProviderID returns Nil)
	if _, err := svc.Upsert(ctx, "ghost", "cid", strPtr("sec"), nil, nil); err == nil {
		t.Fatal("expected unknown provider error")
	}

	// ResolveProviderID store error
	ms.FailNext = errFailNext
	if _, err := svc.Upsert(ctx, "ghost", "cid", strPtr("sec"), nil, nil); err == nil {
		t.Fatal("expected resolve error")
	}

	// Seed a provider so resolve succeeds.
	if err := resolver.UpsertOAuth(ctx, manifests.Manifest{Key: "acme", TokenEndpoint: "t"}); err != nil {
		t.Fatal(err)
	}

	// GetOAuthConfigByProvider store error: resolve calls GetManifestByKey first (1 store call),
	// then GetOAuthConfigByProvider. Arm a store that fails the config lookup.
	cfgFail := configLookupFailStore{ms}
	svcCF := NewOAuthConfigService(cfgFail, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(cfgFail, loader))
	if _, err := svcCF.Upsert(ctx, "acme", "cid", strPtr("sec"), nil, nil); err == nil {
		t.Fatal("expected config lookup error")
	}

	// create with empty client secret -> ValidationError
	if _, err := svc.Upsert(ctx, "acme", "cid", strPtr(""), nil, nil); err == nil {
		t.Fatal("expected secret required on create")
	}

	// InsertOAuthConfig store error on create
	insFail := configInsertFailStore{ms}
	svcIF := NewOAuthConfigService(insFail, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(insFail, loader))
	if _, err := svcIF.Upsert(ctx, "acme", "cid", strPtr("sec"), nil, nil); err == nil {
		t.Fatal("expected insert error")
	}

	// Successful create, then edit error branches.
	id, err := svc.Upsert(ctx, "acme", "cid", strPtr("sec"), []string{"openid"}, strPtr("https://r"))
	if err != nil || id == uuid.Nil {
		t.Fatalf("create config: %v", err)
	}

	// Edit with a NEW secret hits the secret-encrypt branch; force an encrypt failure there.
	encFail := NewOAuthConfigService(ms, &secretEncFailCipher{}, audit.NewLog(10, nil, nil), resolver)
	if _, err := encFail.Upsert(ctx, "acme", "cid", strPtr("newsecret"), nil, nil); err == nil {
		t.Fatal("expected secret encrypt error on edit")
	}

	// UpdateOAuthConfig store error on edit.
	updFail := configUpdateFailStore{ms}
	svcUF := NewOAuthConfigService(updFail, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(updFail, loader))
	if _, err := svcUF.Upsert(ctx, "acme", "cid", strPtr("sec2"), []string{"openid"}, nil); err == nil {
		t.Fatal("expected update error")
	}
}

func TestDecodeScopesInvalidJSON(t *testing.T) {
	bad := "not json"
	if got := decodeScopes(&bad); len(got) != 0 {
		t.Fatalf("expected empty on bad json, got %v", got)
	}
}

// configLookupFailStore fails the GetOAuthConfigByProvider lookup.
type configLookupFailStore struct{ *memstore.Mem }

func (s configLookupFailStore) GetOAuthConfigByProvider(context.Context, uuid.UUID, uuid.UUID) (*store.OAuthProviderConfig, error) {
	return nil, errFailNext
}

// configInsertFailStore fails InsertOAuthConfig.
type configInsertFailStore struct{ *memstore.Mem }

func (s configInsertFailStore) InsertOAuthConfig(context.Context, *store.OAuthProviderConfig) error {
	return errFailNext
}

// configUpdateFailStore fails UpdateOAuthConfig.
type configUpdateFailStore struct{ *memstore.Mem }

func (s configUpdateFailStore) UpdateOAuthConfig(context.Context, *store.OAuthProviderConfig) error {
	return errFailNext
}

// secretEncFailCipher succeeds the first EncryptString (client id) and fails the second (secret),
// so the edit-secret encrypt branch in Upsert is exercised without tripping the client-id encrypt.
type secretEncFailCipher struct{ calls int }

func (c *secretEncFailCipher) Encrypt(b []byte) ([]byte, error) {
	return append([]byte("ct:"), b...), nil
}
func (c *secretEncFailCipher) Decrypt(b []byte) ([]byte, error) { return b, nil }
func (c *secretEncFailCipher) EncryptString(s string) ([]byte, error) {
	c.calls++
	if c.calls >= 2 {
		return nil, errFailNext
	}
	return []byte("ct:" + s), nil
}
func (c *secretEncFailCipher) DecryptToString(b []byte) (string, error) { return string(b), nil }

// ---- oauthflow.go ----

func TestNewOAuthFlowServiceDefaults(t *testing.T) {
	// nil client + nil logger -> defaults filled in.
	svc := NewOAuthFlowService(memstore.New(), testCipher(t), nil, audit.NewLog(10, nil, nil), nil, nil)
	if svc.client == nil || svc.logger == nil {
		t.Fatal("expected defaults for client and logger")
	}
}

func TestBeginErrorBranches(t *testing.T) {
	f := newOAuthFixture(t)

	// GetOAuth store error.
	f.ms.FailNext = errFailNext
	if _, err := f.flow.Begin(f.ctx, "acme", nil, "https://v"); err == nil {
		t.Fatal("expected GetOAuth error")
	}

	// GetOAuthConfigByProvider store error: GetOAuth uses 1 store call, config lookup is next.
	cfgFail := configLookupFailStore{f.ms}
	loader, _ := manifests.NewLoader()
	flowCF := NewOAuthFlowService(cfgFail, testCipher(t), manifests.NewResolver(cfgFail, loader), audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := flowCF.Begin(f.ctx, "acme", nil, "https://v"); err == nil {
		t.Fatal("expected config lookup error")
	}

	// No config for provider: register a provider with no config row.
	if err := f.resolver.UpsertOAuth(f.ctx, manifests.Manifest{Key: "nocfg", TokenEndpoint: f.idp.URL + "/token"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.flow.Begin(f.ctx, "nocfg", nil, "https://v"); err == nil {
		t.Fatal("expected no-config error")
	}

	// client id decrypt error.
	decFail := NewOAuthFlowService(f.ms, failCipher{decFail: true}, f.resolver, audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := decFail.Begin(f.ctx, "acme", nil, "https://v"); err == nil {
		t.Fatal("expected decrypt error")
	}

	// InsertOAuthState store error.
	stFail := stateInsertFailStore{f.ms}
	flowSF := NewOAuthFlowService(stFail, testCipher(t), manifests.NewResolver(stFail, loader), audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := flowSF.Begin(f.ctx, "acme", []string{"openid"}, "https://v"); err == nil {
		t.Fatal("expected insert state error")
	}
}

func TestBeginScopesFromConfigDefault(t *testing.T) {
	f := newOAuthFixture(t)
	// Empty requested scopes + config has ScopesJSON -> decoded from config.
	res, err := f.flow.Begin(f.ctx, "acme", nil, "https://v")
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthorizeURL == "" {
		t.Fatal("expected authorize url")
	}
}

func TestBeginScopesFromManifestDefault(t *testing.T) {
	f := newOAuthFixture(t)
	// Provider whose config has no scopes JSON -> falls back to manifest DefaultScopes.
	if err := f.resolver.UpsertOAuth(f.ctx, manifests.Manifest{
		Key: "mdef", TokenEndpoint: f.idp.URL + "/token", AuthorizationEndpoint: f.idp.URL + "/auth",
		ScopeDelimiter: " ", DefaultScopes: []string{"openid"}, Scopes: []manifests.ScopeDef{{Value: "openid"}},
	}); err != nil {
		t.Fatal(err)
	}
	caller := contracts.CallerFrom(f.ctx)
	pid, _ := f.resolver.ResolveProviderID(f.ctx, "mdef", caller.UserID)
	cidBlob, _ := testCipher(t).EncryptString("cid")
	secBlob, _ := testCipher(t).EncryptString("sec")
	// Insert a config row with nil ScopesJSON.
	if err := f.ms.InsertOAuthConfig(f.ctx, &store.OAuthProviderConfig{
		UserID: caller.UserID, TenantID: caller.TenantID, ProviderID: pid, ProviderKey: "mdef",
		ClientIDCipher: cidBlob, ClientSecretCipher: secBlob, ScopesJSON: nil,
	}); err != nil {
		t.Fatal(err)
	}
	res, err := f.flow.Begin(f.ctx, "mdef", nil, "https://v")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if res.AuthorizeURL == "" {
		t.Fatal("expected url")
	}
}

func TestCompleteCoreErrorBranches(t *testing.T) {
	// invalid/expired state (no row)
	f := newOAuthFixture(t)
	if _, err := f.flow.Complete(context.Background(), "code", "nonexistent-state"); err == nil {
		t.Fatal("expected invalid state error")
	}

	// GetOAuthStateByState store error.
	f.ms.FailNext = errFailNext
	if _, err := f.flow.Complete(context.Background(), "code", "x"); err == nil {
		t.Fatal("expected state lookup error")
	}

	// Expired state row: re-insert with the same ID (memstore keys by ID) but a past expiry.
	expired := newOAuthFixture(t)
	res, _ := expired.flow.Begin(expired.ctx, "acme", []string{"openid"}, "https://v")
	row, _ := expired.ms.GetOAuthStateByState(expired.ctx, res.State)
	row.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	_ = expired.ms.InsertOAuthState(expired.ctx, row)
	if _, err := expired.flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected expired state error")
	}
}

func TestCompleteStateAlreadyUsed(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	// Delete the state row out from under Complete so the atomic claim deletes 0 rows.
	row, _ := f.ms.GetOAuthStateByState(f.ctx, res.State)
	_, _ = f.ms.DeleteOAuthState(f.ctx, row.ID)
	// Re-insert with same state but the claim path: actually after delete, GetOAuthStateByState
	// returns nil -> "invalid or expired". To hit "already used" we need the row present at lookup
	// but gone at delete. Use a store that returns the row but deletes 0.
	claimFail := stateClaimFailStore{Mem: f.ms, row: row}
	loader, _ := manifests.NewLoader()
	flow := NewOAuthFlowService(claimFail, testCipher(t), manifests.NewResolver(claimFail, loader), audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected already-used error")
	}
}

func TestCompleteDeleteStateError(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	row, _ := f.ms.GetOAuthStateByState(f.ctx, res.State)
	delFail := stateDeleteErrStore{Mem: f.ms, row: row}
	loader, _ := manifests.NewLoader()
	flow := NewOAuthFlowService(delFail, testCipher(t), manifests.NewResolver(delFail, loader), audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected delete-state error")
	}
}

func TestCompleteSecretDecryptError(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	// client id decrypts (failCipher returns input), but we want the SECOND decrypt (secret) to fail.
	// failCipher fails ALL decrypts; client-id decrypt would fail first, still an error path.
	dec := NewOAuthFlowService(f.ms, failCipher{decFail: true}, f.resolver, audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := dec.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected decrypt error")
	}
}

func TestCompleteMalformedTokenJSON(t *testing.T) {
	f := newOAuthFixture(t)
	f.tokenResp = `{not json}`
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected malformed json error")
	}
}

func TestCompleteScopesFromConfigWhenTokenOmits(t *testing.T) {
	f := newOAuthFixture(t)
	// Token endpoint returns no scope -> scopes fall back to config ScopesJSON.
	f.tokenResp = `{"access_token":"a1","refresh_token":"r1","expires_in":3600}`
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	done, err := f.flow.Complete(context.Background(), "code", res.State)
	if err != nil {
		t.Fatal(err)
	}
	if len(done.Scopes) == 0 {
		t.Fatal("expected scopes from config fallback")
	}
}

func TestStoreTokenEncryptAndStoreErrors(t *testing.T) {
	// Access token encrypt error.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	enc := NewOAuthFlowService(f.ms, &encOnStoreFailCipher{failOn: 1}, f.resolver, audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := enc.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected access-token encrypt error")
	}

	// Refresh token encrypt error (access encrypt ok, refresh encrypt fails).
	f2 := newOAuthFixture(t)
	res2, _ := f2.flow.Begin(f2.ctx, "acme", []string{"openid"}, "https://v")
	enc2 := NewOAuthFlowService(f2.ms, &encOnStoreFailCipher{failOn: 2}, f2.resolver, audit.NewLog(10, nil, nil), f2.idp.Client(), nil)
	if _, err := enc2.Complete(context.Background(), "code", res2.State); err == nil {
		t.Fatal("expected refresh-token encrypt error")
	}

	// FindOAuthToken store error inside storeToken.
	f3 := newOAuthFixture(t)
	res3, _ := f3.flow.Begin(f3.ctx, "acme", []string{"openid"}, "https://v")
	findFail := findTokenFailStore{f3.ms}
	loader, _ := manifests.NewLoader()
	flow3 := NewOAuthFlowService(findFail, testCipher(t), manifests.NewResolver(findFail, loader), audit.NewLog(10, nil, nil), f3.idp.Client(), nil)
	if _, err := flow3.Complete(context.Background(), "code", res3.State); err == nil {
		t.Fatal("expected find-token error")
	}

	// InsertOAuthToken store error inside storeToken.
	f4 := newOAuthFixture(t)
	res4, _ := f4.flow.Begin(f4.ctx, "acme", []string{"openid"}, "https://v")
	insFail := tokenInsertFailStore{f4.ms}
	flow4 := NewOAuthFlowService(insFail, testCipher(t), manifests.NewResolver(insFail, loader), audit.NewLog(10, nil, nil), f4.idp.Client(), nil)
	if _, err := flow4.Complete(context.Background(), "code", res4.State); err == nil {
		t.Fatal("expected insert-token error")
	}
}

func TestStoreTokenUpdateExisting(t *testing.T) {
	// Completing twice for the same account updates the existing row (exercises the update branch).
	f := newOAuthFixture(t)
	res1, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res1.State); err != nil {
		t.Fatal(err)
	}
	f.tokenResp = `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600,"scope":"openid email"}`
	res2, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res2.State); err != nil {
		t.Fatalf("second complete: %v", err)
	}
	rows, _ := f.ms.ListOAuthTokens(f.ctx, contracts.CallerFrom(f.ctx).UserID)
	if len(rows) != 1 {
		t.Fatalf("expected single updated row, got %d", len(rows))
	}
}

func TestFetchAccountErrorBranches(t *testing.T) {
	// userinfo returns malformed JSON -> account falls back to "default".
	badInfo := newOAuthFixtureWithUserinfo(t, http.StatusOK, `{bad json}`)
	r2, _ := badInfo.flow.Begin(badInfo.ctx, "acme", []string{"openid"}, "https://v")
	done, err := badInfo.flow.Complete(context.Background(), "code", r2.State)
	if err != nil {
		t.Fatal(err)
	}
	if done.Account != "default" {
		t.Fatalf("expected default account on bad userinfo json, got %q", done.Account)
	}
}

// newOAuthFixtureWithUserinfo builds a fixture whose userinfo endpoint returns the given body.
func newOAuthFixtureWithUserinfo(t *testing.T, status int, body string) *oauthFixture {
	t.Helper()
	f := newOAuthFixture(t)
	f.userinfoStatus = status
	// Replace the server handler by swapping tokenResp/userinfo via a new server.
	f.idp.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.tokenStatus)
			_, _ = w.Write([]byte(f.tokenResp))
		case "/me":
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	})
	return f
}

// ---- oauthtoken.go ----

func TestTokenListStoreError(t *testing.T) {
	f := newOAuthFixture(t)
	f.ms.FailNext = errFailNext
	if _, err := f.tokens.List(f.ctx); err == nil {
		t.Fatal("expected list error")
	}
}

func TestTokenDeleteBranches(t *testing.T) {
	f := newOAuthFixture(t)
	// Not found -> (false, nil).
	ok, err := f.tokens.Delete(f.ctx, uuid.New())
	if ok || err != nil {
		t.Fatalf("expected not-found delete, got %v %v", ok, err)
	}
	// Lookup store error.
	f.ms.FailNext = errFailNext
	if _, err := f.tokens.Delete(f.ctx, uuid.New()); err == nil {
		t.Fatal("expected lookup error")
	}

	// Seed a token, then DeleteOAuthToken store error.
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	delFail := tokenDeleteFailStore{f.ms}
	loader, _ := manifests.NewLoader()
	svc := NewOAuthTokenService(delFail, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(delFail, loader), f.idp.Client())
	if _, err := svc.Delete(f.ctx, list[0].ID); err == nil {
		t.Fatal("expected delete error")
	}
}

func TestGetAccessTokenBranches(t *testing.T) {
	// ResolveProviderID store error.
	f := newOAuthFixture(t)
	f.ms.FailNext = errFailNext
	if _, err := f.tokens.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected resolve error")
	}

	// Unknown provider -> nil token, nil error.
	f2 := newOAuthFixture(t)
	tok, err := f2.tokens.GetAccessToken(f2.ctx, "ghost", "")
	if tok != nil || err != nil {
		t.Fatalf("expected nil/nil for unknown provider, got %+v %v", tok, err)
	}

	// FindOAuthToken store error (after a successful resolve).
	f3 := newOAuthFixture(t)
	findFail := findTokenFailStore{f3.ms}
	loader, _ := manifests.NewLoader()
	svc := NewOAuthTokenService(findFail, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(findFail, loader), f3.idp.Client())
	if _, err := svc.GetAccessToken(f3.ctx, "acme", ""); err == nil {
		t.Fatal("expected find error")
	}
}

func TestGetAccessTokenNoRefreshFallback(t *testing.T) {
	f := newOAuthFixture(t)
	// Provider returns no refresh token -> empty refresh cipher.
	f.tokenResp = `{"access_token":"access-1","expires_in":3600,"scope":"openid"}`
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	// Force expiry: with no refresh token, GetAccessToken returns the (stale) access token directly.
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)
	tok, err := f.tokens.GetAccessToken(f.ctx, "acme", "")
	if err != nil || tok == nil || tok.AccessToken != "access-1" {
		t.Fatalf("expected stale token returned, got %+v %v", tok, err)
	}
}

func TestGetAccessTokenManifestOrConfigNilFallback(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)

	// Delete the config so config == nil -> fallback returns stale token without refresh.
	caller := contracts.CallerFrom(f.ctx)
	pid, _ := f.resolver.ResolveProviderID(f.ctx, "acme", caller.UserID)
	cfg, _ := f.ms.GetOAuthConfigByProvider(f.ctx, caller.UserID, pid)
	_, _ = f.ms.DeleteOAuthConfig(f.ctx, caller.UserID, cfg.ID)

	tok, err := f.tokens.GetAccessToken(f.ctx, "acme", "")
	if err != nil || tok == nil || tok.AccessToken != "access-1" {
		t.Fatalf("expected stale token via nil-config fallback, got %+v %v", tok, err)
	}
}

func TestGetAccessTokenManifestErrorOnRefresh(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)

	// GetOAuth (manifest) lookup error during refresh path: ResolveProviderID is the first
	// GetManifestByKey; the manifest GetOAuth is the second, which we fail.
	gf := &getOAuthErrStore{Mem: f.ms, failAfter: 1}
	loader, _ := manifests.NewLoader()
	svc := NewOAuthTokenService(gf, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(gf, loader), f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected manifest lookup error")
	}
}

func TestGetAccessTokenConfigErrorOnRefresh(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)

	cf := configLookupFailStore{f.ms}
	loader, _ := manifests.NewLoader()
	svc := NewOAuthTokenService(cf, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(cf, loader), f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected config lookup error on refresh")
	}
}

func TestRefreshAlreadyFreshBySibling(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	caller := contracts.CallerFrom(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, caller.UserID, list[0].ID)

	// Set expiry into the past in the GetAccessToken view, but the re-read inside refresh sees a
	// FUTURE expiry (sibling already refreshed). Use a store that returns a fresh row on the second
	// FindOAuthToken (the one inside refresh()).
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)

	freshRow := *row
	future := time.Now().Add(time.Hour)
	freshRow.ExpiresAt = &future
	rr := &refreshReReadStore{Mem: f.ms, fresh: &freshRow, findCount: 0}
	loader, _ := manifests.NewLoader()
	svc := NewOAuthTokenService(rr, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(rr, loader), f.idp.Client())
	tok, err := svc.GetAccessToken(f.ctx, "acme", "")
	if err != nil || tok == nil {
		t.Fatalf("expected fresh token from sibling re-read, got %+v %v", tok, err)
	}
	if tok.ExpiresAt == nil || !tok.ExpiresAt.After(time.Now()) {
		t.Fatal("expected the re-read fresh token")
	}
}

func TestRefreshRefreshTokenDecryptError(t *testing.T) {
	// Seed a token whose refresh cipher fails to decrypt within refresh().
	ms := memstore.New()
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(ms, loader)
	ctx := callerCtx()
	caller := contracts.CallerFrom(ctx)
	_ = resolver.UpsertOAuth(ctx, manifests.Manifest{Key: "acme", TokenEndpoint: "t"})
	pid, _ := resolver.ResolveProviderID(ctx, "acme", caller.UserID)
	_ = ms.InsertOAuthConfig(ctx, &store.OAuthProviderConfig{UserID: caller.UserID, ProviderID: pid, ProviderKey: "acme", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{1}})
	past := time.Now().Add(-time.Hour)
	_ = ms.InsertOAuthToken(ctx, &store.OAuthToken{UserID: caller.UserID, ProviderID: pid, ProviderKey: "acme", Account: "a", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{1}, ExpiresAt: &past})

	svc := NewOAuthTokenService(ms, failCipher{decFail: true}, audit.NewLog(10, nil, nil), resolver, nil)
	if _, err := svc.GetAccessToken(ctx, "acme", ""); err == nil {
		t.Fatal("expected decrypt error in refresh")
	}
}

func TestRefreshClientCredsDecryptError(t *testing.T) {
	// refresh token decrypts OK, but client id/secret decrypt fails.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)

	// Cipher that fails on the 2nd decrypt: refresh token (1) ok, client id (2) fails.
	svc := NewOAuthTokenService(f.ms, &decOnNthFailCipher{failOn: 2}, audit.NewLog(10, nil, nil), f.resolver, f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected client-creds decrypt error")
	}
}

func TestRefreshAccessEncryptError(t *testing.T) {
	// Successful refresh exchange, but re-encrypting the new access token fails.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)
	f.tokenResp = `{"access_token":"a2","refresh_token":"r2","expires_in":3600}`

	svc := NewOAuthTokenService(f.ms, encFailDecOkCipher{}, audit.NewLog(10, nil, nil), f.resolver, f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected access-token re-encrypt error")
	}
}

func TestRefreshUpdateStoreError(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)
	f.tokenResp = `{"access_token":"a2","expires_in":3600}`

	upd := tokenUpdateFailStore{f.ms}
	loader, _ := manifests.NewLoader()
	svc := NewOAuthTokenService(upd, testCipher(t), audit.NewLog(10, nil, nil), manifests.NewResolver(upd, loader), f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected update store error in refresh")
	}
}

func TestBeginAuthorizeParamsMerged(t *testing.T) {
	f := newOAuthFixture(t)
	// A provider declaring extra authorize params exercises the params-merge loop.
	if err := f.resolver.UpsertOAuth(f.ctx, manifests.Manifest{
		Key: "params", TokenEndpoint: f.idp.URL + "/token", AuthorizationEndpoint: f.idp.URL + "/auth",
		ScopeDelimiter: " ", DefaultScopes: []string{"openid"}, Scopes: []manifests.ScopeDef{{Value: "openid"}},
		AuthorizeParams: map[string]string{"prompt": "consent", "access_type": "offline"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.configs.Upsert(f.ctx, "params", "cid", strPtr("sec"), []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	res, err := f.flow.Begin(f.ctx, "params", []string{"openid"}, "https://v")
	if err != nil {
		t.Fatal(err)
	}
	if res.AuthorizeURL == "" {
		t.Fatal("expected url")
	}
}

func TestCompleteCoreManifestAndConfigBranches(t *testing.T) {
	// manifest lookup error after the state is claimed.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	row, _ := f.ms.GetOAuthStateByState(f.ctx, res.State)
	_ = row
	loader, _ := manifests.NewLoader()
	// In Complete, the only GetManifestByKey is the manifest GetOAuth, so fail the first call.
	mErr := &getOAuthErrStore{Mem: f.ms, failAfter: 0}
	flow := NewOAuthFlowService(mErr, testCipher(t), manifests.NewResolver(mErr, loader), audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected manifest lookup error")
	}

	// config lookup error after the state is claimed.
	f2 := newOAuthFixture(t)
	res2, _ := f2.flow.Begin(f2.ctx, "acme", []string{"openid"}, "https://v")
	cErr := completeConfigErrStore{f2.ms}
	flow2 := NewOAuthFlowService(cErr, testCipher(t), manifests.NewResolver(cErr, loader), audit.NewLog(10, nil, nil), f2.idp.Client(), nil)
	if _, err := flow2.Complete(context.Background(), "code", res2.State); err == nil {
		t.Fatal("expected config lookup error")
	}

	// config nil after claim: provider exists but no config row.
	f3 := newOAuthFixture(t)
	if err := f3.resolver.UpsertOAuth(f3.ctx, manifests.Manifest{Key: "nocfg2", TokenEndpoint: f3.idp.URL + "/token", AuthorizationEndpoint: f3.idp.URL + "/auth", DefaultScopes: []string{"openid"}, Scopes: []manifests.ScopeDef{{Value: "openid"}}}); err != nil {
		t.Fatal(err)
	}
	// Seed a config so Begin succeeds, then delete it before Complete.
	if _, err := f3.configs.Upsert(f3.ctx, "nocfg2", "cid", strPtr("sec"), []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	res3, _ := f3.flow.Begin(f3.ctx, "nocfg2", []string{"openid"}, "https://v")
	caller := contracts.CallerFrom(f3.ctx)
	pid, _ := f3.resolver.ResolveProviderID(f3.ctx, "nocfg2", caller.UserID)
	cfg, _ := f3.ms.GetOAuthConfigByProvider(f3.ctx, caller.UserID, pid)
	_, _ = f3.ms.DeleteOAuthConfig(f3.ctx, caller.UserID, cfg.ID)
	if _, err := f3.flow.Complete(context.Background(), "code", res3.State); err == nil {
		t.Fatal("expected no-config error")
	}
}

func TestCompleteClientSecretDecryptError(t *testing.T) {
	// clientID decrypts OK (1st), clientSecret decrypt (2nd) fails.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	svc := NewOAuthFlowService(f.ms, &decOnNthFailCipher{failOn: 2}, f.resolver, audit.NewLog(10, nil, nil), f.idp.Client(), nil)
	if _, err := svc.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected client-secret decrypt error")
	}
}

func TestFetchAccountBadRequestURL(t *testing.T) {
	// A userinfo endpoint that is an invalid URL makes http.NewRequestWithContext fail -> "default".
	f := newOAuthFixture(t)
	if err := f.resolver.UpsertOAuth(f.ctx, manifests.Manifest{
		Key: "badurl", TokenEndpoint: f.idp.URL + "/token", AuthorizationEndpoint: f.idp.URL + "/auth",
		UserinfoEndpoint: "://nope", ScopeDelimiter: " ", DefaultScopes: []string{"openid"}, Scopes: []manifests.ScopeDef{{Value: "openid"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.configs.Upsert(f.ctx, "badurl", "cid", strPtr("sec"), []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	res, _ := f.flow.Begin(f.ctx, "badurl", []string{"openid"}, "https://v")
	done, err := f.flow.Complete(context.Background(), "code", res.State)
	if err != nil || done.Account != "default" {
		t.Fatalf("expected default account on bad userinfo url: %+v %v", done, err)
	}
}

func TestFetchAccountUserinfoNetworkError(t *testing.T) {
	// Token exchange succeeds (its own server), but the userinfo host is unreachable -> "default".
	f := newOAuthFixture(t)
	// Point userinfo at a closed port via a separate, immediately-closed server.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // now connections to deadURL fail
	if err := f.resolver.UpsertOAuth(f.ctx, manifests.Manifest{
		Key: "deadinfo", TokenEndpoint: f.idp.URL + "/token", AuthorizationEndpoint: f.idp.URL + "/auth",
		UserinfoEndpoint: deadURL + "/me", ScopeDelimiter: " ", DefaultScopes: []string{"openid"}, Scopes: []manifests.ScopeDef{{Value: "openid"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.configs.Upsert(f.ctx, "deadinfo", "cid", strPtr("sec"), []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	res, _ := f.flow.Begin(f.ctx, "deadinfo", []string{"openid"}, "https://v")
	done, err := f.flow.Complete(context.Background(), "code", res.State)
	if err != nil || done.Account != "default" {
		t.Fatalf("expected default account on userinfo network error: %+v %v", done, err)
	}
}

func TestFetchAccountNoKnownClaim(t *testing.T) {
	// userinfo returns 200 JSON without any recognised identity key -> "default".
	f := newOAuthFixtureWithUserinfo(t, http.StatusOK, `{"unrelated":"x"}`)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	done, err := f.flow.Complete(context.Background(), "code", res.State)
	if err != nil || done.Account != "default" {
		t.Fatalf("expected default account when no known claim: %+v %v", done, err)
	}
}

func TestGetAccessTokenNoRefreshDecryptError(t *testing.T) {
	// Expired token with empty refresh cipher + failing decrypt hits the fallback decrypt-error path.
	ms := memstore.New()
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(ms, loader)
	ctx := callerCtx()
	caller := contracts.CallerFrom(ctx)
	_ = resolver.UpsertOAuth(ctx, manifests.Manifest{Key: "acme", TokenEndpoint: "t"})
	pid, _ := resolver.ResolveProviderID(ctx, "acme", caller.UserID)
	past := time.Now().Add(-time.Hour)
	// empty refresh cipher -> manifest/config present but no-refresh branch.
	_ = ms.InsertOAuthConfig(ctx, &store.OAuthProviderConfig{UserID: caller.UserID, ProviderID: pid, ProviderKey: "acme", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{1}})
	_ = ms.InsertOAuthToken(ctx, &store.OAuthToken{UserID: caller.UserID, ProviderID: pid, ProviderKey: "acme", Account: "a", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{}, ExpiresAt: &past})
	svc := NewOAuthTokenService(ms, failCipher{decFail: true}, audit.NewLog(10, nil, nil), resolver, nil)
	if _, err := svc.GetAccessToken(ctx, "acme", ""); err == nil {
		t.Fatal("expected decrypt error in no-refresh fallback")
	}
}

func TestRefreshSiblingReReadDecryptError(t *testing.T) {
	// The sibling-re-read branch sees a fresh row but its access decrypt fails.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	caller := contracts.CallerFrom(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, caller.UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)

	fresh := *row
	future := time.Now().Add(time.Hour)
	fresh.ExpiresAt = &future
	rr := &refreshReReadStore{Mem: f.ms, fresh: &fresh}
	loader, _ := manifests.NewLoader()
	svc := NewOAuthTokenService(rr, failCipher{decFail: true}, audit.NewLog(10, nil, nil), manifests.NewResolver(rr, loader), f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected decrypt error in sibling re-read branch")
	}
}

func TestRefreshClientSecretDecryptError(t *testing.T) {
	// refresh token (1) + client id (2) decrypt OK; client secret (3) fails.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)
	svc := NewOAuthTokenService(f.ms, &decOnNthFailCipher{failOn: 3}, audit.NewLog(10, nil, nil), f.resolver, f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected client-secret decrypt error in refresh")
	}
}

func TestRefreshNetworkError(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)
	// A client whose transport always errors fails the refresh postForm.
	svc := NewOAuthTokenService(f.ms, testCipher(t), audit.NewLog(10, nil, nil), f.resolver, &http.Client{Transport: errRoundTripper{}})
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected refresh network error")
	}
}

func TestRefreshRotatesRefreshToken(t *testing.T) {
	// A refresh response carrying a new refresh_token exercises the rotate-and-re-encrypt branch.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)
	f.tokenResp = `{"access_token":"access-rot","refresh_token":"refresh-rot","expires_in":3600}`
	tok, err := f.tokens.GetAccessToken(f.ctx, "acme", "")
	if err != nil || tok == nil || tok.AccessToken != "access-rot" {
		t.Fatalf("expected rotated refresh, got %+v %v", tok, err)
	}
}

func TestAPIKeyEditBasicRequiresPassword(t *testing.T) {
	ms := memstore.New()
	svc := NewAPIKeyService(ms, testCipher(t), audit.NewLog(10, nil, nil))
	ctx := callerCtx()
	// Create a header-style key with NO secret stored is impossible (create needs a secret), so make
	// a key whose FieldsCipher is empty by inserting directly, then edit it to Basic without a secret.
	caller := contracts.CallerFrom(ctx)
	if err := ms.InsertAPIKey(ctx, &store.APIKey{UserID: caller.UserID, TenantID: caller.TenantID, Name: "nopw", Kind: "opaque"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "nopw", Username: strPtr("user")}); err == nil {
		t.Fatal("expected Basic-requires-password error on edit")
	}
}

func TestAPIKeyBasicHeaderOverride(t *testing.T) {
	ms := memstore.New()
	svc := NewAPIKeyService(ms, testCipher(t), audit.NewLog(10, nil, nil))
	ctx := callerCtx()
	// http_basic + explicit non-empty header -> that header is used (not defaulted to Authorization).
	if _, err := svc.Create(ctx, CreateAPIKeyParams{Name: "b", Secret: strPtr("pw"), Username: strPtr("u"), Header: strPtr("X-Auth"), Kind: contracts.KindHTTPBasic}); err != nil {
		t.Fatal(err)
	}
	sec, _ := svc.GetByName(ctx, "b")
	if deref(sec.Header) != "X-Auth" {
		t.Fatalf("expected overridden header, got %q", deref(sec.Header))
	}
}

func TestOAuthConfigCreateSecretEncryptError(t *testing.T) {
	ms := memstore.New()
	loader, _ := manifests.NewLoader()
	resolver := manifests.NewResolver(ms, loader)
	ctx := callerCtx()
	if err := resolver.UpsertOAuth(ctx, manifests.Manifest{Key: "acme", TokenEndpoint: "t"}); err != nil {
		t.Fatal(err)
	}
	// client id encrypt (1) OK, client secret encrypt (2) fails on create.
	svc := NewOAuthConfigService(ms, &secretEncFailCipher{}, audit.NewLog(10, nil, nil), resolver)
	if _, err := svc.Upsert(ctx, "acme", "cid", strPtr("sec"), nil, nil); err == nil {
		t.Fatal("expected secret encrypt error on create")
	}
}

func TestCompleteManifestNilAfterClaim(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	// Delete the provider manifest between Begin and Complete so GetOAuth returns nil.
	if _, err := f.resolver.Delete(f.ctx, "oauth", "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected unknown-provider error after manifest deleted")
	}
}

func TestRefreshRotateReEncryptError(t *testing.T) {
	// Refresh returns a new refresh_token; access re-encrypt (1) OK, refresh re-encrypt (2) fails.
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	row, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	row.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, row)
	f.tokenResp = `{"access_token":"a2","refresh_token":"r2","expires_in":3600}`
	// decrypts pass through; EncryptString fails on the 2nd call (the rotated refresh token).
	svc := NewOAuthTokenService(f.ms, &encDecOrderedCipher{encFailOn: 2}, audit.NewLog(10, nil, nil), f.resolver, f.idp.Client())
	if _, err := svc.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected rotated-refresh re-encrypt error")
	}
}

// encDecOrderedCipher passes all decrypts through and fails EncryptString on the Nth call.
type encDecOrderedCipher struct {
	encFailOn int
	encCalls  int
}

func (c *encDecOrderedCipher) Encrypt(b []byte) ([]byte, error) {
	return append([]byte("ct:"), b...), nil
}
func (c *encDecOrderedCipher) Decrypt(b []byte) ([]byte, error) { return b, nil }
func (c *encDecOrderedCipher) EncryptString(s string) ([]byte, error) {
	c.encCalls++
	if c.encCalls == c.encFailOn {
		return nil, errFailNext
	}
	return []byte("ct:" + s), nil
}
func (c *encDecOrderedCipher) DecryptToString(b []byte) (string, error) { return string(b), nil }

// ---- httpform.go ----

func TestPostFormBadEndpoint(t *testing.T) {
	// An invalid URL makes http.NewRequestWithContext fail.
	if _, _, err := postForm(context.Background(), http.DefaultClient, "://bad url", nil); err == nil {
		t.Fatal("expected request build error")
	}
}

func TestPostFormOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()
	status, body, err := postForm(context.Background(), srv.Client(), srv.URL, nil)
	if err != nil || status != 200 || string(body) != "ok" {
		t.Fatalf("postForm: %d %q %v", status, body, err)
	}
}

// ---- store fakes for the flow/token error branches ----

// stateInsertFailStore fails InsertOAuthState.
type stateInsertFailStore struct{ *memstore.Mem }

func (s stateInsertFailStore) InsertOAuthState(context.Context, *store.OAuthState) error {
	return errFailNext
}

// stateClaimFailStore returns a state row from lookup but deletes 0 rows (claim lost the race).
type stateClaimFailStore struct {
	*memstore.Mem
	row *store.OAuthState
}

func (s stateClaimFailStore) GetOAuthStateByState(context.Context, string) (*store.OAuthState, error) {
	return s.row, nil
}
func (s stateClaimFailStore) DeleteOAuthState(context.Context, uuid.UUID) (int64, error) {
	return 0, nil
}

// stateDeleteErrStore returns a state row but errors on the delete (claim) call.
type stateDeleteErrStore struct {
	*memstore.Mem
	row *store.OAuthState
}

func (s stateDeleteErrStore) GetOAuthStateByState(context.Context, string) (*store.OAuthState, error) {
	return s.row, nil
}
func (s stateDeleteErrStore) DeleteOAuthState(context.Context, uuid.UUID) (int64, error) {
	return 0, errFailNext
}

// completeConfigErrStore fails GetOAuthConfigByProvider (the config lookup inside completeCore).
type completeConfigErrStore struct{ *memstore.Mem }

func (s completeConfigErrStore) GetOAuthConfigByProvider(context.Context, uuid.UUID, uuid.UUID) (*store.OAuthProviderConfig, error) {
	return nil, errFailNext
}

// findTokenFailStore fails FindOAuthToken.
type findTokenFailStore struct{ *memstore.Mem }

func (s findTokenFailStore) FindOAuthToken(context.Context, uuid.UUID, uuid.UUID, string) (*store.OAuthToken, error) {
	return nil, errFailNext
}

// tokenInsertFailStore fails InsertOAuthToken (find returns nil first).
type tokenInsertFailStore struct{ *memstore.Mem }

func (s tokenInsertFailStore) InsertOAuthToken(context.Context, *store.OAuthToken) error {
	return errFailNext
}

// tokenDeleteFailStore fails DeleteOAuthToken (lookup returns the row).
type tokenDeleteFailStore struct{ *memstore.Mem }

func (s tokenDeleteFailStore) DeleteOAuthToken(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return false, errFailNext
}

// tokenUpdateFailStore fails UpdateOAuthToken.
type tokenUpdateFailStore struct{ *memstore.Mem }

func (s tokenUpdateFailStore) UpdateOAuthToken(context.Context, *store.OAuthToken) error {
	return errFailNext
}

// getOAuthErrStore fails GetManifestByKey after failAfter successful calls (to error a later
// manifest lookup while letting earlier resolve/find calls succeed).
type getOAuthErrStore struct {
	*memstore.Mem
	failAfter int
	calls     int
}

func (s *getOAuthErrStore) GetManifestByKey(ctx context.Context, userID uuid.UUID, kind, key string) (*store.ProviderManifest, error) {
	s.calls++
	if s.calls > s.failAfter {
		return nil, errFailNext
	}
	return s.Mem.GetManifestByKey(ctx, userID, kind, key)
}

// refreshReReadStore returns a fresh (future-expiry) token on the second FindOAuthToken call,
// simulating a sibling having refreshed the row while we held the lock.
type refreshReReadStore struct {
	*memstore.Mem
	fresh     *store.OAuthToken
	findCount int
}

func (s *refreshReReadStore) FindOAuthToken(ctx context.Context, userID, providerID uuid.UUID, account string) (*store.OAuthToken, error) {
	s.findCount++
	if s.findCount >= 2 {
		return s.fresh, nil
	}
	return s.Mem.FindOAuthToken(ctx, userID, providerID, account)
}

// ---- ciphers for ordered enc/dec failures ----

// encOnStoreFailCipher fails the Nth EncryptString call; decrypts pass through.
type encOnStoreFailCipher struct {
	failOn int
	calls  int
}

func (c encOnStoreFailCipher) Encrypt(b []byte) ([]byte, error) {
	return append([]byte("ct:"), b...), nil
}
func (c encOnStoreFailCipher) Decrypt(b []byte) ([]byte, error) { return b, nil }
func (c *encOnStoreFailCipher) EncryptString(s string) ([]byte, error) {
	c.calls++
	if c.calls == c.failOn {
		return nil, errFailNext
	}
	return []byte("ct:" + s), nil
}
func (c encOnStoreFailCipher) DecryptToString(b []byte) (string, error) { return string(b), nil }

// decOnNthFailCipher fails the Nth DecryptToString; encrypts pass through.
type decOnNthFailCipher struct {
	failOn int
	calls  int
}

func (c decOnNthFailCipher) Encrypt(b []byte) ([]byte, error) {
	return append([]byte("ct:"), b...), nil
}
func (c decOnNthFailCipher) Decrypt(b []byte) ([]byte, error)       { return b, nil }
func (c decOnNthFailCipher) EncryptString(s string) ([]byte, error) { return []byte("ct:" + s), nil }
func (c *decOnNthFailCipher) DecryptToString(b []byte) (string, error) {
	c.calls++
	if c.calls == c.failOn {
		return "", errFailNext
	}
	return string(b), nil
}

// encFailDecOkCipher decrypts fine but fails every EncryptString (for the refresh re-encrypt path).
type encFailDecOkCipher struct{}

func (encFailDecOkCipher) Encrypt(b []byte) ([]byte, error)         { return b, nil }
func (encFailDecOkCipher) Decrypt(b []byte) ([]byte, error)         { return b, nil }
func (encFailDecOkCipher) EncryptString(string) ([]byte, error)     { return nil, errFailNext }
func (encFailDecOkCipher) DecryptToString(b []byte) (string, error) { return string(b), nil }
