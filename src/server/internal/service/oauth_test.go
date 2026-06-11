package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

func testCipher(t *testing.T) crypto.Cipher {
	t.Helper()
	kek, err := crypto.NewLocalKekProvider("local:v1", map[string]string{"local:v1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	if err != nil {
		t.Fatal(err)
	}
	return crypto.NewEnvelopeCipher(kek)
}

type oauthFixture struct {
	ms             *memstore.Mem
	resolver       *manifests.Resolver
	flow           *OAuthFlowService
	tokens         *OAuthTokenService
	configs        *OAuthConfigService
	ctx            context.Context
	idp            *httptest.Server
	tokenResp      string
	tokenStatus    int
	userinfoStatus int
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	cipher := testCipher(t)
	ms := memstore.New()
	loader, err := manifests.NewLoader()
	if err != nil {
		t.Fatal(err)
	}
	resolver := manifests.NewResolver(ms, loader)
	log := audit.NewLog(100, nil, nil)
	f := &oauthFixture{ms: ms, resolver: resolver}
	f.tokenResp = `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600,"scope":"openid email"}`
	f.tokenStatus = 200
	f.userinfoStatus = 200

	f.idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.tokenStatus)
			_, _ = w.Write([]byte(f.tokenResp))
		case "/me":
			w.WriteHeader(f.userinfoStatus)
			_, _ = w.Write([]byte(`{"email":"alice@example.com"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.idp.Close)

	client := f.idp.Client()
	f.flow = NewOAuthFlowService(ms, cipher, resolver, log, client, nil)
	f.tokens = NewOAuthTokenService(ms, cipher, log, resolver, client)
	f.configs = NewOAuthConfigService(ms, cipher, log, resolver)

	u, tn := uuid.New(), uuid.New()
	f.ctx = contracts.WithCaller(context.Background(), contracts.Caller{UserID: u, TenantID: tn})

	// Seed provider manifest + app config.
	if err := resolver.UpsertOAuth(f.ctx, manifests.Manifest{
		Key: "acme", TokenEndpoint: f.idp.URL + "/token", AuthorizationEndpoint: f.idp.URL + "/auth",
		UserinfoEndpoint: f.idp.URL + "/me", ScopeDelimiter: " ",
		DefaultScopes: []string{"openid"}, Scopes: []manifests.ScopeDef{{Value: "openid"}, {Value: "email"}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.configs.Upsert(f.ctx, "acme", "client-id", strPtr("client-secret"), []string{"openid", "email"}, nil); err != nil {
		t.Fatal(err)
	}
	return f
}

func strPtr(s string) *string { return &s }

func TestBeginBuildsAuthorizeURL(t *testing.T) {
	f := newOAuthFixture(t)
	res, err := f.flow.Begin(f.ctx, "acme", []string{"openid", "bogus"}, "https://vault.example")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.AuthorizeURL, "code_challenge=") || !strings.Contains(res.AuthorizeURL, "client_id=client-id") {
		t.Fatalf("authorize url: %s", res.AuthorizeURL)
	}
	if !strings.Contains(res.AuthorizeURL, "state="+res.State) {
		t.Fatal("state not in url")
	}
	// "bogus" must have been filtered out by the catalog allowlist.
	if strings.Contains(res.AuthorizeURL, "bogus") {
		t.Fatal("uncatalogued scope leaked")
	}
}

func TestBeginUnknownProvider(t *testing.T) {
	f := newOAuthFixture(t)
	if _, err := f.flow.Begin(f.ctx, "ghost", nil, "https://v"); err == nil {
		t.Fatal("expected unknown provider error")
	}
}

func TestCompleteAndGetToken(t *testing.T) {
	f := newOAuthFixture(t)
	res, err := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://vault.example")
	if err != nil {
		t.Fatal(err)
	}
	// Complete is anonymous (identity from the state row).
	done, err := f.flow.Complete(context.Background(), "auth-code", res.State)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if done.Account != "alice@example.com" || done.Provider != "acme" {
		t.Fatalf("complete result: %+v", done)
	}

	// Replaying the same state is rejected (already claimed).
	if _, err := f.flow.Complete(context.Background(), "auth-code", res.State); err == nil {
		t.Fatal("expected replay rejection")
	}

	// List + fresh access token.
	list, _ := f.tokens.List(f.ctx)
	if len(list) != 1 {
		t.Fatalf("tokens %d", len(list))
	}
	tok, err := f.tokens.GetAccessToken(f.ctx, "acme", "")
	if err != nil || tok == nil || tok.AccessToken != "access-1" {
		t.Fatalf("get token: %+v %v", tok, err)
	}

	// Delete.
	ok, err := f.tokens.Delete(f.ctx, list[0].ID)
	if err != nil || !ok {
		t.Fatalf("delete token: %v %v", ok, err)
	}
}

func TestGetTokenRefresh(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://vault.example")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}

	// Force expiry so the next read refreshes.
	list, _ := f.tokens.List(f.ctx)
	tokRow, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	tokRow.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, tokRow)

	f.tokenResp = `{"access_token":"access-2","expires_in":3600}`
	tok, err := f.tokens.GetAccessToken(f.ctx, "acme", "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if tok.AccessToken != "access-2" {
		t.Fatalf("expected refreshed token, got %q", tok.AccessToken)
	}
}

func TestGetTokenNotFound(t *testing.T) {
	f := newOAuthFixture(t)
	tok, err := f.tokens.GetAccessToken(f.ctx, "acme", "")
	if err != nil || tok != nil {
		t.Fatalf("expected nil token, got %+v %v", tok, err)
	}
}

func TestCompleteTokenExchangeFails(t *testing.T) {
	f := newOAuthFixture(t)
	f.tokenResp = `` // will still 200 with empty body → no access_token
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://vault.example")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected error on missing access_token")
	}
}

func TestFilterScopesToCatalog(t *testing.T) {
	m := &manifests.Manifest{Scopes: []manifests.ScopeDef{{Value: "a"}}, DefaultScopes: []string{"b"}}
	kept, dropped := FilterScopesToCatalog(m, []string{"a", "b", "c"})
	if strings.Join(kept, ",") != "a,b" || strings.Join(dropped, ",") != "c" {
		t.Fatalf("kept=%v dropped=%v", kept, dropped)
	}
	// No catalog → passthrough.
	empty := &manifests.Manifest{}
	kept, dropped = FilterScopesToCatalog(empty, []string{"x"})
	if len(kept) != 1 || dropped != nil {
		t.Fatalf("passthrough failed: %v %v", kept, dropped)
	}
}

func TestCredentialUsage(t *testing.T) {
	if Scheme("") != "header" || Scheme("u") != "basic" {
		t.Fatal("scheme")
	}
	if HeaderName("") != "Authorization" || HeaderName("X") != "X" {
		t.Fatal("header name")
	}
	n, v := AssembleHeader("X-Key", "tok-", "", "abc")
	if n != "X-Key" || v != "tok-abc" {
		t.Fatalf("assemble header: %s %s", n, v)
	}
	n, v = AssembleHeader("", "", "user", "pass")
	if n != "Authorization" || !strings.HasPrefix(v, "Basic ") {
		t.Fatalf("assemble basic: %s %s", n, v)
	}
}

func TestErrorMessages(t *testing.T) {
	if (ValidationError{"a"}).Error() != "a" {
		t.Fatal("validation")
	}
	if (OAuthAuthorizationError{"b"}).Error() != "b" {
		t.Fatal("authz")
	}
	if (OAuthRefreshError{"c"}).Error() != "c" {
		t.Fatal("refresh")
	}
}

func TestRefreshFailure(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	tok, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	tok.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, tok)

	f.tokenStatus = 500 // refresh now fails
	if _, err := f.tokens.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected refresh error")
	} else if _, ok := err.(OAuthRefreshError); !ok {
		t.Fatalf("expected OAuthRefreshError, got %T", err)
	}
}

func TestCompleteTokenEndpoint500(t *testing.T) {
	f := newOAuthFixture(t)
	f.tokenStatus = 500
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected token exchange failure")
	}
}

func TestFetchAccountFallback(t *testing.T) {
	f := newOAuthFixture(t)
	f.userinfoStatus = 500 // userinfo fails -> account "default"
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	done, err := f.flow.Complete(context.Background(), "code", res.State)
	if err != nil {
		t.Fatal(err)
	}
	if done.Account != "default" {
		t.Fatalf("expected default account, got %q", done.Account)
	}
}

type errRoundTripper struct{}

func (errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errStub
}

var errStub = &netErr{}

type netErr struct{}

func (*netErr) Error() string { return "network down" }

func TestCompleteNetworkError(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	bad := NewOAuthFlowService(f.ms, testCipher(t), f.resolver, audit.NewLog(10, nil, nil), &http.Client{Transport: errRoundTripper{}}, nil)
	if _, err := bad.Complete(context.Background(), "code", res.State); err == nil {
		t.Fatal("expected network error")
	}
}

func TestRefreshMalformedJSON(t *testing.T) {
	f := newOAuthFixture(t)
	res, _ := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://v")
	if _, err := f.flow.Complete(context.Background(), "code", res.State); err != nil {
		t.Fatal(err)
	}
	list, _ := f.tokens.List(f.ctx)
	tok, _ := f.ms.GetOAuthTokenByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, list[0].ID)
	past := time.Now().Add(-time.Hour)
	tok.ExpiresAt = &past
	_ = f.ms.UpdateOAuthToken(f.ctx, tok)

	f.tokenResp = `{}` // 200 but no access_token
	if _, err := f.tokens.GetAccessToken(f.ctx, "acme", ""); err == nil {
		t.Fatal("expected refresh parse error")
	}
}

func TestCompleteNoUserinfoEndpoint(t *testing.T) {
	f := newOAuthFixture(t)
	// A provider without a userinfo endpoint yields the "default" account.
	if err := f.resolver.UpsertOAuth(f.ctx, manifests.Manifest{Key: "noinfo", TokenEndpoint: f.idp.URL + "/token", DefaultScopes: []string{"openid"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.configs.Upsert(f.ctx, "noinfo", "cid", strPtr("sec"), []string{"openid"}, nil); err != nil {
		t.Fatal(err)
	}
	res, _ := f.flow.Begin(f.ctx, "noinfo", []string{"openid"}, "https://v")
	done, err := f.flow.Complete(context.Background(), "code", res.State)
	if err != nil || done.Account != "default" {
		t.Fatalf("expected default account: %+v %v", done, err)
	}
}

func TestCompleteWithoutRefreshTokenStoresEmptyCipher(t *testing.T) {
	f := newOAuthFixture(t)
	// Providers like GitHub OAuth apps return no refresh_token at all.
	f.tokenResp = `{"access_token":"access-1","expires_in":3600,"scope":"openid"}`
	res, err := f.flow.Begin(f.ctx, "acme", []string{"openid"}, "https://vault.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.flow.Complete(context.Background(), "auth-code", res.State); err != nil {
		t.Fatalf("complete: %v", err)
	}
	rows, err := f.ms.ListOAuthTokens(f.ctx, contracts.CallerFrom(f.ctx).UserID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("tokens %d err=%v", len(rows), err)
	}
	// The column is NOT NULL in Postgres: a nil slice would be encoded as SQL NULL and fail.
	if rows[0].RefreshTokenCipher == nil || len(rows[0].RefreshTokenCipher) != 0 {
		t.Fatalf("refresh cipher must be non-nil empty, got %v", rows[0].RefreshTokenCipher)
	}
}
