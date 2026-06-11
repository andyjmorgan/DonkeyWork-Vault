package store_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/db"
	"donkeywork.dev/vault-server/internal/store"
)

var pg *store.Postgres

func TestMain(m *testing.M) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	if dsn == "" {
		// No database configured: skip the integration suite.
		os.Exit(0)
	}
	ctx := context.Background()
	p, err := store.NewPostgres(ctx, dsn)
	if err != nil {
		panic(err)
	}
	// Fresh schema each run.
	if _, err := p.Pool().Exec(ctx, `DROP SCHEMA IF EXISTS vault CASCADE`); err != nil {
		panic(err)
	}
	if err := db.Migrate(ctx, p.Pool()); err != nil {
		panic(err)
	}
	// Re-running Migrate is a no-op (idempotency path).
	if err := db.Migrate(ctx, p.Pool()); err != nil {
		panic(err)
	}
	pg = p
	code := m.Run()
	p.Close()
	os.Exit(code)
}

func ctx() context.Context { return context.Background() }
func sp(s string) *string  { return &s }

func TestAccessKeyCRUD(t *testing.T) {
	u := uuid.New()
	k := &store.AccessKey{UserID: u, TenantID: uuid.New(), Name: "k1", Description: sp("d"),
		KeyHash: []byte("hash-" + u.String()), KeyPrefix: "dwv_ab", Scopes: []string{"vault:read"}, Enabled: true}
	if err := pg.InsertAccessKey(ctx(), k); err != nil {
		t.Fatal(err)
	}
	if k.ID == uuid.Nil || k.CreatedAt.IsZero() {
		t.Fatal("insert should populate id/created_at")
	}
	got, err := pg.GetAccessKeyByID(ctx(), u, k.ID)
	if err != nil || got == nil || got.Name != "k1" {
		t.Fatalf("get: %+v %v", got, err)
	}
	if other, _ := pg.GetAccessKeyByID(ctx(), uuid.New(), k.ID); other != nil {
		t.Fatal("user scoping leak")
	}
	byHash, _ := pg.GetAccessKeyByHash(ctx(), k.KeyHash)
	if byHash == nil {
		t.Fatal("by hash")
	}
	if err := pg.TouchAccessKeyLastUsed(ctx(), k.ID); err != nil {
		t.Fatal(err)
	}
	upd, err := pg.SetAccessKeyEnabled(ctx(), u, k.ID, false)
	if err != nil || upd.Enabled {
		t.Fatalf("set enabled: %+v %v", upd, err)
	}
	list, _ := pg.ListAccessKeys(ctx(), u)
	if len(list) != 1 {
		t.Fatalf("list %d", len(list))
	}
	ok, _ := pg.DeleteAccessKey(ctx(), u, k.ID)
	if !ok {
		t.Fatal("delete")
	}
	ok, _ = pg.DeleteAccessKey(ctx(), u, k.ID)
	if ok {
		t.Fatal("double delete")
	}
}

func TestAPIKeyCRUD(t *testing.T) {
	u := uuid.New()
	k := &store.APIKey{UserID: u, TenantID: uuid.New(), Name: "api1", ProviderKey: "", Kind: "opaque",
		FieldsCipher: []byte{1, 2, 3}, Description: sp("desc"), HeaderName: sp("Authorization")}
	if err := pg.InsertAPIKey(ctx(), k); err != nil {
		t.Fatal(err)
	}
	got, _ := pg.GetAPIKeyByName(ctx(), u, "api1")
	if got == nil {
		t.Fatal("get by name")
	}
	got.FieldsCipher = []byte{4, 5}
	got.Username = sp("bob")
	if err := pg.UpdateAPIKey(ctx(), got); err != nil {
		t.Fatal(err)
	}
	_ = pg.TouchAPIKeyLastUsed(ctx(), k.ID)
	if l, _ := pg.ListAPIKeys(ctx(), u); len(l) != 1 {
		t.Fatalf("list %d", len(l))
	}
	if ok, _ := pg.DeleteAPIKey(ctx(), u, k.ID); !ok {
		t.Fatal("delete")
	}
}

func TestOAuthConfigAndTokenAndState(t *testing.T) {
	u := uuid.New()
	pid := uuid.New()
	cfg := &store.OAuthProviderConfig{UserID: u, TenantID: uuid.New(), ProviderID: pid, ProviderKey: "acme",
		ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{2}, ScopesJSON: sp(`["openid"]`), RedirectURI: sp("https://r")}
	if err := pg.InsertOAuthConfig(ctx(), cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ClientIDCipher = []byte{9}
	if err := pg.UpdateOAuthConfig(ctx(), cfg); err != nil {
		t.Fatal(err)
	}
	if c, _ := pg.GetOAuthConfigByProvider(ctx(), u, pid); c == nil {
		t.Fatal("get config")
	}
	if l, _ := pg.ListOAuthConfigs(ctx(), u); len(l) != 1 {
		t.Fatalf("list configs %d", len(l))
	}

	// state
	st := &store.OAuthState{State: "s-" + u.String(), Provider: "acme", CodeVerifier: "v",
		OwnerUserID: u, OwnerTenantID: uuid.New(), RedirectURI: "https://cb", ExpiresAt: time.Now().Add(time.Minute)}
	if err := pg.InsertOAuthState(ctx(), st); err != nil {
		t.Fatal(err)
	}
	if got, _ := pg.GetOAuthStateByState(ctx(), st.State); got == nil {
		t.Fatal("get state")
	}
	n, _ := pg.DeleteOAuthState(ctx(), st.ID)
	if n != 1 {
		t.Fatalf("delete state %d", n)
	}
	n, _ = pg.DeleteOAuthState(ctx(), st.ID)
	if n != 0 {
		t.Fatal("double delete state")
	}

	// token
	exp := time.Now().Add(time.Hour)
	tok := &store.OAuthToken{UserID: u, TenantID: uuid.New(), ProviderID: pid, ProviderKey: "acme", Account: "a@b.com",
		AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{2}, ScopesJSON: sp(`["openid"]`), ExpiresAt: &exp}
	if err := pg.InsertOAuthToken(ctx(), tok); err != nil {
		t.Fatal(err)
	}
	tok.AccessTokenCipher = []byte{7}
	if err := pg.UpdateOAuthToken(ctx(), tok); err != nil {
		t.Fatal(err)
	}
	if f, _ := pg.FindOAuthToken(ctx(), u, pid, "a@b.com"); f == nil {
		t.Fatal("find token by account")
	}
	if f, _ := pg.FindOAuthToken(ctx(), u, pid, ""); f == nil {
		t.Fatal("find token no account")
	}
	if g, _ := pg.GetOAuthTokenByID(ctx(), u, tok.ID); g == nil {
		t.Fatal("get token")
	}
	if l, _ := pg.ListOAuthTokens(ctx(), u); len(l) != 1 {
		t.Fatalf("list tokens %d", len(l))
	}
	if ok, _ := pg.DeleteOAuthToken(ctx(), u, tok.ID); !ok {
		t.Fatal("delete token")
	}
	if ok, _ := pg.DeleteOAuthConfig(ctx(), u, cfg.ID); !ok {
		t.Fatal("delete config")
	}
}

// TestDeleteExpiredOAuthStates exercises the abandoned-flow reaper against real Postgres: a lapsed
// state is removed while a still-live one survives.
func TestDeleteExpiredOAuthStates(t *testing.T) {
	u := uuid.New()
	expired := &store.OAuthState{State: "exp-" + u.String(), Provider: "acme", CodeVerifier: "v",
		OwnerUserID: u, OwnerTenantID: uuid.New(), RedirectURI: "https://cb", ExpiresAt: time.Now().Add(-time.Minute)}
	live := &store.OAuthState{State: "live-" + u.String(), Provider: "acme", CodeVerifier: "v",
		OwnerUserID: u, OwnerTenantID: uuid.New(), RedirectURI: "https://cb", ExpiresAt: time.Now().Add(time.Hour)}
	if err := pg.InsertOAuthState(ctx(), expired); err != nil {
		t.Fatal(err)
	}
	if err := pg.InsertOAuthState(ctx(), live); err != nil {
		t.Fatal(err)
	}

	n, err := pg.DeleteExpiredOAuthStates(ctx())
	if err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatalf("expected at least the expired row reaped, got %d", n)
	}
	if g, _ := pg.GetOAuthStateByState(ctx(), expired.State); g != nil {
		t.Fatal("expired state should be reaped")
	}
	if g, _ := pg.GetOAuthStateByState(ctx(), live.State); g == nil {
		t.Fatal("live state should remain")
	}
	// Clean up the live row so it does not leak into other tests sharing the schema.
	if _, err := pg.DeleteOAuthState(ctx(), live.ID); err != nil {
		t.Fatal(err)
	}
}

func TestManifestCascade(t *testing.T) {
	u := uuid.New()
	pid := uuid.New()
	m := &store.ProviderManifest{UserID: u, TenantID: uuid.New(), Kind: "oauth", Key: "acme",
		ProviderID: pid, ParentID: uuid.Nil, DocumentJSON: `{"key":"acme"}`}
	if err := pg.InsertManifest(ctx(), m); err != nil {
		t.Fatal(err)
	}
	m.DocumentJSON = `{"key":"acme","name":"Acme"}`
	if err := pg.UpdateManifest(ctx(), m); err != nil {
		t.Fatal(err)
	}
	if got, _ := pg.GetManifestByKey(ctx(), u, "oauth", "acme"); got == nil {
		t.Fatal("get manifest")
	}
	if l, _ := pg.ListOAuthManifests(ctx(), u); len(l) != 1 {
		t.Fatalf("list manifests %d", len(l))
	}
	// Seed a config + token under the same provider id, then cascade-delete.
	_ = pg.InsertOAuthConfig(ctx(), &store.OAuthProviderConfig{UserID: u, TenantID: uuid.New(), ProviderID: pid, ProviderKey: "acme", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{2}})
	_ = pg.InsertOAuthToken(ctx(), &store.OAuthToken{UserID: u, TenantID: uuid.New(), ProviderID: pid, ProviderKey: "acme", Account: "x", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{2}})
	ok, err := pg.DeleteManifestCascade(ctx(), u, "oauth", "acme")
	if err != nil || !ok {
		t.Fatalf("cascade: %v %v", ok, err)
	}
	if l, _ := pg.ListOAuthConfigs(ctx(), u); len(l) != 0 {
		t.Fatal("configs should be cascaded")
	}
	if l, _ := pg.ListOAuthTokens(ctx(), u); len(l) != 0 {
		t.Fatal("tokens should be cascaded")
	}
	if ok, _ := pg.DeleteManifestCascade(ctx(), u, "oauth", "missing"); ok {
		t.Fatal("missing cascade should be false")
	}
}

func TestAuditStore(t *testing.T) {
	u := uuid.New()
	tn := uuid.New()
	ip := "203.0.113.5"
	mk := func(et int, age time.Duration) store.AuditEntry {
		return store.AuditEntry{EventType: et, Outcome: 0, UserID: u, TenantID: tn, SourceIP: &ip,
			Headers: map[string]string{"user-agent": "curl"}, Transport: "http", Method: sp("GET /x"), CreatedAt: time.Now().Add(-age)}
	}
	if err := pg.InsertAuditBatch(ctx(), []store.AuditEntry{mk(1, 0), mk(6, 0), mk(1, 400*24*time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := pg.InsertAuditBatch(ctx(), nil); err != nil {
		t.Fatal("empty batch")
	}
	items, total, err := pg.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: tn, Limit: 10})
	if err != nil || total != 3 || len(items) != 3 {
		t.Fatalf("query: total=%d items=%d err=%v", total, len(items), err)
	}
	if items[0].SourceIP == nil || *items[0].SourceIP != ip {
		t.Fatalf("source ip round-trip: %+v", items[0].SourceIP)
	}
	et := 1
	_, total, _ = pg.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, EventType: &et})
	if total != 2 {
		t.Fatalf("filtered total %d", total)
	}
	// Retention deletes the one 400-day-old row.
	deleted, err := pg.DeleteAuditOlderThan(ctx(), time.Now().AddDate(0, 0, -180), 100)
	if err != nil || deleted != 1 {
		t.Fatalf("retention deleted=%d err=%v", deleted, err)
	}
}

func TestNewPostgresErrors(t *testing.T) {
	if _, err := store.NewPostgres(context.Background(), "::::bad-dsn"); err == nil {
		t.Fatal("expected parse error")
	}
	if _, err := store.NewPostgres(context.Background(), "postgres://nobody@127.0.0.1:1/none?sslmode=disable"); err == nil {
		t.Fatal("expected connect/ping error")
	}
	// Pool opens lazily, so a DSN that parses and reaches the live host but fails auth surfaces at
	// Ping — exercising the close-and-return-ping-error branch (distinct from the open-pool error).
	if dsn := os.Getenv("VAULT_TEST_DSN"); dsn != "" {
		bad := strings.Replace(dsn, "vault:vault@", "vault:wrongpassword@", 1)
		if _, err := store.NewPostgres(context.Background(), bad); err == nil {
			t.Fatal("expected ping/auth error")
		}
	}
}

func TestPoolAccessor(t *testing.T) {
	if pg.Pool() == nil {
		t.Fatal("pool")
	}
}

// TestNotFoundPaths exercises the noRows mapping (return nil, nil) on every getter and the
// false/zero returns on deletes of nonexistent rows, plus update-of-nonexistent no-ops.
func TestNotFoundPaths(t *testing.T) {
	u := uuid.New()
	missing := uuid.New()

	if g, err := pg.GetAccessKeyByID(ctx(), u, missing); g != nil || err != nil {
		t.Fatalf("access by id miss: %+v %v", g, err)
	}
	if g, err := pg.GetAccessKeyByHash(ctx(), []byte("no-such-hash")); g != nil || err != nil {
		t.Fatalf("access by hash miss: %+v %v", g, err)
	}
	if g, err := pg.SetAccessKeyEnabled(ctx(), u, missing, true); g != nil || err != nil {
		t.Fatalf("set enabled miss: %+v %v", g, err)
	}
	if ok, err := pg.DeleteAccessKey(ctx(), u, missing); ok || err != nil {
		t.Fatalf("delete access miss: %v %v", ok, err)
	}

	if g, err := pg.GetAPIKeyByName(ctx(), u, "no-such-name"); g != nil || err != nil {
		t.Fatalf("api by name miss: %+v %v", g, err)
	}
	if ok, err := pg.DeleteAPIKey(ctx(), u, missing); ok || err != nil {
		t.Fatalf("delete api miss: %v %v", ok, err)
	}

	if g, err := pg.GetOAuthConfigByProvider(ctx(), u, missing); g != nil || err != nil {
		t.Fatalf("config by provider miss: %+v %v", g, err)
	}
	if ok, err := pg.DeleteOAuthConfig(ctx(), u, missing); ok || err != nil {
		t.Fatalf("delete config miss: %v %v", ok, err)
	}

	if g, err := pg.GetOAuthStateByState(ctx(), "no-such-state"); g != nil || err != nil {
		t.Fatalf("state miss: %+v %v", g, err)
	}
	if n, err := pg.DeleteOAuthState(ctx(), missing); n != 0 || err != nil {
		t.Fatalf("delete state miss: %d %v", n, err)
	}

	if g, err := pg.GetOAuthTokenByID(ctx(), u, missing); g != nil || err != nil {
		t.Fatalf("token by id miss: %+v %v", g, err)
	}
	if g, err := pg.FindOAuthToken(ctx(), u, missing, "acct"); g != nil || err != nil {
		t.Fatalf("find token miss: %+v %v", g, err)
	}
	if g, err := pg.FindOAuthToken(ctx(), u, missing, ""); g != nil || err != nil {
		t.Fatalf("find token no-account miss: %+v %v", g, err)
	}
	if ok, err := pg.DeleteOAuthToken(ctx(), u, missing); ok || err != nil {
		t.Fatalf("delete token miss: %v %v", ok, err)
	}

	if g, err := pg.GetManifestByKey(ctx(), u, "oauth", "no-such-key"); g != nil || err != nil {
		t.Fatalf("manifest by key miss: %+v %v", g, err)
	}

	// Update of a nonexistent row is a no-op (zero rows affected, no error).
	if err := pg.UpdateAPIKey(ctx(), &store.APIKey{ID: missing, UserID: u, Kind: "opaque", FieldsCipher: []byte{1}}); err != nil {
		t.Fatalf("update api miss: %v", err)
	}
	if err := pg.UpdateOAuthConfig(ctx(), &store.OAuthProviderConfig{ID: missing, UserID: u, ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{1}}); err != nil {
		t.Fatalf("update config miss: %v", err)
	}
	if err := pg.UpdateOAuthToken(ctx(), &store.OAuthToken{ID: missing, UserID: u, AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{1}}); err != nil {
		t.Fatalf("update token miss: %v", err)
	}
	if err := pg.UpdateManifest(ctx(), &store.ProviderManifest{ID: missing, UserID: u, Kind: "oauth", Key: "x", DocumentJSON: "{}"}); err != nil {
		t.Fatalf("update manifest miss: %v", err)
	}
	if err := pg.TouchAccessKeyLastUsed(ctx(), missing); err != nil {
		t.Fatalf("touch access miss: %v", err)
	}
	if err := pg.TouchAPIKeyLastUsed(ctx(), missing); err != nil {
		t.Fatalf("touch api miss: %v", err)
	}
}

// TestQueryAuditFilters drives every optional WHERE clause (Outcome, FilterUserID, Since, Until)
// and the offset/limit paging path so QueryAudit's filter assembly is fully covered.
func TestQueryAuditFilters(t *testing.T) {
	u := uuid.New()
	tn := uuid.New()
	now := time.Now()
	h := map[string]string{"user-agent": "curl"}
	entries := []store.AuditEntry{
		{EventType: 1, Outcome: 0, UserID: u, TenantID: tn, Headers: h, Transport: "http", CreatedAt: now.Add(-2 * time.Hour)},
		{EventType: 2, Outcome: 1, UserID: u, TenantID: tn, Headers: h, Transport: "http", CreatedAt: now.Add(-1 * time.Hour)},
		{EventType: 1, Outcome: 1, UserID: u, TenantID: tn, Headers: h, Transport: "http", CreatedAt: now},
	}
	if err := pg.InsertAuditBatch(ctx(), entries); err != nil {
		t.Fatal(err)
	}

	outcome := 1
	if _, total, err := pg.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, Outcome: &outcome}); err != nil || total != 2 {
		t.Fatalf("outcome filter total=%d err=%v", total, err)
	}
	if _, total, err := pg.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, FilterUserID: &u}); err != nil || total != 3 {
		t.Fatalf("filter-user total=%d err=%v", total, err)
	}
	since := now.Add(-90 * time.Minute)
	if _, total, err := pg.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, Since: &since}); err != nil || total != 2 {
		t.Fatalf("since total=%d err=%v", total, err)
	}
	until := now.Add(-30 * time.Minute)
	if _, total, err := pg.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, Until: &until}); err != nil || total != 2 {
		t.Fatalf("until total=%d err=%v", total, err)
	}
	// Offset paging: skip the first row.
	items, total, err := pg.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: tn, Limit: 1, Offset: 1})
	if err != nil || total != 3 || len(items) != 1 {
		t.Fatalf("paged total=%d items=%d err=%v", total, len(items), err)
	}
}

// TestQueryErrorPaths uses a pool that is closed mid-test to drive the post-Query error returns
// in the List* methods, the InsertAuditBatch send-batch error, the QueryAudit count error, and the
// DeleteManifestCascade Begin error — the unhappy branches a healthy pool never reaches.
func TestQueryErrorPaths(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	bad, err := store.NewPostgres(ctx(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	bad.Close() // pool is now closed; every query errors.
	u := uuid.New()

	if _, err := bad.ListAccessKeys(ctx(), u); err == nil {
		t.Fatal("list access keys should error on closed pool")
	}
	if _, err := bad.ListAPIKeys(ctx(), u); err == nil {
		t.Fatal("list api keys should error")
	}
	if _, err := bad.ListOAuthConfigs(ctx(), u); err == nil {
		t.Fatal("list configs should error")
	}
	if _, err := bad.ListOAuthTokens(ctx(), u); err == nil {
		t.Fatal("list tokens should error")
	}
	if _, err := bad.ListOAuthManifests(ctx(), u); err == nil {
		t.Fatal("list manifests should error")
	}
	if _, _, err := bad.QueryAudit(ctx(), store.AuditFilter{UserID: u, TenantID: u, Limit: 1}); err == nil {
		t.Fatal("query audit should error")
	}
	if err := bad.InsertAuditBatch(ctx(), []store.AuditEntry{{UserID: u, TenantID: u, Transport: "http", CreatedAt: time.Now()}}); err == nil {
		t.Fatal("insert audit batch should error")
	}
	if _, err := bad.DeleteManifestCascade(ctx(), u, "oauth", "k"); err == nil {
		t.Fatal("cascade should error on Begin")
	}
	// Getters/inserts/updates/deletes also surface the closed-pool error.
	if _, err := bad.GetAccessKeyByID(ctx(), u, u); err == nil {
		t.Fatal("get access should error")
	}
	if err := bad.InsertAccessKey(ctx(), &store.AccessKey{UserID: u, Name: "x", KeyHash: []byte("h"), KeyPrefix: "p"}); err == nil {
		t.Fatal("insert access should error")
	}
	if err := bad.TouchAccessKeyLastUsed(ctx(), u); err == nil {
		t.Fatal("touch should error")
	}
	if _, err := bad.DeleteAccessKey(ctx(), u, u); err == nil {
		t.Fatal("delete access should error")
	}
	// GetOAuthStateByState's non-noRows error branch (distinct from its nil/nil miss).
	if _, err := bad.GetOAuthStateByState(ctx(), "any-state"); err == nil {
		t.Fatal("get state should error on closed pool")
	}

}

// TestDeleteManifestCascadeInnerErrors drives the cascade's transactional unhappy branches: the
// per-table inner DELETE errors (configs/tokens/manifests) by dropping the target tables so the
// statements inside the committed transaction fail after the lookup succeeds. Runs on a private
// schema-restoring pool so the suite's shared schema is left intact.
func TestDeleteManifestCascadeInnerErrors(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	live, err := store.NewPostgres(ctx(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()

	seed := func(key string) uuid.UUID {
		u := uuid.New()
		m := &store.ProviderManifest{UserID: u, TenantID: uuid.New(), Kind: "oauth", Key: key,
			ProviderID: uuid.New(), ParentID: uuid.Nil, DocumentJSON: "{}"}
		if err := live.InsertManifest(ctx(), m); err != nil {
			t.Fatal(err)
		}
		return u
	}

	// 1) oauth_tokens DELETE fails: drop the table, attempt cascade, then restore it.
	u1 := seed("cascade-tokens")
	if _, err := live.Pool().Exec(ctx(), `ALTER TABLE vault.oauth_tokens RENAME TO oauth_tokens_bak`); err != nil {
		t.Fatal(err)
	}
	if _, err := live.DeleteManifestCascade(ctx(), u1, "oauth", "cascade-tokens"); err == nil {
		t.Fatal("expected inner token-delete error")
	}
	if _, err := live.Pool().Exec(ctx(), `ALTER TABLE vault.oauth_tokens_bak RENAME TO oauth_tokens`); err != nil {
		t.Fatal(err)
	}

	// 2) oauth_provider_configs DELETE fails (first inner statement).
	u2 := seed("cascade-configs")
	if _, err := live.Pool().Exec(ctx(), `ALTER TABLE vault.oauth_provider_configs RENAME TO configs_bak`); err != nil {
		t.Fatal(err)
	}
	if _, err := live.DeleteManifestCascade(ctx(), u2, "oauth", "cascade-configs"); err == nil {
		t.Fatal("expected inner config-delete error")
	}
	if _, err := live.Pool().Exec(ctx(), `ALTER TABLE vault.configs_bak RENAME TO oauth_provider_configs`); err != nil {
		t.Fatal(err)
	}

	// 3) Non-oauth cascade reaches the final manifest DELETE without the oauth cleanup block; drop
	// the manifests table to fail that statement.
	u3 := uuid.New()
	mc := &store.ProviderManifest{UserID: u3, TenantID: uuid.New(), Kind: "custom", Key: "cascade-final",
		ProviderID: uuid.New(), ParentID: uuid.Nil, DocumentJSON: "{}"}
	if err := live.InsertManifest(ctx(), mc); err != nil {
		t.Fatal(err)
	}
	if _, err := live.Pool().Exec(ctx(), `ALTER TABLE vault.provider_manifests RENAME TO manifests_bak`); err != nil {
		t.Fatal(err)
	}
	// The lookup itself now also fails (table gone) — exercises the QueryRow non-noRows error path.
	if _, err := live.DeleteManifestCascade(ctx(), u3, "custom", "cascade-final"); err == nil {
		t.Fatal("expected manifest-table error")
	}
	if _, err := live.Pool().Exec(ctx(), `ALTER TABLE vault.manifests_bak RENAME TO provider_manifests`); err != nil {
		t.Fatal(err)
	}
}

// TestClose covers the Close accessor against a throwaway pool.
func TestClose(t *testing.T) {
	p, err := store.NewPostgres(ctx(), os.Getenv("VAULT_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
}

// TestQueryAuditMainQueryError covers QueryAudit's branch where the count succeeds but the row
// SELECT fails: a column referenced only by the row query (not by count(*)) is dropped. This runs
// in a dedicated, freshly-migrated database so the irreversible DROP COLUMN never perturbs the
// shared suite schema (a result-type change there would poison pgx's cached plans across reruns).
func TestQueryAuditMainQueryError(t *testing.T) {
	dsn := os.Getenv("VAULT_TEST_DSN")
	const isoDB = "vault_store_audit_test"

	admin, err := store.NewPostgres(ctx(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Pool().Exec(ctx(), `DROP DATABASE IF EXISTS `+isoDB+` WITH (FORCE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Pool().Exec(ctx(), `CREATE DATABASE `+isoDB); err != nil {
		t.Fatal(err)
	}
	admin.Close()
	t.Cleanup(func() {
		a, err := store.NewPostgres(ctx(), dsn)
		if err != nil {
			return
		}
		defer a.Close()
		_, _ = a.Pool().Exec(ctx(), `DROP DATABASE IF EXISTS `+isoDB+` WITH (FORCE)`)
	})

	isoDSN := strings.Replace(dsn, "/vault_test?", "/"+isoDB+"?", 1)
	live, err := store.NewPostgres(ctx(), isoDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if err := db.Migrate(ctx(), live.Pool()); err != nil {
		t.Fatal(err)
	}

	if _, err := live.Pool().Exec(ctx(), `ALTER TABLE vault.audit_log DROP COLUMN transport`); err != nil {
		t.Fatal(err)
	}
	if _, _, qerr := live.QueryAudit(ctx(), store.AuditFilter{UserID: uuid.New(), TenantID: uuid.New(), Limit: 1}); qerr == nil {
		t.Fatal("expected row-query error when transport column is missing")
	}
}
