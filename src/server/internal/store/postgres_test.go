package store_test

import (
	"context"
	"os"
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
}

func TestPoolAccessor(t *testing.T) {
	if pg.Pool() == nil {
		t.Fatal("pool")
	}
}
