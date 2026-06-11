package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func TestMemAccessKeys(t *testing.T) {
	ctx := context.Background()
	m := New()
	u := uuid.New()
	k := &store.AccessKey{UserID: u, Name: "k", KeyHash: []byte("h"), KeyPrefix: "dwv_", Scopes: []string{"vault:read"}, Enabled: true}
	if err := m.InsertAccessKey(ctx, k); err != nil {
		t.Fatal(err)
	}
	if g, _ := m.GetAccessKeyByID(ctx, u, k.ID); g == nil {
		t.Fatal("getbyid")
	}
	if g, _ := m.GetAccessKeyByID(ctx, uuid.New(), k.ID); g != nil {
		t.Fatal("wrong user")
	}
	if g, _ := m.GetAccessKeyByHash(ctx, []byte("h")); g == nil {
		t.Fatal("byhash")
	}
	if g, _ := m.GetAccessKeyByHash(ctx, []byte("nope")); g != nil {
		t.Fatal("byhash miss")
	}
	_ = m.TouchAccessKeyLastUsed(ctx, k.ID)
	if upd, _ := m.SetAccessKeyEnabled(ctx, u, k.ID, false); upd == nil || upd.Enabled {
		t.Fatal("setenabled")
	}
	if upd, _ := m.SetAccessKeyEnabled(ctx, u, uuid.New(), true); upd != nil {
		t.Fatal("setenabled miss")
	}
	if l, _ := m.ListAccessKeys(ctx, u); len(l) != 1 {
		t.Fatal("list")
	}
	if ok, _ := m.DeleteAccessKey(ctx, u, k.ID); !ok {
		t.Fatal("delete")
	}
	if ok, _ := m.DeleteAccessKey(ctx, u, k.ID); ok {
		t.Fatal("delete miss")
	}
}

func TestMemAPIKeys(t *testing.T) {
	ctx := context.Background()
	m := New()
	u := uuid.New()
	k := &store.APIKey{UserID: u, Name: "a", Kind: "opaque", FieldsCipher: []byte{1}}
	_ = m.InsertAPIKey(ctx, k)
	k.FieldsCipher = []byte{2}
	_ = m.UpdateAPIKey(ctx, k)
	if g, _ := m.GetAPIKeyByName(ctx, u, "a"); g == nil {
		t.Fatal("getbyname")
	}
	if g, _ := m.GetAPIKeyByName(ctx, u, "z"); g != nil {
		t.Fatal("getbyname miss")
	}
	_ = m.TouchAPIKeyLastUsed(ctx, k.ID)
	if l, _ := m.ListAPIKeys(ctx, u); len(l) != 1 {
		t.Fatal("list")
	}
	if ok, _ := m.DeleteAPIKey(ctx, u, k.ID); !ok {
		t.Fatal("delete")
	}
}

func TestMemOAuth(t *testing.T) {
	ctx := context.Background()
	m := New()
	u, pid := uuid.New(), uuid.New()
	c := &store.OAuthProviderConfig{UserID: u, ProviderID: pid, ProviderKey: "p", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{2}}
	_ = m.InsertOAuthConfig(ctx, c)
	c.ClientIDCipher = []byte{9}
	_ = m.UpdateOAuthConfig(ctx, c)
	if g, _ := m.GetOAuthConfigByProvider(ctx, u, pid); g == nil {
		t.Fatal("get config")
	}
	if l, _ := m.ListOAuthConfigs(ctx, u); len(l) != 1 {
		t.Fatal("list config")
	}

	s := &store.OAuthState{State: "s", Provider: "p", OwnerUserID: u, ExpiresAt: time.Now().Add(time.Minute)}
	_ = m.InsertOAuthState(ctx, s)
	if g, _ := m.GetOAuthStateByState(ctx, "s"); g == nil {
		t.Fatal("get state")
	}
	if g, _ := m.GetOAuthStateByState(ctx, "no"); g != nil {
		t.Fatal("get state miss")
	}
	if n, _ := m.DeleteOAuthState(ctx, s.ID); n != 1 {
		t.Fatal("delete state")
	}
	if n, _ := m.DeleteOAuthState(ctx, s.ID); n != 0 {
		t.Fatal("delete state miss")
	}

	tok := &store.OAuthToken{UserID: u, ProviderID: pid, ProviderKey: "p", Account: "a", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{2}}
	_ = m.InsertOAuthToken(ctx, tok)
	tok.AccessTokenCipher = []byte{3}
	_ = m.UpdateOAuthToken(ctx, tok)
	if g, _ := m.GetOAuthTokenByID(ctx, u, tok.ID); g == nil {
		t.Fatal("get token")
	}
	if f, _ := m.FindOAuthToken(ctx, u, pid, "a"); f == nil {
		t.Fatal("find account")
	}
	if f, _ := m.FindOAuthToken(ctx, u, pid, ""); f == nil {
		t.Fatal("find any")
	}
	if f, _ := m.FindOAuthToken(ctx, u, pid, "other"); f != nil {
		t.Fatal("find miss")
	}
	if l, _ := m.ListOAuthTokens(ctx, u); len(l) != 1 {
		t.Fatal("list tokens")
	}
	if ok, _ := m.DeleteOAuthToken(ctx, u, tok.ID); !ok {
		t.Fatal("delete token")
	}
	if ok, _ := m.DeleteOAuthConfig(ctx, u, c.ID); !ok {
		t.Fatal("delete config")
	}
}

func TestMemManifestsAndAudit(t *testing.T) {
	ctx := context.Background()
	m := New()
	u, pid := uuid.New(), uuid.New()
	man := &store.ProviderManifest{UserID: u, Kind: "oauth", Key: "k", ProviderID: pid, DocumentJSON: "{}"}
	_ = m.InsertManifest(ctx, man)
	man.DocumentJSON = `{"x":1}`
	_ = m.UpdateManifest(ctx, man)
	if g, _ := m.GetManifestByKey(ctx, u, "oauth", "k"); g == nil {
		t.Fatal("get manifest")
	}
	if l, _ := m.ListOAuthManifests(ctx, u); len(l) != 1 {
		t.Fatal("list manifests")
	}
	_ = m.InsertOAuthConfig(ctx, &store.OAuthProviderConfig{UserID: u, ProviderID: pid, ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{1}})
	_ = m.InsertOAuthToken(ctx, &store.OAuthToken{UserID: u, ProviderID: pid, AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{1}})
	if ok, _ := m.DeleteManifestCascade(ctx, u, "oauth", "k"); !ok {
		t.Fatal("cascade")
	}
	if ok, _ := m.DeleteManifestCascade(ctx, u, "oauth", "gone"); ok {
		t.Fatal("cascade miss")
	}

	tn := uuid.New()
	rows := []store.AuditEntry{
		{EventType: 1, UserID: u, TenantID: tn, CreatedAt: time.Now()},
		{EventType: 2, UserID: u, TenantID: tn, CreatedAt: time.Now().Add(-400 * 24 * time.Hour)},
	}
	_ = m.InsertAuditBatch(ctx, rows)
	if _, total, _ := m.QueryAudit(ctx, store.AuditFilter{UserID: u, TenantID: tn, Limit: 1, Offset: 5}); total != 2 {
		t.Fatal("query total")
	}
	et := 1
	if _, total, _ := m.QueryAudit(ctx, store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, EventType: &et}); total != 1 {
		t.Fatal("filter type")
	}
	if d, _ := m.DeleteAuditOlderThan(ctx, time.Now().AddDate(0, 0, -180), 10); d != 1 {
		t.Fatalf("retention %d", d)
	}
	if m.AuditCount() != 1 {
		t.Fatal("count")
	}
}

func TestMemFailNext(t *testing.T) {
	ctx := context.Background()
	m := New()
	m.FailNext = errors.New("boom")
	if err := m.InsertAccessKey(ctx, &store.AccessKey{}); err == nil {
		t.Fatal("expected fail")
	}
	// FailNext is one-shot.
	if err := m.InsertAccessKey(ctx, &store.AccessKey{UserID: uuid.New()}); err != nil {
		t.Fatal("should succeed after one-shot")
	}
}

// TestMemFailNextAllMethods sets FailNext before each method so every fail() guard returns its
// injected error — covering the error branch each method shares.
func TestMemFailNextAllMethods(t *testing.T) {
	ctx := context.Background()
	u, pid := uuid.New(), uuid.New()
	boom := errors.New("boom")

	// each entry arms FailNext then invokes one method; all must surface the error.
	checks := []func(m *Mem) error{
		func(m *Mem) error { return m.InsertAccessKey(ctx, &store.AccessKey{}) },
		func(m *Mem) error { _, e := m.ListAccessKeys(ctx, u); return e },
		func(m *Mem) error { _, e := m.GetAccessKeyByID(ctx, u, u); return e },
		func(m *Mem) error { _, e := m.SetAccessKeyEnabled(ctx, u, u, true); return e },
		func(m *Mem) error { _, e := m.DeleteAccessKey(ctx, u, u); return e },
		func(m *Mem) error { _, e := m.GetAccessKeyByHash(ctx, []byte("h")); return e },
		func(m *Mem) error { return m.TouchAccessKeyLastUsed(ctx, u) },
		func(m *Mem) error { return m.InsertAPIKey(ctx, &store.APIKey{}) },
		func(m *Mem) error { return m.UpdateAPIKey(ctx, &store.APIKey{}) },
		func(m *Mem) error { _, e := m.ListAPIKeys(ctx, u); return e },
		func(m *Mem) error { _, e := m.GetAPIKeyByName(ctx, u, "n"); return e },
		func(m *Mem) error { _, e := m.DeleteAPIKey(ctx, u, u); return e },
		func(m *Mem) error { return m.TouchAPIKeyLastUsed(ctx, u) },
		func(m *Mem) error { return m.InsertOAuthConfig(ctx, &store.OAuthProviderConfig{}) },
		func(m *Mem) error { return m.UpdateOAuthConfig(ctx, &store.OAuthProviderConfig{}) },
		func(m *Mem) error { _, e := m.ListOAuthConfigs(ctx, u); return e },
		func(m *Mem) error { _, e := m.GetOAuthConfigByProvider(ctx, u, pid); return e },
		func(m *Mem) error { _, e := m.DeleteOAuthConfig(ctx, u, u); return e },
		func(m *Mem) error { return m.InsertOAuthState(ctx, &store.OAuthState{}) },
		func(m *Mem) error { _, e := m.GetOAuthStateByState(ctx, "s"); return e },
		func(m *Mem) error { _, e := m.DeleteOAuthState(ctx, u); return e },
		func(m *Mem) error { return m.InsertOAuthToken(ctx, &store.OAuthToken{}) },
		func(m *Mem) error { return m.UpdateOAuthToken(ctx, &store.OAuthToken{}) },
		func(m *Mem) error { _, e := m.ListOAuthTokens(ctx, u); return e },
		func(m *Mem) error { _, e := m.GetOAuthTokenByID(ctx, u, u); return e },
		func(m *Mem) error { _, e := m.FindOAuthToken(ctx, u, pid, ""); return e },
		func(m *Mem) error { _, e := m.DeleteOAuthToken(ctx, u, u); return e },
		func(m *Mem) error { _, e := m.ListOAuthManifests(ctx, u); return e },
		func(m *Mem) error { _, e := m.GetManifestByKey(ctx, u, "oauth", "k"); return e },
		func(m *Mem) error { return m.InsertManifest(ctx, &store.ProviderManifest{}) },
		func(m *Mem) error { return m.UpdateManifest(ctx, &store.ProviderManifest{}) },
		func(m *Mem) error { _, e := m.DeleteManifestCascade(ctx, u, "oauth", "k"); return e },
		func(m *Mem) error { return m.InsertAuditBatch(ctx, []store.AuditEntry{{}}) },
		func(m *Mem) error { _, _, e := m.QueryAudit(ctx, store.AuditFilter{}); return e },
		func(m *Mem) error { _, e := m.DeleteAuditOlderThan(ctx, time.Now(), 1); return e },
	}
	for i, c := range checks {
		m := New()
		m.FailNext = boom
		if err := c(m); !errors.Is(err, boom) {
			t.Fatalf("check %d: expected injected error, got %v", i, err)
		}
	}
}

// TestMemNotFoundAndScoping covers the wrong-user / not-found / no-op branches the happy-path
// tests don't reach.
func TestMemNotFoundAndScoping(t *testing.T) {
	ctx := context.Background()
	m := New()
	u, other, pid := uuid.New(), uuid.New(), uuid.New()
	missing := uuid.New()

	// Token wrong-user and missing.
	tok := &store.OAuthToken{UserID: u, ProviderID: pid, ProviderKey: "p", Account: "a", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{2}}
	_ = m.InsertOAuthToken(ctx, tok)
	if g, _ := m.GetOAuthTokenByID(ctx, other, tok.ID); g != nil {
		t.Fatal("token wrong user should miss")
	}
	if g, _ := m.GetOAuthTokenByID(ctx, u, missing); g != nil {
		t.Fatal("token missing should be nil")
	}
	if ok, _ := m.DeleteOAuthToken(ctx, other, tok.ID); ok {
		t.Fatal("delete token wrong user")
	}
	// Update token wrong id is a no-op (no panic, stays put).
	_ = m.UpdateOAuthToken(ctx, &store.OAuthToken{ID: missing})

	// Config wrong-user / missing.
	cfg := &store.OAuthProviderConfig{UserID: u, ProviderID: pid, ProviderKey: "p", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{2}}
	_ = m.InsertOAuthConfig(ctx, cfg)
	if g, _ := m.GetOAuthConfigByProvider(ctx, other, pid); g != nil {
		t.Fatal("config wrong user")
	}
	if ok, _ := m.DeleteOAuthConfig(ctx, other, cfg.ID); ok {
		t.Fatal("delete config wrong user")
	}
	_ = m.UpdateOAuthConfig(ctx, &store.OAuthProviderConfig{ID: missing, UserID: u}) // no-op

	// Access key wrong user / missing on hash and delete.
	ak := &store.AccessKey{UserID: u, Name: "k", KeyHash: []byte("hh"), KeyPrefix: "p", Enabled: true}
	_ = m.InsertAccessKey(ctx, ak)
	if ok, _ := m.DeleteAccessKey(ctx, other, ak.ID); ok {
		t.Fatal("delete access wrong user")
	}
	_ = m.TouchAccessKeyLastUsed(ctx, missing) // no matching key: no-op

	// API key wrong-user update no-op + wrong-user delete + touch-miss.
	apik := &store.APIKey{UserID: u, Name: "a", Kind: "opaque", FieldsCipher: []byte{1}}
	_ = m.InsertAPIKey(ctx, apik)
	_ = m.UpdateAPIKey(ctx, &store.APIKey{ID: apik.ID, UserID: other}) // wrong user no-op
	if ok, _ := m.DeleteAPIKey(ctx, other, apik.ID); ok {
		t.Fatal("delete api wrong user")
	}
	_ = m.TouchAPIKeyLastUsed(ctx, missing) // no-op

	// Manifest wrong-user update no-op + non-oauth cascade path.
	man := &store.ProviderManifest{UserID: u, Kind: "custom", Key: "ck", ProviderID: pid, DocumentJSON: "{}"}
	_ = m.InsertManifest(ctx, man)
	_ = m.UpdateManifest(ctx, &store.ProviderManifest{ID: man.ID, UserID: other}) // wrong user no-op
	if g, _ := m.GetManifestByKey(ctx, other, "custom", "ck"); g != nil {
		t.Fatal("manifest wrong user")
	}
	// Cascade a non-oauth manifest: skips the config/token cleanup block but still deletes.
	if ok, _ := m.DeleteManifestCascade(ctx, u, "custom", "ck"); !ok {
		t.Fatal("non-oauth cascade should delete")
	}
}

// TestMemQueryAuditFilters covers the Outcome / Since / Until predicate branches and the
// offset-beyond-total clamp in QueryAudit, plus InsertAuditBatch ID assignment.
func TestMemQueryAuditFilters(t *testing.T) {
	ctx := context.Background()
	m := New()
	u, tn := uuid.New(), uuid.New()
	now := time.Now()
	id := uuid.New()
	rows := []store.AuditEntry{
		{ID: id, EventType: 1, Outcome: 0, UserID: u, TenantID: tn, CreatedAt: now.Add(-2 * time.Hour)},
		{EventType: 2, Outcome: 1, UserID: u, TenantID: tn, CreatedAt: now.Add(-1 * time.Hour)},
		{EventType: 1, Outcome: 1, UserID: u, TenantID: tn, CreatedAt: now},
		// Different tenant: filtered out by the user/tenant guard.
		{EventType: 1, Outcome: 0, UserID: u, TenantID: uuid.New(), CreatedAt: now},
	}
	_ = m.InsertAuditBatch(ctx, rows)

	outcome := 1
	if _, total, _ := m.QueryAudit(ctx, store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, Outcome: &outcome}); total != 2 {
		t.Fatalf("outcome filter %d", total)
	}
	since := now.Add(-90 * time.Minute)
	if _, total, _ := m.QueryAudit(ctx, store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, Since: &since}); total != 2 {
		t.Fatalf("since filter %d", total)
	}
	until := now.Add(-30 * time.Minute)
	if _, total, _ := m.QueryAudit(ctx, store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, Until: &until}); total != 2 {
		t.Fatalf("until filter %d", total)
	}
	// Offset within range: returns the slice tail.
	if items, _, _ := m.QueryAudit(ctx, store.AuditFilter{UserID: u, TenantID: tn, Limit: 10, Offset: 1}); len(items) != 2 {
		t.Fatalf("offset tail %d", len(items))
	}
}

// TestMemListSortComparators inserts multiple rows per entity so each List sort comparator returns
// both orderings, and FindOAuthToken compares two candidates (the "newer wins" branch).
func TestMemListSortComparators(t *testing.T) {
	ctx := context.Background()
	m := New()
	u, pid := uuid.New(), uuid.New()
	t0 := time.Now()

	_ = m.InsertAccessKey(ctx, &store.AccessKey{UserID: u, Name: "a", KeyHash: []byte("1"), KeyPrefix: "p", CreatedAt: t0})
	_ = m.InsertAccessKey(ctx, &store.AccessKey{UserID: u, Name: "b", KeyHash: []byte("2"), KeyPrefix: "p", CreatedAt: t0.Add(time.Second)})
	if l, _ := m.ListAccessKeys(ctx, u); len(l) != 2 || l[0].CreatedAt.Before(l[1].CreatedAt) {
		t.Fatal("access keys not sorted newest-first")
	}

	_ = m.InsertAPIKey(ctx, &store.APIKey{UserID: u, Name: "a", Kind: "opaque", FieldsCipher: []byte{1}, CreatedAt: t0})
	_ = m.InsertAPIKey(ctx, &store.APIKey{UserID: u, Name: "b", Kind: "opaque", FieldsCipher: []byte{1}, CreatedAt: t0.Add(time.Second)})
	if l, _ := m.ListAPIKeys(ctx, u); len(l) != 2 || l[0].CreatedAt.Before(l[1].CreatedAt) {
		t.Fatal("api keys not sorted newest-first")
	}

	_ = m.InsertOAuthConfig(ctx, &store.OAuthProviderConfig{UserID: u, ProviderID: uuid.New(), ProviderKey: "b", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{1}})
	_ = m.InsertOAuthConfig(ctx, &store.OAuthProviderConfig{UserID: u, ProviderID: uuid.New(), ProviderKey: "a", ClientIDCipher: []byte{1}, ClientSecretCipher: []byte{1}})
	if l, _ := m.ListOAuthConfigs(ctx, u); len(l) != 2 || l[0].ProviderKey != "a" {
		t.Fatal("configs not sorted by provider key")
	}

	_ = m.InsertOAuthToken(ctx, &store.OAuthToken{UserID: u, ProviderID: pid, ProviderKey: "b", Account: "x", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{1}, CreatedAt: t0})
	_ = m.InsertOAuthToken(ctx, &store.OAuthToken{UserID: u, ProviderID: pid, ProviderKey: "a", Account: "x", AccessTokenCipher: []byte{1}, RefreshTokenCipher: []byte{1}, CreatedAt: t0.Add(time.Second)})
	if l, _ := m.ListOAuthTokens(ctx, u); len(l) != 2 || l[0].ProviderKey != "a" {
		t.Fatal("tokens not sorted by provider key")
	}
	// Two matching tokens: FindOAuthToken returns the newer one (the After comparison branch).
	if f, _ := m.FindOAuthToken(ctx, u, pid, "x"); f == nil || !f.CreatedAt.Equal(t0.Add(time.Second)) {
		t.Fatalf("find should return newest: %+v", f)
	}
}
