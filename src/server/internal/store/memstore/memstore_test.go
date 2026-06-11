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
