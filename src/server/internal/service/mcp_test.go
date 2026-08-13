package service

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/mcp"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

func newMCPServiceTest(t *testing.T) (*MCPService, *memstore.Mem, context.Context) {
	t.Helper()
	kek, err := crypto.NewLocalKekProvider("local:v1", map[string]string{"local:v1": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
	if err != nil {
		t.Fatal(err)
	}
	memory := memstore.New()
	userID, tenantID := uuid.New(), uuid.New()
	ctx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: userID, TenantID: tenantID})
	return NewMCPService(memory, crypto.NewEnvelopeCipher(kek)), memory, ctx
}

func TestMCPServiceConnectionValidationAndLifecycle(t *testing.T) {
	service, _, ctx := newMCPServiceTest(t)
	invalid := []MCPConnectionParams{
		{Name: "x", Slug: "bad slug", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted"},
		{Slug: "x", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted"},
		{Name: "x", Slug: "x", UpstreamURL: "http://example.com/mcp", AuthMode: "none", AuditMode: "redacted"},
		{Name: "x", Slug: "x", UpstreamURL: "https://user@example.com/mcp", AuthMode: "none", AuditMode: "redacted"},
		{Name: "x", Slug: "x", UpstreamURL: "https://example.com/mcp#x", AuthMode: "none", AuditMode: "redacted"},
		{Name: "x", Slug: "x", UpstreamURL: "https://example.com/mcp", AuthMode: "bad", AuditMode: "redacted"},
		{Name: "x", Slug: "x", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "full"},
		{Name: "x", Slug: "x", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted", UpstreamProtocolMode: "future"},
		{Name: "x", Slug: "x", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted", LegacyProtocolVersion: "2024-01-01"},
	}
	for i, params := range invalid {
		if _, err := service.UpsertConnection(ctx, params); err == nil {
			t.Fatalf("invalid %d accepted", i)
		}
	}
	created, err := service.UpsertConnection(ctx, MCPConnectionParams{Name: "Example", Slug: "EXAMPLE", UpstreamURL: " \thttps://example.com/mcp\n", AuthMode: "none", Enabled: true})
	if err != nil || created == nil || created.AuditMode != "redacted" ||
		created.UpstreamURL != "https://example.com/mcp" || created.UpstreamProtocolMode != "modern_2026_07" || created.LegacyProtocolVersion != "2025-06-18" {
		t.Fatalf("create: %#v %v", created, err)
	}
	if rows, _ := service.ListConnections(ctx); len(rows) != 1 {
		t.Fatalf("list %d", len(rows))
	}
	if row, _ := service.GetConnection(ctx, created.ID); row == nil {
		t.Fatal("get")
	}
	description := "updated"
	updated, err := service.UpsertConnection(ctx, MCPConnectionParams{ID: created.ID, Name: "Updated", Slug: created.Slug, Description: &description, UpstreamURL: created.UpstreamURL, AuthMode: "headers", AuditMode: "metadata", UpstreamProtocolMode: "legacy_session", LegacyProtocolVersion: "2025-11-25", Enabled: false})
	if err != nil || updated == nil || updated.Name != "Updated" || updated.UpstreamProtocolMode != "legacy_session" || updated.LegacyProtocolVersion != "2025-11-25" {
		t.Fatalf("update: %#v %v", updated, err)
	}
	missing, err := service.UpsertConnection(ctx, MCPConnectionParams{ID: uuid.New(), Name: "Missing", Slug: "missing", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "metadata", Enabled: true})
	if err != nil || missing != nil {
		t.Fatalf("missing update %#v %v", missing, err)
	}
	if deleted, _ := service.DeleteConnection(ctx, created.ID); !deleted {
		t.Fatal("delete")
	}
	if deleted, _ := service.DeleteConnection(ctx, created.ID); deleted {
		t.Fatal("delete twice")
	}
}

func TestMCPServiceConfigurationAndResolve(t *testing.T) {
	service, memory, ctx := newMCPServiceTest(t)
	caller := contracts.CallerFrom(ctx)
	connection, _ := service.UpsertConnection(ctx, MCPConnectionParams{Name: "x", Slug: "x", UpstreamURL: "https://example.com/mcp", AuthMode: "headers", AuditMode: "redacted", Enabled: true})
	accessKey := &store.AccessKey{UserID: caller.UserID, TenantID: caller.TenantID, Name: "eval", KeyHash: []byte("h"), KeyPrefix: "dwv_x", Scopes: []string{"vault:mcp"}, Enabled: true, ExpiresAt: timePtr(time.Now().Add(time.Hour))}
	if err := memory.InsertAccessKey(ctx, accessKey); err != nil {
		t.Fatal(err)
	}
	secret, err := service.cipher.EncryptString("secret")
	if err != nil {
		t.Fatal(err)
	}
	header, prefix := "X-Upstream-Key", "Bearer "
	credential := &store.APIKey{UserID: caller.UserID, TenantID: caller.TenantID, Name: "upstream", FieldsCipher: secret, Kind: "header_api_key", HeaderName: &header, Prefix: &prefix}
	if err := memory.InsertAPIKey(ctx, credential); err != nil {
		t.Fatal(err)
	}
	if row, _ := service.Grant(ctx, connection.ID, uuid.New()); row != nil {
		t.Fatal("granted missing key")
	}
	grant, err := service.Grant(ctx, connection.ID, accessKey.ID)
	if err != nil || grant == nil {
		t.Fatalf("grant %v", err)
	}
	if rows, _ := service.ListGrants(ctx, connection.ID); len(rows) != 1 {
		t.Fatal("list grants")
	}
	badHeader := "bad\nheader"
	if _, err := service.BindHeader(ctx, connection.ID, credential.ID, &badHeader); err == nil {
		t.Fatal("bad header accepted")
	}
	reservedHeader := "Mcp-Method"
	if _, err := service.BindHeader(ctx, connection.ID, credential.ID, &reservedHeader); err == nil {
		t.Fatal("reserved header accepted")
	}
	for _, name := range []string{"Accept", "Content-Type", "Cookie", "Connection", "Proxy-Authorization"} {
		if allowedMCPUpstreamHeader(name) {
			t.Fatalf("reserved %s allowed", name)
		}
	}
	if !allowedMCPUpstreamHeader("X-Custom") {
		t.Fatal("custom denied")
	}
	binding, err := service.BindHeader(ctx, connection.ID, credential.ID, nil)
	if err != nil || binding == nil {
		t.Fatalf("binding %v", err)
	}
	if rows, _ := service.ListHeaderBindings(ctx, connection.ID); len(rows) != 1 {
		t.Fatal("list headers")
	}
	if _, err := service.PutPolicy(ctx, connection.ID, "", "", true); err == nil {
		t.Fatal("empty method")
	}
	if _, err := service.PutPolicy(ctx, connection.ID, "resources/read", "tool", true); err == nil {
		t.Fatal("tool on wrong method")
	}
	allow, _ := service.PutPolicy(ctx, connection.ID, "tools/call", "allowed", true)
	deny, _ := service.PutPolicy(ctx, connection.ID, "resources/read", "", false)
	if rows, _ := service.ListPolicies(ctx, connection.ID); len(rows) != 2 {
		t.Fatal("list policies")
	}
	resolved, err := service.ResolveProxy(ctx, connection.Slug, accessKey.ID)
	if err != nil || resolved.Headers.Get(header) != "Bearer secret" {
		t.Fatalf("resolve %#v %v", resolved, err)
	}
	if decision := resolved.Policy.Evaluate(clientMessage("tools/call", "other")); decision.Allowed {
		t.Fatal("allow list should default deny")
	}
	if decision := resolved.Policy.Evaluate(clientMessage("tools/call", "allowed")); !decision.Allowed {
		t.Fatal("allowed tool denied")
	}
	if decision := resolved.Policy.Evaluate(clientMessage("resources/read", "")); decision.Allowed {
		t.Fatal("denied method allowed")
	}
	probeResolved, err := service.ResolveProbe(ctx, connection.ID)
	if err != nil || probeResolved == nil || probeResolved.Headers.Get(header) != "Bearer secret" {
		t.Fatalf("probe resolve %#v %v", probeResolved, err)
	}
	if missing, err := service.ResolveProbe(ctx, uuid.New()); err != nil || missing != nil {
		t.Fatalf("missing probe resolve %#v %v", missing, err)
	}
	connection.Enabled = false
	if _, err := memory.UpdateMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	if disabled, err := service.ResolveProbe(ctx, connection.ID); err != nil || disabled == nil || disabled.Connection.Enabled {
		t.Fatalf("disabled connection must remain admin-probeable: %#v %v", disabled, err)
	}
	connection.Enabled = true
	if _, err := memory.UpdateMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	if ok, _ := service.DeletePolicy(ctx, allow.ID); !ok {
		t.Fatal("delete policy")
	}
	if ok, _ := service.DeletePolicy(ctx, deny.ID); !ok {
		t.Fatal("delete policy 2")
	}
	if ok, _ := service.DeleteHeaderBinding(ctx, binding.ID); !ok {
		t.Fatal("delete header")
	}
	if ok, _ := service.DeleteGrant(ctx, grant.ID); !ok {
		t.Fatal("delete grant")
	}
	if _, err := service.ResolveProxy(ctx, connection.Slug, accessKey.ID); err == nil {
		t.Fatal("resolve without grant")
	}
	if got := service.Store(); got != memory {
		t.Fatal("store accessor")
	}
}

func timePtr(value time.Time) *time.Time { return &value }

func clientMessage(method, tool string) mcp.ClientMessage {
	return mcp.ClientMessage{Audit: mcp.AuditFields{Method: method, ToolName: tool}}
}
