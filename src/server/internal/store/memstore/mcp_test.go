package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func TestMCPStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	m := New()
	userID, tenantID := uuid.New(), uuid.New()
	otherUser := uuid.New()
	expires := time.Now().Add(time.Hour)
	key := &store.AccessKey{UserID: userID, TenantID: tenantID, Name: "run", KeyHash: []byte("run"), ExpiresAt: &expires}
	credential := &store.APIKey{UserID: userID, TenantID: tenantID, Name: "upstream", FieldsCipher: []byte{1}}
	if err := m.InsertAccessKey(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertAPIKey(ctx, credential); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.GetAPIKeyByID(ctx, userID, credential.ID); got == nil {
		t.Fatal("get API key by ID")
	}
	if got, _ := m.GetAPIKeyByID(ctx, otherUser, credential.ID); got != nil {
		t.Fatal("API key owner scope")
	}

	first := &store.MCPConnection{UserID: userID, TenantID: tenantID, Slug: "zulu", Name: "Zulu", UpstreamURL: "https://z.example/mcp"}
	second := &store.MCPConnection{UserID: userID, TenantID: tenantID, Slug: "alpha", Name: "Alpha", UpstreamURL: "https://a.example/mcp"}
	if err := m.InsertMCPConnection(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := m.InsertMCPConnection(ctx, second); err != nil {
		t.Fatal(err)
	}
	if list, _ := m.ListMCPConnections(ctx, userID); len(list) != 2 || list[0].Name != "Alpha" {
		t.Fatalf("connection list: %+v", list)
	}
	if got, _ := m.GetMCPConnectionByID(ctx, userID, first.ID); got == nil {
		t.Fatal("get connection by ID")
	}
	if got, _ := m.GetMCPConnectionBySlug(ctx, userID, "zulu"); got == nil {
		t.Fatal("get connection by slug")
	}
	if got, _ := m.GetMCPConnectionBySlug(ctx, otherUser, "zulu"); got != nil {
		t.Fatal("connection slug owner scope")
	}
	first.Name = "Updated"
	if ok, err := m.UpdateMCPConnection(ctx, first); err != nil || !ok || first.UpdatedAt == nil {
		t.Fatalf("update connection: %v %v", ok, err)
	}
	if ok, _ := m.UpdateMCPConnection(ctx, &store.MCPConnection{ID: uuid.New(), UserID: userID}); ok {
		t.Fatal("update missing connection")
	}

	grant := &store.MCPConnectionGrant{UserID: userID, TenantID: tenantID, ConnectionID: first.ID, AccessKeyID: key.ID}
	if err := m.InsertMCPConnectionGrant(ctx, grant); err != nil {
		t.Fatal(err)
	}
	if allowed, _ := m.HasMCPConnectionGrant(ctx, key.ID, first.ID); !allowed {
		t.Fatal("grant lookup")
	}
	if allowed, _ := m.HasMCPConnectionGrant(ctx, uuid.New(), first.ID); allowed {
		t.Fatal("missing grant")
	}
	if list, _ := m.ListMCPConnectionGrants(ctx, userID, first.ID); len(list) != 1 {
		t.Fatalf("grant list: %d", len(list))
	}
	badGrant := &store.MCPConnectionGrant{UserID: otherUser, TenantID: tenantID, ConnectionID: first.ID, AccessKeyID: key.ID}
	if err := m.InsertMCPConnectionGrant(ctx, badGrant); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner grant: %v", err)
	}

	headerName := "X-API-Key"
	header := &store.MCPHeaderBinding{UserID: userID, TenantID: tenantID, ConnectionID: first.ID, CredentialID: credential.ID, HeaderName: &headerName}
	if err := m.InsertMCPHeaderBinding(ctx, header); err != nil {
		t.Fatal(err)
	}
	if list, _ := m.ListMCPHeaderBindings(ctx, userID, first.ID); len(list) != 1 {
		t.Fatalf("header list: %d", len(list))
	}
	badHeader := &store.MCPHeaderBinding{UserID: otherUser, TenantID: tenantID, ConnectionID: first.ID, CredentialID: credential.ID}
	if err := m.InsertMCPHeaderBinding(ctx, badHeader); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner header: %v", err)
	}

	policy := &store.MCPToolPolicy{UserID: userID, TenantID: tenantID, ConnectionID: first.ID, Method: "tools/call", ToolName: "logs", Allow: true}
	if err := m.UpsertMCPToolPolicy(ctx, policy); err != nil {
		t.Fatal(err)
	}
	policy.Allow = false
	if err := m.UpsertMCPToolPolicy(ctx, policy); err != nil || policy.UpdatedAt == nil {
		t.Fatalf("update policy: %v", err)
	}
	methodPolicy := &store.MCPToolPolicy{UserID: userID, TenantID: tenantID, ConnectionID: first.ID, Method: "prompts/get", Allow: true}
	if err := m.UpsertMCPToolPolicy(ctx, methodPolicy); err != nil {
		t.Fatal(err)
	}
	if list, _ := m.ListMCPToolPolicies(ctx, userID, first.ID); len(list) != 2 || list[0].Method != "prompts/get" {
		t.Fatalf("policy list: %+v", list)
	}
	badPolicy := &store.MCPToolPolicy{UserID: otherUser, TenantID: tenantID, ConnectionID: first.ID, Method: "tools/call"}
	if err := m.UpsertMCPToolPolicy(ctx, badPolicy); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner policy: %v", err)
	}

	oauth := &store.MCPOAuthAuthorization{UserID: userID, TenantID: tenantID, ConnectionID: first.ID, TokenAuthMethod: "client_secret_post", AccessTokenCipher: []byte{1}}
	if err := m.InsertMCPOAuthAuthorization(ctx, oauth); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.GetMCPOAuthAuthorization(ctx, userID, first.ID); got == nil {
		t.Fatal("get OAuth")
	}
	oauth.AccessTokenCipher = []byte{2}
	if ok, err := m.UpdateMCPOAuthAuthorization(ctx, oauth); err != nil || !ok || oauth.UpdatedAt == nil {
		t.Fatalf("update OAuth: %v %v", ok, err)
	}
	if ok, _ := m.UpdateMCPOAuthAuthorization(ctx, &store.MCPOAuthAuthorization{ID: uuid.New(), UserID: userID}); ok {
		t.Fatal("update missing OAuth")
	}

	state := &store.MCPOAuthState{State: "state", ConnectionID: first.ID, UserID: userID, TenantID: tenantID, ExpiresAt: expires}
	if err := m.InsertMCPOAuthState(ctx, state); err != nil {
		t.Fatal(err)
	}
	if claimed, _ := m.ClaimMCPOAuthState(ctx, state.State); claimed == nil || claimed.CreatedAt.IsZero() {
		t.Fatalf("claim state: %+v", claimed)
	}
	if claimed, _ := m.ClaimMCPOAuthState(ctx, state.State); claimed != nil {
		t.Fatal("state must be single use")
	}
	badState := &store.MCPOAuthState{State: "bad", ConnectionID: first.ID, UserID: otherUser, TenantID: tenantID}
	if err := m.InsertMCPOAuthState(ctx, badState); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner state: %v", err)
	}

	evalRun := "eval-1"
	exchange := &store.MCPAuditExchange{ConnectionID: first.ID, UserID: userID, TenantID: tenantID, AccessKeyID: key.ID, EvalRunID: &evalRun, HTTPMethod: "POST", ProtocolVersion: "2026-07-28", Outcome: "started"}
	if err := m.InsertMCPAuditExchange(ctx, exchange); err != nil {
		t.Fatal(err)
	}
	method, tool := "tools/call", "logs"
	payload := `{"jsonrpc":"2.0"}`
	message := &store.MCPAuditMessage{ExchangeID: exchange.ID, ConnectionID: first.ID, UserID: userID, TenantID: tenantID, SequenceNo: 1, Direction: "client_to_server", MessageKind: "request", PolicyDecision: "allowed", Method: &method, ToolName: &tool, PayloadRedacted: &payload, PayloadSHA256: []byte{1}}
	if err := m.InsertMCPAuditMessage(ctx, message); err != nil {
		t.Fatal(err)
	}
	badMessage := *message
	badMessage.ID, badMessage.UserID = uuid.Nil, otherUser
	if err := m.InsertMCPAuditMessage(ctx, &badMessage); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner audit: %v", err)
	}
	decision, direction := "allowed", "client_to_server"
	filter := store.MCPAuditFilter{UserID: userID, TenantID: tenantID, Limit: 10, ConnectionID: &first.ID, AccessKeyID: &key.ID, EvalRunID: &evalRun, Direction: &direction, Method: &method, ToolName: &tool, PolicyDecision: &decision}
	if messages, total, err := m.QueryMCPAudit(ctx, filter); err != nil || total != 1 || len(messages) != 1 {
		t.Fatalf("query audit: %d %d %v", len(messages), total, err)
	}
	now := time.Now().UTC()
	status := 200
	exchange.Outcome, exchange.CompletedAt, exchange.StatusCode = "success", &now, &status
	if ok, err := m.CompleteMCPAuditExchange(ctx, exchange); err != nil || !ok {
		t.Fatalf("complete exchange: %v %v", ok, err)
	}
	if ok, _ := m.CompleteMCPAuditExchange(ctx, &store.MCPAuditExchange{ID: uuid.New(), UserID: userID, TenantID: tenantID}); ok {
		t.Fatal("complete missing exchange")
	}

	for name, remove := range map[string]func() (bool, error){
		"grant":  func() (bool, error) { return m.DeleteMCPConnectionGrant(ctx, userID, grant.ID) },
		"header": func() (bool, error) { return m.DeleteMCPHeaderBinding(ctx, userID, header.ID) },
		"policy": func() (bool, error) { return m.DeleteMCPToolPolicy(ctx, userID, policy.ID) },
		"oauth":  func() (bool, error) { return m.DeleteMCPOAuthAuthorization(ctx, userID, first.ID) },
	} {
		if ok, err := remove(); err != nil || !ok {
			t.Fatalf("delete %s: %v %v", name, ok, err)
		}
		if ok, _ := remove(); ok {
			t.Fatalf("double delete %s", name)
		}
	}
	if ok, err := m.DeleteMCPConnection(ctx, userID, first.ID); err != nil || !ok {
		t.Fatalf("delete connection: %v %v", ok, err)
	}
	if ok, _ := m.DeleteMCPConnection(ctx, userID, first.ID); ok {
		t.Fatal("double delete connection")
	}
}

func TestMCPStoreFailureInjection(t *testing.T) {
	ctx := context.Background()
	id := uuid.New()
	boom := errors.New("boom")
	checks := []func(*Mem) error{
		func(m *Mem) error { return m.InsertMCPConnection(ctx, &store.MCPConnection{}) },
		func(m *Mem) error { _, e := m.UpdateMCPConnection(ctx, &store.MCPConnection{}); return e },
		func(m *Mem) error { _, e := m.ListMCPConnections(ctx, id); return e },
		func(m *Mem) error { _, e := m.GetMCPConnectionByID(ctx, id, id); return e },
		func(m *Mem) error { _, e := m.GetMCPConnectionBySlug(ctx, id, "slug"); return e },
		func(m *Mem) error { _, e := m.DeleteMCPConnection(ctx, id, id); return e },
		func(m *Mem) error { return m.InsertMCPConnectionGrant(ctx, &store.MCPConnectionGrant{}) },
		func(m *Mem) error { _, e := m.ListMCPConnectionGrants(ctx, id, id); return e },
		func(m *Mem) error { _, e := m.HasMCPConnectionGrant(ctx, id, id); return e },
		func(m *Mem) error { _, e := m.DeleteMCPConnectionGrant(ctx, id, id); return e },
		func(m *Mem) error { return m.InsertMCPHeaderBinding(ctx, &store.MCPHeaderBinding{}) },
		func(m *Mem) error { _, e := m.ListMCPHeaderBindings(ctx, id, id); return e },
		func(m *Mem) error { _, e := m.DeleteMCPHeaderBinding(ctx, id, id); return e },
		func(m *Mem) error { return m.UpsertMCPToolPolicy(ctx, &store.MCPToolPolicy{}) },
		func(m *Mem) error { _, e := m.ListMCPToolPolicies(ctx, id, id); return e },
		func(m *Mem) error { _, e := m.DeleteMCPToolPolicy(ctx, id, id); return e },
		func(m *Mem) error { return m.InsertMCPOAuthAuthorization(ctx, &store.MCPOAuthAuthorization{}) },
		func(m *Mem) error {
			_, e := m.UpdateMCPOAuthAuthorization(ctx, &store.MCPOAuthAuthorization{})
			return e
		},
		func(m *Mem) error { _, e := m.GetMCPOAuthAuthorization(ctx, id, id); return e },
		func(m *Mem) error { _, e := m.DeleteMCPOAuthAuthorization(ctx, id, id); return e },
		func(m *Mem) error { return m.InsertMCPOAuthState(ctx, &store.MCPOAuthState{}) },
		func(m *Mem) error { _, e := m.ClaimMCPOAuthState(ctx, "state"); return e },
		func(m *Mem) error { return m.InsertMCPAuditExchange(ctx, &store.MCPAuditExchange{}) },
		func(m *Mem) error { _, e := m.CompleteMCPAuditExchange(ctx, &store.MCPAuditExchange{}); return e },
		func(m *Mem) error { return m.InsertMCPAuditMessage(ctx, &store.MCPAuditMessage{}) },
		func(m *Mem) error { _, _, e := m.QueryMCPAudit(ctx, store.MCPAuditFilter{}); return e },
		func(m *Mem) error { _, e := m.GetAPIKeyByID(ctx, id, id); return e },
	}
	for i, check := range checks {
		m := New()
		m.FailNext = boom
		if err := check(m); !errors.Is(err, boom) {
			t.Fatalf("check %d: %v", i, err)
		}
	}
}
