package store_test

import (
	"context"
	"errors"
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
	if byID, _ := pg.GetAPIKeyByID(ctx(), u, k.ID); byID == nil {
		t.Fatal("get by ID")
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

func TestMCPStore(t *testing.T) {
	u, tenant := uuid.New(), uuid.New()
	other := uuid.New()
	expires := time.Now().Add(time.Hour)
	accessKey := &store.AccessKey{UserID: u, TenantID: tenant, Name: "mcp-run-" + u.String(),
		KeyHash: []byte("mcp-hash-" + u.String()), KeyPrefix: "dwv_mcp", Scopes: []string{"vault:mcp"}, Enabled: true, ExpiresAt: &expires}
	if err := pg.InsertAccessKey(ctx(), accessKey); err != nil {
		t.Fatal(err)
	}
	if got, _ := pg.GetAccessKeyByID(ctx(), u, accessKey.ID); got == nil || got.ExpiresAt == nil {
		t.Fatalf("access key expiry: %+v", got)
	}
	credential := &store.APIKey{UserID: u, TenantID: tenant, Name: "mcp-upstream-" + u.String(), FieldsCipher: []byte{1}, Kind: "opaque"}
	if err := pg.InsertAPIKey(ctx(), credential); err != nil {
		t.Fatal(err)
	}
	if got, _ := pg.GetAPIKeyByID(ctx(), u, credential.ID); got == nil {
		t.Fatal("get API key by ID")
	}
	if got, _ := pg.GetAPIKeyByID(ctx(), other, credential.ID); got != nil {
		t.Fatal("API key owner scope")
	}

	connection := &store.MCPConnection{UserID: u, TenantID: tenant, Slug: "datadog-" + u.String(), Name: "Datadog", UpstreamURL: "https://mcp.datadoghq.com/mcp", AuthMode: "headers", AuditMode: "redacted", ProtocolVersion: "2026-07-28", Enabled: true}
	if err := pg.InsertMCPConnection(ctx(), connection); err != nil {
		t.Fatal(err)
	}
	connection.Name = "Datadog Updated"
	if ok, err := pg.UpdateMCPConnection(ctx(), connection); err != nil || !ok || connection.UpdatedAt == nil {
		t.Fatalf("update connection: %v %v", ok, err)
	}
	if got, _ := pg.GetMCPConnectionByID(ctx(), u, connection.ID); got == nil {
		t.Fatal("get connection by ID")
	}
	if got, _ := pg.GetMCPConnectionBySlug(ctx(), u, connection.Slug); got == nil {
		t.Fatal("get connection by slug")
	}
	if got, _ := pg.GetMCPConnectionBySlug(ctx(), other, connection.Slug); got != nil {
		t.Fatal("connection owner scope")
	}
	if list, err := pg.ListMCPConnections(ctx(), u); err != nil || len(list) != 1 {
		t.Fatalf("list connections: %d %v", len(list), err)
	}

	grant := &store.MCPConnectionGrant{UserID: u, TenantID: tenant, ConnectionID: connection.ID, AccessKeyID: accessKey.ID}
	if err := pg.InsertMCPConnectionGrant(ctx(), grant); err != nil {
		t.Fatal(err)
	}
	if allowed, err := pg.HasMCPConnectionGrant(ctx(), accessKey.ID, connection.ID); err != nil || !allowed {
		t.Fatalf("grant lookup: %v %v", allowed, err)
	}
	if list, err := pg.ListMCPConnectionGrants(ctx(), u, connection.ID); err != nil || len(list) != 1 {
		t.Fatalf("grant list: %d %v", len(list), err)
	}
	badGrant := &store.MCPConnectionGrant{UserID: other, TenantID: tenant, ConnectionID: connection.ID, AccessKeyID: accessKey.ID}
	if err := pg.InsertMCPConnectionGrant(ctx(), badGrant); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner grant: %v", err)
	}

	headerName := "DD-API-KEY"
	header := &store.MCPHeaderBinding{UserID: u, TenantID: tenant, ConnectionID: connection.ID, CredentialID: credential.ID, HeaderName: &headerName}
	if err := pg.InsertMCPHeaderBinding(ctx(), header); err != nil {
		t.Fatal(err)
	}
	if list, err := pg.ListMCPHeaderBindings(ctx(), u, connection.ID); err != nil || len(list) != 1 {
		t.Fatalf("header list: %d %v", len(list), err)
	}
	badHeader := &store.MCPHeaderBinding{UserID: other, TenantID: tenant, ConnectionID: connection.ID, CredentialID: credential.ID}
	if err := pg.InsertMCPHeaderBinding(ctx(), badHeader); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner header: %v", err)
	}

	policy := &store.MCPToolPolicy{UserID: u, TenantID: tenant, ConnectionID: connection.ID, Method: "tools/call", ToolName: "search_logs", Allow: true}
	if err := pg.UpsertMCPToolPolicy(ctx(), policy); err != nil {
		t.Fatal(err)
	}
	policy.Allow = false
	if err := pg.UpsertMCPToolPolicy(ctx(), policy); err != nil || policy.UpdatedAt == nil {
		t.Fatalf("update policy: %v", err)
	}
	if list, err := pg.ListMCPToolPolicies(ctx(), u, connection.ID); err != nil || len(list) != 1 || list[0].Allow {
		t.Fatalf("policy list: %+v %v", list, err)
	}
	badPolicy := &store.MCPToolPolicy{UserID: other, TenantID: tenant, ConnectionID: connection.ID, Method: "tools/call"}
	if err := pg.UpsertMCPToolPolicy(ctx(), badPolicy); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner policy: %v", err)
	}

	issuer := "https://auth.example"
	oauth := &store.MCPOAuthAuthorization{UserID: u, TenantID: tenant, ConnectionID: connection.ID,
		IssuerURL: &issuer, TokenAuthMethod: "client_secret_post", ClientIDCipher: []byte{1},
		ClientSecretCipher: []byte{2}, AccessTokenCipher: []byte{3}, RefreshTokenCipher: []byte{4},
		Scopes: []string{"mcp"}, ExpiresAt: &expires}
	if err := pg.InsertMCPOAuthAuthorization(ctx(), oauth); err != nil {
		t.Fatal(err)
	}
	if got, err := pg.GetMCPOAuthAuthorization(ctx(), u, connection.ID); err != nil || got == nil || got.TokenAuthMethod != "client_secret_post" {
		t.Fatalf("get OAuth: %+v %v", got, err)
	}
	oauth.AccessTokenCipher = []byte{9}
	if ok, err := pg.UpdateMCPOAuthAuthorization(ctx(), oauth); err != nil || !ok || oauth.UpdatedAt == nil {
		t.Fatalf("update OAuth: %v %v", ok, err)
	}

	state := &store.MCPOAuthState{State: "mcp-state-" + u.String(), ConnectionID: connection.ID,
		UserID: u, TenantID: tenant, CodeVerifier: "verifier", RedirectURI: "https://vault.example/callback",
		Resource: connection.UpstreamURL, IssuerURL: issuer, AuthEndpoint: issuer + "/authorize",
		TokenEndpoint: issuer + "/token", TokenAuthMethod: "client_secret_post", Scopes: []string{"mcp"}, ExpiresAt: expires}
	if err := pg.InsertMCPOAuthState(ctx(), state); err != nil {
		t.Fatal(err)
	}
	if claimed, err := pg.ClaimMCPOAuthState(ctx(), state.State); err != nil || claimed == nil || claimed.TokenEndpoint == "" {
		t.Fatalf("claim state: %+v %v", claimed, err)
	}
	if claimed, err := pg.ClaimMCPOAuthState(ctx(), state.State); err != nil || claimed != nil {
		t.Fatalf("claim state replay: %+v %v", claimed, err)
	}

	evalRun := "eval-" + u.String()
	exchange := &store.MCPAuditExchange{ConnectionID: connection.ID, UserID: u, TenantID: tenant,
		AccessKeyID: accessKey.ID, EvalRunID: &evalRun, HTTPMethod: "POST", ProtocolVersion: "2026-07-28",
		Outcome: "started", StartedAt: time.Now().Add(-time.Second)}
	if err := pg.InsertMCPAuditExchange(ctx(), exchange); err != nil {
		t.Fatal(err)
	}
	method, tool, decision := "tools/call", "search_logs", "allowed"
	payload := `{"jsonrpc":"2.0","method":"tools/call"}`
	message := &store.MCPAuditMessage{ExchangeID: exchange.ID, ConnectionID: connection.ID, UserID: u,
		TenantID: tenant, SequenceNo: 1, ObservedAt: time.Now(), Direction: "client_to_server",
		MessageKind: "request", PolicyDecision: decision, Method: &method, ToolName: &tool,
		PayloadRedacted: &payload, PayloadSHA256: []byte{1, 2}, PayloadBytes: int64(len(payload)),
		RedactionPaths: []string{"/params/token"}}
	if err := pg.InsertMCPAuditMessage(ctx(), message); err != nil {
		t.Fatal(err)
	}
	direction := "client_to_server"
	filter := store.MCPAuditFilter{UserID: u, TenantID: tenant, Limit: 10, ConnectionID: &connection.ID,
		AccessKeyID: &accessKey.ID, EvalRunID: &evalRun, Direction: &direction, Method: &method,
		ToolName: &tool, PolicyDecision: &decision}
	if list, total, err := pg.QueryMCPAudit(ctx(), filter); err != nil || total != 1 || len(list) != 1 || list[0].PayloadRedacted == nil {
		t.Fatalf("query MCP audit: %d %d %v", len(list), total, err)
	}
	badMessage := *message
	badMessage.ID, badMessage.UserID = uuid.Nil, other
	if err := pg.InsertMCPAuditMessage(ctx(), &badMessage); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner audit message: %v", err)
	}
	completed := time.Now()
	status := 200
	exchange.CompletedAt, exchange.StatusCode, exchange.Outcome = &completed, &status, "success"
	if ok, err := pg.CompleteMCPAuditExchange(ctx(), exchange); err != nil || !ok {
		t.Fatalf("complete exchange: %v %v", ok, err)
	}

	for name, remove := range map[string]func() (bool, error){
		"grant":  func() (bool, error) { return pg.DeleteMCPConnectionGrant(ctx(), u, grant.ID) },
		"header": func() (bool, error) { return pg.DeleteMCPHeaderBinding(ctx(), u, header.ID) },
		"policy": func() (bool, error) { return pg.DeleteMCPToolPolicy(ctx(), u, policy.ID) },
		"oauth":  func() (bool, error) { return pg.DeleteMCPOAuthAuthorization(ctx(), u, connection.ID) },
	} {
		if ok, err := remove(); err != nil || !ok {
			t.Fatalf("delete %s: %v %v", name, ok, err)
		}
		if ok, err := remove(); err != nil || ok {
			t.Fatalf("double delete %s: %v %v", name, ok, err)
		}
	}
	if ok, err := pg.DeleteMCPConnection(ctx(), u, connection.ID); err != nil || !ok {
		t.Fatalf("delete connection: %v %v", ok, err)
	}
}

func TestMCPAuditRetention(t *testing.T) {
	u, tenant, connectionID, accessKeyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	if deleted, err := pg.DeleteMCPAuditOlderThan(ctx(), now, 0); err != nil || deleted != 0 {
		t.Fatalf("zero batch: deleted=%d err=%v", deleted, err)
	}
	seed := func(startedAt time.Time) (*store.MCPAuditExchange, *store.MCPAuditMessage) {
		t.Helper()
		completedAt := startedAt.Add(time.Minute)
		exchange := &store.MCPAuditExchange{ConnectionID: connectionID, UserID: u, TenantID: tenant,
			AccessKeyID: accessKeyID, HTTPMethod: "POST", ProtocolVersion: "2026-07-28",
			Outcome: "complete", StartedAt: startedAt, CompletedAt: &completedAt}
		if err := pg.InsertMCPAuditExchange(ctx(), exchange); err != nil {
			t.Fatal(err)
		}
		message := &store.MCPAuditMessage{ExchangeID: exchange.ID, ConnectionID: connectionID,
			UserID: u, TenantID: tenant, SequenceNo: 1, ObservedAt: startedAt,
			Direction: "client_to_server", MessageKind: "request", PolicyDecision: "allowed",
			PayloadSHA256: []byte{1}, PayloadBytes: 1}
		if err := pg.InsertMCPAuditMessage(ctx(), message); err != nil {
			t.Fatal(err)
		}
		return exchange, message
	}
	oldest, oldestMessage := seed(now.Add(-72 * time.Hour))
	middle, _ := seed(now.Add(-48 * time.Hour))
	newest, _ := seed(now.Add(-time.Hour))
	inFlight, _ := seed(now.Add(-96 * time.Hour))
	if _, err := pg.Pool().Exec(ctx(), `UPDATE vault.mcp_audit_exchanges SET completed_at=NULL WHERE id=$1`, inFlight.ID); err != nil {
		t.Fatal(err)
	}

	deleted, err := pg.DeleteMCPAuditOlderThan(ctx(), now.Add(-24*time.Hour), 1)
	if err != nil || deleted != 1 {
		t.Fatalf("first batch: deleted=%d err=%v", deleted, err)
	}
	var parentCount, childCount int
	if err := pg.Pool().QueryRow(ctx(), `SELECT count(*) FROM vault.mcp_audit_exchanges WHERE id=$1`, oldest.ID).Scan(&parentCount); err != nil {
		t.Fatal(err)
	}
	if err := pg.Pool().QueryRow(ctx(), `SELECT count(*) FROM vault.mcp_audit_messages WHERE id=$1`, oldestMessage.ID).Scan(&childCount); err != nil {
		t.Fatal(err)
	}
	if parentCount != 0 || childCount != 0 {
		t.Fatalf("cascade failed: parents=%d children=%d", parentCount, childCount)
	}
	rows, total, err := pg.QueryMCPAudit(ctx(), store.MCPAuditFilter{UserID: u, TenantID: tenant, Limit: 10})
	if err != nil || total != 3 || len(rows) != 3 || rows[0].ExchangeID != newest.ID || rows[1].ExchangeID != middle.ID || rows[2].ExchangeID != inFlight.ID {
		t.Fatalf("first retention result: rows=%+v total=%d err=%v", rows, total, err)
	}
	deleted, err = pg.DeleteMCPAuditOlderThan(ctx(), now.Add(-24*time.Hour), 10)
	if err != nil || deleted != 1 {
		t.Fatalf("second batch: deleted=%d err=%v", deleted, err)
	}
	rows, total, err = pg.QueryMCPAudit(ctx(), store.MCPAuditFilter{UserID: u, TenantID: tenant, Limit: 10})
	if err != nil || total != 2 || rows[0].ExchangeID != newest.ID || rows[1].ExchangeID != inFlight.ID {
		t.Fatalf("new exchange retention: rows=%+v total=%d err=%v", rows, total, err)
	}
	if deleted, err = pg.DeleteMCPAuditOlderThan(ctx(), now.Add(-24*time.Hour), 10); err != nil || deleted != 0 {
		t.Fatalf("empty batch: deleted=%d err=%v", deleted, err)
	}
	var indexExists bool
	if err := pg.Pool().QueryRow(ctx(), `SELECT EXISTS(
		SELECT 1 FROM pg_indexes WHERE schemaname='vault' AND indexname='ix_mcp_audit_exchanges_completed_id')`).Scan(&indexExists); err != nil || !indexExists {
		t.Fatalf("retention index: exists=%v err=%v", indexExists, err)
	}
}

func TestMCPEvalRunLifecycle(t *testing.T) {
	u, tenant := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: u, TenantID: tenant, Slug: "eval-" + uuid.NewString(),
		Name: "Eval upstream", UpstreamURL: "https://example.com/mcp", AuthMode: "none",
		AuditMode: "redacted", ProtocolVersion: "2026-07-28", Enabled: true}
	if err := pg.InsertMCPConnection(ctx(), connection); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC()
	run := &store.MCPEvalRun{UserID: u, TenantID: tenant, RunID: "run-" + uuid.NewString(), ExpiresAt: expiresAt}
	key := &store.AccessKey{UserID: u, TenantID: tenant, Name: "eval-key-" + uuid.NewString(),
		KeyHash: []byte("eval-hash-" + uuid.NewString()), KeyPrefix: "dwv_eval", Scopes: []string{"vault:mcp"},
		Enabled: true, ExpiresAt: &expiresAt}
	if err := pg.CreateMCPEvalRun(ctx(), run, key, []uuid.UUID{connection.ID}); err != nil {
		t.Fatal(err)
	}
	if run.ID == uuid.Nil || key.ID == uuid.Nil || run.AccessKeyID != key.ID || run.CreatedAt.IsZero() || key.CreatedAt.IsZero() {
		t.Fatalf("generated fields: run=%+v key=%+v", run, key)
	}
	if allowed, err := pg.HasMCPConnectionGrant(ctx(), key.ID, connection.ID); err != nil || !allowed {
		t.Fatalf("grant: %v %v", allowed, err)
	}
	if got, err := pg.GetMCPEvalRunByAccessKey(ctx(), key.ID); err != nil || got == nil || got.RunID != run.RunID {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if got, err := pg.GetMCPEvalRunByAccessKey(ctx(), uuid.New()); err != nil || got != nil {
		t.Fatalf("missing lookup: %+v %v", got, err)
	}
	if list, err := pg.ListMCPEvalRuns(ctx(), u); err != nil || len(list) != 1 || list[0].ID != run.ID {
		t.Fatalf("owner list: %+v %v", list, err)
	}
	if list, err := pg.ListMCPEvalRuns(ctx(), uuid.New()); err != nil || len(list) != 0 {
		t.Fatalf("cross-owner list: %+v %v", list, err)
	}
	if ok, err := pg.RevokeMCPEvalRun(ctx(), uuid.New(), run.ID); err != nil || ok {
		t.Fatalf("cross-owner revoke: %v %v", ok, err)
	}
	if ok, err := pg.RevokeMCPEvalRun(ctx(), u, run.ID); err != nil || !ok {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	persistedRun, _ := pg.GetMCPEvalRunByAccessKey(ctx(), key.ID)
	persistedKey, _ := pg.GetAccessKeyByID(ctx(), u, key.ID)
	if persistedRun.RevokedAt == nil || persistedKey == nil || persistedKey.Enabled || persistedKey.UpdatedAt == nil {
		t.Fatalf("revoked run/key: %+v %+v", persistedRun, persistedKey)
	}
	if ok, err := pg.RevokeMCPEvalRun(ctx(), u, run.ID); err != nil || ok {
		t.Fatalf("second revoke: %v %v", ok, err)
	}
	if ok, err := pg.DeleteAccessKey(ctx(), u, key.ID); err != nil || !ok {
		t.Fatalf("delete key: %v %v", ok, err)
	}
	if got, err := pg.GetMCPEvalRunByAccessKey(ctx(), key.ID); err != nil || got != nil {
		t.Fatalf("key cascade: %+v %v", got, err)
	}
}

func TestMCPEvalRunCreationRollback(t *testing.T) {
	u, tenant := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: u, TenantID: tenant, Slug: "rollback-" + uuid.NewString(),
		Name: "Rollback", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted",
		ProtocolVersion: "2026-07-28", Enabled: true}
	if err := pg.InsertMCPConnection(ctx(), connection); err != nil {
		t.Fatal(err)
	}
	other := &store.MCPConnection{UserID: uuid.New(), TenantID: tenant, Slug: "other-" + uuid.NewString(),
		Name: "Other", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted",
		ProtocolVersion: "2026-07-28", Enabled: true}
	if err := pg.InsertMCPConnection(ctx(), other); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC()
	run := &store.MCPEvalRun{UserID: u, TenantID: tenant, RunID: "rollback-" + uuid.NewString(), ExpiresAt: expiresAt}
	key := &store.AccessKey{UserID: u, TenantID: tenant, Name: "rollback-key-" + uuid.NewString(),
		KeyHash: []byte("rollback-hash-" + uuid.NewString()), KeyPrefix: "dwv_eval", Scopes: []string{"vault:mcp"},
		Enabled: true, ExpiresAt: &expiresAt}
	if err := pg.CreateMCPEvalRun(ctx(), run, key, []uuid.UUID{connection.ID, other.ID}); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("cross-owner create: %v", err)
	}
	if got, err := pg.GetAccessKeyByHash(ctx(), key.KeyHash); err != nil || got != nil {
		t.Fatalf("partial key: %+v %v", got, err)
	}
	if list, err := pg.ListMCPEvalRuns(ctx(), u); err != nil || len(list) != 0 {
		t.Fatalf("partial run: %+v %v", list, err)
	}
	disabled := &store.MCPConnection{UserID: u, TenantID: tenant, Slug: "disabled-" + uuid.NewString(),
		Name: "Disabled", UpstreamURL: "https://example.com/mcp", AuthMode: "none", AuditMode: "redacted",
		ProtocolVersion: "2026-07-28", Enabled: false}
	if err := pg.InsertMCPConnection(ctx(), disabled); err != nil {
		t.Fatal(err)
	}
	if err := pg.CreateMCPEvalRun(ctx(), run, key, []uuid.UUID{disabled.ID}); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("disabled create: %v", err)
	}
	if got, err := pg.GetAccessKeyByHash(ctx(), key.KeyHash); err != nil || got != nil {
		t.Fatalf("disabled partial key: %+v %v", got, err)
	}
	if err := pg.CreateMCPEvalRun(ctx(), run, key, []uuid.UUID{connection.ID}); err != nil {
		t.Fatal(err)
	}
	duplicateKey := *key
	duplicateKey.ID, duplicateKey.CreatedAt = uuid.Nil, time.Time{}
	duplicateKey.Name = "duplicate-key-" + uuid.NewString()
	duplicateKey.KeyHash = []byte("duplicate-hash-" + uuid.NewString())
	duplicateRun := *run
	duplicateRun.ID, duplicateRun.AccessKeyID, duplicateRun.CreatedAt = uuid.Nil, uuid.Nil, time.Time{}
	if err := pg.CreateMCPEvalRun(ctx(), &duplicateRun, &duplicateKey, []uuid.UUID{connection.ID}); err == nil {
		t.Fatal("duplicate run ID should fail")
	} else if !errors.Is(err, store.ErrInvalidMCPEvalRun) {
		t.Fatalf("duplicate run error: %v", err)
	}
	if got, err := pg.GetAccessKeyByHash(ctx(), duplicateKey.KeyHash); err != nil || got != nil {
		t.Fatalf("duplicate rollback key: %+v %v", got, err)
	}
	if err := pg.CreateMCPEvalRun(ctx(), run, key, []uuid.UUID{connection.ID, connection.ID}); !errors.Is(err, store.ErrInvalidMCPEvalRun) {
		t.Fatalf("duplicate connections: %v", err)
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
	if g, err := pg.GetAPIKeyByID(ctx(), u, missing); g != nil || err != nil {
		t.Fatalf("api by ID miss: %+v %v", g, err)
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

	if g, err := pg.GetMCPConnectionByID(ctx(), u, missing); g != nil || err != nil {
		t.Fatalf("MCP connection ID miss: %+v %v", g, err)
	}
	if g, err := pg.GetMCPConnectionBySlug(ctx(), u, "missing"); g != nil || err != nil {
		t.Fatalf("MCP connection slug miss: %+v %v", g, err)
	}
	if ok, err := pg.UpdateMCPConnection(ctx(), &store.MCPConnection{ID: missing, UserID: u}); ok || err != nil {
		t.Fatalf("update MCP connection miss: %v %v", ok, err)
	}
	if ok, err := pg.DeleteMCPConnection(ctx(), u, missing); ok || err != nil {
		t.Fatalf("delete MCP connection miss: %v %v", ok, err)
	}
	if g, err := pg.GetMCPOAuthAuthorization(ctx(), u, missing); g != nil || err != nil {
		t.Fatalf("MCP OAuth miss: %+v %v", g, err)
	}
	if ok, err := pg.UpdateMCPOAuthAuthorization(ctx(), &store.MCPOAuthAuthorization{ID: missing, UserID: u, ConnectionID: missing}); ok || err != nil {
		t.Fatalf("update MCP OAuth miss: %v %v", ok, err)
	}
	if state, err := pg.ClaimMCPOAuthState(ctx(), "missing"); state != nil || err != nil {
		t.Fatalf("claim MCP OAuth state miss: %+v %v", state, err)
	}
	if ok, err := pg.CompleteMCPAuditExchange(ctx(), &store.MCPAuditExchange{ID: missing, UserID: u, TenantID: u}); ok || err != nil {
		t.Fatalf("complete MCP audit miss: %v %v", ok, err)
	}
}

func TestQueryMCPAuditFilters(t *testing.T) {
	u, tenant, connectionID, accessKeyID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	evalRun := "filter-run"
	exchange := &store.MCPAuditExchange{ConnectionID: connectionID, UserID: u, TenantID: tenant,
		AccessKeyID: accessKeyID, EvalRunID: &evalRun, HTTPMethod: "POST", ProtocolVersion: "2026-07-28",
		Outcome: "success", StartedAt: time.Now()}
	if err := pg.InsertMCPAuditExchange(ctx(), exchange); err != nil {
		t.Fatal(err)
	}
	method, tool := "tools/call", "search"
	for i, direction := range []string{"client_to_server", "server_to_client"} {
		decision := "allowed"
		if i == 1 {
			decision = "denied"
		}
		message := &store.MCPAuditMessage{ExchangeID: exchange.ID, ConnectionID: connectionID,
			UserID: u, TenantID: tenant, SequenceNo: int64(i + 1), ObservedAt: time.Now().Add(time.Duration(i) * time.Second),
			Direction: direction, MessageKind: "request", PolicyDecision: decision, Method: &method,
			ToolName: &tool, PayloadSHA256: []byte{byte(i)}, PayloadBytes: 1}
		if err := pg.InsertMCPAuditMessage(ctx(), message); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name   string
		filter store.MCPAuditFilter
		want   int
	}{
		{name: "connection", filter: store.MCPAuditFilter{ConnectionID: &connectionID}, want: 2},
		{name: "access key", filter: store.MCPAuditFilter{AccessKeyID: &accessKeyID}, want: 2},
		{name: "eval run", filter: store.MCPAuditFilter{EvalRunID: &evalRun}, want: 2},
		{name: "direction", filter: store.MCPAuditFilter{Direction: sp("client_to_server")}, want: 1},
		{name: "method", filter: store.MCPAuditFilter{Method: &method}, want: 2},
		{name: "tool", filter: store.MCPAuditFilter{ToolName: &tool}, want: 2},
		{name: "decision", filter: store.MCPAuditFilter{PolicyDecision: sp("denied")}, want: 1},
		{name: "since", filter: store.MCPAuditFilter{Since: timePtr(time.Now().Add(-time.Minute))}, want: 2},
		{name: "until", filter: store.MCPAuditFilter{Until: timePtr(time.Now().Add(time.Minute))}, want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.filter.UserID, test.filter.TenantID, test.filter.Limit = u, tenant, 10
			items, total, err := pg.QueryMCPAudit(ctx(), test.filter)
			if err != nil || total != test.want || len(items) != test.want {
				t.Fatalf("query: items=%d total=%d err=%v", len(items), total, err)
			}
		})
	}
	items, total, err := pg.QueryMCPAudit(ctx(), store.MCPAuditFilter{UserID: u, TenantID: tenant, Limit: 1, Offset: 1})
	if err != nil || total != 2 || len(items) != 1 {
		t.Fatalf("paging: items=%d total=%d err=%v", len(items), total, err)
	}
}

func TestMCPToolParameterHeaders(t *testing.T) {
	u, tenant := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: u, TenantID: tenant, Slug: "headers-" + u.String(),
		Name: "Headers", UpstreamURL: "https://example.test/mcp", AuthMode: "none", AuditMode: "redacted",
		ProtocolVersion: "2026-07-28", Enabled: true}
	if err := pg.InsertMCPConnection(ctx(), connection); err != nil {
		t.Fatal(err)
	}
	headers := []store.MCPToolParameterHeader{
		{ToolName: "search", HeaderName: "Tenant", ArgumentPath: []string{"filters", "tenant"}, Required: true},
		{ToolName: "search", HeaderName: "Region", ArgumentPath: []string{"region"}},
		{ToolName: "fetch", HeaderName: "Document", ArgumentPath: []string{"id"}, Required: true},
	}
	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, headers); err != nil {
		t.Fatal(err)
	}
	for i, header := range headers {
		if header.ID == uuid.Nil || header.CreatedAt.IsZero() || header.UserID != u ||
			header.TenantID != tenant || header.ConnectionID != connection.ID {
			t.Fatalf("generated header %d: %+v", i, header)
		}
	}
	search, err := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "search")
	if err != nil || len(search) != 2 || search[0].HeaderName != "Region" ||
		len(search[1].ArgumentPath) != 2 || !search[1].Required {
		t.Fatalf("list search: %+v %v", search, err)
	}
	if other, err := pg.ListMCPToolParameterHeaders(ctx(), uuid.New(), connection.ID, "search"); err != nil || len(other) != 0 {
		t.Fatalf("owner scope: %+v %v", other, err)
	}

	invalid := []store.MCPToolParameterHeader{
		{ToolName: "search", HeaderName: "Region", ArgumentPath: []string{"one"}},
		{ToolName: "search", HeaderName: "region", ArgumentPath: []string{"two"}},
	}
	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, invalid); !errors.Is(err, store.ErrInvalidMCPToolParameterHeader) {
		t.Fatalf("invalid metadata: %v", err)
	}
	if retained, _ := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "search"); len(retained) != 2 {
		t.Fatalf("invalid replace must not mutate: %+v", retained)
	}
	tooLong := strings.Repeat("x", 256)
	databaseFailure := []store.MCPToolParameterHeader{{ToolName: "search", HeaderName: tooLong, ArgumentPath: []string{"value"}}}
	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, databaseFailure); err == nil {
		t.Fatal("expected database constraint error")
	}
	if retained, _ := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "search"); len(retained) != 2 {
		t.Fatalf("transaction rollback must retain prior metadata: %+v", retained)
	}
	wrongOwner := []store.MCPToolParameterHeader{{UserID: uuid.New(), ToolName: "search", HeaderName: "Site", ArgumentPath: []string{"site"}}}
	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, wrongOwner); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("embedded owner: %v", err)
	}
	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), uuid.New(), tenant, connection.ID, nil); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("connection owner: %v", err)
	}

	replacement := []store.MCPToolParameterHeader{{ToolName: "search", HeaderName: "Site", ArgumentPath: []string{"site"}}}
	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, replacement); err != nil {
		t.Fatal(err)
	}
	if stale, _ := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "fetch"); len(stale) != 0 {
		t.Fatal("replacement must delete stale tool metadata")
	}
	page := []store.MCPToolHeaderSnapshot{
		{ToolName: "search", Headers: []store.MCPToolParameterHeader{{HeaderName: "Region", ArgumentPath: []string{"region"}}}},
		{ToolName: "fetch", Headers: []store.MCPToolParameterHeader{{HeaderName: "Document", ArgumentPath: []string{"id"}}}},
	}
	if err := pg.UpsertMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, page); err != nil {
		t.Fatal(err)
	}
	clearFetch := []store.MCPToolHeaderSnapshot{{ToolName: "fetch"}}
	if err := pg.UpsertMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, clearFetch); err != nil {
		t.Fatal(err)
	}
	if fetch, _ := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "fetch"); len(fetch) != 0 {
		t.Fatalf("page clear: %+v", fetch)
	}
	if search, _ := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "search"); len(search) != 1 || search[0].HeaderName != "Region" {
		t.Fatalf("unobserved tool preservation: %+v", search)
	}
	invalidPage := []store.MCPToolHeaderSnapshot{{ToolName: "search"}, {ToolName: "search"}}
	if err := pg.UpsertMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, invalidPage); !errors.Is(err, store.ErrInvalidMCPToolParameterHeader) {
		t.Fatalf("invalid page: %v", err)
	}
	failingPage := []store.MCPToolHeaderSnapshot{{ToolName: "search", Headers: []store.MCPToolParameterHeader{{HeaderName: tooLong, ArgumentPath: []string{"value"}}}}}
	if err := pg.UpsertMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, failingPage); err == nil {
		t.Fatal("expected paginated database constraint error")
	}
	if search, _ := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "search"); len(search) != 1 || search[0].HeaderName != "Region" {
		t.Fatalf("paginated transaction rollback: %+v", search)
	}
	if err := pg.UpsertMCPToolParameterHeaders(ctx(), uuid.New(), tenant, connection.ID, nil); !errors.Is(err, store.ErrOwnershipMismatch) {
		t.Fatalf("page owner: %v", err)
	}
	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, nil); err != nil {
		t.Fatal(err)
	}
	if cleared, _ := pg.ListMCPToolParameterHeaders(ctx(), u, connection.ID, "search"); len(cleared) != 0 {
		t.Fatal("empty replacement must clear")
	}

	if err := pg.ReplaceMCPToolParameterHeaders(ctx(), u, tenant, connection.ID, headers); err != nil {
		t.Fatal(err)
	}
	if ok, err := pg.DeleteMCPConnection(ctx(), u, connection.ID); err != nil || !ok {
		t.Fatalf("delete connection: %v %v", ok, err)
	}
	var count int
	if err := pg.Pool().QueryRow(ctx(), `SELECT count(*) FROM vault.mcp_tool_parameter_headers WHERE connection_id=$1`, connection.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("cascade: count=%d err=%v", count, err)
	}
}

func TestMCPProtocolProbe(t *testing.T) {
	u, tenant := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: u, TenantID: tenant, Slug: "probe-" + u.String(),
		Name: "Before", UpstreamURL: "https://example.test/mcp", AuthMode: "none", AuditMode: "redacted",
		ProtocolVersion: "2026-07-28", Enabled: true}
	if err := pg.InsertMCPConnection(ctx(), connection); err != nil {
		t.Fatal(err)
	}
	if connection.ProtocolEra != "unknown" || connection.ProbeStatus != "not_checked" {
		t.Fatalf("probe defaults: %+v", connection)
	}
	if connection.UpstreamProtocolMode != "modern_2026_07" || connection.LegacyProtocolVersion != "2025-06-18" {
		t.Fatalf("upstream protocol defaults: %+v", connection)
	}
	checkedAt := time.Now().UTC().Truncate(time.Microsecond)
	detail, serverName, serverVersion := "modern stateless endpoint", "Acme MCP", "1.2.3"
	result := &store.MCPProtocolProbeResult{ConnectionID: connection.ID, UserID: u, TenantID: tenant,
		ProtocolEra: "modern_2026_07", Status: "compatible", CheckedAt: checkedAt,
		Detail: &detail, SupportedVersions: []string{"2026-07-28"}, ServerName: &serverName, ServerVersion: &serverVersion}
	if ok, err := pg.RecordMCPProtocolProbe(ctx(), result); err != nil || !ok {
		t.Fatalf("record probe: %v %v", ok, err)
	}
	got, err := pg.GetMCPConnectionByID(ctx(), u, connection.ID)
	if err != nil || got == nil || got.ProtocolEra != result.ProtocolEra || got.ProbeStatus != result.Status ||
		got.ProbeCheckedAt == nil || !got.ProbeCheckedAt.Equal(checkedAt) || len(got.SupportedVersions) != 1 ||
		got.ServerName == nil || *got.ServerName != serverName {
		t.Fatalf("probe round trip: %+v %v", got, err)
	}

	// Editable updates do not include probe-owned columns and must preserve the result.
	connection.Name = "After"
	connection.UpstreamProtocolMode = "legacy_session"
	connection.LegacyProtocolVersion = "2025-11-25"
	if ok, err := pg.UpdateMCPConnection(ctx(), connection); err != nil || !ok {
		t.Fatalf("config update: %v %v", ok, err)
	}
	if connection.UpstreamProtocolMode != "legacy_session" || connection.LegacyProtocolVersion != "2025-11-25" || connection.ProbeStatus != "compatible" || connection.ServerVersion == nil ||
		len(connection.SupportedVersions) != 1 {
		t.Fatalf("updated entity lost probe result: %+v", connection)
	}
	got, _ = pg.GetMCPConnectionByID(ctx(), u, connection.ID)
	if got.Name != "After" || got.UpstreamProtocolMode != "legacy_session" || got.LegacyProtocolVersion != "2025-11-25" || got.ProbeStatus != "compatible" || got.ServerVersion == nil {
		t.Fatalf("config update overwrote probe: %+v", got)
	}

	errorClass := "authentication_required"
	failed := &store.MCPProtocolProbeResult{ConnectionID: connection.ID, UserID: u, TenantID: tenant,
		ProtocolEra: "unknown", Status: "auth_required", CheckedAt: checkedAt.Add(time.Minute), Error: &errorClass}
	if ok, err := pg.RecordMCPProtocolProbe(ctx(), failed); err != nil || !ok {
		t.Fatalf("replace probe: %v %v", ok, err)
	}
	got, _ = pg.GetMCPConnectionByID(ctx(), u, connection.ID)
	if got.ProbeError == nil || got.ProbeDetail != nil || got.ServerName != nil || len(got.SupportedVersions) != 0 {
		t.Fatalf("replacement did not clear prior result: %+v", got)
	}
	if ok, err := pg.RecordMCPProtocolProbe(ctx(), &store.MCPProtocolProbeResult{
		ConnectionID: connection.ID, UserID: uuid.New(), TenantID: tenant,
		ProtocolEra: "unknown", Status: "error", CheckedAt: checkedAt,
	}); err != nil || ok {
		t.Fatalf("owner scope: %v %v", ok, err)
	}
	invalid := *failed
	invalid.Status = "maybe"
	if ok, err := pg.RecordMCPProtocolProbe(ctx(), &invalid); ok || !errors.Is(err, store.ErrInvalidMCPProtocolProbe) {
		t.Fatalf("invalid result: %v %v", ok, err)
	}
	got, _ = pg.GetMCPConnectionByID(ctx(), u, connection.ID)
	if got.ProbeStatus != "auth_required" {
		t.Fatal("invalid result must not mutate probe state")
	}
	if ok, err := pg.RecordMCPProtocolProbe(ctx(), nil); ok || !errors.Is(err, store.ErrInvalidMCPProtocolProbe) {
		t.Fatalf("nil result: %v %v", ok, err)
	}
	list, err := pg.ListMCPConnections(ctx(), u)
	if err != nil || len(list) != 1 || list[0].ProbeCheckedAt == nil {
		t.Fatalf("list probe result: %+v %v", list, err)
	}
}

func timePtr(value time.Time) *time.Time { return &value }

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
	if _, err := bad.GetAPIKeyByID(ctx(), u, u); err == nil {
		t.Fatal("get API key by ID should error")
	}
	if err := bad.InsertMCPConnection(ctx(), &store.MCPConnection{}); err == nil {
		t.Fatal("insert MCP connection should error")
	}
	if _, err := bad.UpdateMCPConnection(ctx(), &store.MCPConnection{}); err == nil {
		t.Fatal("update MCP connection should error")
	}
	if _, err := bad.ListMCPConnections(ctx(), u); err == nil {
		t.Fatal("list MCP connections should error")
	}
	if _, err := bad.GetMCPConnectionByID(ctx(), u, u); err == nil {
		t.Fatal("get MCP connection should error")
	}
	expiresAt := time.Now().Add(time.Hour)
	if err := bad.CreateMCPEvalRun(ctx(), &store.MCPEvalRun{UserID: u, RunID: "run", ExpiresAt: expiresAt},
		&store.AccessKey{UserID: u, Name: "run", KeyHash: []byte("hash"), KeyPrefix: "dwv_eval", Scopes: []string{"vault:mcp"}, Enabled: true, ExpiresAt: &expiresAt},
		[]uuid.UUID{u}); err == nil {
		t.Fatal("create MCP eval run should error")
	}
	if _, err := bad.ListMCPEvalRuns(ctx(), u); err == nil {
		t.Fatal("list MCP eval runs should error")
	}
	if _, err := bad.GetMCPEvalRunByAccessKey(ctx(), u); err == nil {
		t.Fatal("get MCP eval run should error")
	}
	if _, err := bad.RevokeMCPEvalRun(ctx(), u, u); err == nil {
		t.Fatal("revoke MCP eval run should error")
	}
	if _, err := bad.RecordMCPProtocolProbe(ctx(), &store.MCPProtocolProbeResult{
		ConnectionID: u, UserID: u, TenantID: u, ProtocolEra: "unknown", Status: "error", CheckedAt: time.Now(),
	}); err == nil {
		t.Fatal("record MCP protocol probe should error")
	}
	if err := bad.InsertMCPOAuthAuthorization(ctx(), &store.MCPOAuthAuthorization{}); err == nil {
		t.Fatal("insert MCP OAuth should error")
	}
	if _, err := bad.UpdateMCPOAuthAuthorization(ctx(), &store.MCPOAuthAuthorization{}); err == nil {
		t.Fatal("update MCP OAuth should error")
	}
	if _, err := bad.GetMCPOAuthAuthorization(ctx(), u, u); err == nil {
		t.Fatal("get MCP OAuth should error")
	}
	if err := bad.InsertMCPOAuthState(ctx(), &store.MCPOAuthState{}); err == nil {
		t.Fatal("insert MCP OAuth state should error")
	}
	if _, err := bad.ClaimMCPOAuthState(ctx(), "state"); err == nil {
		t.Fatal("claim MCP OAuth state should error")
	}
	if _, _, err := bad.QueryMCPAudit(ctx(), store.MCPAuditFilter{}); err == nil {
		t.Fatal("query MCP audit should error")
	}
	if _, err := bad.DeleteMCPAuditOlderThan(ctx(), time.Now(), 10); err == nil {
		t.Fatal("delete MCP audit should error")
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
