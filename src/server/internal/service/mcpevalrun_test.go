package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
	"donkeywork.dev/vault-server/internal/store/memstore"
)

type mcpEvalRunFixture struct {
	service *MCPEvalRunService
	memory  *memstore.Mem
	audit   *audit.Log
	ctx     context.Context
	now     time.Time
}

func newMCPEvalRunFixture(t *testing.T) mcpEvalRunFixture {
	t.Helper()
	memory := memstore.New()
	auditLog := audit.NewLog(10, nil, nil)
	caller := contracts.Caller{UserID: uuid.New(), TenantID: uuid.New()}
	ctx := contracts.WithCaller(context.Background(), caller)
	now := time.Now().UTC()
	svc := NewMCPEvalRunService(memory, auditLog)
	svc.now = func() time.Time { return now }
	return mcpEvalRunFixture{service: svc, memory: memory, audit: auditLog, ctx: ctx, now: now}
}

func (f mcpEvalRunFixture) connection(t *testing.T, name string, enabled bool) store.MCPConnection {
	t.Helper()
	caller := contracts.CallerFrom(f.ctx)
	connection := store.MCPConnection{
		UserID:      caller.UserID,
		TenantID:    caller.TenantID,
		Slug:        strings.ToLower(name),
		Name:        name,
		UpstreamURL: "https://example.com/mcp",
		AuthMode:    "none",
		AuditMode:   "redacted",
		Enabled:     enabled,
	}
	if err := f.memory.InsertMCPConnection(f.ctx, &connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func TestMCPEvalRunServiceCreate(t *testing.T) {
	f := newMCPEvalRunFixture(t)
	first := f.connection(t, "First", true)
	second := f.connection(t, "Second", true)
	expiresAt := f.now.Add(24 * time.Hour)

	created, err := f.service.Create(f.ctx, "  sandbox-42  ", []uuid.UUID{second.ID, first.ID}, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if created.Run.ID == uuid.Nil || created.Run.AccessKeyID == uuid.Nil || created.Run.RunID != "sandbox-42" {
		t.Fatalf("unexpected run: %+v", created.Run)
	}
	if !created.Run.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("expiry = %v, want %v", created.Run.ExpiresAt, expiresAt)
	}
	if !strings.HasPrefix(created.Secret, SecretPrefix) {
		t.Fatalf("secret = %q", created.Secret)
	}
	if len(created.Connections) != 2 || created.Connections[0].ID != second.ID || created.Connections[1].ID != first.ID {
		t.Fatalf("connection order not preserved: %+v", created.Connections)
	}

	key, err := f.memory.GetAccessKeyByID(f.ctx, contracts.CallerFrom(f.ctx).UserID, created.Run.AccessKeyID)
	if err != nil || key == nil {
		t.Fatalf("stored key: %+v, %v", key, err)
	}
	if len(key.Scopes) != 1 || key.Scopes[0] != mcpEvalRunScope || !key.Enabled {
		t.Fatalf("stored key scope/state: %+v", key)
	}
	if key.ExpiresAt == nil || !key.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("stored key expiry: %+v", key.ExpiresAt)
	}
	if string(key.KeyHash) == created.Secret || !equalBytes(key.KeyHash, hashSecret(created.Secret)) {
		t.Fatal("store did not retain only the secret hash")
	}
	if key.KeyPrefix != created.Secret[:9] {
		t.Fatalf("prefix = %q", key.KeyPrefix)
	}

	principal, err := NewAccessKeyService(f.memory, f.audit).Authenticate(f.ctx, created.Secret)
	if err != nil || principal == nil || principal.ID != created.Run.AccessKeyID {
		t.Fatalf("authenticate: %+v, %v", principal, err)
	}
	for _, connectionID := range []uuid.UUID{first.ID, second.ID} {
		granted, grantErr := f.memory.HasMCPConnectionGrant(f.ctx, created.Run.AccessKeyID, connectionID)
		if grantErr != nil || !granted {
			t.Fatalf("grant %s: %v, %v", connectionID, granted, grantErr)
		}
	}

	select {
	case event := <-f.audit.Reader():
		if event.Type != audit.EventCredentialCreated || event.TargetKind == nil || *event.TargetKind != "mcp_eval_run" || event.TargetName == nil || *event.TargetName != "sandbox-42" {
			t.Fatalf("unexpected audit event: %+v", event)
		}
	default:
		t.Fatal("credential creation was not audited")
	}
}

func TestMCPEvalRunServiceCreateValidation(t *testing.T) {
	f := newMCPEvalRunFixture(t)
	enabled := f.connection(t, "Enabled", true)
	disabled := f.connection(t, "Disabled", false)

	other := contracts.Caller{UserID: uuid.New(), TenantID: uuid.New()}
	otherConnection := store.MCPConnection{UserID: other.UserID, TenantID: other.TenantID, Name: "Other", Slug: "other", Enabled: true}
	if err := f.memory.InsertMCPConnection(f.ctx, &otherConnection); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		runID       string
		connections []uuid.UUID
		expiresAt   time.Time
	}{
		{name: "blank run id", runID: " \t ", connections: []uuid.UUID{enabled.ID}, expiresAt: f.now.Add(time.Hour)},
		{name: "long run id", runID: strings.Repeat("x", 256), connections: []uuid.UUID{enabled.ID}, expiresAt: f.now.Add(time.Hour)},
		{name: "no connections", runID: "run", expiresAt: f.now.Add(time.Hour)},
		{name: "nil connection", runID: "run", connections: []uuid.UUID{uuid.Nil}, expiresAt: f.now.Add(time.Hour)},
		{name: "duplicate connection", runID: "run", connections: []uuid.UUID{enabled.ID, enabled.ID}, expiresAt: f.now.Add(time.Hour)},
		{name: "expired", runID: "run", connections: []uuid.UUID{enabled.ID}, expiresAt: f.now.Add(-time.Second)},
		{name: "expires now", runID: "run", connections: []uuid.UUID{enabled.ID}, expiresAt: f.now},
		{name: "over 24 hours", runID: "run", connections: []uuid.UUID{enabled.ID}, expiresAt: f.now.Add(24*time.Hour + time.Nanosecond)},
		{name: "missing connection", runID: "run", connections: []uuid.UUID{uuid.New()}, expiresAt: f.now.Add(time.Hour)},
		{name: "other owner connection", runID: "run", connections: []uuid.UUID{otherConnection.ID}, expiresAt: f.now.Add(time.Hour)},
		{name: "disabled connection", runID: "run", connections: []uuid.UUID{disabled.ID}, expiresAt: f.now.Add(time.Hour)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := f.service.Create(f.ctx, test.runID, test.connections, test.expiresAt); err == nil {
				t.Fatal("invalid creation succeeded")
			} else {
				var validationErr ValidationError
				if !errors.As(err, &validationErr) {
					t.Fatalf("error type = %T, want ValidationError", err)
				}
			}
		})
	}
}

func TestMCPEvalRunServiceListAndRevoke(t *testing.T) {
	f := newMCPEvalRunFixture(t)
	connection := f.connection(t, "Connection", true)
	created, err := f.service.Create(f.ctx, "run", []uuid.UUID{connection.ID}, f.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	runs, err := f.service.List(f.ctx)
	if err != nil || len(runs) != 1 || runs[0].ID != created.Run.ID {
		t.Fatalf("list: %+v, %v", runs, err)
	}
	otherCtx := contracts.WithCaller(context.Background(), contracts.Caller{UserID: uuid.New(), TenantID: uuid.New()})
	if otherRuns, listErr := f.service.List(otherCtx); listErr != nil || len(otherRuns) != 0 {
		t.Fatalf("other owner list: %+v, %v", otherRuns, listErr)
	}
	if revoked, revokeErr := f.service.Revoke(otherCtx, created.Run.ID); revokeErr != nil || revoked {
		t.Fatalf("other owner revoke: %v, %v", revoked, revokeErr)
	}
	if revoked, revokeErr := f.service.Revoke(f.ctx, created.Run.ID); revokeErr != nil || !revoked {
		t.Fatalf("revoke: %v, %v", revoked, revokeErr)
	}
	if principal, authErr := NewAccessKeyService(f.memory, f.audit).Authenticate(f.ctx, created.Secret); authErr != nil || principal != nil {
		t.Fatalf("revoked key authenticated: %+v, %v", principal, authErr)
	}
	stored, err := f.memory.GetMCPEvalRunByAccessKey(f.ctx, created.Run.AccessKeyID)
	if err != nil || stored == nil || stored.RevokedAt == nil {
		t.Fatalf("stored revoked run: %+v, %v", stored, err)
	}
	if revoked, revokeErr := f.service.Revoke(f.ctx, created.Run.ID); revokeErr != nil || revoked {
		t.Fatalf("second revoke: %v, %v", revoked, revokeErr)
	}
	if revoked, revokeErr := f.service.Revoke(f.ctx, uuid.New()); revokeErr != nil || revoked {
		t.Fatalf("missing revoke: %v, %v", revoked, revokeErr)
	}
}

type failCreateMCPEvalRunStore struct {
	store.Store
	err error
}

func (s failCreateMCPEvalRunStore) CreateMCPEvalRun(context.Context, *store.MCPEvalRun, *store.AccessKey, []uuid.UUID) error {
	return s.err
}

func TestMCPEvalRunServiceStoreErrors(t *testing.T) {
	f := newMCPEvalRunFixture(t)
	connection := f.connection(t, "Connection", true)
	boom := errors.New("store failed")

	f.memory.FailNext = boom
	if _, err := f.service.Create(f.ctx, "run", []uuid.UUID{connection.ID}, f.now.Add(time.Hour)); !errors.Is(err, boom) {
		t.Fatalf("lookup error = %v", err)
	}
	failing := NewMCPEvalRunService(failCreateMCPEvalRunStore{Store: f.memory, err: boom}, f.audit)
	failing.now = f.service.now
	if _, err := failing.Create(f.ctx, "run", []uuid.UUID{connection.ID}, f.now.Add(time.Hour)); !errors.Is(err, boom) {
		t.Fatalf("create error = %v", err)
	}

	f.memory.FailNext = boom
	if _, err := f.service.List(f.ctx); !errors.Is(err, boom) {
		t.Fatalf("list error = %v", err)
	}
	f.memory.FailNext = boom
	if _, err := f.service.Revoke(f.ctx, uuid.New()); !errors.Is(err, boom) {
		t.Fatalf("revoke error = %v", err)
	}
}

func TestMCPEvalRunServiceMapsAtomicValidation(t *testing.T) {
	f := newMCPEvalRunFixture(t)
	connection := f.connection(t, "Connection", true)
	for _, storeErr := range []error{store.ErrInvalidMCPEvalRun, store.ErrOwnershipMismatch} {
		failing := NewMCPEvalRunService(failCreateMCPEvalRunStore{Store: f.memory, err: storeErr}, f.audit)
		failing.now = f.service.now
		if _, err := failing.Create(f.ctx, "run", []uuid.UUID{connection.ID}, f.now.Add(time.Hour)); err == nil {
			t.Fatal("atomic validation error was not returned")
		} else {
			var validationErr ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error type = %T, want ValidationError", err)
			}
		}
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
