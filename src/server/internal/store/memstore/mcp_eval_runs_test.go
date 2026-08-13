package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

func evalRunFixture(ctx context.Context, t *testing.T, m *Mem) (*store.MCPEvalRun, *store.AccessKey, *store.MCPConnection) {
	t.Helper()
	userID, tenantID := uuid.New(), uuid.New()
	connection := &store.MCPConnection{UserID: userID, TenantID: tenantID, Slug: uuid.NewString(), Name: "Datadog", Enabled: true}
	if err := m.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(time.Hour).UTC()
	run := &store.MCPEvalRun{UserID: userID, TenantID: tenantID, RunID: uuid.NewString(), ExpiresAt: expiresAt}
	key := &store.AccessKey{UserID: userID, TenantID: tenantID, Name: uuid.NewString(), KeyHash: []byte(uuid.NewString()), KeyPrefix: "dwv_eval", Scopes: []string{"vault:mcp"}, Enabled: true, ExpiresAt: &expiresAt}
	return run, key, connection
}

func TestMCPEvalRunLifecycle(t *testing.T) {
	ctx := context.Background()
	m := New()
	run, key, connection := evalRunFixture(ctx, t, m)
	if err := m.CreateMCPEvalRun(ctx, run, key, []uuid.UUID{connection.ID}); err != nil {
		t.Fatal(err)
	}
	if run.ID == uuid.Nil || run.AccessKeyID != key.ID || run.CreatedAt.IsZero() || key.CreatedAt.IsZero() {
		t.Fatalf("generated fields: run=%+v key=%+v", run, key)
	}
	if allowed, err := m.HasMCPConnectionGrant(ctx, key.ID, connection.ID); err != nil || !allowed {
		t.Fatalf("grant: %v %v", allowed, err)
	}
	if got, err := m.GetMCPEvalRunByAccessKey(ctx, key.ID); err != nil || got == nil || got.RunID != run.RunID {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if got, _ := m.GetMCPEvalRunByAccessKey(ctx, uuid.New()); got != nil {
		t.Fatal("missing lookup")
	}
	otherRun, otherKey, _ := evalRunFixture(ctx, t, m)
	otherRun.CreatedAt = run.CreatedAt.Add(time.Second)
	if err := m.CreateMCPEvalRun(ctx, otherRun, otherKey, []uuid.UUID{connectionForOwner(ctx, t, m, otherRun).ID}); err != nil {
		t.Fatal(err)
	}
	if list, err := m.ListMCPEvalRuns(ctx, run.UserID); err != nil || len(list) != 1 || list[0].ID != run.ID {
		t.Fatalf("owner list: %+v %v", list, err)
	}
	if ok, err := m.RevokeMCPEvalRun(ctx, uuid.New(), run.ID); err != nil || ok {
		t.Fatalf("cross-owner revoke: %v %v", ok, err)
	}
	if ok, err := m.RevokeMCPEvalRun(ctx, run.UserID, run.ID); err != nil || !ok {
		t.Fatalf("revoke: %v %v", ok, err)
	}
	got, _ := m.GetMCPEvalRunByAccessKey(ctx, key.ID)
	persistedKey, _ := m.GetAccessKeyByID(ctx, key.UserID, key.ID)
	if got.RevokedAt == nil || persistedKey == nil || persistedKey.Enabled || persistedKey.UpdatedAt == nil {
		t.Fatalf("revoked run/key: %+v %+v", got, persistedKey)
	}
	if ok, err := m.RevokeMCPEvalRun(ctx, run.UserID, run.ID); err != nil || ok {
		t.Fatalf("second revoke: %v %v", ok, err)
	}
	if ok, err := m.DeleteAccessKey(ctx, key.UserID, key.ID); err != nil || !ok {
		t.Fatalf("delete key: %v %v", ok, err)
	}
	if got, _ := m.GetMCPEvalRunByAccessKey(ctx, key.ID); got != nil {
		t.Fatal("key deletion should cascade run")
	}
}

func connectionForOwner(ctx context.Context, t *testing.T, m *Mem, run *store.MCPEvalRun) *store.MCPConnection {
	t.Helper()
	connection := &store.MCPConnection{UserID: run.UserID, TenantID: run.TenantID, Slug: uuid.NewString(), Name: "owner", Enabled: true}
	if err := m.InsertMCPConnection(ctx, connection); err != nil {
		t.Fatal(err)
	}
	return connection
}

func TestMCPEvalRunAtomicValidation(t *testing.T) {
	ctx := context.Background()
	t.Run("ownership mismatch has no partial writes", func(t *testing.T) {
		m := New()
		run, key, connection := evalRunFixture(ctx, t, m)
		connection.UserID = uuid.New()
		m.mcpConnections[connection.ID] = *connection
		if err := m.CreateMCPEvalRun(ctx, run, key, []uuid.UUID{connection.ID}); !errors.Is(err, store.ErrOwnershipMismatch) {
			t.Fatalf("create: %v", err)
		}
		if got, _ := m.GetAccessKeyByHash(ctx, key.KeyHash); got != nil || len(m.mcpEvalRuns) != 0 || len(m.mcpGrants) != 0 {
			t.Fatal("partial state persisted")
		}
	})
	t.Run("disabled connection has no partial writes", func(t *testing.T) {
		m := New()
		run, key, connection := evalRunFixture(ctx, t, m)
		connection.Enabled = false
		m.mcpConnections[connection.ID] = *connection
		if err := m.CreateMCPEvalRun(ctx, run, key, []uuid.UUID{connection.ID}); !errors.Is(err, store.ErrOwnershipMismatch) {
			t.Fatalf("create: %v", err)
		}
		if got, _ := m.GetAccessKeyByHash(ctx, key.KeyHash); got != nil || len(m.mcpEvalRuns) != 0 || len(m.mcpGrants) != 0 {
			t.Fatal("partial state persisted")
		}
	})

	tests := []struct {
		name   string
		mutate func(*store.MCPEvalRun, *store.AccessKey, *[]uuid.UUID)
	}{
		{name: "nil run", mutate: func(run *store.MCPEvalRun, _ *store.AccessKey, _ *[]uuid.UUID) { *run = store.MCPEvalRun{} }},
		{name: "empty run id", mutate: func(run *store.MCPEvalRun, _ *store.AccessKey, _ *[]uuid.UUID) { run.RunID = " " }},
		{name: "past expiry", mutate: func(run *store.MCPEvalRun, key *store.AccessKey, _ *[]uuid.UUID) {
			expiry := time.Now().Add(-time.Hour)
			run.ExpiresAt, key.ExpiresAt = expiry, &expiry
		}},
		{name: "wrong scope", mutate: func(_ *store.MCPEvalRun, key *store.AccessKey, _ *[]uuid.UUID) { key.Scopes = []string{"vault:read"} }},
		{name: "duplicate connection", mutate: func(_ *store.MCPEvalRun, _ *store.AccessKey, ids *[]uuid.UUID) { *ids = append(*ids, (*ids)[0]) }},
		{name: "nil connection", mutate: func(_ *store.MCPEvalRun, _ *store.AccessKey, ids *[]uuid.UUID) { *ids = []uuid.UUID{uuid.Nil} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := New()
			run, key, connection := evalRunFixture(ctx, t, m)
			ids := []uuid.UUID{connection.ID}
			test.mutate(run, key, &ids)
			if err := m.CreateMCPEvalRun(ctx, run, key, ids); !errors.Is(err, store.ErrInvalidMCPEvalRun) {
				t.Fatalf("create: %v", err)
			}
		})
	}
}

func TestMCPEvalRunFailureInjection(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	checks := []func(*Mem, *store.MCPEvalRun, *store.AccessKey, uuid.UUID) error{
		func(m *Mem, run *store.MCPEvalRun, key *store.AccessKey, connectionID uuid.UUID) error {
			return m.CreateMCPEvalRun(ctx, run, key, []uuid.UUID{connectionID})
		},
		func(m *Mem, run *store.MCPEvalRun, _ *store.AccessKey, _ uuid.UUID) error {
			_, err := m.ListMCPEvalRuns(ctx, run.UserID)
			return err
		},
		func(m *Mem, _ *store.MCPEvalRun, key *store.AccessKey, _ uuid.UUID) error {
			_, err := m.GetMCPEvalRunByAccessKey(ctx, key.ID)
			return err
		},
		func(m *Mem, run *store.MCPEvalRun, _ *store.AccessKey, _ uuid.UUID) error {
			_, err := m.RevokeMCPEvalRun(ctx, run.UserID, run.ID)
			return err
		},
	}
	for i, check := range checks {
		m := New()
		run, key, connection := evalRunFixture(ctx, t, m)
		m.FailNext = boom
		if err := check(m, run, key, connection.ID); !errors.Is(err, boom) {
			t.Fatalf("check %d: %v", i, err)
		}
	}
}

func TestMCPEvalRunCreationConflictsAndMissingKey(t *testing.T) {
	ctx := context.Background()
	m := New()
	run, key, connection := evalRunFixture(ctx, t, m)
	if err := m.CreateMCPEvalRun(ctx, run, key, []uuid.UUID{connection.ID}); err != nil {
		t.Fatal(err)
	}

	conflicts := []struct {
		name   string
		mutate func(*store.MCPEvalRun, *store.AccessKey)
	}{
		{name: "key hash", mutate: func(_ *store.MCPEvalRun, candidateKey *store.AccessKey) {
			candidateKey.KeyHash = key.KeyHash
		}},
		{name: "key name", mutate: func(_ *store.MCPEvalRun, candidateKey *store.AccessKey) { candidateKey.Name = key.Name }},
		{name: "run ID", mutate: func(candidateRun *store.MCPEvalRun, _ *store.AccessKey) { candidateRun.RunID = run.RunID }},
		{name: "key UUID", mutate: func(_ *store.MCPEvalRun, candidateKey *store.AccessKey) { candidateKey.ID = key.ID }},
		{name: "run UUID", mutate: func(candidateRun *store.MCPEvalRun, _ *store.AccessKey) { candidateRun.ID = run.ID }},
	}
	for _, test := range conflicts {
		t.Run(test.name, func(t *testing.T) {
			expiresAt := time.Now().Add(time.Hour).UTC()
			candidateRun := &store.MCPEvalRun{UserID: run.UserID, TenantID: run.TenantID, RunID: uuid.NewString(), ExpiresAt: expiresAt}
			candidateKey := &store.AccessKey{UserID: run.UserID, TenantID: run.TenantID, Name: uuid.NewString(), KeyHash: []byte(uuid.NewString()), KeyPrefix: "dwv_eval", Scopes: []string{"vault:mcp"}, Enabled: true, ExpiresAt: &expiresAt}
			candidateConnection := connectionForOwner(ctx, t, m, candidateRun)
			test.mutate(candidateRun, candidateKey)
			if err := m.CreateMCPEvalRun(ctx, candidateRun, candidateKey, []uuid.UUID{candidateConnection.ID}); !errors.Is(err, store.ErrInvalidMCPEvalRun) {
				t.Fatalf("conflict: %v", err)
			}
		})
	}

	missingRun := *run
	missingRun.ID, missingRun.AccessKeyID, missingRun.RunID, missingRun.CreatedAt = uuid.New(), uuid.New(), uuid.NewString(), time.Time{}
	m.mcpEvalRuns[missingRun.ID] = missingRun
	if ok, err := m.RevokeMCPEvalRun(ctx, missingRun.UserID, missingRun.ID); err != nil || ok {
		t.Fatalf("missing key revoke: %v %v", ok, err)
	}
}
