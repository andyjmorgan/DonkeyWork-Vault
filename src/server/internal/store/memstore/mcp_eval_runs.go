package memstore

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

// CreateMCPEvalRun atomically creates an access key, run and connection grants.
func (m *Mem) CreateMCPEvalRun(_ context.Context, run *store.MCPEvalRun, key *store.AccessKey, connectionIDs []uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := store.ValidateMCPEvalRunCreation(run, key, connectionIDs, now); err != nil {
		return err
	}
	for _, connectionID := range connectionIDs {
		connection, ok := m.mcpConnections[connectionID]
		if !ok || connection.UserID != run.UserID || connection.TenantID != run.TenantID || !connection.Enabled {
			return store.ErrOwnershipMismatch
		}
	}
	for _, existing := range m.accessKeys {
		if string(existing.KeyHash) == string(key.KeyHash) || existing.UserID == key.UserID && existing.Name == key.Name {
			return store.ErrInvalidMCPEvalRun
		}
	}
	for _, existing := range m.mcpEvalRuns {
		if existing.UserID == run.UserID && existing.RunID == run.RunID {
			return store.ErrInvalidMCPEvalRun
		}
	}
	if key.ID != uuid.Nil {
		if _, exists := m.accessKeys[key.ID]; exists {
			return store.ErrInvalidMCPEvalRun
		}
	}
	if run.ID != uuid.Nil {
		if _, exists := m.mcpEvalRuns[run.ID]; exists {
			return store.ErrInvalidMCPEvalRun
		}
	}

	setIdentity(&key.ID, &key.CreatedAt)
	setIdentity(&run.ID, &run.CreatedAt)
	run.AccessKeyID = key.ID
	m.accessKeys[key.ID] = *key
	m.mcpEvalRuns[run.ID] = *run
	for _, connectionID := range connectionIDs {
		grant := store.MCPConnectionGrant{
			ID:           uuid.New(),
			UserID:       run.UserID,
			TenantID:     run.TenantID,
			ConnectionID: connectionID,
			AccessKeyID:  key.ID,
			CreatedAt:    now,
		}
		m.mcpGrants[grant.ID] = grant
	}
	return nil
}

// ListMCPEvalRuns returns an owner's eval runs, newest first.
func (m *Mem) ListMCPEvalRuns(_ context.Context, userID uuid.UUID) ([]store.MCPEvalRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.MCPEvalRun
	for _, run := range m.mcpEvalRuns {
		if run.UserID == userID {
			out = append(out, run)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// GetMCPEvalRunByAccessKey returns the run owning an authenticated access key.
func (m *Mem) GetMCPEvalRunByAccessKey(_ context.Context, accessKeyID uuid.UUID) (*store.MCPEvalRun, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, run := range m.mcpEvalRuns {
		if run.AccessKeyID == accessKeyID {
			return &run, nil
		}
	}
	return nil, nil
}

// RevokeMCPEvalRun revokes an owner-scoped run and disables its access key atomically.
func (m *Mem) RevokeMCPEvalRun(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	run, ok := m.mcpEvalRuns[id]
	if !ok || run.UserID != userID || run.RevokedAt != nil {
		return false, nil
	}
	key, ok := m.accessKeys[run.AccessKeyID]
	if !ok {
		return false, nil
	}
	now := time.Now().UTC()
	run.RevokedAt = &now
	key.Enabled = false
	key.UpdatedAt = &now
	m.mcpEvalRuns[id] = run
	m.accessKeys[key.ID] = key
	return true, nil
}
