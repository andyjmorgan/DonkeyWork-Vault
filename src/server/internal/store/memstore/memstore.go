// Package memstore is an in-memory implementation of store.Store. It backs unit tests across the
// service and HTTP layers (no Postgres required) and is handy for local experimentation. It applies
// the same explicit per-user scoping the SQL store does, so tests exercise the real authorization
// behaviour.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

// Mem is a goroutine-safe in-memory Store.
type Mem struct {
	mu        sync.Mutex
	accessKeys map[uuid.UUID]store.AccessKey
	apiKeys    map[uuid.UUID]store.APIKey
	configs    map[uuid.UUID]store.OAuthProviderConfig
	states     map[uuid.UUID]store.OAuthState
	tokens     map[uuid.UUID]store.OAuthToken
	manifests  map[uuid.UUID]store.ProviderManifest
	audit      []store.AuditEntry

	// FailNext, when non-nil, makes the next call to any method return it (for error-path tests).
	FailNext error
}

// New builds an empty store.
func New() *Mem {
	return &Mem{
		accessKeys: map[uuid.UUID]store.AccessKey{},
		apiKeys:    map[uuid.UUID]store.APIKey{},
		configs:    map[uuid.UUID]store.OAuthProviderConfig{},
		states:     map[uuid.UUID]store.OAuthState{},
		tokens:     map[uuid.UUID]store.OAuthToken{},
		manifests:  map[uuid.UUID]store.ProviderManifest{},
	}
}

func (m *Mem) fail() error {
	if m.FailNext != nil {
		err := m.FailNext
		m.FailNext = nil
		return err
	}
	return nil
}

var _ store.Store = (*Mem)(nil)

// ---- access keys ----

func (m *Mem) InsertAccessKey(_ context.Context, k *store.AccessKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	m.accessKeys[k.ID] = *k
	return nil
}

func (m *Mem) ListAccessKeys(_ context.Context, userID uuid.UUID) ([]store.AccessKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.AccessKey
	for _, k := range m.accessKeys {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Mem) GetAccessKeyByID(_ context.Context, userID, id uuid.UUID) (*store.AccessKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	if k, ok := m.accessKeys[id]; ok && k.UserID == userID {
		return &k, nil
	}
	return nil, nil
}

func (m *Mem) SetAccessKeyEnabled(_ context.Context, userID, id uuid.UUID, enabled bool) (*store.AccessKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	k, ok := m.accessKeys[id]
	if !ok || k.UserID != userID {
		return nil, nil
	}
	k.Enabled = enabled
	now := time.Now().UTC()
	k.UpdatedAt = &now
	m.accessKeys[id] = k
	return &k, nil
}

func (m *Mem) DeleteAccessKey(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if k, ok := m.accessKeys[id]; ok && k.UserID == userID {
		delete(m.accessKeys, id)
		return true, nil
	}
	return false, nil
}

func (m *Mem) GetAccessKeyByHash(_ context.Context, hash []byte) (*store.AccessKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, k := range m.accessKeys {
		if string(k.KeyHash) == string(hash) {
			return &k, nil
		}
	}
	return nil, nil
}

func (m *Mem) TouchAccessKeyLastUsed(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if k, ok := m.accessKeys[id]; ok {
		now := time.Now().UTC()
		k.LastUsedAt = &now
		m.accessKeys[id] = k
	}
	return nil
}

// ---- api keys ----

func (m *Mem) InsertAPIKey(_ context.Context, k *store.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	m.apiKeys[k.ID] = *k
	return nil
}

func (m *Mem) UpdateAPIKey(_ context.Context, k *store.APIKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if existing, ok := m.apiKeys[k.ID]; ok && existing.UserID == k.UserID {
		m.apiKeys[k.ID] = *k
	}
	return nil
}

func (m *Mem) ListAPIKeys(_ context.Context, userID uuid.UUID) ([]store.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.APIKey
	for _, k := range m.apiKeys {
		if k.UserID == userID {
			out = append(out, k)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *Mem) GetAPIKeyByName(_ context.Context, userID uuid.UUID, name string) (*store.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, k := range m.apiKeys {
		if k.UserID == userID && k.Name == name {
			return &k, nil
		}
	}
	return nil, nil
}

func (m *Mem) DeleteAPIKey(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if k, ok := m.apiKeys[id]; ok && k.UserID == userID {
		delete(m.apiKeys, id)
		return true, nil
	}
	return false, nil
}

func (m *Mem) TouchAPIKeyLastUsed(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if k, ok := m.apiKeys[id]; ok {
		now := time.Now().UTC()
		k.LastUsedAt = &now
		m.apiKeys[id] = k
	}
	return nil
}

// ---- oauth configs ----

func (m *Mem) InsertOAuthConfig(_ context.Context, c *store.OAuthProviderConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	m.configs[c.ID] = *c
	return nil
}

func (m *Mem) UpdateOAuthConfig(_ context.Context, c *store.OAuthProviderConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if existing, ok := m.configs[c.ID]; ok && existing.UserID == c.UserID {
		m.configs[c.ID] = *c
	}
	return nil
}

func (m *Mem) ListOAuthConfigs(_ context.Context, userID uuid.UUID) ([]store.OAuthProviderConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.OAuthProviderConfig
	for _, c := range m.configs {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProviderKey < out[j].ProviderKey })
	return out, nil
}

func (m *Mem) GetOAuthConfigByProvider(_ context.Context, userID, providerID uuid.UUID) (*store.OAuthProviderConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, c := range m.configs {
		if c.UserID == userID && c.ProviderID == providerID {
			return &c, nil
		}
	}
	return nil, nil
}

func (m *Mem) DeleteOAuthConfig(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if c, ok := m.configs[id]; ok && c.UserID == userID {
		delete(m.configs, id)
		return true, nil
	}
	return false, nil
}

// ---- oauth states ----

func (m *Mem) InsertOAuthState(_ context.Context, s *store.OAuthState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now().UTC()
	}
	m.states[s.ID] = *s
	return nil
}

func (m *Mem) GetOAuthStateByState(_ context.Context, state string) (*store.OAuthState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, s := range m.states {
		if s.State == state {
			return &s, nil
		}
	}
	return nil, nil
}

func (m *Mem) DeleteOAuthState(_ context.Context, id uuid.UUID) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return 0, err
	}
	if _, ok := m.states[id]; ok {
		delete(m.states, id)
		return 1, nil
	}
	return 0, nil
}

// ---- oauth tokens ----

func (m *Mem) InsertOAuthToken(_ context.Context, t *store.OAuthToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	m.tokens[t.ID] = *t
	return nil
}

func (m *Mem) UpdateOAuthToken(_ context.Context, t *store.OAuthToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if _, ok := m.tokens[t.ID]; ok {
		m.tokens[t.ID] = *t
	}
	return nil
}

func (m *Mem) ListOAuthTokens(_ context.Context, userID uuid.UUID) ([]store.OAuthToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.OAuthToken
	for _, t := range m.tokens {
		if t.UserID == userID {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProviderKey < out[j].ProviderKey })
	return out, nil
}

func (m *Mem) GetOAuthTokenByID(_ context.Context, userID, id uuid.UUID) (*store.OAuthToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	if t, ok := m.tokens[id]; ok && t.UserID == userID {
		return &t, nil
	}
	return nil, nil
}

func (m *Mem) FindOAuthToken(_ context.Context, userID, providerID uuid.UUID, account string) (*store.OAuthToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var found *store.OAuthToken
	for _, t := range m.tokens {
		if t.UserID != userID || t.ProviderID != providerID {
			continue
		}
		if account != "" && t.Account != account {
			continue
		}
		tt := t
		if found == nil || tt.CreatedAt.After(found.CreatedAt) {
			found = &tt
		}
	}
	return found, nil
}

func (m *Mem) DeleteOAuthToken(_ context.Context, userID, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	if t, ok := m.tokens[id]; ok && t.UserID == userID {
		delete(m.tokens, id)
		return true, nil
	}
	return false, nil
}

// ---- manifests ----

func (m *Mem) ListOAuthManifests(_ context.Context, userID uuid.UUID) ([]store.ProviderManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	var out []store.ProviderManifest
	for _, r := range m.manifests {
		if r.Kind == "oauth" && r.UserID == userID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *Mem) GetManifestByKey(_ context.Context, ownerUserID uuid.UUID, kind, key string) (*store.ProviderManifest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, err
	}
	for _, r := range m.manifests {
		if r.Kind == kind && r.Key == key && r.UserID == ownerUserID {
			return &r, nil
		}
	}
	return nil, nil
}

func (m *Mem) InsertManifest(_ context.Context, r *store.ProviderManifest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	m.manifests[r.ID] = *r
	return nil
}

func (m *Mem) UpdateManifest(_ context.Context, r *store.ProviderManifest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	if existing, ok := m.manifests[r.ID]; ok && existing.UserID == r.UserID {
		m.manifests[r.ID] = *r
	}
	return nil
}

func (m *Mem) DeleteManifestCascade(_ context.Context, userID uuid.UUID, kind, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return false, err
	}
	var target *store.ProviderManifest
	for _, r := range m.manifests {
		if r.Kind == kind && r.Key == key && r.UserID == userID {
			rr := r
			target = &rr
			break
		}
	}
	if target == nil {
		return false, nil
	}
	if kind == "oauth" {
		for id, c := range m.configs {
			if c.ProviderID == target.ProviderID {
				delete(m.configs, id)
			}
		}
		for id, t := range m.tokens {
			if t.ProviderID == target.ProviderID {
				delete(m.tokens, id)
			}
		}
	}
	delete(m.manifests, target.ID)
	return true, nil
}

// ---- audit ----

func (m *Mem) InsertAuditBatch(_ context.Context, entries []store.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	for _, e := range entries {
		if e.ID == uuid.Nil {
			e.ID = uuid.New()
		}
		m.audit = append(m.audit, e)
	}
	return nil
}

func (m *Mem) QueryAudit(_ context.Context, f store.AuditFilter) ([]store.AuditEntry, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return nil, 0, err
	}
	var matched []store.AuditEntry
	for _, e := range m.audit {
		if e.UserID != f.UserID || e.TenantID != f.TenantID {
			continue
		}
		if f.EventType != nil && e.EventType != *f.EventType {
			continue
		}
		if f.Outcome != nil && e.Outcome != *f.Outcome {
			continue
		}
		if f.Since != nil && e.CreatedAt.Before(*f.Since) {
			continue
		}
		if f.Until != nil && !e.CreatedAt.Before(*f.Until) {
			continue
		}
		matched = append(matched, e)
	}
	sort.Slice(matched, func(i, j int) bool { return matched[i].CreatedAt.After(matched[j].CreatedAt) })
	total := len(matched)
	lo := f.Offset
	if lo > total {
		lo = total
	}
	hi := lo + f.Limit
	if hi > total {
		hi = total
	}
	return matched[lo:hi], total, nil
}

func (m *Mem) DeleteAuditOlderThan(_ context.Context, cutoff time.Time, batchSize int) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return 0, err
	}
	var kept []store.AuditEntry
	var deleted int64
	for _, e := range m.audit {
		if e.CreatedAt.Before(cutoff) && deleted < int64(batchSize) {
			deleted++
			continue
		}
		kept = append(kept, e)
	}
	m.audit = kept
	return deleted, nil
}

// AuditCount returns the number of stored audit rows (test helper).
func (m *Mem) AuditCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.audit)
}
