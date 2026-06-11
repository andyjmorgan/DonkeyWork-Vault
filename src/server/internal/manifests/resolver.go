package manifests

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
)

const oauthKind = "oauth"

var slugRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ErrInvalidSlug is returned when a provider slug is empty or contains disallowed characters.
type ErrInvalidSlug struct{ Slug string }

func (e ErrInvalidSlug) Error() string {
	return fmt.Sprintf("provider slug %q must be non-empty and match [a-zA-Z0-9_-]", e.Slug)
}

// Resolver resolves OAuth providers from the caller's DB rows (the embedded YAML is a template
// library, never a resolution fallback).
type Resolver struct {
	store  store.Store
	loader *Loader
}

// NewResolver builds a resolver over the store and the embedded catalog.
func NewResolver(s store.Store, l *Loader) *Resolver { return &Resolver{store: s, loader: l} }

// ListTemplates returns the embedded library of templates available to add.
func (r *Resolver) ListTemplates() []Manifest { return r.loader.All() }

// ListOAuth returns the caller's added providers (DB rows), ordered by key.
func (r *Resolver) ListOAuth(ctx context.Context) ([]Manifest, error) {
	caller := contracts.CallerFrom(ctx)
	rows, err := r.store.ListOAuthManifests(ctx, caller.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]Manifest, 0, len(rows))
	for i := range rows {
		m, err := materialize(&rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// GetOAuth resolves an added provider by slug for a specific owning user (DB row only).
func (r *Resolver) GetOAuth(ctx context.Context, key string, userID uuid.UUID) (*Manifest, error) {
	row, err := r.store.GetManifestByKey(ctx, userID, oauthKind, key)
	if err != nil || row == nil {
		return nil, err
	}
	return materialize(row)
}

// ResolveProviderID returns the stable provider id for an added slug owned by userID, or uuid.Nil.
func (r *Resolver) ResolveProviderID(ctx context.Context, key string, userID uuid.UUID) (uuid.UUID, error) {
	row, err := r.store.GetManifestByKey(ctx, userID, oauthKind, key)
	if err != nil || row == nil {
		return uuid.Nil, err
	}
	return row.ProviderID, nil
}

// UpsertOAuth adds or edits one of the caller's providers. The row keeps its stable provider id
// across edits, and its parent_id breadcrumb is set on first add.
func (r *Resolver) UpsertOAuth(ctx context.Context, m Manifest) error {
	if m.Key == "" || !slugRe.MatchString(m.Key) {
		return ErrInvalidSlug{Slug: m.Key}
	}
	caller := contracts.CallerFrom(ctx)
	row, err := r.store.GetManifestByKey(ctx, caller.UserID, oauthKind, m.Key)
	if err != nil {
		return err
	}

	providerID := uuid.New()
	parentID := m.ParentID
	if row != nil {
		if row.ProviderID != uuid.Nil {
			providerID = row.ProviderID
		}
		if row.ParentID != uuid.Nil {
			parentID = row.ParentID
		}
	}
	m.ID = providerID
	m.ParentID = parentID
	doc, err := json.Marshal(m)
	if err != nil {
		return err
	}

	if row == nil {
		return r.store.InsertManifest(ctx, &store.ProviderManifest{
			UserID:       caller.UserID,
			TenantID:     caller.TenantID,
			Kind:         oauthKind,
			Key:          m.Key,
			ProviderID:   providerID,
			ParentID:     parentID,
			DocumentJSON: string(doc),
		})
	}
	row.ProviderID = providerID
	row.ParentID = parentID
	row.DocumentJSON = string(doc)
	now := time.Now().UTC()
	row.UpdatedAt = &now
	return r.store.UpdateManifest(ctx, row)
}

// Delete removes one of the caller's providers and cascades its configs + tokens.
func (r *Resolver) Delete(ctx context.Context, kind, key string) (bool, error) {
	caller := contracts.CallerFrom(ctx)
	return r.store.DeleteManifestCascade(ctx, caller.UserID, kind, key)
}

// materialize reconstructs a Manifest from a stored row, stamping id/parent/slug from the row.
func materialize(row *store.ProviderManifest) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal([]byte(row.DocumentJSON), &m); err != nil {
		return nil, fmt.Errorf("materialize manifest %q: %w", row.Key, err)
	}
	m.ID = row.ProviderID
	m.ParentID = row.ParentID
	m.Key = row.Key
	if m.ScopeDelimiter == "" {
		m.ScopeDelimiter = " "
	}
	return &m, nil
}
