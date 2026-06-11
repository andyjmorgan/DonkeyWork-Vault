package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/store"
)

// SecretPrefix is the public marker for a vault access-key secret.
const SecretPrefix = "dwv_"

// ValidScopes are the scopes an access key may carry.
var ValidScopes = map[string]bool{"vault:read": true, "vault:readwrite": true, "vault:audit": true}

// StoredAccessKey is the non-secret metadata for a scoped access key.
type StoredAccessKey struct {
	ID          uuid.UUID
	Name        string
	Description *string
	Scopes      []string
	Enabled     bool
	Prefix      string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

// AccessKeyPrincipal is the result of authenticating a presented secret.
type AccessKeyPrincipal struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	TenantID  uuid.UUID
	Scopes    []string
	Name      string
	KeyPrefix string
}

// AccessKeyService mints and resolves scoped access keys (show-once secrets).
type AccessKeyService struct {
	store store.Store
	audit *audit.Log
}

// NewAccessKeyService builds the service.
func NewAccessKeyService(s store.Store, a *audit.Log) *AccessKeyService {
	return &AccessKeyService{store: s, audit: a}
}

// Create mints a key and returns its metadata plus the plaintext secret (shown ONCE).
func (s *AccessKeyService) Create(ctx context.Context, name string, description *string, scopes []string) (*StoredAccessKey, string, error) {
	ctx, span := startSpan(ctx, "accesskey.create")
	defer span.End()
	span.SetAttributes(attribute.String("credential.name", name))

	if strings.TrimSpace(name) == "" {
		return nil, "", ValidationError{"name is required."}
	}
	normalized := normalizeScopes(scopes)
	if len(normalized) == 0 {
		return nil, "", ValidationError{"at least one scope is required."}
	}
	var invalid []string
	for _, sc := range normalized {
		if !ValidScopes[sc] {
			invalid = append(invalid, sc)
		}
	}
	if len(invalid) > 0 {
		return nil, "", ValidationError{"unknown scope(s): " + strings.Join(invalid, ", ") + "."}
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", err
	}
	secret := SecretPrefix + base64.RawURLEncoding.EncodeToString(raw)
	prefix := secret
	if len(prefix) > 9 {
		prefix = secret[:9]
	}

	caller := contracts.CallerFrom(ctx)
	entity := &store.AccessKey{
		UserID: caller.UserID, TenantID: caller.TenantID, Name: name, Description: description,
		KeyHash: hashSecret(secret), KeyPrefix: prefix, Scopes: normalized, Enabled: true,
	}
	if err := s.store.InsertAccessKey(ctx, entity); err != nil {
		return nil, "", err
	}
	s.audit.Emit(ctx, audit.EmitParams{Type: audit.EventCredentialCreated, Outcome: audit.OutcomeSuccess,
		TargetKind: "access_key", TargetName: entity.Name})

	return toStoredAccessKey(entity), secret, nil
}

// List returns the caller's access keys (newest first).
func (s *AccessKeyService) List(ctx context.Context) ([]StoredAccessKey, error) {
	ctx, span := startSpan(ctx, "accesskey.list")
	defer span.End()
	rows, err := s.store.ListAccessKeys(ctx, contracts.CallerFrom(ctx).UserID)
	if err != nil {
		return nil, err
	}
	out := make([]StoredAccessKey, len(rows))
	for i := range rows {
		out[i] = *toStoredAccessKey(&rows[i])
	}
	return out, nil
}

// SetEnabled toggles a key on/off; returns nil when no such key for the caller.
func (s *AccessKeyService) SetEnabled(ctx context.Context, id uuid.UUID, enabled bool) (*StoredAccessKey, error) {
	ctx, span := startSpan(ctx, "accesskey.set_enabled")
	defer span.End()
	entity, err := s.store.SetAccessKeyEnabled(ctx, contracts.CallerFrom(ctx).UserID, id, enabled)
	if err != nil || entity == nil {
		return nil, err
	}
	return toStoredAccessKey(entity), nil
}

// Delete removes one of the caller's keys.
func (s *AccessKeyService) Delete(ctx context.Context, id uuid.UUID) (bool, error) {
	ctx, span := startSpan(ctx, "accesskey.delete")
	defer span.End()
	return s.store.DeleteAccessKey(ctx, contracts.CallerFrom(ctx).UserID, id)
}

// Authenticate resolves a presented secret to its owner + scopes, or nil if unknown/disabled.
func (s *AccessKeyService) Authenticate(ctx context.Context, secret string) (*AccessKeyPrincipal, error) {
	ctx, span := startSpan(ctx, "accesskey.authenticate")
	defer span.End()
	if secret == "" {
		return nil, nil
	}
	entity, err := s.store.GetAccessKeyByHash(ctx, hashSecret(secret))
	if err != nil {
		return nil, err
	}
	if entity == nil || !entity.Enabled {
		return nil, nil
	}
	// last_used_at is best-effort bookkeeping — a failed touch must not reject a valid key.
	if err := s.store.TouchAccessKeyLastUsed(ctx, entity.ID); err != nil {
		slog.Warn("access key last-used touch failed", "err", err)
	}
	return &AccessKeyPrincipal{
		ID: entity.ID, UserID: entity.UserID, TenantID: entity.TenantID,
		Scopes: entity.Scopes, Name: entity.Name, KeyPrefix: entity.KeyPrefix,
	}, nil
}

func normalizeScopes(scopes []string) []string {
	var out []string
	for _, sc := range scopes {
		if strings.TrimSpace(sc) == "" {
			continue
		}
		if !slices.Contains(out, sc) {
			out = append(out, sc)
		}
	}
	return out
}

func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func toStoredAccessKey(k *store.AccessKey) *StoredAccessKey {
	return &StoredAccessKey{
		ID: k.ID, Name: k.Name, Description: k.Description, Scopes: k.Scopes,
		Enabled: k.Enabled, Prefix: k.KeyPrefix, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
	}
}
