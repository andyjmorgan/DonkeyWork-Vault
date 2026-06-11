package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/store"
)

// StoredAPIKey is the non-secret, self-describing view of a stored API key.
type StoredAPIKey struct {
	ID          uuid.UUID
	Name        string
	Description *string
	BaseURL     *string
	DocsURL     *string
	Header      *string
	Prefix      *string
	Username    *string
	Kind        contracts.CredentialKind
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

// APIKeySecret is the revealed secret plus the metadata needed to use it.
type APIKeySecret struct {
	Secret      string
	Header      *string
	Prefix      *string
	Username    *string
	Kind        contracts.CredentialKind
	BaseURL     *string
	DocsURL     *string
	Description *string
}

// CreateAPIKeyParams mirrors the create/edit request; optional fields are nil when omitted.
type CreateAPIKeyParams struct {
	Name        string
	Secret      *string
	Description *string
	BaseURL     *string
	DocsURL     *string
	Header      *string
	Prefix      *string
	Username    *string
	Kind        contracts.CredentialKind
}

// APIKeyService manages self-describing API-key credentials.
type APIKeyService struct {
	store  store.Store
	cipher crypto.Cipher
	audit  *audit.Log
}

// NewAPIKeyService builds the service.
func NewAPIKeyService(s store.Store, c crypto.Cipher, a *audit.Log) *APIKeyService {
	return &APIKeyService{store: s, cipher: c, audit: a}
}

// Create inserts a new credential or edits an existing one of the same name. A blank secret on edit
// keeps the stored secret. Only a create emits a CredentialCreated audit event.
func (s *APIKeyService) Create(ctx context.Context, p CreateAPIKeyParams) (*StoredAPIKey, error) {
	ctx, span := startSpan(ctx, "apikey.create")
	defer span.End()
	span.SetAttributes(attribute.String("credential.name", p.Name))

	if strings.TrimSpace(p.Name) == "" {
		return nil, ValidationError{"name is required."}
	}
	secret := deref(p.Secret)

	// username present ⇒ HTTP Basic; the username must not contain ':' (it delimits Basic creds).
	username := strings.TrimSpace(deref(p.Username))
	var usernamePtr *string
	if username != "" {
		if strings.Contains(username, ":") {
			return nil, ValidationError{"username must not contain ':' (it delimits Basic credentials)."}
		}
		usernamePtr = &username
	}

	caller := contracts.CallerFrom(ctx)
	existing, err := s.store.GetAPIKeyByName(ctx, caller.UserID, p.Name)
	if err != nil {
		return nil, err
	}
	isNew := existing == nil
	if isNew {
		if secret == "" {
			return nil, ValidationError{"secret is required."}
		}
		existing = &store.APIKey{UserID: caller.UserID, TenantID: caller.TenantID, ProviderKey: "", Name: p.Name, Kind: string(contracts.KindOpaque)}
	}

	// Basic requires both halves; on edit a blank secret keeps the stored password.
	if usernamePtr != nil && secret == "" && (isNew || len(existing.FieldsCipher) == 0) {
		return nil, ValidationError{"Basic auth requires a password (secret) alongside the username."}
	}

	existing.Description = p.Description
	existing.BaseURL = p.BaseURL
	existing.DocsURL = p.DocsURL
	existing.Username = usernamePtr
	existing.Kind = string(contracts.CredentialKindFromWire(string(p.Kind)))

	header := strings.TrimSpace(deref(p.Header))
	if usernamePtr != nil {
		// For Basic, default the header to Authorization so list/shape read sensibly.
		hn := "Authorization"
		if header != "" {
			hn = header
		}
		existing.HeaderName = &hn
		existing.Prefix = nil
	} else {
		existing.HeaderName = ptrIfNotEmpty(header)
		existing.Prefix = p.Prefix
	}

	if secret != "" { // blank on edit keeps the existing secret
		blob, err := s.cipher.EncryptString(secret)
		if err != nil {
			return nil, err
		}
		existing.FieldsCipher = blob
	}

	if isNew {
		if err := s.store.InsertAPIKey(ctx, existing); err != nil {
			return nil, err
		}
		s.audit.Emit(ctx, audit.EmitParams{Type: audit.EventCredentialCreated, Outcome: audit.OutcomeSuccess,
			TargetKind: "api_key", TargetName: existing.Name})
	} else if err := s.store.UpdateAPIKey(ctx, existing); err != nil {
		return nil, err
	}

	return toStoredAPIKey(existing), nil
}

// List returns the caller's API keys (newest first).
func (s *APIKeyService) List(ctx context.Context) ([]StoredAPIKey, error) {
	ctx, span := startSpan(ctx, "apikey.list")
	defer span.End()
	rows, err := s.store.ListAPIKeys(ctx, contracts.CallerFrom(ctx).UserID)
	if err != nil {
		return nil, err
	}
	out := make([]StoredAPIKey, len(rows))
	for i := range rows {
		out[i] = *toStoredAPIKey(&rows[i])
	}
	return out, nil
}

// GetByName reveals the secret for a credential, recording the access (success or not-found failure).
func (s *APIKeyService) GetByName(ctx context.Context, name string) (*APIKeySecret, error) {
	ctx, span := startSpan(ctx, "apikey.reveal")
	defer span.End()
	span.SetAttributes(attribute.String("credential.name", name))

	caller := contracts.CallerFrom(ctx)
	entity, err := s.store.GetAPIKeyByName(ctx, caller.UserID, name)
	if err != nil {
		return nil, err
	}
	if entity == nil {
		s.audit.Emit(ctx, audit.EmitParams{Type: audit.EventTokenAccessed, Outcome: audit.OutcomeFailure,
			TargetKind: "api_key", TargetName: name, Detail: "credential not found"})
		return nil, nil
	}
	secret, err := s.cipher.DecryptToString(entity.FieldsCipher)
	if err != nil {
		return nil, err
	}
	if err := s.store.TouchAPIKeyLastUsed(ctx, entity.ID); err != nil {
		return nil, err
	}
	s.audit.Emit(ctx, audit.EmitParams{Type: audit.EventTokenAccessed, Outcome: audit.OutcomeSuccess,
		TargetKind: "api_key", TargetName: entity.Name})

	return &APIKeySecret{
		Secret: secret, Header: entity.HeaderName, Prefix: entity.Prefix, Username: entity.Username,
		Kind: contracts.CredentialKindFromWire(entity.Kind), BaseURL: entity.BaseURL, DocsURL: entity.DocsURL, Description: entity.Description,
	}, nil
}

// Delete removes one of the caller's credentials.
func (s *APIKeyService) Delete(ctx context.Context, id uuid.UUID) (bool, error) {
	ctx, span := startSpan(ctx, "apikey.delete")
	defer span.End()
	return s.store.DeleteAPIKey(ctx, contracts.CallerFrom(ctx).UserID, id)
}

func toStoredAPIKey(k *store.APIKey) *StoredAPIKey {
	return &StoredAPIKey{
		ID: k.ID, Name: k.Name, Description: k.Description, BaseURL: k.BaseURL, DocsURL: k.DocsURL,
		Header: k.HeaderName, Prefix: k.Prefix, Username: k.Username,
		Kind: contracts.CredentialKindFromWire(k.Kind), CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
	}
}
