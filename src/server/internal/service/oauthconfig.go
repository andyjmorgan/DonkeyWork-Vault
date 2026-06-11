package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"

	"donkeywork.dev/vault-server/internal/audit"
	"donkeywork.dev/vault-server/internal/contracts"
	"donkeywork.dev/vault-server/internal/crypto"
	"donkeywork.dev/vault-server/internal/manifests"
	"donkeywork.dev/vault-server/internal/store"
)

// OAuthConfigSummary is the non-secret view of a stored provider app config.
type OAuthConfigSummary struct {
	ID             uuid.UUID
	Provider       string
	ClientIDMasked string
	Scopes         []string
	RedirectURI    *string
	CreatedAt      time.Time
}

// OAuthConfigService manages per-user OAuth app credentials (client id/secret are envelope-encrypted).
type OAuthConfigService struct {
	store    store.Store
	cipher   crypto.Cipher
	audit    *audit.Log
	resolver *manifests.Resolver
}

// NewOAuthConfigService builds the service.
func NewOAuthConfigService(s store.Store, c crypto.Cipher, a *audit.Log, r *manifests.Resolver) *OAuthConfigService {
	return &OAuthConfigService{store: s, cipher: c, audit: a, resolver: r}
}

// List returns the caller's configs with the client id masked.
func (s *OAuthConfigService) List(ctx context.Context) ([]OAuthConfigSummary, error) {
	ctx, span := startSpan(ctx, "oauthconfig.list")
	defer span.End()
	rows, err := s.store.ListOAuthConfigs(ctx, contracts.CallerFrom(ctx).UserID)
	if err != nil {
		return nil, err
	}
	out := make([]OAuthConfigSummary, 0, len(rows))
	for i := range rows {
		clientID, err := s.cipher.DecryptToString(rows[i].ClientIDCipher)
		if err != nil {
			return nil, err
		}
		out = append(out, OAuthConfigSummary{
			ID: rows[i].ID, Provider: rows[i].ProviderKey, ClientIDMasked: mask(clientID),
			Scopes: decodeScopes(rows[i].ScopesJSON), RedirectURI: rows[i].RedirectURI, CreatedAt: rows[i].CreatedAt,
		})
	}
	return out, nil
}

// Upsert adds or edits the config for a provider, keyed by its stable provider identity.
func (s *OAuthConfigService) Upsert(ctx context.Context, provider, clientID string, clientSecret *string, scopes []string, redirectURI *string) (uuid.UUID, error) {
	ctx, span := startSpan(ctx, "oauthconfig.upsert")
	defer span.End()
	span.SetAttributes(attribute.String("oauth.provider", provider))

	caller := contracts.CallerFrom(ctx)
	providerID, err := s.resolver.ResolveProviderID(ctx, provider, caller.UserID)
	if err != nil {
		return uuid.Nil, err
	}
	if providerID == uuid.Nil {
		return uuid.Nil, ValidationError{"unknown provider '" + provider + "'. Save the provider first."}
	}

	row, err := s.store.GetOAuthConfigByProvider(ctx, caller.UserID, providerID)
	if err != nil {
		return uuid.Nil, err
	}
	scopesJSON := encodeScopes(scopes)
	clientIDBlob, err := s.cipher.EncryptString(clientID)
	if err != nil {
		return uuid.Nil, err
	}

	if row == nil {
		if deref(clientSecret) == "" {
			return uuid.Nil, ValidationError{"client secret is required when creating a provider config."}
		}
		secretBlob, err := s.cipher.EncryptString(*clientSecret)
		if err != nil {
			return uuid.Nil, err
		}
		row = &store.OAuthProviderConfig{
			UserID: caller.UserID, TenantID: caller.TenantID, ProviderID: providerID, ProviderKey: provider,
			ClientIDCipher: clientIDBlob, ClientSecretCipher: secretBlob, ScopesJSON: &scopesJSON, RedirectURI: redirectURI,
		}
		if err := s.store.InsertOAuthConfig(ctx, row); err != nil {
			return uuid.Nil, err
		}
		s.audit.Emit(ctx, audit.EmitParams{Type: audit.EventCredentialCreated, Outcome: audit.OutcomeSuccess,
			TargetKind: "provider_config", TargetProvider: provider, TargetName: provider})
		return row.ID, nil
	}

	row.ProviderKey = provider
	row.ClientIDCipher = clientIDBlob
	if deref(clientSecret) != "" {
		secretBlob, err := s.cipher.EncryptString(*clientSecret)
		if err != nil {
			return uuid.Nil, err
		}
		row.ClientSecretCipher = secretBlob
	}
	row.ScopesJSON = &scopesJSON
	row.RedirectURI = redirectURI
	if err := s.store.UpdateOAuthConfig(ctx, row); err != nil {
		return uuid.Nil, err
	}
	return row.ID, nil
}

// Delete removes one of the caller's configs.
func (s *OAuthConfigService) Delete(ctx context.Context, id uuid.UUID) (bool, error) {
	ctx, span := startSpan(ctx, "oauthconfig.delete")
	defer span.End()
	return s.store.DeleteOAuthConfig(ctx, contracts.CallerFrom(ctx).UserID, id)
}

func mask(s string) string {
	if len([]rune(s)) <= 10 {
		return "***"
	}
	r := []rune(s)
	return string(r[:6]) + "…" + string(r[len(r)-4:])
}

func encodeScopes(scopes []string) string {
	if scopes == nil {
		scopes = []string{}
	}
	b, _ := json.Marshal(scopes)
	return string(b)
}

func decodeScopes(j *string) []string {
	if j == nil || *j == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(*j), &out); err != nil {
		return []string{}
	}
	return out
}
