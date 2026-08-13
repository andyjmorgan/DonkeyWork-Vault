package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Store is the persistence surface used by the domain services. It is an interface so services can
// be unit-tested against an in-memory fake, while production uses the pgx-backed Postgres impl.
type Store interface {
	// --- access keys ---
	InsertAccessKey(ctx context.Context, k *AccessKey) error
	ListAccessKeys(ctx context.Context, userID uuid.UUID) ([]AccessKey, error)
	GetAccessKeyByID(ctx context.Context, userID, id uuid.UUID) (*AccessKey, error)
	SetAccessKeyEnabled(ctx context.Context, userID, id uuid.UUID, enabled bool) (*AccessKey, error)
	DeleteAccessKey(ctx context.Context, userID, id uuid.UUID) (bool, error)
	// GetAccessKeyByHash bypasses user scoping (auth precedes knowing the caller); the hash is unique.
	GetAccessKeyByHash(ctx context.Context, hash []byte) (*AccessKey, error)
	TouchAccessKeyLastUsed(ctx context.Context, id uuid.UUID) error

	// --- api keys ---
	InsertAPIKey(ctx context.Context, k *APIKey) error
	UpdateAPIKey(ctx context.Context, k *APIKey) error
	ListAPIKeys(ctx context.Context, userID uuid.UUID) ([]APIKey, error)
	GetAPIKeyByName(ctx context.Context, userID uuid.UUID, name string) (*APIKey, error)
	GetAPIKeyByID(ctx context.Context, userID, id uuid.UUID) (*APIKey, error)
	DeleteAPIKey(ctx context.Context, userID, id uuid.UUID) (bool, error)
	TouchAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error

	// --- oauth provider configs ---
	InsertOAuthConfig(ctx context.Context, c *OAuthProviderConfig) error
	UpdateOAuthConfig(ctx context.Context, c *OAuthProviderConfig) error
	ListOAuthConfigs(ctx context.Context, userID uuid.UUID) ([]OAuthProviderConfig, error)
	GetOAuthConfigByProvider(ctx context.Context, userID, providerID uuid.UUID) (*OAuthProviderConfig, error)
	DeleteOAuthConfig(ctx context.Context, userID, id uuid.UUID) (bool, error)

	// --- oauth states ---
	InsertOAuthState(ctx context.Context, s *OAuthState) error
	GetOAuthStateByState(ctx context.Context, state string) (*OAuthState, error)
	// DeleteOAuthState returns the number of rows deleted, so a concurrent replay can be rejected.
	DeleteOAuthState(ctx context.Context, id uuid.UUID) (int64, error)

	// --- oauth tokens ---
	InsertOAuthToken(ctx context.Context, t *OAuthToken) error
	UpdateOAuthToken(ctx context.Context, t *OAuthToken) error
	ListOAuthTokens(ctx context.Context, userID uuid.UUID) ([]OAuthToken, error)
	GetOAuthTokenByID(ctx context.Context, userID, id uuid.UUID) (*OAuthToken, error)
	// FindOAuthToken resolves the newest token for a provider (optionally an account) for a user.
	FindOAuthToken(ctx context.Context, userID, providerID uuid.UUID, account string) (*OAuthToken, error)
	DeleteOAuthToken(ctx context.Context, userID, id uuid.UUID) (bool, error)

	// --- provider manifests ---
	ListOAuthManifests(ctx context.Context, userID uuid.UUID) ([]ProviderManifest, error)
	GetManifestByKey(ctx context.Context, ownerUserID uuid.UUID, kind, key string) (*ProviderManifest, error)
	InsertManifest(ctx context.Context, m *ProviderManifest) error
	UpdateManifest(ctx context.Context, m *ProviderManifest) error
	// DeleteManifestCascade removes a manifest and its provider's configs + tokens in one tx.
	DeleteManifestCascade(ctx context.Context, userID uuid.UUID, kind, key string) (bool, error)

	// --- audit ---
	InsertAuditBatch(ctx context.Context, entries []AuditEntry) error
	QueryAudit(ctx context.Context, f AuditFilter) (items []AuditEntry, total int, err error)
	DeleteAuditOlderThan(ctx context.Context, cutoff time.Time, batchSize int) (int64, error)

	// --- MCP connections ---
	InsertMCPConnection(ctx context.Context, c *MCPConnection) error
	UpdateMCPConnection(ctx context.Context, c *MCPConnection) (bool, error)
	ListMCPConnections(ctx context.Context, userID uuid.UUID) ([]MCPConnection, error)
	GetMCPConnectionByID(ctx context.Context, userID, id uuid.UUID) (*MCPConnection, error)
	GetMCPConnectionBySlug(ctx context.Context, userID uuid.UUID, slug string) (*MCPConnection, error)
	DeleteMCPConnection(ctx context.Context, userID, id uuid.UUID) (bool, error)

	// --- MCP access grants and upstream credentials ---
	InsertMCPConnectionGrant(ctx context.Context, g *MCPConnectionGrant) error
	ListMCPConnectionGrants(ctx context.Context, userID, connectionID uuid.UUID) ([]MCPConnectionGrant, error)
	// HasMCPConnectionGrant bypasses user scoping because access-key authentication supplies the
	// key ID; database ownership constraints prevent cross-owner grants from being inserted.
	HasMCPConnectionGrant(ctx context.Context, accessKeyID, connectionID uuid.UUID) (bool, error)
	DeleteMCPConnectionGrant(ctx context.Context, userID, id uuid.UUID) (bool, error)
	InsertMCPHeaderBinding(ctx context.Context, b *MCPHeaderBinding) error
	ListMCPHeaderBindings(ctx context.Context, userID, connectionID uuid.UUID) ([]MCPHeaderBinding, error)
	DeleteMCPHeaderBinding(ctx context.Context, userID, id uuid.UUID) (bool, error)

	// --- MCP policies ---
	UpsertMCPToolPolicy(ctx context.Context, p *MCPToolPolicy) error
	ListMCPToolPolicies(ctx context.Context, userID, connectionID uuid.UUID) ([]MCPToolPolicy, error)
	DeleteMCPToolPolicy(ctx context.Context, userID, id uuid.UUID) (bool, error)

	// --- MCP upstream OAuth ---
	InsertMCPOAuthAuthorization(ctx context.Context, a *MCPOAuthAuthorization) error
	UpdateMCPOAuthAuthorization(ctx context.Context, a *MCPOAuthAuthorization) (bool, error)
	GetMCPOAuthAuthorization(ctx context.Context, userID, connectionID uuid.UUID) (*MCPOAuthAuthorization, error)
	DeleteMCPOAuthAuthorization(ctx context.Context, userID, connectionID uuid.UUID) (bool, error)
	InsertMCPOAuthState(ctx context.Context, s *MCPOAuthState) error
	// ClaimMCPOAuthState atomically consumes a state so concurrent callback replays cannot succeed.
	ClaimMCPOAuthState(ctx context.Context, state string) (*MCPOAuthState, error)

	// --- MCP message audit ---
	InsertMCPAuditExchange(ctx context.Context, e *MCPAuditExchange) error
	CompleteMCPAuditExchange(ctx context.Context, e *MCPAuditExchange) (bool, error)
	InsertMCPAuditMessage(ctx context.Context, m *MCPAuditMessage) error
	QueryMCPAudit(ctx context.Context, f MCPAuditFilter) (items []MCPAuditMessage, total int, err error)
}
