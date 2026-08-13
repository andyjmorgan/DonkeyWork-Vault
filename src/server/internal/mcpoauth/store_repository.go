package mcpoauth

import (
	"context"
	"errors"
	"slices"

	"github.com/google/uuid"

	"donkeywork.dev/vault-server/internal/store"
)

// StoreRepository adapts the server Store to the MCP OAuth persistence boundary.
type StoreRepository struct {
	store store.Store
}

// NewStoreRepository constructs a Store-backed MCP OAuth repository.
func NewStoreRepository(s store.Store) *StoreRepository { return &StoreRepository{store: s} }

// WithRefreshLock serializes the callback for a connection across all server replicas.
func (r *StoreRepository) WithRefreshLock(ctx context.Context, connectionID uuid.UUID, fn func() error) error {
	return r.store.WithMCPOAuthRefreshLock(ctx, connectionID, fn)
}

// DeleteAuthorization removes an owner-scoped OAuth client configuration and token set.
func (r *StoreRepository) DeleteAuthorization(ctx context.Context, userID, connectionID uuid.UUID) (bool, error) {
	return r.store.DeleteMCPOAuthAuthorization(ctx, userID, connectionID)
}

// GetStatus returns a secret-free owner-scoped OAuth projection. An existing connection without an
// OAuth row is represented as unconfigured rather than being indistinguishable from a missing row.
func (r *StoreRepository) GetStatus(ctx context.Context, userID, connectionID uuid.UUID) (*Status, error) {
	connection, err := r.store.GetMCPConnectionByID(ctx, userID, connectionID)
	if err != nil || connection == nil {
		return nil, err
	}
	row, err := r.store.GetMCPOAuthAuthorization(ctx, userID, connectionID)
	if err != nil {
		return nil, err
	}
	status := &Status{ConnectionID: connectionID}
	if row == nil {
		return status, nil
	}
	status.Configured = len(row.ClientIDCipher) > 0
	status.Authorized = len(row.AccessTokenCipher) > 0
	status.Issuer = dereference(row.IssuerURL)
	status.Resource = dereference(row.Resource)
	if status.Resource == "" {
		status.Resource = connection.UpstreamURL
	}
	status.Scopes = slices.Clone(row.Scopes)
	status.ExpiresAt = row.ExpiresAt
	status.LastRefreshedAt = row.LastRefreshedAt
	return status, nil
}

// SaveClientConfiguration creates or replaces the encrypted OAuth client registration while
// clearing tokens minted under the previous registration.
func (r *StoreRepository) SaveClientConfiguration(ctx context.Context, configuration *ClientConfiguration) error {
	connection, err := r.store.GetMCPConnectionByID(ctx, configuration.UserID, configuration.ConnectionID)
	if err != nil {
		return err
	}
	if connection == nil || connection.TenantID != configuration.TenantID {
		return errors.New("MCP connection not found")
	}
	row, err := r.store.GetMCPOAuthAuthorization(ctx, configuration.UserID, configuration.ConnectionID)
	if err != nil {
		return err
	}
	issuer := configuration.Issuer
	if row == nil {
		return r.store.InsertMCPOAuthAuthorization(ctx, &store.MCPOAuthAuthorization{
			UserID: configuration.UserID, TenantID: configuration.TenantID, ConnectionID: configuration.ConnectionID,
			IssuerURL: &issuer, TokenAuthMethod: "none", ClientIDCipher: configuration.ClientIDCipher,
			ClientSecretCipher: configuration.ClientSecretCipher, Scopes: configuration.Scopes,
		})
	}
	row.IssuerURL = &issuer
	row.AuthorizationEndpoint, row.TokenEndpoint, row.Resource, row.TokenType = nil, nil, nil, nil
	row.TokenAuthMethod = "none"
	row.ClientIDCipher, row.ClientSecretCipher = configuration.ClientIDCipher, configuration.ClientSecretCipher
	row.AccessTokenCipher, row.RefreshTokenCipher = nil, nil
	row.Scopes, row.ExpiresAt, row.LastRefreshedAt = configuration.Scopes, nil, nil
	updated, err := r.store.UpdateMCPOAuthAuthorization(ctx, row)
	if err != nil {
		return err
	}
	if !updated {
		return errors.New("MCP OAuth client configuration no longer exists")
	}
	return nil
}

// GetConnectionOAuth resolves the owner-scoped connection and its OAuth client configuration.
func (r *StoreRepository) GetConnectionOAuth(ctx context.Context, userID, connectionID uuid.UUID) (*ConnectionOAuth, error) {
	connection, err := r.store.GetMCPConnectionByID(ctx, userID, connectionID)
	if err != nil || connection == nil {
		return nil, err
	}
	authorization, err := r.store.GetMCPOAuthAuthorization(ctx, userID, connectionID)
	if err != nil || authorization == nil {
		return nil, err
	}
	issuer := dereference(authorization.IssuerURL)
	resource := dereference(authorization.Resource)
	if resource == "" {
		resource = connection.UpstreamURL
	}
	return &ConnectionOAuth{
		ConnectionID: connection.ID, UserID: connection.UserID, TenantID: connection.TenantID,
		Resource: resource, Issuer: issuer,
		ClientIDCipher: authorization.ClientIDCipher, ClientSecretCipher: authorization.ClientSecretCipher,
		Scopes: authorization.Scopes,
	}, nil
}

// SaveState persists a one-use authorization state.
func (r *StoreRepository) SaveState(ctx context.Context, state *State) error {
	return r.store.InsertMCPOAuthState(ctx, &store.MCPOAuthState{
		State: state.State, ConnectionID: state.ConnectionID, UserID: state.UserID, TenantID: state.TenantID,
		CodeVerifier: state.CodeVerifier, RedirectURI: state.RedirectURI, Resource: state.Resource,
		IssuerURL: state.Issuer, AuthEndpoint: state.AuthorizationEndpoint, TokenEndpoint: state.TokenEndpoint,
		TokenAuthMethod: state.TokenAuthMethod, Scopes: state.Scopes, ExpiresAt: state.ExpiresAt,
	})
}

// ClaimState atomically consumes and maps an authorization state.
func (r *StoreRepository) ClaimState(ctx context.Context, state string) (*State, error) {
	row, err := r.store.ClaimMCPOAuthState(ctx, state)
	if err != nil || row == nil {
		return nil, err
	}
	return &State{
		State: row.State, ConnectionID: row.ConnectionID, UserID: row.UserID, TenantID: row.TenantID,
		CodeVerifier: row.CodeVerifier, RedirectURI: row.RedirectURI, Resource: row.Resource,
		Issuer: row.IssuerURL, AuthorizationEndpoint: row.AuthEndpoint, TokenEndpoint: row.TokenEndpoint,
		TokenAuthMethod: row.TokenAuthMethod, Scopes: row.Scopes, ExpiresAt: row.ExpiresAt,
	}, nil
}

// GetAuthorization loads one owner-scoped encrypted upstream token set.
func (r *StoreRepository) GetAuthorization(ctx context.Context, userID, connectionID uuid.UUID) (*Authorization, error) {
	row, err := r.store.GetMCPOAuthAuthorization(ctx, userID, connectionID)
	if err != nil || row == nil || len(row.AccessTokenCipher) == 0 {
		return nil, err
	}
	return authorizationFromStore(row), nil
}

// UpsertAuthorization updates an existing OAuth client row with its token set. Client
// configuration is created before Begin; a callback never manufactures missing client credentials.
func (r *StoreRepository) UpsertAuthorization(ctx context.Context, authorization *Authorization) error {
	row, err := r.store.GetMCPOAuthAuthorization(ctx, authorization.UserID, authorization.ConnectionID)
	if err != nil {
		return err
	}
	now := authorization.LastRefreshedAt
	issuer, authorizationEndpoint, tokenEndpoint := authorization.Issuer, authorization.AuthorizationEndpoint, authorization.TokenEndpoint
	resource, tokenType := authorization.Resource, authorization.TokenType
	if row == nil {
		return errors.New("MCP OAuth client configuration no longer exists")
	}
	row.IssuerURL, row.AuthorizationEndpoint, row.TokenEndpoint = &issuer, &authorizationEndpoint, &tokenEndpoint
	row.Resource, row.TokenType, row.TokenAuthMethod = &resource, &tokenType, authorization.TokenAuthMethod
	row.AccessTokenCipher = authorization.AccessTokenCipher
	row.RefreshTokenCipher = authorization.RefreshTokenCipher
	row.Scopes = authorization.Scopes
	row.ExpiresAt = authorization.ExpiresAt
	row.LastRefreshedAt = &now
	updated, err := r.store.UpdateMCPOAuthAuthorization(ctx, row)
	if err != nil {
		return err
	}
	if !updated {
		return errors.New("MCP OAuth authorization no longer exists")
	}
	return nil
}

func authorizationFromStore(row *store.MCPOAuthAuthorization) *Authorization {
	lastRefreshed := row.CreatedAt
	if row.LastRefreshedAt != nil {
		lastRefreshed = *row.LastRefreshedAt
	}
	return &Authorization{
		ConnectionID: row.ConnectionID, UserID: row.UserID, TenantID: row.TenantID,
		Resource: dereference(row.Resource), Issuer: dereference(row.IssuerURL),
		AuthorizationEndpoint: dereference(row.AuthorizationEndpoint), TokenEndpoint: dereference(row.TokenEndpoint),
		TokenAuthMethod: row.TokenAuthMethod, AccessTokenCipher: row.AccessTokenCipher,
		RefreshTokenCipher: row.RefreshTokenCipher, TokenType: dereference(row.TokenType),
		Scopes: row.Scopes, ExpiresAt: row.ExpiresAt, LastRefreshedAt: lastRefreshed,
	}
}

func dereference(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
